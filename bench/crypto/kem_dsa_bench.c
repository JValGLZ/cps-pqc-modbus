/* bench/crypto/kem_dsa_bench.c -- tracker row 5: KEM / signature microbenchmarks.
 *
 * Times the primitives each TLS condition actually runs, through the same libraries the handshake uses:
 *   PQC (liboqs 0.8.0, what wolfSSL --with-liboqs calls):
 *     Kyber512/768/1024   keygen, encaps, decaps
 *     Dilithium2/3/5      keygen, sign, verify
 *   Classical (wolfCrypt 5.6.3, what C1 uses):
 *     X25519, P-256 ECDH  keygen, derive (one TLS key share = keygen + derive per side)
 *     ECDSA P-256         keygen, sign, verify (SHA-256 digest of the message)
 *
 * Method: --runs R runs (default 30); in each run every op is executed --iters N times (default 1000)
 * after --warmup W untimed calls, and the run records the mean us/op. Report mean +/- std across runs.
 * Output rows use the shared CSV schema (phase MICRO, op = <alg>-<operation>, trial = run, unit us,
 * bytes = public key / ciphertext / signature size where relevant).
 *
 *   bench/crypto/run_microbench.sh            # builds + runs, CSV under results/raw/<host>/<date>/
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/version.h>

#include <oqs/oqs.h>

static int ITERS = 1000, RUNS = 30, WARMUP = 50;
static FILE *out;
static char host[256], stamp[32], notes_base[256];

static double now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void host_label(char *o, size_t cap) /* same rule as harness/mb_poll.c */
{
    char h[200] = "unknown", rel[256] = "";
    gethostname(h, sizeof h - 1);
    FILE *f = fopen("/proc/sys/kernel/osrelease", "r");
    int wsl = 0;
    if (f) {
        if (fgets(rel, sizeof rel, f) && (strcasestr(rel, "microsoft") || strcasestr(rel, "wsl"))) wsl = 1;
        fclose(f);
    }
    snprintf(o, cap, "%s%s", h, wsl ? "-wsl2" : "");
}

static void row(const char *cond, const char *kem, const char *sig, const char *op, int run, double us,
                long bytes)
{
    char ts[40];
    time_t t = time(NULL);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    char b[24] = "";
    if (bytes > 0) snprintf(b, sizeof b, "%ld", bytes);
    fprintf(out, "MICRO-%s,%s,MICRO,%s,%s,%s,%s,%d,%.4f,us,%s,iters=%d;%s,%s\n", stamp, host, cond, kem, sig, op,
            run, us, b, ITERS, notes_base, ts);
}

/* Times ITERS calls of body(ctx); returns mean us/op. body returns nonzero on failure. */
typedef int (*op_fn)(void *);
static double time_op(op_fn body, void *ctx)
{
    for (int i = 0; i < WARMUP; i++)
        if (body(ctx)) { fprintf(stderr, "op failed in warmup\n"); exit(1); }
    double t0 = now_us();
    for (int i = 0; i < ITERS; i++)
        if (body(ctx)) { fprintf(stderr, "op failed\n"); exit(1); }
    return (now_us() - t0) / ITERS;
}

/* ---------- liboqs KEM ---------- */
typedef struct { OQS_KEM *k; uint8_t *pk, *sk, *ct, *ss; } kem_ctx;
static int kem_keygen(void *c) { kem_ctx *x = c; return OQS_KEM_keypair(x->k, x->pk, x->sk) != OQS_SUCCESS; }
static int kem_encaps(void *c) { kem_ctx *x = c; return OQS_KEM_encaps(x->k, x->ct, x->ss, x->pk) != OQS_SUCCESS; }
static int kem_decaps(void *c) { kem_ctx *x = c; return OQS_KEM_decaps(x->k, x->ss, x->ct, x->sk) != OQS_SUCCESS; }

static void bench_kem(const char *label, const char *alg)
{
    kem_ctx x = {OQS_KEM_new(alg)};
    if (!x.k) { fprintf(stderr, "%s not enabled in liboqs\n", alg); return; }
    x.pk = malloc(x.k->length_public_key); x.sk = malloc(x.k->length_secret_key);
    x.ct = malloc(x.k->length_ciphertext); x.ss = malloc(x.k->length_shared_secret);
    kem_keygen(&x); kem_encaps(&x);
    char op[64];
    for (int r = 1; r <= RUNS; r++) {
        snprintf(op, sizeof op, "%s-keygen", label); row("PQC", label, "", op, r, time_op(kem_keygen, &x), (long)x.k->length_public_key);
        snprintf(op, sizeof op, "%s-encaps", label); row("PQC", label, "", op, r, time_op(kem_encaps, &x), (long)x.k->length_ciphertext);
        kem_encaps(&x);
        snprintf(op, sizeof op, "%s-decaps", label); row("PQC", label, "", op, r, time_op(kem_decaps, &x), 0);
    }
    fprintf(stderr, "  %-10s pk %4zu B  ct %4zu B  (%s)\n", label, x.k->length_public_key, x.k->length_ciphertext,
            x.k->method_name);
    free(x.pk); free(x.sk); free(x.ct); free(x.ss); OQS_KEM_free(x.k);
}

/* ---------- liboqs signatures ---------- */
typedef struct { OQS_SIG *s; uint8_t *pk, *sk, *sig, msg[64]; size_t siglen; } sig_ctx;
static int sig_keygen(void *c) { sig_ctx *x = c; return OQS_SIG_keypair(x->s, x->pk, x->sk) != OQS_SUCCESS; }
static int sig_sign(void *c)
{
    sig_ctx *x = c;
    return OQS_SIG_sign(x->s, x->sig, &x->siglen, x->msg, sizeof x->msg, x->sk) != OQS_SUCCESS;
}
static int sig_verify(void *c)
{
    sig_ctx *x = c;
    return OQS_SIG_verify(x->s, x->msg, sizeof x->msg, x->sig, x->siglen, x->pk) != OQS_SUCCESS;
}

static void bench_sig(const char *label, const char *alg)
{
    sig_ctx x = {OQS_SIG_new(alg)};
    if (!x.s) { fprintf(stderr, "%s not enabled in liboqs\n", alg); return; }
    x.pk = malloc(x.s->length_public_key); x.sk = malloc(x.s->length_secret_key);
    x.sig = malloc(x.s->length_signature);
    OQS_randombytes(x.msg, sizeof x.msg);
    sig_keygen(&x); sig_sign(&x);
    char op[64];
    for (int r = 1; r <= RUNS; r++) {
        snprintf(op, sizeof op, "%s-keygen", label); row("PQC", "", label, op, r, time_op(sig_keygen, &x), (long)x.s->length_public_key);
        sig_sign(&x);
        snprintf(op, sizeof op, "%s-sign", label); row("PQC", "", label, op, r, time_op(sig_sign, &x), (long)x.s->length_signature);
        snprintf(op, sizeof op, "%s-verify", label); row("PQC", "", label, op, r, time_op(sig_verify, &x), 0);
    }
    fprintf(stderr, "  %-10s pk %4zu B  sig %4zu B  (%s)\n", label, x.s->length_public_key, x.s->length_signature,
            x.s->method_name);
    free(x.pk); free(x.sk); free(x.sig); OQS_SIG_free(x.s);
}

/* ---------- wolfCrypt classical ---------- */
static WC_RNG rng;

typedef struct { curve25519_key a, b; byte ss[32]; } x25519_ctx;
static int x25519_keygen(void *c)
{
    x25519_ctx *x = c;
    wc_curve25519_free(&x->a); wc_curve25519_init(&x->a);
    return wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &x->a);
}
static int x25519_derive(void *c)
{
    x25519_ctx *x = c;
    word32 n = sizeof x->ss;
    return wc_curve25519_shared_secret(&x->a, &x->b, x->ss, &n);
}

typedef struct { ecc_key a, b; byte ss[66], hash[32], sig[ECC_MAX_SIG_SIZE]; word32 siglen; } ecc_ctx;
static int p256_keygen(void *c)
{
    ecc_ctx *x = c;
    wc_ecc_free(&x->a); wc_ecc_init(&x->a);
    int r = wc_ecc_make_key_ex(&rng, 32, &x->a, ECC_SECP256R1);
    if (r == 0) r = wc_ecc_set_rng(&x->a, &rng);
    return r;
}
static int p256_derive(void *c)
{
    ecc_ctx *x = c;
    word32 n = sizeof x->ss;
    return wc_ecc_shared_secret(&x->a, &x->b, x->ss, &n);
}
static int ecdsa_sign(void *c)
{
    ecc_ctx *x = c;
    x->siglen = sizeof x->sig;
    return wc_ecc_sign_hash(x->hash, sizeof x->hash, x->sig, &x->siglen, &rng, &x->a);
}
static int ecdsa_verify(void *c)
{
    ecc_ctx *x = c;
    int ok = 0;
    int r = wc_ecc_verify_hash(x->sig, x->siglen, x->hash, sizeof x->hash, &ok, &x->a);
    return r || !ok;
}

static void bench_classical(void)
{
    x25519_ctx xc;
    wc_curve25519_init(&xc.a); wc_curve25519_init(&xc.b);
    if (wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &xc.b) || x25519_keygen(&xc)) { fprintf(stderr, "x25519 setup failed\n"); exit(1); }
    for (int r = 1; r <= RUNS; r++) {
        row("CLASSICAL", "x25519", "", "x25519-keygen", r, time_op(x25519_keygen, &xc), 32);
        row("CLASSICAL", "x25519", "", "x25519-derive", r, time_op(x25519_derive, &xc), 0);
    }

    ecc_ctx ec;
    wc_ecc_init(&ec.a); wc_ecc_init(&ec.b);
    if (wc_ecc_make_key_ex(&rng, 32, &ec.b, ECC_SECP256R1) || p256_keygen(&ec)) { fprintf(stderr, "p256 setup failed\n"); exit(1); }
    byte msg[64];
    wc_RNG_GenerateBlock(&rng, msg, sizeof msg);
    wc_Sha256Hash(msg, sizeof msg, ec.hash);
    for (int r = 1; r <= RUNS; r++) {
        row("CLASSICAL", "p256", "", "p256-keygen", r, time_op(p256_keygen, &ec), 65);
        row("CLASSICAL", "p256", "", "p256-derive", r, time_op(p256_derive, &ec), 0);
        ecdsa_sign(&ec);
        row("CLASSICAL", "", "ecdsa-p256", "ecdsa-p256-sign", r, time_op(ecdsa_sign, &ec), (long)ec.siglen);
        row("CLASSICAL", "", "ecdsa-p256", "ecdsa-p256-verify", r, time_op(ecdsa_verify, &ec), 0);
    }
    fprintf(stderr, "  x25519, p256 ECDH, ecdsa-p256 (wolfCrypt %s)\n", LIBWOLFSSL_VERSION_STRING);
}

int main(int argc, char **argv)
{
    const char *outpath = NULL;
    int cpu = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) ITERS = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--runs") && i + 1 < argc) RUNS = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) WARMUP = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cpu") && i + 1 < argc) cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) outpath = argv[++i];
        else { fprintf(stderr, "usage: kem_dsa_bench [--runs 30] [--iters 1000] [--warmup 50] [--cpu N] --out FILE\n"); return 2; }
    }
    if (!outpath) { fprintf(stderr, "--out FILE required\n"); return 2; }
    if (cpu >= 0) {
        cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof set, &set)) perror("sched_setaffinity");
    }
    out = fopen(outpath, "w");
    if (!out) { perror(outpath); return 1; }
    host_label(host, sizeof host);
    time_t t = time(NULL);
    strftime(stamp, sizeof stamp, "%H%M%S", localtime(&t));

    OQS_init();
#if defined(__x86_64__)
    snprintf(notes_base, sizeof notes_base, "oqs_avx2=%d;wolfssl_sp_asm=%s",
             OQS_CPU_has_extension(OQS_CPU_EXT_AVX2),
#elif defined(__aarch64__)
    snprintf(notes_base, sizeof notes_base, "oqs_neon=%d;wolfssl_sp_asm=%s",
             OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON),
#else
    snprintf(notes_base, sizeof notes_base, "cpu_ext=unknown;wolfssl_sp_asm=%s",
#endif
#if defined(WOLFSSL_SP_X86_64_ASM) || defined(WOLFSSL_SP_ARM64_ASM)
             "1"
#else
             "0"
#endif
    );
    if (wc_InitRng(&rng)) { fprintf(stderr, "wc_InitRng failed\n"); return 1; }

    fprintf(out, "run_id,host,phase,condition,kem,sig,op,trial,value,unit,bytes,notes,timestamp\n");
    fprintf(stderr, "kem_dsa_bench: %d runs x %d iters (%s)\n", RUNS, ITERS, notes_base);
    bench_kem("kyber512", OQS_KEM_alg_kyber_512);
    bench_kem("kyber768", OQS_KEM_alg_kyber_768);
    bench_kem("kyber1024", OQS_KEM_alg_kyber_1024);
    bench_sig("dilithium2", OQS_SIG_alg_dilithium_2);
    bench_sig("dilithium3", OQS_SIG_alg_dilithium_3);
    bench_sig("dilithium5", OQS_SIG_alg_dilithium_5);
    bench_classical();

    wc_FreeRng(&rng);
    OQS_destroy();
    fclose(out);
    fprintf(stderr, "csv: %s\n", outpath);
    return 0;
}
