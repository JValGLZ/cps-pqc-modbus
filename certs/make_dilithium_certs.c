/* certs/make_dilithium_certs.c
 * Generates a Dilithium-signed CA + server + client certificate chain for
 * one Dilithium level (2, 3, or 5), matching certs/out/<alg>/... layout.
 * Output is DER (cert: <who>.der, key: <who>.key.der) -- see note in repo
 * README about transport.c needing WOLFSSL_FILETYPE_ASN1 for these.
 * Known simplification: no subjectAltName/extendedKeyUsage extensions yet.
 * Usage: ./make_dilithium_certs 2|3|5
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <oqs/oqs.h>

#define DER_MAX 16384

static int write_file(const char* path, const byte* buf, word32 sz) {
    FILE* f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    size_t n = fwrite(buf, 1, sz, f);
    fclose(f);
    return (n == sz) ? 0 : -1;
}

/* transport.c (shared with the classical/C1 path) only knows how to load
 * PEM: ca.pem, <who>.pem, <who>.key via plain wolfSSL_CTX_* PEM functions.
 * Rather than teach shared code a second, DER-specific loading path, PEM-
 * encode here instead -- wc_DerToPem does the DER->PEM wrapping wolfSSL's
 * own PEM loaders expect, so C2/C3 reuses the exact same cert_dir
 * convention as C1 with zero transport.c changes.
 * CERT_TYPE / PKCS8_PRIVATEKEY_TYPE select the PEM header text; our key
 * DER really is PKCS8-wrapped (confirmed via wolfSSL's parse_private_key),
 * so PKCS8_PRIVATEKEY_TYPE's generic "BEGIN PRIVATE KEY" header is the
 * accurate one, not an algorithm-specific header. */
#define PEM_MAX (DER_MAX * 2)

static int write_pem(const char* path, const byte* der, word32 derSz, int pemType) {
    byte pem[PEM_MAX];
    int pemSz = wc_DerToPem(der, derSz, pem, sizeof(pem), pemType);
    if (pemSz <= 0) { fprintf(stderr, "wc_DerToPem(%s): %d\n", path, pemSz); return -1; }
    return write_file(path, pem, (word32)pemSz);
}

/* Minimal DER TLV header writer (lengths < 65536). */
static word32 der_hdr(byte* out, byte tag, word32 len) {
    word32 i = 0;
    out[i++] = tag;
    if (len < 0x80) { out[i++] = (byte)len; }
    else if (len <= 0xFF) { out[i++] = 0x81; out[i++] = (byte)len; }
    else { out[i++] = 0x82; out[i++] = (byte)(len >> 8); out[i++] = (byte)len; }
    return i;
}
static word32 der_hdr_len(word32 len) {
    return (len < 0x80) ? 2 : ((len <= 0xFF) ? 3 : 4);
}

/* wolfSSL 5.6.3's own reader (dilithium.c parse_private_key) strips
 * PKCS8 (incl. the outer OCTET STRING header), then ONE more OCTET STRING
 * header, then requires exactly KEY_SIZE + PUB_KEY_SIZE bytes remaining,
 * i.e. priv||pub. wc_Dilithium_PrivateKeyToDer writes priv only, so its
 * output is rejected by wolfSSL's own loader (-173). Build the layout the
 * reader actually expects, reusing the AlgorithmIdentifier bytes from
 * wolfSSL's output so the OID is exactly what it wants:
 *   SEQ { INT 0, AlgoId, OCTET { OCTET { priv || pub } } } */
static int build_priv_pub_pkcs8(const byte* ref, int refSz,
                                const uint8_t* priv, word32 privLen,
                                const uint8_t* pub, word32 pubLen,
                                byte* out, word32 outMax)
{
    word32 off, algoSz, innerLen, outerLen, seqLen, total, i = 0;
    if (refSz < 10 || ref[0] != 0x30) return -1;
    off = (ref[1] & 0x80) ? 2 + (ref[1] & 0x7F) : 2;   /* skip SEQ hdr */
    off += 3;                                          /* skip INT 0   */
    if (ref[off] != 0x30 || (ref[off + 1] & 0x80)) return -1;
    algoSz = 2 + ref[off + 1];

    innerLen = privLen + pubLen;
    outerLen = der_hdr_len(innerLen) + innerLen;
    seqLen   = 3 + algoSz + der_hdr_len(outerLen) + outerLen;
    total    = der_hdr_len(seqLen) + seqLen;
    if (total > outMax) return -1;

    i += der_hdr(out + i, 0x30, seqLen);
    out[i++] = 0x02; out[i++] = 0x01; out[i++] = 0x00;
    memcpy(out + i, ref + off, algoSz); i += algoSz;
    i += der_hdr(out + i, 0x04, outerLen);
    i += der_hdr(out + i, 0x04, innerLen);
    memcpy(out + i, priv, privLen); i += privLen;
    memcpy(out + i, pub, pubLen);   i += pubLen;
    return (int)i;
}

/* wolfSSL has no native Dilithium keygen in this build -- it only
 * signs/verifies/imports -- so liboqs generates the raw keypair and we
 * import it into a wolfSSL dilithium_key. */
static int make_dilithium_key(int level, const char* oqs_alg,
                               dilithium_key* key, const char* keyout_path)
{
    OQS_SIG* sig = OQS_SIG_new(oqs_alg);
    if (!sig) { fprintf(stderr, "OQS_SIG_new(%s) failed\n", oqs_alg); return -1; }

    uint8_t* pub = malloc(sig->length_public_key);
    uint8_t* priv = malloc(sig->length_secret_key);
    if (!pub || !priv) { fprintf(stderr, "oom\n"); return -1; }

    if (OQS_SIG_keypair(sig, pub, priv) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_SIG_keypair failed\n"); return -1;
    }

    int ret = wc_dilithium_init(key);
    if (ret != 0) { fprintf(stderr, "wc_dilithium_init: %d\n", ret); return -1; }

    ret = wc_dilithium_set_level(key, (byte)level);
    if (ret != 0) { fprintf(stderr, "wc_dilithium_set_level: %d\n", ret); return -1; }

    /* wolfSSL's import_private_key/import_private_only both expect a
     * PKCS8-wrapped blob (they run it through an ASN.1 parser first) --
     * liboqs gives us genuinely raw bytes, so we write them into key->k
     * directly, which is exactly what those functions do internally
     * after unwrapping. key->k is sized to hold the full raw secret key
     * (DILITHIUM_LEVELx_KEY_SIZE == liboqs's own length_secret_key). */
    if (sig->length_secret_key > sizeof(key->k)) {
        fprintf(stderr, "private key too large for key->k buffer\n"); return -1;
    }
    memcpy(key->k, priv, sig->length_secret_key);
    key->prvKeySet = 1;

    ret = wc_dilithium_import_public(pub, (word32)sig->length_public_key, key);
    if (ret != 0) { fprintf(stderr, "wc_dilithium_import_public: %d\n", ret); return -1; }

    byte der[DER_MAX];
    int derSz = wc_Dilithium_PrivateKeyToDer(key, der, sizeof(der));
    if (derSz <= 0) { fprintf(stderr, "wc_Dilithium_PrivateKeyToDer: %d\n", derSz); return -1; }
    {
        byte fixed[DER_MAX];
        int fixedSz = build_priv_pub_pkcs8(der, derSz,
                          priv, (word32)sig->length_secret_key,
                          pub,  (word32)sig->length_public_key,
                          fixed, sizeof(fixed));
        if (fixedSz <= 0) { fprintf(stderr, "build_priv_pub_pkcs8 failed\n"); return -1; }
        memcpy(der, fixed, (size_t)fixedSz);
        derSz = fixedSz;
    }
    if (write_pem(keyout_path, der, (word32)derSz, PKCS8_PRIVATEKEY_TYPE) != 0) return -1;

    OQS_SIG_free(sig);
    free(pub); free(priv);
    return 0;
}

static void set_subject_cn(Cert* cert, const char* cn) {
    strncpy(cert->subject.commonName, cn, CTC_NAME_SIZE - 1);
    cert->subject.commonNameEnc = CTC_UTF8;
}

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s 2|3|5\n", argv[0]); return 2; }
    int level = atoi(argv[1]);
    const char* oqs_alg;
    /* Two DIFFERENT "keyType" concepts in wolfSSL, easy to conflate:
     *  - mkKeyType: passed to wc_MakeCert_ex/wc_SignCert_ex, used to cast
     *    our void* key pointer -- must be the DILITHIUM_LEVELx_TYPE enum
     *    (asn_public.h, public).
     *  - certKeyType: stored in cert.keyType, used later by the
     *    public-key-DER-encoding switch in asn.c -- must be the
     *    DILITHIUM_LEVELx_KEY enum (asn.h, internal; not included here,
     *    so literal: LEVEL2=18, LEVEL3=19, LEVEL5=20). */
    int mkKeyType, certKeyType, sigType;
    switch (level) {
        case 2: oqs_alg = OQS_SIG_alg_dilithium_2; mkKeyType = DILITHIUM_LEVEL2_TYPE; certKeyType = 18; sigType = CTC_DILITHIUM_LEVEL2; break;
        case 3: oqs_alg = OQS_SIG_alg_dilithium_3; mkKeyType = DILITHIUM_LEVEL3_TYPE; certKeyType = 19; sigType = CTC_DILITHIUM_LEVEL3; break;
        case 5: oqs_alg = OQS_SIG_alg_dilithium_5; mkKeyType = DILITHIUM_LEVEL5_TYPE; certKeyType = 20; sigType = CTC_DILITHIUM_LEVEL5; break;
        default: fprintf(stderr, "level must be 2, 3, or 5\n"); return 2;
    }

    char outdir[256], path[512];
    snprintf(outdir, sizeof(outdir), "out/dilithium%d", level);
    char mkdirCmd[300]; snprintf(mkdirCmd, sizeof(mkdirCmd), "mkdir -p %s", outdir);
    system(mkdirCmd);

    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) { fprintf(stderr, "wc_InitRng failed\n"); return 1; }

    /* ---------- CA (self-signed) ---------- */
    dilithium_key caKey;
    snprintf(path, sizeof(path), "%s/ca.key", outdir);
    if (make_dilithium_key(level, oqs_alg, &caKey, path) != 0) return 1;

    Cert caCert;
    wc_InitCert(&caCert);
    set_subject_cn(&caCert, "CPS Modbus PQC Test CA");
    caCert.selfSigned = 1;
    caCert.isCA = 1;
    caCert.daysValid = 365;
    caCert.sigType = sigType;
    caCert.keyType = certKeyType;

    byte caDer[DER_MAX];
    int caRet = wc_MakeCert_ex(&caCert, caDer, sizeof(caDer), mkKeyType, &caKey, &rng);
    if (caRet <= 0) { fprintf(stderr, "wc_MakeCert_ex(ca): %d\n", caRet); return 1; }
    int caDerSz = wc_SignCert_ex(caCert.bodySz, sigType, caDer, sizeof(caDer), mkKeyType, &caKey, &rng);
    if (caDerSz <= 0) { fprintf(stderr, "wc_SignCert_ex(ca): %d\n", caDerSz); return 1; }
    snprintf(path, sizeof(path), "%s/ca.pem", outdir);
    if (write_pem(path, caDer, (word32)caDerSz, CERT_TYPE) != 0) return 1;
    printf("  ca:     %d bytes\n", caDerSz);

    /* ---------- server + client (CA-signed) ---------- */
    const char* who[2] = { "server", "client" };
    for (int i = 0; i < 2; i++) {
        dilithium_key eeKey;
        snprintf(path, sizeof(path), "%s/%s.key", outdir, who[i]);
        if (make_dilithium_key(level, oqs_alg, &eeKey, path) != 0) return 1;

        Cert eeCert;
        wc_InitCert(&eeCert);
        char cn[64]; snprintf(cn, sizeof(cn), "modbus-%s", who[i]);
        set_subject_cn(&eeCert, cn);
        eeCert.selfSigned = 0;
        eeCert.isCA = 0;
        eeCert.daysValid = 365;
        eeCert.sigType = sigType;
        eeCert.keyType = certKeyType;
        if (wc_SetIssuerBuffer(&eeCert, caDer, caDerSz) != 0) {
            fprintf(stderr, "wc_SetIssuerBuffer(%s) failed\n", who[i]); return 1;
        }

        byte eeDer[DER_MAX];
        int eeRet = wc_MakeCert_ex(&eeCert, eeDer, sizeof(eeDer), mkKeyType, &eeKey, &rng);
        if (eeRet <= 0) { fprintf(stderr, "wc_MakeCert_ex(%s): %d\n", who[i], eeRet); return 1; }
        /* signed BY the CA key */
        int eeDerSz = wc_SignCert_ex(eeCert.bodySz, sigType, eeDer, sizeof(eeDer), mkKeyType, &caKey, &rng);
        if (eeDerSz <= 0) { fprintf(stderr, "wc_SignCert_ex(%s): %d\n", who[i], eeDerSz); return 1; }
        snprintf(path, sizeof(path), "%s/%s.pem", outdir, who[i]);
        if (write_pem(path, eeDer, (word32)eeDerSz, CERT_TYPE) != 0) return 1;
        printf("  %s: %d bytes\n", who[i], eeDerSz);

        wc_dilithium_free(&eeKey);
    }

    wc_dilithium_free(&caKey);
    wc_FreeRng(&rng);
    printf("dilithium%d chain written to %s/\n", level, outdir);
    return 0;
}
