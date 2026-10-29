/*
 * transport.c - C0 (plain TCP) always; C1-C3 (TLS 1.3 via wolfSSL) when built with -DUSE_WOLFSSL.
 */
#define _GNU_SOURCE
#include "transport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#endif

struct transport {
    int fd;
    condition_t cond;
#ifdef USE_WOLFSSL
    WOLFSSL *ssl;
#endif
    char desc[160];
};

struct transport_listener {
    int fd;
    transport_cfg cfg;
};

/* ------------------------------------------------------------------ helpers */

int transport_parse_condition(const char *s)
{
    if (!s) return -1;
    if (!strcasecmp(s, "c0")) return COND_C0;
    if (!strcasecmp(s, "c1")) return COND_C1;
    if (!strcasecmp(s, "c2")) return COND_C2;
    if (!strcasecmp(s, "c3")) return COND_C3;
    return -1;
}

const char *transport_condition_name(condition_t c)
{
    static const char *n[] = {"C0", "C1", "C2", "C3"};
    return (c >= COND_C0 && c <= COND_C3) ? n[c] : "C?";
}

int transport_has_tls(void)
{
#ifdef USE_WOLFSSL
    return 1;
#else
    return 0;
#endif
}

static void set_sock_opts(int fd, int timeout_ms)
{
    int one = 1;
    /* Without TCP_NODELAY, Nagle + delayed ACK can add ~40 ms to small Modbus frames. */
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (timeout_ms > 0) {
        struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    }
}

/* ------------------------------------------------------------------ TLS context */

#ifdef USE_WOLFSSL
static WOLFSSL_CTX *g_ctx;
static int g_group = -1;   /* key-exchange group to force, -1 = library default */

static int group_from_name(const char *kem)
{
    if (!kem || !*kem) return -1;
    if (!strcasecmp(kem, "p256") || !strcasecmp(kem, "secp256r1")) return WOLFSSL_ECC_SECP256R1;
    if (!strcasecmp(kem, "p384") || !strcasecmp(kem, "secp384r1")) return WOLFSSL_ECC_SECP384R1;
    if (!strcasecmp(kem, "p521") || !strcasecmp(kem, "secp521r1")) return WOLFSSL_ECC_SECP521R1;
#ifdef HAVE_CURVE25519
    if (!strcasecmp(kem, "x25519")) return WOLFSSL_ECC_X25519;
#endif
#ifdef HAVE_PQC
    /* wolfSSL 5.6.3 + liboqs 0.8.0 names (pre-standard Kyber, as in Shahid et al.). */
    if (!strcasecmp(kem, "kyber512"))  return WOLFSSL_KYBER_LEVEL1;
    if (!strcasecmp(kem, "kyber768"))  return WOLFSSL_KYBER_LEVEL3;
    if (!strcasecmp(kem, "kyber1024")) return WOLFSSL_KYBER_LEVEL5;
    if (!strcasecmp(kem, "p256_kyber512"))  return WOLFSSL_P256_KYBER_LEVEL1;
    if (!strcasecmp(kem, "p384_kyber768"))  return WOLFSSL_P384_KYBER_LEVEL3;
    if (!strcasecmp(kem, "p521_kyber1024")) return WOLFSSL_P521_KYBER_LEVEL5;
#endif
    return -2;
}

static int load_file(int rc, const char *what, const char *path)
{
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr, "transport: failed to load %s from %s (rc=%d)\n", what, path, rc);
        return -1;
    }
    return 0;
}
#endif

int transport_global_init(const transport_cfg *cfg, int is_server)
{
    if (cfg->cond == COND_C0) return 0;
#ifndef USE_WOLFSSL
    (void)is_server;
    fprintf(stderr, "transport: %s needs TLS; rebuild with `make TLS=1 WOLFSSL_PREFIX=...`\n",
            transport_condition_name(cfg->cond));
    return -1;
#else
    if (!cfg->cert_dir) {
        fprintf(stderr, "transport: --certs DIR is required for %s\n", transport_condition_name(cfg->cond));
        return -1;
    }
    g_group = group_from_name(cfg->kem);
    if (g_group == -2) {
        fprintf(stderr, "transport: unknown or unsupported KEM/group '%s' in this wolfSSL build\n", cfg->kem);
        return -1;
    }
    wolfSSL_Init();
    g_ctx = wolfSSL_CTX_new(is_server ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method());
    if (!g_ctx) { fprintf(stderr, "transport: wolfSSL_CTX_new failed\n"); return -1; }

    char ca[512], cert[512], key[512];
    const char *who = is_server ? "server" : "client";
    snprintf(ca, sizeof ca, "%s/ca.pem", cfg->cert_dir);
    snprintf(cert, sizeof cert, "%s/%s.pem", cfg->cert_dir, who);
    snprintf(key, sizeof key, "%s/%s.key", cfg->cert_dir, who);

    if (load_file(wolfSSL_CTX_load_verify_locations(g_ctx, ca, NULL), "CA", ca)) return -1;
    if (load_file(wolfSSL_CTX_use_certificate_chain_file(g_ctx, cert), "certificate", cert)) return -1;
    if (load_file(wolfSSL_CTX_use_PrivateKey_file(g_ctx, key, WOLFSSL_FILETYPE_PEM), "private key", key)) return -1;

    const char *cipher = cfg->cipher ? cfg->cipher : "TLS13-AES256-GCM-SHA384";
    if (wolfSSL_CTX_set_cipher_list(g_ctx, cipher) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "transport: cipher '%s' not available\n", cipher);
        return -1;
    }
    /* Mutual authentication, as in the Modbus/TCP Security spec: both sides present certificates. */
    if (is_server)
        wolfSSL_CTX_set_verify(g_ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    else
        wolfSSL_CTX_set_verify(g_ctx, WOLFSSL_VERIFY_PEER, NULL);

    if (g_group >= 0) {
        int groups[1] = {g_group};
        if (wolfSSL_CTX_set_groups(g_ctx, groups, 1) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "transport: could not restrict groups to '%s'\n", cfg->kem);
            return -1;
        }
    }
    return 0;
#endif
}

void transport_global_cleanup(void)
{
#ifdef USE_WOLFSSL
    if (g_ctx) { wolfSSL_CTX_free(g_ctx); g_ctx = NULL; wolfSSL_Cleanup(); }
#endif
}

/* ------------------------------------------------------------------ TLS per-connection */

#ifdef USE_WOLFSSL
static int tls_wrap(transport *t, int is_server)
{
    char err[WOLFSSL_MAX_ERROR_SZ];
    t->ssl = wolfSSL_new(g_ctx);
    if (!t->ssl) { fprintf(stderr, "transport: wolfSSL_new failed\n"); return -1; }
    wolfSSL_set_fd(t->ssl, t->fd);
    if (!is_server && g_group >= 0) {
        /* Send a key share for exactly this group so there is no HelloRetryRequest round trip. */
        if (wolfSSL_UseKeyShare(t->ssl, (word16)g_group) != WOLFSSL_SUCCESS) {
            fprintf(stderr, "transport: wolfSSL_UseKeyShare failed\n");
            return -1;
        }
    }
    int rc = is_server ? wolfSSL_accept(t->ssl) : wolfSSL_connect(t->ssl);
    if (rc != WOLFSSL_SUCCESS) {
        int e = wolfSSL_get_error(t->ssl, rc);
        fprintf(stderr, "transport: TLS handshake failed: %d %s\n", e, wolfSSL_ERR_error_string(e, err));
        return -1;
    }
    const char *group = NULL;
#if defined(HAVE_ECC) || defined(HAVE_PQC)
    group = wolfSSL_get_curve_name(t->ssl);
#endif
    snprintf(t->desc, sizeof t->desc, "%s %s group=%s", wolfSSL_get_version(t->ssl),
             wolfSSL_get_cipher_name(t->ssl), group ? group : "?");
    return 0;
}
#endif

/* ------------------------------------------------------------------ connect / listen */

transport *transport_connect(const transport_cfg *cfg, const char *host, int port)
{
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *res, *ai;
    int rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc) { fprintf(stderr, "transport: %s: %s\n", host, gai_strerror(rc)); return NULL; }

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        set_sock_opts(fd, cfg->timeout_ms);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { fprintf(stderr, "transport: connect %s:%d: %s\n", host, port, strerror(errno)); return NULL; }

    transport *t = calloc(1, sizeof *t);
    t->fd = fd;
    t->cond = cfg->cond;
    snprintf(t->desc, sizeof t->desc, "plain TCP");
    if (cfg->cond != COND_C0) {
#ifdef USE_WOLFSSL
        if (tls_wrap(t, 0)) { transport_close(t); return NULL; }
#else
        transport_close(t);
        return NULL;
#endif
    }
    return t;
}

transport_listener *transport_listen(const transport_cfg *cfg, const char *bind_addr, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return NULL; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    if (inet_pton(AF_INET, bind_addr ? bind_addr : "0.0.0.0", &sa.sin_addr) != 1) {
        fprintf(stderr, "transport: bad bind address %s\n", bind_addr);
        close(fd);
        return NULL;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) || listen(fd, 8)) {
        fprintf(stderr, "transport: bind/listen port %d: %s\n", port, strerror(errno));
        close(fd);
        return NULL;
    }
    transport_listener *l = calloc(1, sizeof *l);
    l->fd = fd;
    l->cfg = *cfg;
    return l;
}

transport *transport_accept(transport_listener *l)
{
    int fd = accept(l->fd, NULL, NULL);
    if (fd < 0) { if (errno != EINTR) perror("accept"); return NULL; }   /* EINTR: caller checks its stop flag */
    set_sock_opts(fd, l->cfg.timeout_ms);
    transport *t = calloc(1, sizeof *t);
    t->fd = fd;
    t->cond = l->cfg.cond;
    snprintf(t->desc, sizeof t->desc, "plain TCP");
    if (t->cond != COND_C0) {
#ifdef USE_WOLFSSL
        if (tls_wrap(t, 1)) { transport_close(t); return NULL; }
#else
        transport_close(t);
        return NULL;
#endif
    }
    return t;
}

void transport_listener_close(transport_listener *l)
{
    if (!l) return;
    close(l->fd);
    free(l);
}

/* ------------------------------------------------------------------ I/O */

ssize_t transport_send_all(transport *t, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n;
#ifdef USE_WOLFSSL
        if (t->ssl) {
            n = wolfSSL_write(t->ssl, p + done, (int)(len - done));
            if (n <= 0) return -1;
        } else
#endif
        {
            n = send(t->fd, p + done, len - done, MSG_NOSIGNAL);
            if (n < 0) return -1;   /* includes EINTR (Ctrl-C/kill) and SO_RCVTIMEO timeouts */
        }
        done += (size_t)n;
    }
    return (ssize_t)done;
}

ssize_t transport_recv_exact(transport *t, void *buf, size_t len)
{
    unsigned char *p = buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n;
#ifdef USE_WOLFSSL
        if (t->ssl) {
            n = wolfSSL_read(t->ssl, p + done, (int)(len - done));
            if (n <= 0) {
                int e = wolfSSL_get_error(t->ssl, (int)n);
                if (e == WOLFSSL_ERROR_ZERO_RETURN || e == SOCKET_PEER_CLOSED_E) return done ? -1 : 0;
                return -1;
            }
        } else
#endif
        {
            n = recv(t->fd, p + done, len - done, 0);
            if (n == 0) return done ? -1 : 0;   /* closed mid-frame is an error */
            if (n < 0) return -1;   /* includes EINTR (Ctrl-C/kill) and SO_RCVTIMEO timeouts */
        }
        done += (size_t)n;
    }
    return (ssize_t)done;
}

void transport_close(transport *t)
{
    if (!t) return;
#ifdef USE_WOLFSSL
    if (t->ssl) { wolfSSL_shutdown(t->ssl); wolfSSL_free(t->ssl); }
#endif
    if (t->fd >= 0) close(t->fd);
    free(t);
}

const char *transport_describe(transport *t)
{
    return t ? t->desc : "";
}
