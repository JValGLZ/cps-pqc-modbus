/*
 * transport.h - the one interface Modbus code uses to move bytes.
 *
 * Shared contract item 3: Modbus code never touches sockets or TLS directly.
 *   C0  plain TCP                         (always built)
 *   C1  TLS 1.3, classical (ECDHE + ECDSA) (built with TLS=1, stock wolfSSL)
 *   C2  TLS 1.3, PQC (Kyber + Dilithium)   (built with TLS=1 against wolfSSL --with-liboqs)
 *   C3  TLS 1.3, hybrid key exchange       (same, hybrid group)
 *
 * The key-exchange group comes from cfg->kem; the signature algorithm comes from
 * the certificates in cfg->cert_dir (ca.pem, server.pem/.key, client.pem/.key).
 */
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stddef.h>
#include <sys/types.h>

typedef enum { COND_C0 = 0, COND_C1 = 1, COND_C2 = 2, COND_C3 = 3 } condition_t;

typedef struct transport_cfg {
    condition_t cond;
    const char *kem;      /* key-exchange group: "p256", "x25519", "kyber512", "kyber768", "kyber1024",
                             "p256_kyber512", ... ; ignored for C0 */
    const char *sig;      /* label only (e.g. "ecdsa-p256", "dilithium3"); the certs decide the real algorithm */
    const char *cert_dir; /* directory holding ca.pem, server.pem, server.key, client.pem, client.key */
    const char *cipher;   /* TLS 1.3 suite; NULL = TLS13-AES256-GCM-SHA384 (Shahid et al.) */
    int timeout_ms;       /* socket receive/send timeout, 0 = none */
} transport_cfg;

typedef struct transport transport;                 /* one established connection */
typedef struct transport_listener transport_listener;

/* Call once per process before anything else (loads TLS context/certs for C1-C3). 0 on success. */
int  transport_global_init(const transport_cfg *cfg, int is_server);
void transport_global_cleanup(void);

/* Client side: TCP connect + (C1-C3) full TLS handshake. NULL on failure (reason on stderr). */
transport *transport_connect(const transport_cfg *cfg, const char *host, int port);

/* Server side. */
transport_listener *transport_listen(const transport_cfg *cfg, const char *bind_addr, int port);
transport *transport_accept(transport_listener *l);   /* blocks; does the TLS handshake for C1-C3 */
void transport_listener_close(transport_listener *l);

/* Byte I/O. Return bytes moved, 0 on orderly close (recv only), -1 on error/timeout. */
ssize_t transport_send_all(transport *t, const void *buf, size_t len);
ssize_t transport_recv_exact(transport *t, void *buf, size_t len);

void transport_close(transport *t);

/* Human-readable negotiated parameters, e.g. "TLSv1.3 TLS13-AES256-GCM-SHA384 group=SECP256R1". */
const char *transport_describe(transport *t);

/* Parse "c0".."c3" (case-insensitive). Returns -1 if unknown. */
int transport_parse_condition(const char *s);
const char *transport_condition_name(condition_t c);

/* 1 if this binary was built with TLS support. */
int transport_has_tls(void);

#endif
