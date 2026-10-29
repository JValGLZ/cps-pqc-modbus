/*
 * mb_server - Modbus/TCP server (field device side) over C0/C1/C2/C3 transports.
 *
 * Holds N holding registers. Register 0 counts read requests (so captured traffic shows a value
 * changing over time); register i (i >= 1) starts at i. Serves one client connection at a time.
 *
 *   mb_server --port 1502 [--cond c0] [--regs 100] [--cpu 2] [--once]
 *   mb_server --port 1502 --cond c1 --kem p256 --certs certs/out/ecdsa-p256
 */
#define _GNU_SOURCE
#include <getopt.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "modbus.h"

static volatile sig_atomic_t g_stop;
static void on_signal(int s) { (void)s; g_stop = 1; }

static void usage(void)
{
    fprintf(stderr,
        "usage: mb_server [options]\n"
        "  --port N        TCP port (default 1502; 502 needs root, 802 is Modbus/TCP Security)\n"
        "  --bind ADDR     bind address (default 0.0.0.0)\n"
        "  --cond c0|c1|c2|c3   transport condition (default c0)\n"
        "  --kem NAME      key-exchange group for TLS (p256, x25519, kyber768, ...)\n"
        "  --sig LABEL     signature label (informational; certs decide)\n"
        "  --certs DIR     dir with ca.pem server.pem server.key (TLS only)\n"
        "  --regs N        number of holding registers (default 100)\n"
        "  --cpu N         pin to CPU N\n"
        "  --once          exit after the first client disconnects\n"
        "  --quiet         no per-connection log lines\n");
}

int main(int argc, char **argv)
{
    transport_cfg cfg = {.cond = COND_C0, .timeout_ms = 0};
    const char *bind_addr = "0.0.0.0";
    int port = 1502, nregs = 100, cpu = -1, once = 0, quiet = 0;

    static const struct option opts[] = {
        {"port", 1, 0, 'p'}, {"bind", 1, 0, 'b'}, {"cond", 1, 0, 'c'}, {"kem", 1, 0, 'k'},
        {"sig", 1, 0, 's'},  {"certs", 1, 0, 'C'}, {"regs", 1, 0, 'r'}, {"cpu", 1, 0, 'u'},
        {"once", 0, 0, 'o'}, {"quiet", 0, 0, 'q'}, {"help", 0, 0, 'h'}, {0, 0, 0, 0}};
    int o;
    while ((o = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (o) {
        case 'p': port = atoi(optarg); break;
        case 'b': bind_addr = optarg; break;
        case 'c':
            if (transport_parse_condition(optarg) < 0) { fprintf(stderr, "bad --cond %s\n", optarg); return 2; }
            cfg.cond = (condition_t)transport_parse_condition(optarg);
            break;
        case 'k': cfg.kem = optarg; break;
        case 's': cfg.sig = optarg; break;
        case 'C': cfg.cert_dir = optarg; break;
        case 'r': nregs = atoi(optarg); break;
        case 'u': cpu = atoi(optarg); break;
        case 'o': once = 1; break;
        case 'q': quiet = 1; break;
        default: usage(); return o == 'h' ? 0 : 2;
        }
    }
    if (nregs < 1 || nregs > 65535) { fprintf(stderr, "--regs must be 1..65535\n"); return 2; }

    if (cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof set, &set)) perror("sched_setaffinity");
    }

    struct sigaction sa = {.sa_handler = on_signal};
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    uint16_t *regs = calloc((size_t)nregs, sizeof *regs);
    for (int i = 1; i < nregs; i++) regs[i] = (uint16_t)i;

    if (transport_global_init(&cfg, 1)) return 1;
    transport_listener *l = transport_listen(&cfg, bind_addr, port);
    if (!l) return 1;
    fprintf(stderr, "mb_server: %s listening on %s:%d, %d registers%s\n",
            transport_condition_name(cfg.cond), bind_addr, port, nregs, transport_has_tls() ? " (TLS-capable build)" : "");

    uint8_t req[MB_MAX_ADU], resp[MB_MAX_ADU];
    while (!g_stop) {
        transport *t = transport_accept(l);
        if (!t) { if (g_stop) break; continue; }
        if (!quiet) fprintf(stderr, "mb_server: client connected (%s)\n", transport_describe(t));
        unsigned long served = 0;
        for (;;) {
            ssize_t n = mb_recv_adu(t, req, sizeof req);
            if (n <= 0) break;
            if (req[7] == MB_FC_READ_HOLDING) regs[0]++;
            size_t m = mb_server_handle(req, (size_t)n, resp, regs, (uint16_t)nregs);
            if (m == 0 || transport_send_all(t, resp, m) != (ssize_t)m) break;
            served++;
        }
        if (!quiet) fprintf(stderr, "mb_server: client closed after %lu requests\n", served);
        transport_close(t);
        if (once) break;
    }
    transport_listener_close(l);
    transport_global_cleanup();
    free(regs);
    return 0;
}
