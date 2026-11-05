/*
 * mb_server - Modbus/TCP server (field device side) over C0/C1/C2/C3 transports.
 *
 * Holds N holding registers. Register 0 counts read requests (so captured traffic shows a value
 * changing over time); register i (i >= 1) starts at i. Serves one client connection at a time.
 *
 * Sensor (--sensor): a separate thread samples the sensor every --sample-ms and stores the latest
 * reading in register R (--sensor-reg, default 1) as round(value * scale), and a sample counter in
 * register R+1. Modbus requests are answered from those stored values, so a slow sensor never adds
 * to the measured poll time.
 *   --sensor fake        simulated temperature, about 22.5 C +/- 2 C (no hardware needed)
 *   --sensor file:PATH   reads a number from PATH each sample; any script (e.g. Python reading a
 *                        DHT22/BME280 on the Pi) can keep that file updated
 *
 *   mb_server --port 1502 [--cond c0] [--regs 100] [--cpu 2] [--once]
 *   mb_server --port 1502 --cond c1 --kem p256 --certs certs/out/ecdsa-p256
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "modbus.h"

static volatile sig_atomic_t g_stop;
static void on_signal(int s) { (void)s; g_stop = 1; }

/* ---- sensor sampling thread */
static pthread_mutex_t g_regs_lock = PTHREAD_MUTEX_INITIALIZER;
static uint16_t *g_regs;
static int g_nregs;
static struct {
    const char *spec;   /* "fake" or "file:PATH" */
    int reg, sample_ms;
    double scale;
} g_sensor = {NULL, 1, 1000, 10.0};

static int read_sensor(double *out)
{
    if (!strcmp(g_sensor.spec, "fake")) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        double t = (double)ts.tv_sec + ts.tv_nsec / 1e9;
        *out = 22.5 + 2.0 * sin(2 * M_PI * t / 60.0) + 0.1 * ((double)(rand() % 21) - 10) / 10.0;
        return 0;
    }
    const char *path = g_sensor.spec + 5;   /* after "file:" */
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int ok = fscanf(f, "%lf", out) == 1;
    fclose(f);
    return ok ? 0 : -1;
}

static void *sensor_thread(void *arg)
{
    (void)arg;
    uint16_t samples = 0;
    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);
    while (!g_stop) {
        double v;
        if (read_sensor(&v) == 0) {
            long scaled = lround(v * g_sensor.scale);
            if (scaled < 0) scaled = 0;
            if (scaled > 65535) scaled = 65535;
            samples++;
            pthread_mutex_lock(&g_regs_lock);
            g_regs[g_sensor.reg] = (uint16_t)scaled;
            if (g_sensor.reg + 1 < g_nregs) g_regs[g_sensor.reg + 1] = samples;
            pthread_mutex_unlock(&g_regs_lock);
        }
        next.tv_nsec += (long)g_sensor.sample_ms * 1000000L;
        while (next.tv_nsec >= 1000000000L) { next.tv_nsec -= 1000000000L; next.tv_sec++; }
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL) == EINTR && !g_stop) {}
    }
    return NULL;
}

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
        "  --sensor fake|file:PATH   sample a sensor into a register (see top of mb_server.c)\n"
        "  --sensor-reg R  register for the reading (default 1; R+1 holds a sample counter)\n"
        "  --sample-ms N   sensor sampling period (default 1000)\n"
        "  --sensor-scale X  stored value = round(reading * X) (default 10, e.g. 23.5 C -> 235)\n"
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
        {"once", 0, 0, 'o'}, {"quiet", 0, 0, 'q'}, {"help", 0, 0, 'h'}, {"sensor", 1, 0, 'S'},
        {"sensor-reg", 1, 0, 'g'}, {"sample-ms", 1, 0, 'm'}, {"sensor-scale", 1, 0, 'x'}, {0, 0, 0, 0}};
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
        case 'S': g_sensor.spec = optarg; break;
        case 'g': g_sensor.reg = atoi(optarg); break;
        case 'm': g_sensor.sample_ms = atoi(optarg); break;
        case 'x': g_sensor.scale = atof(optarg); break;
        default: usage(); return o == 'h' ? 0 : 2;
        }
    }
    if (nregs < 1 || nregs > 65535) { fprintf(stderr, "--regs must be 1..65535\n"); return 2; }
    if (g_sensor.spec && strcmp(g_sensor.spec, "fake") && strncmp(g_sensor.spec, "file:", 5)) {
        fprintf(stderr, "--sensor must be fake or file:PATH\n");
        return 2;
    }
    if (g_sensor.spec && (g_sensor.reg < 0 || g_sensor.reg >= nregs || g_sensor.sample_ms < 1)) {
        fprintf(stderr, "--sensor-reg must be < --regs and --sample-ms >= 1\n");
        return 2;
    }

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
    g_regs = regs;
    g_nregs = nregs;
    pthread_t sensor_tid;
    int sensor_on = 0;
    if (g_sensor.spec) {
        double v;
        if (read_sensor(&v)) fprintf(stderr, "mb_server: warning: first sensor read failed (%s)\n", g_sensor.spec);
        /* Keep SIGINT/SIGTERM on the main thread so they interrupt accept()/recv() there. */
        sigset_t block, old;
        sigemptyset(&block);
        sigaddset(&block, SIGINT);
        sigaddset(&block, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &block, &old);
        if (pthread_create(&sensor_tid, NULL, sensor_thread, NULL) == 0) sensor_on = 1;
        else perror("pthread_create");
        pthread_sigmask(SIG_SETMASK, &old, NULL);
    }

    if (transport_global_init(&cfg, 1)) return 1;
    transport_listener *l = transport_listen(&cfg, bind_addr, port);
    if (!l) return 1;
    fprintf(stderr, "mb_server: %s listening on %s:%d, %d registers%s%s%s\n",
            transport_condition_name(cfg.cond), bind_addr, port, nregs, transport_has_tls() ? " (TLS-capable build)" : "",
            g_sensor.spec ? ", sensor=" : "", g_sensor.spec ? g_sensor.spec : "");

    uint8_t req[MB_MAX_ADU], resp[MB_MAX_ADU];
    while (!g_stop) {
        transport *t = transport_accept(l);
        if (!t) { if (g_stop) break; continue; }
        if (!quiet) fprintf(stderr, "mb_server: client connected (%s)\n", transport_describe(t));
        unsigned long served = 0;
        for (;;) {
            ssize_t n = mb_recv_adu(t, req, sizeof req);
            if (n <= 0) break;
            pthread_mutex_lock(&g_regs_lock);
            if (req[7] == MB_FC_READ_HOLDING) regs[0]++;
            size_t m = mb_server_handle(req, (size_t)n, resp, regs, (uint16_t)nregs);
            pthread_mutex_unlock(&g_regs_lock);
            if (m == 0 || transport_send_all(t, resp, m) != (ssize_t)m) break;
            served++;
        }
        if (!quiet) fprintf(stderr, "mb_server: client closed after %lu requests\n", served);
        transport_close(t);
        if (once) break;
    }
    transport_listener_close(l);
    transport_global_cleanup();
    g_stop = 1;
    if (sensor_on) pthread_join(sensor_tid, NULL);
    free(regs);
    return 0;
}
