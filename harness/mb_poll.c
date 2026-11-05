/*
 * mb_poll - Modbus/TCP master (control-loop side) with a strict repeating deadline.
 *
 * Polls one slave, or N slaves (--servers / --nservers), once per cycle. Every cycle starts at an
 * ABSOLUTE release time (clock_nanosleep + TIMER_ABSTIME on CLOCK_MONOTONIC, so the schedule never
 * drifts). Within a cycle the slaves are polled one after another, the way a simple master does it.
 * All times come from the master's own clock (no cross-device clock sync needed).
 *
 * Per cycle k (release time r_k = t0 + k * period):
 *   wake_late = wake - r_k                       OS timer jitter (the "jitter floor" with C0)
 *   connect   = TCP connect + TLS handshake      per slave: every cycle with --session per-poll, once otherwise
 *   poll_rtt  = response received - request sent (per slave)
 *   poll_resp = last slave's response - r_k      the cycle time; what the deadline is judged on
 *   miss      = poll_resp > deadline (default deadline = period) or any slave failed
 * Once per run (multi-session analysis):
 *   connect_all   = time to connect every slave at startup (persistent sessions)
 *   master_rss_kb = master memory before connecting, with all sessions open, and at the end
 *
 * Results are buffered in memory and written after the run (no file I/O inside the timed loop),
 * as rows of the shared CSV schema:
 *   run_id,host,phase,condition,kem,sig,op,trial,value,unit,bytes,notes,timestamp
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../modbus/modbus.h"

#define MAX_SERVERS 256

typedef struct {            /* one slave in one cycle */
    int64_t connect_ns;     /* -1 if no connect happened */
    int64_t rtt_ns;         /* -1 if the poll failed */
    int status;             /* 0 ok, >0 Modbus exception code, -1 transport/protocol error */
    int bytes;
} poll_t;

typedef struct {            /* one cycle */
    int64_t wake_late_ns;
    int64_t resp_ns;        /* cycle time from release; -1 if any slave failed */
    int miss, nfail, status, bytes;
    struct timespec wall;
} cycle_t;

typedef struct { char host[256]; int port; } server_t;

static volatile sig_atomic_t g_stop;
static void on_signal(int s) { (void)s; g_stop = 1; }

static inline int64_t ts_ns(const struct timespec *t) { return (int64_t)t->tv_sec * 1000000000LL + t->tv_nsec; }
static inline struct timespec ns_ts(int64_t ns) { struct timespec t = {ns / 1000000000LL, ns % 1000000000LL}; return t; }
static inline int64_t now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return ts_ns(&t); }

static int cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* Nearest-rank percentile on a sorted array. */
static double pct(const int64_t *s, size_t n, double p)
{
    if (!n) return NAN;
    size_t k = (size_t)ceil(p / 100.0 * (double)n);
    if (k < 1) k = 1;
    if (k > n) k = n;
    return (double)s[k - 1];
}

/* Resident memory of this process in kB (VmRSS), -1 if unavailable. */
static long rss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "VmRSS:", 6)) { kb = strtol(line + 6, NULL, 10); break; }
    fclose(f);
    return kb;
}

static void host_label(char *out, size_t cap)
{
    char h[200] = "unknown";
    gethostname(h, sizeof h - 1);
    int wsl = 0;
    FILE *f = fopen("/proc/sys/kernel/osrelease", "r");
    if (f) {
        char rel[256] = "";
        if (fgets(rel, sizeof rel, f) && (strcasestr(rel, "microsoft") || strcasestr(rel, "wsl"))) wsl = 1;
        fclose(f);
    }
    /* Shared contract item 4: record VM/WSL2 in the host field. */
    snprintf(out, cap, "%s%s", h, wsl ? "-wsl2" : "");
}

static int mkdir_p(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    return (mkdir(tmp, 0755) && errno != EEXIST) ? -1 : 0;
}

static void iso_utc(const struct timespec *t, char *out, size_t cap)
{
    struct tm tm;
    gmtime_r(&t->tv_sec, &tm);
    size_t n = strftime(out, cap, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out + n, cap - n, ".%06ldZ", t->tv_nsec / 1000);
}

/* "host:port,host:port,..." -> servers. Returns count or -1. */
static int parse_servers(const char *list, server_t *sv)
{
    char buf[8192];
    snprintf(buf, sizeof buf, "%s", list);
    int n = 0;
    for (char *save = NULL, *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char *colon = strrchr(tok, ':');
        if (!colon || n >= MAX_SERVERS) return -1;
        *colon = 0;
        snprintf(sv[n].host, sizeof sv[n].host, "%s", tok);
        sv[n].port = atoi(colon + 1);
        if (sv[n].port <= 0) return -1;
        n++;
    }
    return n;
}

static void usage(void)
{
    fprintf(stderr,
        "usage: mb_poll [options]\n"
        "  --host H --port N          one slave (default 127.0.0.1:1502)\n"
        "  --nservers N               N slaves on --host at ports port, port+1, ..., port+N-1\n"
        "  --servers H:P,H:P,...      explicit slave list (overrides --host/--port/--nservers)\n"
        "  --cond c0|c1|c2|c3         transport condition (default c0)\n"
        "  --kem NAME --sig LABEL     TLS key-exchange group and signature label (C1-C3)\n"
        "  --certs DIR                dir with ca.pem client.pem client.key (C1-C3)\n"
        "  --period-ms X              cycle period, may be fractional (default 100)\n"
        "  --deadline-ms X            deadline per cycle (default = period)\n"
        "  --count N                  measured cycles (default 1000)\n"
        "  --warmup N                 cycles run but not recorded (default 20)\n"
        "  --session persistent|per-poll   sessions stay open, or a new connection+handshake every poll\n"
        "  --op read|write            0x03 read holding registers (default) or 0x06 write single register\n"
        "  --addr A --qty Q --unit U  register address/quantity/unit id (default 0, 10, 1)\n"
        "  --timeout-ms N             per-I/O timeout (default 1000)\n"
        "  --cpu N                    pin to CPU N\n"
        "  --rt                       SCHED_FIFO priority 50 + mlockall (needs root/CAP_SYS_NICE)\n"
        "  --phase P --run-id ID --notes TEXT   labels written into the CSV\n"
        "  --out FILE                 CSV path (default <results-dir>/<host>/<date>/<run_id>.csv)\n"
        "  --results-dir DIR          base dir for the default path (default results/raw)\n");
}

/* Close (if open) and reconnect one slave, timing it. */
static transport *reconnect(transport *t, const transport_cfg *cfg, const server_t *s, int64_t *connect_ns)
{
    if (t) transport_close(t);
    int64_t c0 = now_ns();
    t = transport_connect(cfg, s->host, s->port);
    *connect_ns = t ? now_ns() - c0 : -1;
    return t;
}

int main(int argc, char **argv)
{
    transport_cfg cfg = {.cond = COND_C0, .timeout_ms = 1000};
    const char *host = "127.0.0.1", *phase = "P0", *run_id_arg = NULL, *out_arg = NULL, *extra = NULL;
    const char *results_dir = "results/raw", *session = "persistent", *op = "read", *server_list = NULL;
    int port = 1502, nservers = 1, count = 1000, warmup = 20, cpu = -1, rt = 0, unit = 1, addr = 0, qty = 10;
    double period_ms = 100.0, deadline_ms = -1.0;

    static const struct option opts[] = {
        {"host", 1, 0, 'H'},    {"port", 1, 0, 'p'},     {"cond", 1, 0, 'c'},      {"kem", 1, 0, 'k'},
        {"sig", 1, 0, 's'},     {"certs", 1, 0, 'C'},    {"period-ms", 1, 0, 'P'}, {"deadline-ms", 1, 0, 'D'},
        {"count", 1, 0, 'n'},   {"warmup", 1, 0, 'w'},   {"session", 1, 0, 'S'},   {"op", 1, 0, 'O'},
        {"addr", 1, 0, 'a'},    {"qty", 1, 0, 'Q'},      {"unit", 1, 0, 'U'},      {"timeout-ms", 1, 0, 'T'},
        {"cpu", 1, 0, 'u'},     {"rt", 0, 0, 'R'},       {"phase", 1, 0, 'f'},     {"run-id", 1, 0, 'i'},
        {"notes", 1, 0, 'N'},   {"out", 1, 0, 'o'},      {"results-dir", 1, 0, 'd'}, {"nservers", 1, 0, 'm'},
        {"servers", 1, 0, 'L'}, {"help", 0, 0, 'h'},     {0, 0, 0, 0}};
    int o;
    while ((o = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (o) {
        case 'H': host = optarg; break;
        case 'p': port = atoi(optarg); break;
        case 'c':
            if (transport_parse_condition(optarg) < 0) { fprintf(stderr, "bad --cond %s\n", optarg); return 2; }
            cfg.cond = (condition_t)transport_parse_condition(optarg);
            break;
        case 'k': cfg.kem = optarg; break;
        case 's': cfg.sig = optarg; break;
        case 'C': cfg.cert_dir = optarg; break;
        case 'P': period_ms = atof(optarg); break;
        case 'D': deadline_ms = atof(optarg); break;
        case 'n': count = atoi(optarg); break;
        case 'w': warmup = atoi(optarg); break;
        case 'S': session = optarg; break;
        case 'O': op = optarg; break;
        case 'a': addr = atoi(optarg); break;
        case 'Q': qty = atoi(optarg); break;
        case 'U': unit = atoi(optarg); break;
        case 'T': cfg.timeout_ms = atoi(optarg); break;
        case 'u': cpu = atoi(optarg); break;
        case 'R': rt = 1; break;
        case 'f': phase = optarg; break;
        case 'i': run_id_arg = optarg; break;
        case 'N': extra = optarg; break;
        case 'o': out_arg = optarg; break;
        case 'd': results_dir = optarg; break;
        case 'm': nservers = atoi(optarg); break;
        case 'L': server_list = optarg; break;
        default: usage(); return o == 'h' ? 0 : 2;
        }
    }
    int per_poll = !strcmp(session, "per-poll");
    if (!per_poll && strcmp(session, "persistent")) { fprintf(stderr, "--session must be persistent or per-poll\n"); return 2; }
    int do_write = !strcmp(op, "write");
    if (!do_write && strcmp(op, "read")) { fprintf(stderr, "--op must be read or write\n"); return 2; }
    if (period_ms <= 0 || count < 1 || warmup < 0) { fprintf(stderr, "bad --period-ms/--count/--warmup\n"); return 2; }
    if (qty < 1 || qty > MB_MAX_READ_QTY) { fprintf(stderr, "--qty must be 1..%d\n", MB_MAX_READ_QTY); return 2; }
    if (deadline_ms <= 0) deadline_ms = period_ms;
    if (strchr(extra ? extra : "", ',')) { fprintf(stderr, "--notes must not contain commas\n"); return 2; }

    static server_t sv[MAX_SERVERS];
    int N;
    if (server_list) {
        N = parse_servers(server_list, sv);
        if (N < 1) { fprintf(stderr, "bad --servers list (want host:port,host:port,...; max %d)\n", MAX_SERVERS); return 2; }
    } else {
        if (nservers < 1 || nservers > MAX_SERVERS) { fprintf(stderr, "--nservers must be 1..%d\n", MAX_SERVERS); return 2; }
        N = nservers;
        for (int i = 0; i < N; i++) { snprintf(sv[i].host, sizeof sv[i].host, "%s", host); sv[i].port = port + i; }
    }

    /* ---- labels and output path */
    char hostlbl[256], run_id[256], out_path[1400], datestr[16];
    host_label(hostlbl, sizeof hostlbl);
    time_t now = time(NULL);
    struct tm lt;
    localtime_r(&now, &lt);
    strftime(datestr, sizeof datestr, "%Y-%m-%d", &lt);
    const char *kem = cfg.cond == COND_C0 ? "" : (cfg.kem ? cfg.kem : "default");
    const char *sig = cfg.cond == COND_C0 ? "" : (cfg.sig ? cfg.sig : "");
    if (run_id_arg) {
        snprintf(run_id, sizeof run_id, "%s", run_id_arg);
    } else {
        char hms[16], ntag[16] = "";
        strftime(hms, sizeof hms, "%H%M%S", &lt);
        if (N > 1) snprintf(ntag, sizeof ntag, "-n%d", N);
        snprintf(run_id, sizeof run_id, "%s-%s%s%s-%gms-%s%s-%s-%s",
                 transport_condition_name(cfg.cond), cfg.cond == COND_C0 ? "plain" : kem,
                 *sig ? "-" : "", sig, period_ms, per_poll ? "perpoll" : "persist", ntag, op, hms);
    }
    if (out_arg) {
        snprintf(out_path, sizeof out_path, "%s", out_arg);
    } else {
        char dir[900];
        snprintf(dir, sizeof dir, "%s/%s/%s", results_dir, hostlbl, datestr);
        if (mkdir_p(dir)) { fprintf(stderr, "cannot create %s: %s\n", dir, strerror(errno)); return 1; }
        snprintf(out_path, sizeof out_path, "%s/%s.csv", dir, run_id);
    }

    /* ---- process setup */
    if (cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof set, &set)) perror("sched_setaffinity");
    }
    if (rt) {
        struct sched_param sp = {.sched_priority = 50};
        if (sched_setscheduler(0, SCHED_FIFO, &sp)) perror("SCHED_FIFO (continuing without)");
        if (mlockall(MCL_CURRENT | MCL_FUTURE)) perror("mlockall (continuing without)");
    }
    struct sigaction sa = {.sa_handler = on_signal};
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (transport_global_init(&cfg, 0)) return 1;

    const int total = warmup + count;
    cycle_t *cyc = calloc((size_t)count, sizeof *cyc);
    poll_t *pr = calloc((size_t)count * (size_t)N, sizeof *pr);
    poll_t *init = calloc((size_t)N, sizeof *init);          /* startup connects (persistent) */
    transport **t = calloc((size_t)N, sizeof *t);
    if (!cyc || !pr || !init || !t) { fprintf(stderr, "out of memory\n"); return 1; }

    const int64_t period_ns = (int64_t)llround(period_ms * 1e6);
    const int64_t deadline_ns = (int64_t)llround(deadline_ms * 1e6);
    uint8_t req[MB_MAX_ADU], resp[MB_MAX_ADU];
    char desc[200] = "";
    long rss_before = rss_kb(), rss_connected = -1, rss_end = -1;
    int64_t connect_all_ns = -1;

    struct timespec start_wall;
    clock_gettime(CLOCK_REALTIME, &start_wall);
    /* Persistent sessions: connect every slave before the schedule starts (trial 0). */
    if (!per_poll) {
        int64_t a0 = now_ns();
        for (int i = 0; i < N; i++) {
            t[i] = reconnect(NULL, &cfg, &sv[i], &init[i].connect_ns);
            if (!t[i]) { fprintf(stderr, "initial connect to %s:%d failed\n", sv[i].host, sv[i].port); return 1; }
        }
        connect_all_ns = now_ns() - a0;
        snprintf(desc, sizeof desc, "%s", transport_describe(t[0]));
        rss_connected = rss_kb();
    }

    const int64_t t0 = now_ns() + 50 * 1000000LL;   /* first release 50 ms from now */
    int consecutive_err = 0, done = 0;

    for (int k = 0; k < total && !g_stop; k++) {
        const int64_t release = t0 + (int64_t)k * period_ns;
        struct timespec rel_ts = ns_ts(release);
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &rel_ts, NULL) == EINTR && !g_stop) {}
        const int64_t wake = now_ns();
        const int rec = k >= warmup;
        cycle_t c = {.wake_late_ns = wake - release, .resp_ns = -1};
        int64_t last_got = wake;

        for (int i = 0; i < N; i++) {
            poll_t p = {.connect_ns = -1, .rtt_ns = -1, .status = -1};
            const uint16_t tid = (uint16_t)(k + 1);
            if (per_poll || !t[i]) {
                t[i] = reconnect(per_poll ? NULL : t[i], &cfg, &sv[i], &p.connect_ns);
                if (t[i] && !*desc) snprintf(desc, sizeof desc, "%s", transport_describe(t[i]));
            }
            if (t[i]) {
                size_t qlen = do_write ? mb_build_write_single(req, tid, (uint8_t)unit, (uint16_t)addr, (uint16_t)k)
                                       : mb_build_read_holding(req, tid, (uint8_t)unit, (uint16_t)addr, (uint16_t)qty);
                const int64_t sent = now_ns();
                ssize_t n = -1;
                if (transport_send_all(t[i], req, qlen) == (ssize_t)qlen) n = mb_recv_adu(t[i], resp, sizeof resp);
                const int64_t got = now_ns();
                if (n > 0) {
                    p.status = mb_check_response(req, qlen, resp, (size_t)n);
                    p.rtt_ns = got - sent;
                    p.bytes = (int)(qlen + (size_t)n);
                    last_got = got;
                }
                if (n <= 0 || p.status < 0) { transport_close(t[i]); t[i] = NULL; }   /* reconnect next cycle */
            }
            if (per_poll && t[i]) { transport_close(t[i]); t[i] = NULL; }
            if (p.status != 0) { c.nfail++; if (c.status == 0) c.status = p.status; }
            c.bytes += p.bytes;
            if (rec) pr[(size_t)(k - warmup) * N + i] = p;
        }
        if (!c.nfail) c.resp_ns = last_got - release;
        c.miss = c.nfail > 0 || c.resp_ns > deadline_ns;
        clock_gettime(CLOCK_REALTIME, &c.wall);

        consecutive_err = c.nfail == N ? consecutive_err + 1 : 0;
        if (rec) { cyc[k - warmup] = c; done++; }
        if (consecutive_err >= 10) { fprintf(stderr, "mb_poll: 10 cycles with every slave failing, stopping\n"); break; }
    }
    rss_end = rss_kb();
    for (int i = 0; i < N; i++) if (t[i]) transport_close(t[i]);
    transport_global_cleanup();

    /* ---- write CSV */
    FILE *f = fopen(out_path, "w");
    if (!f) { fprintf(stderr, "cannot write %s: %s\n", out_path, strerror(errno)); return 1; }
    fprintf(f, "run_id,host,phase,condition,kem,sig,op,trial,value,unit,bytes,notes,timestamp\n");
    char common[512], ts[40];
    snprintf(common, sizeof common, "period_ms=%g;deadline_ms=%g;session=%s;mb_op=%s;qty=%d;n_servers=%d%s%s",
             period_ms, deadline_ms, session, op, do_write ? 1 : qty, N, extra ? ";" : "", extra ? extra : "");
    const char *cond = transport_condition_name(cfg.cond);
#define ROW_PREFIX run_id, hostlbl, phase, cond, kem, sig

    iso_utc(&start_wall, ts, sizeof ts);
    if (!per_poll) {
        for (int i = 0; i < N; i++)
            fprintf(f, "%s,%s,%s,%s,%s,%s,connect,0,%.6f,ms,,%s;server=%d;desc=%s,%s\n", ROW_PREFIX,
                    init[i].connect_ns / 1e6, common, i, desc, ts);
        fprintf(f, "%s,%s,%s,%s,%s,%s,connect_all,0,%.6f,ms,,%s,%s\n", ROW_PREFIX, connect_all_ns / 1e6, common, ts);
    }
    const char *stage[3] = {"before_connect", "all_connected", "end"};
    long rss[3] = {rss_before, rss_connected, rss_end};
    for (int s = 0; s < 3; s++)
        if (rss[s] >= 0)
            fprintf(f, "%s,%s,%s,%s,%s,%s,master_rss_kb,%d,%ld,kB,,%s;stage=%s,%s\n", ROW_PREFIX, s, rss[s], common,
                    stage[s], ts);

    for (int k = 0; k < done; k++) {
        const cycle_t *c = &cyc[k];
        iso_utc(&c->wall, ts, sizeof ts);
        for (int i = 0; i < N; i++) {
            const poll_t *p = &pr[(size_t)k * N + i];
            if (p->connect_ns >= 0)
                fprintf(f, "%s,%s,%s,%s,%s,%s,connect,%d,%.6f,ms,,%s;server=%d;desc=%s,%s\n", ROW_PREFIX, k + 1,
                        p->connect_ns / 1e6, common, i, desc, ts);
            if (p->rtt_ns >= 0)
                fprintf(f, "%s,%s,%s,%s,%s,%s,poll_rtt,%d,%.6f,ms,%d,%s;server=%d;status=%d,%s\n", ROW_PREFIX, k + 1,
                        p->rtt_ns / 1e6, p->bytes, common, i, p->status, ts);
        }
        char val[32];
        if (c->resp_ns >= 0) snprintf(val, sizeof val, "%.6f", c->resp_ns / 1e6);
        else snprintf(val, sizeof val, "nan");
        fprintf(f, "%s,%s,%s,%s,%s,%s,poll_resp,%d,%s,ms,%d,%s;status=%d;miss=%d;nfail=%d;wake_late_us=%.3f,%s\n",
                ROW_PREFIX, k + 1, val, c->bytes, common, c->status, c->miss, c->nfail, c->wake_late_ns / 1e3, ts);
    }
    fclose(f);

    /* ---- summary on stderr */
    size_t np = (size_t)done * N;
    int64_t *rtt = malloc(sizeof(int64_t) * (np ? np : 1));
    int64_t *cy = malloc(sizeof(int64_t) * (size_t)(done ? done : 1));
    int64_t *late = malloc(sizeof(int64_t) * (size_t)(done ? done : 1));
    size_t nr = 0, ncy = 0, nconn = 0;
    int misses = 0, fails = 0;
    double sum = 0, csum = 0;
    for (int k = 0; k < done; k++) {
        late[k] = cyc[k].wake_late_ns;
        misses += cyc[k].miss;
        if (cyc[k].resp_ns >= 0) cy[ncy++] = cyc[k].resp_ns;
        for (int i = 0; i < N; i++) {
            const poll_t *p = &pr[(size_t)k * N + i];
            if (p->rtt_ns >= 0 && p->status == 0) { rtt[nr++] = p->rtt_ns; sum += (double)p->rtt_ns; }
            else fails++;
            if (p->connect_ns >= 0) { csum += (double)p->connect_ns; nconn++; }
        }
    }
    if (!per_poll) for (int i = 0; i < N; i++) { csum += (double)init[i].connect_ns; nconn++; }
    qsort(rtt, nr, sizeof *rtt, cmp_i64);
    qsort(cy, ncy, sizeof *cy, cmp_i64);
    qsort(late, (size_t)done, sizeof *late, cmp_i64);
    fprintf(stderr, "mb_poll: %s %s  slaves=%d  period=%gms deadline=%gms session=%s  cycles=%d  (%s)\n", cond,
            cfg.cond == COND_C0 ? "plain" : kem, N, period_ms, deadline_ms, session, done, *desc ? desc : "no connection");
    fprintf(stderr, "  rtt ms     mean %.4f  p50 %.4f  p95 %.4f  p99 %.4f  max %.4f  (per slave poll)\n",
            nr ? sum / (double)nr / 1e6 : NAN, pct(rtt, nr, 50) / 1e6, pct(rtt, nr, 95) / 1e6, pct(rtt, nr, 99) / 1e6,
            nr ? rtt[nr - 1] / 1e6 : NAN);
    if (N > 1)
        fprintf(stderr, "  cycle ms   p50 %.4f  p99 %.4f  max %.4f  (release -> last slave answered)\n",
                pct(cy, ncy, 50) / 1e6, pct(cy, ncy, 99) / 1e6, ncy ? cy[ncy - 1] / 1e6 : NAN);
    fprintf(stderr, "  wake late  p50 %.1f us  p99 %.1f us  max %.1f us\n", pct(late, (size_t)done, 50) / 1e3,
            pct(late, (size_t)done, 99) / 1e3, done ? late[done - 1] / 1e3 : NAN);
    if (nconn) fprintf(stderr, "  connect    n=%zu mean %.4f ms\n", nconn, csum / (double)nconn / 1e6);
    if (connect_all_ns >= 0) fprintf(stderr, "  connect all %d slaves: %.3f ms\n", N, connect_all_ns / 1e6);
    if (rss_before >= 0 && rss_connected >= 0)
        fprintf(stderr, "  master RSS  before %ld kB  all connected %ld kB  end %ld kB\n", rss_before, rss_connected,
                rss_end);
    else if (rss_before >= 0)
        fprintf(stderr, "  master RSS  before %ld kB  end %ld kB\n", rss_before, rss_end);
    fprintf(stderr, "  deadline misses %d / %d cycles (%.3f%%), failed slave polls %d\n", misses, done,
            done ? 100.0 * misses / done : 0.0, fails);
    fprintf(stderr, "  csv: %s\n", out_path);
    free(rtt); free(cy); free(late); free(cyc); free(pr); free(init); free(t);
    return g_stop ? 130 : 0;
}
