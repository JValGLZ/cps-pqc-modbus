/*
 * mb_poll - Modbus/TCP polling client (control-loop side) with a strict repeating deadline.
 *
 * Every period the client wakes at an ABSOLUTE release time (clock_nanosleep + TIMER_ABSTIME on
 * CLOCK_MONOTONIC, so the schedule never drifts), sends one request and waits for the response.
 * All times come from the client's own clock (no cross-device clock sync needed).
 *
 * Per poll k (release time r_k = t0 + k * period):
 *   wake_late = wake - r_k                     OS timer jitter (the "jitter floor" with C0)
 *   connect   = TCP connect + TLS handshake    every poll with --session per-poll, once otherwise
 *   poll_rtt  = response received - request sent
 *   poll_resp = response received - r_k       what the deadline is judged on
 *   miss      = poll_resp > deadline (default deadline = period) or the poll failed
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

typedef struct {
    int64_t wake_late_ns;
    int64_t connect_ns;     /* -1 if no connect happened in this poll */
    int64_t rtt_ns;         /* -1 if the poll failed */
    int64_t resp_ns;        /* response time from release; -1 if failed */
    int miss;
    int status;             /* 0 ok, >0 Modbus exception code, -1 transport/protocol error */
    int bytes;
    struct timespec wall;
} rec_t;

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

static void usage(void)
{
    fprintf(stderr,
        "usage: mb_poll [options]\n"
        "  --host H --port N          server (default 127.0.0.1:1502)\n"
        "  --cond c0|c1|c2|c3         transport condition (default c0)\n"
        "  --kem NAME --sig LABEL     TLS key-exchange group and signature label (C1-C3)\n"
        "  --certs DIR                dir with ca.pem client.pem client.key (C1-C3)\n"
        "  --period-ms X              polling period, may be fractional (default 100)\n"
        "  --deadline-ms X            deadline per poll (default = period)\n"
        "  --count N                  measured polls (default 1000)\n"
        "  --warmup N                 polls run but not recorded (default 20)\n"
        "  --session persistent|per-poll   one connection, or a new connection+handshake every poll\n"
        "  --op read|write            0x03 read holding registers (default) or 0x06 write single register\n"
        "  --addr A --qty Q --unit U  register address/quantity/unit id (default 0, 10, 1)\n"
        "  --timeout-ms N             per-I/O timeout (default 1000)\n"
        "  --cpu N                    pin to CPU N\n"
        "  --rt                       SCHED_FIFO priority 50 + mlockall (needs root/CAP_SYS_NICE)\n"
        "  --phase P --run-id ID --notes TEXT   labels written into the CSV\n"
        "  --out FILE                 CSV path (default <results-dir>/<host>/<date>/<run_id>.csv)\n"
        "  --results-dir DIR          base dir for the default path (default results/raw)\n");
}

/* Close the current connection (if any) and open a new one, timing it. */
static transport *reconnect(transport *t, const transport_cfg *cfg, const char *host, int port, int64_t *connect_ns)
{
    if (t) transport_close(t);
    int64_t c0 = now_ns();
    t = transport_connect(cfg, host, port);
    *connect_ns = t ? now_ns() - c0 : -1;
    return t;
}

int main(int argc, char **argv)
{
    transport_cfg cfg = {.cond = COND_C0, .timeout_ms = 1000};
    const char *host = "127.0.0.1", *phase = "P0", *run_id_arg = NULL, *out_arg = NULL, *extra = NULL;
    const char *results_dir = "results/raw", *session = "persistent", *op = "read";
    int port = 1502, count = 1000, warmup = 20, cpu = -1, rt = 0, unit = 1, addr = 0, qty = 10;
    double period_ms = 100.0, deadline_ms = -1.0;

    static const struct option opts[] = {
        {"host", 1, 0, 'H'},    {"port", 1, 0, 'p'},     {"cond", 1, 0, 'c'},      {"kem", 1, 0, 'k'},
        {"sig", 1, 0, 's'},     {"certs", 1, 0, 'C'},    {"period-ms", 1, 0, 'P'}, {"deadline-ms", 1, 0, 'D'},
        {"count", 1, 0, 'n'},   {"warmup", 1, 0, 'w'},   {"session", 1, 0, 'S'},   {"op", 1, 0, 'O'},
        {"addr", 1, 0, 'a'},    {"qty", 1, 0, 'Q'},      {"unit", 1, 0, 'U'},      {"timeout-ms", 1, 0, 'T'},
        {"cpu", 1, 0, 'u'},     {"rt", 0, 0, 'R'},       {"phase", 1, 0, 'f'},     {"run-id", 1, 0, 'i'},
        {"notes", 1, 0, 'N'},   {"out", 1, 0, 'o'},      {"results-dir", 1, 0, 'd'}, {"help", 0, 0, 'h'},
        {0, 0, 0, 0}};
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
        char hms[16];
        strftime(hms, sizeof hms, "%H%M%S", &lt);
        snprintf(run_id, sizeof run_id, "%s-%s%s%s-%gms-%s-%s-%s",
                 transport_condition_name(cfg.cond), cfg.cond == COND_C0 ? "plain" : kem,
                 *sig ? "-" : "", sig, period_ms, per_poll ? "perpoll" : "persist", op, hms);
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

    int total = warmup + count;
    rec_t *recs = calloc((size_t)count, sizeof *recs);
    int64_t *conn_ns = calloc((size_t)total + 1, sizeof *conn_ns);   /* every connect, warmup excluded */
    int *conn_trial = calloc((size_t)total + 1, sizeof *conn_trial);
    int nconn = 0;
    if (!recs || !conn_ns || !conn_trial) { fprintf(stderr, "out of memory\n"); return 1; }

    const int64_t period_ns = (int64_t)llround(period_ms * 1e6);
    const int64_t deadline_ns = (int64_t)llround(deadline_ms * 1e6);
    uint8_t req[MB_MAX_ADU], resp[MB_MAX_ADU];
    transport *t = NULL;
    int64_t cns = -1;
    char desc[200] = "";

    struct timespec start_wall;
    clock_gettime(CLOCK_REALTIME, &start_wall);
    /* Persistent session: connect before the schedule starts (recorded as trial 0). */
    if (!per_poll) {
        t = reconnect(NULL, &cfg, host, port, &cns);
        if (!t) { fprintf(stderr, "initial connect failed\n"); return 1; }
        snprintf(desc, sizeof desc, "%s", transport_describe(t));
        conn_ns[nconn] = cns;
        conn_trial[nconn++] = 0;
    }

    const int64_t t0 = now_ns() + 50 * 1000000LL;   /* first release 50 ms from now */
    int consecutive_err = 0, done = 0;

    for (int k = 0; k < total && !g_stop; k++) {
        const int64_t release = t0 + (int64_t)k * period_ns;
        struct timespec rel_ts = ns_ts(release);
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &rel_ts, NULL) == EINTR && !g_stop) {}
        const int64_t wake = now_ns();

        rec_t r = {.wake_late_ns = wake - release, .connect_ns = -1, .rtt_ns = -1, .resp_ns = -1, .status = -1};
        const uint16_t tid = (uint16_t)(k + 1);

        if (per_poll || !t) {
            t = reconnect(per_poll ? NULL : t, &cfg, host, port, &cns);
            r.connect_ns = cns;
            if (t && !*desc) snprintf(desc, sizeof desc, "%s", transport_describe(t));
        }
        if (t) {
            size_t qlen = do_write ? mb_build_write_single(req, tid, (uint8_t)unit, (uint16_t)addr, (uint16_t)k)
                                   : mb_build_read_holding(req, tid, (uint8_t)unit, (uint16_t)addr, (uint16_t)qty);
            const int64_t sent = now_ns();
            ssize_t n = -1;
            if (transport_send_all(t, req, qlen) == (ssize_t)qlen) n = mb_recv_adu(t, resp, sizeof resp);
            const int64_t got = now_ns();
            if (n > 0) {
                r.status = mb_check_response(req, qlen, resp, (size_t)n);
                r.rtt_ns = got - sent;
                r.resp_ns = got - release;
                r.bytes = (int)(qlen + (size_t)n);
            }
            if (n <= 0 || r.status < 0) {   /* broken connection: drop it, reconnect next poll */
                transport_close(t);
                t = NULL;
            }
        }
        r.miss = (r.status != 0) || r.resp_ns > deadline_ns;
        clock_gettime(CLOCK_REALTIME, &r.wall);
        if (per_poll && t) { transport_close(t); t = NULL; }

        consecutive_err = r.status < 0 ? consecutive_err + 1 : 0;
        if (k >= warmup) {
            recs[k - warmup] = r;
            if (r.connect_ns >= 0) { conn_ns[nconn] = r.connect_ns; conn_trial[nconn++] = k - warmup + 1; }
            done++;
        }
        if (consecutive_err >= 10) { fprintf(stderr, "mb_poll: 10 consecutive failures, stopping\n"); break; }
    }
    if (t) transport_close(t);
    transport_global_cleanup();

    /* ---- write CSV */
    FILE *f = fopen(out_path, "w");
    if (!f) { fprintf(stderr, "cannot write %s: %s\n", out_path, strerror(errno)); return 1; }
    fprintf(f, "run_id,host,phase,condition,kem,sig,op,trial,value,unit,bytes,notes,timestamp\n");
    char common[512], ts[40];
    snprintf(common, sizeof common, "period_ms=%g;deadline_ms=%g;session=%s;mb_op=%s;qty=%d%s%s",
             period_ms, deadline_ms, session, op, do_write ? 1 : qty, extra ? ";" : "", extra ? extra : "");
    const char *cond = transport_condition_name(cfg.cond);

    for (int i = 0; i < nconn; i++) {
        struct timespec w = conn_trial[i] ? recs[conn_trial[i] - 1].wall : start_wall;
        iso_utc(&w, ts, sizeof ts);
        fprintf(f, "%s,%s,%s,%s,%s,%s,connect,%d,%.6f,ms,,%s;desc=%s,%s\n", run_id, hostlbl, phase, cond, kem, sig,
                conn_trial[i], conn_ns[i] / 1e6, common, desc, ts);
    }
    for (int i = 0; i < done; i++) {
        const rec_t *r = &recs[i];
        iso_utc(&r->wall, ts, sizeof ts);
        if (r->rtt_ns >= 0)
            fprintf(f, "%s,%s,%s,%s,%s,%s,poll_rtt,%d,%.6f,ms,%d,%s;status=%d,%s\n", run_id, hostlbl, phase, cond, kem,
                    sig, i + 1, r->rtt_ns / 1e6, r->bytes, common, r->status, ts);
        char val[32];
        if (r->resp_ns >= 0) snprintf(val, sizeof val, "%.6f", r->resp_ns / 1e6);
        else snprintf(val, sizeof val, "nan");
        fprintf(f, "%s,%s,%s,%s,%s,%s,poll_resp,%d,%s,ms,%d,%s;status=%d;miss=%d;wake_late_us=%.3f,%s\n", run_id,
                hostlbl, phase, cond, kem, sig, i + 1, val, r->bytes, common, r->status, r->miss,
                r->wake_late_ns / 1e3, ts);
    }
    fclose(f);

    /* ---- summary on stderr */
    int64_t *rtt = malloc(sizeof(int64_t) * (size_t)(done ? done : 1));
    int64_t *late = malloc(sizeof(int64_t) * (size_t)(done ? done : 1));
    int nr = 0, misses = 0, fails = 0;
    double sum = 0;
    for (int i = 0; i < done; i++) {
        late[i] = recs[i].wake_late_ns;
        misses += recs[i].miss;
        if (recs[i].rtt_ns >= 0 && recs[i].status == 0) { rtt[nr++] = recs[i].rtt_ns; sum += (double)recs[i].rtt_ns; }
        else fails++;
    }
    qsort(rtt, (size_t)nr, sizeof *rtt, cmp_i64);
    qsort(late, (size_t)done, sizeof *late, cmp_i64);
    fprintf(stderr, "mb_poll: %s %s  period=%gms deadline=%gms session=%s  polls=%d  (%s)\n", cond,
            cfg.cond == COND_C0 ? "plain" : kem, period_ms, deadline_ms, session, done, *desc ? desc : "no connection");
    fprintf(stderr, "  rtt ms     mean %.4f  p50 %.4f  p95 %.4f  p99 %.4f  max %.4f\n", nr ? sum / nr / 1e6 : NAN,
            pct(rtt, (size_t)nr, 50) / 1e6, pct(rtt, (size_t)nr, 95) / 1e6, pct(rtt, (size_t)nr, 99) / 1e6,
            nr ? rtt[nr - 1] / 1e6 : NAN);
    fprintf(stderr, "  wake late  p50 %.1f us  p99 %.1f us  max %.1f us\n", pct(late, (size_t)done, 50) / 1e3,
            pct(late, (size_t)done, 99) / 1e3, done ? late[done - 1] / 1e3 : NAN);
    if (nconn) {
        double cs = 0;
        for (int i = 0; i < nconn; i++) cs += (double)conn_ns[i];
        fprintf(stderr, "  connect    n=%d mean %.4f ms\n", nconn, cs / nconn / 1e6);
    }
    fprintf(stderr, "  deadline misses %d / %d (%.3f%%), failed polls %d\n", misses, done,
            done ? 100.0 * misses / done : 0.0, fails);
    fprintf(stderr, "  csv: %s\n", out_path);
    free(rtt);
    free(late);
    free(recs);
    free(conn_ns);
    free(conn_trial);
    return g_stop ? 130 : 0;
}
