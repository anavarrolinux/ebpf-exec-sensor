// SPDX-License-Identifier: GPL-2.0
/*
 * main.c
 * ------
 * User-space loader + event printer for the eBPF program.
 *
 * Responsibilities:
 *  - Open/load/attach BPF skeleton (libbpf)
 *  - Consume ring buffer events
 *  - Convert monotonic timestamp to wall-clock time
 *  - Optional JSON output (--json) for Grafana Loki / Promtail ingestion
 *  - Optional stats output (--stats) showing event and drop rates
 *  - Optional sampling control (--sample N) by writing cfg map (default off)
 *
 * Design principles:
 *  - Keep kernel side simple, do formatting in user space
 *  - Exit cleanly on SIGTERM (systemd stop/restart) with status 0
 *  - Line-buffer output so journald doesn’t batch logs unexpectedly
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "sensor.skel.h"
#include "interface.h"

static volatile sig_atomic_t exiting = 0;

/*
 * We store an offset so we can convert:
 *   wall_time_ns ~= (realtime_now_ns - monotonic_now_ns) + event.ts_ns
 *
 * bpf_ktime_get_ns() gives monotonic time.
 * We want readable clock timestamps for logs, so we do conversion here.
 */
static __u64 realtime_minus_monotonic_ns = 0;

/* Output controls */
static bool g_json_output = false;   /* --json */
static bool g_stats_enabled = false; /* --stats */

/* SIGINT/SIGTERM handler: set a flag; main loop will exit cleanly. */
static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

/* Read nanoseconds from a POSIX clock. */
static __u64 get_time_ns(clockid_t clk)
{
    struct timespec ts;
    if (clock_gettime(clk, &ts) != 0)
        return 0;
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

/* Compute realtime - monotonic offset once at startup. */
static void init_time_offset(void)
{
    __u64 rt = get_time_ns(CLOCK_REALTIME);
    __u64 mono = get_time_ns(CLOCK_MONOTONIC);
    realtime_minus_monotonic_ns = (rt && mono) ? (rt - mono) : 0;
}

/*
 * prettify_args()
 * --------------
 * Args preview from BPF is a bounded slice of user memory containing
 * NUL-separated argv entries.
 *
 * For display, convert embedded NULs to spaces and trim trailing padding.
 *
 * This is best done in user space (cheap, flexible, no verifier risk).
 */
static void prettify_args(char *s, size_t n)
{
    if (n == 0) return;
    s[n - 1] = '\0';

    /* Find last non-NUL byte (the "used" region). */
    size_t end = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] != '\0')
            end = i + 1;
    }

    if (end == 0) {
        s[0] = '\0';
        return;
    }

    /* Convert embedded NULs within used region to spaces. */
    for (size_t i = 0; i < end; i++) {
        if (s[i] == '\0')
            s[i] = ' ';
    }

    /* Trim trailing whitespace. */
    while (end > 0 && isspace((unsigned char)s[end - 1]))
        end--;

    s[end] = '\0';
}

/*
 * json_escape_and_print()
 * ----------------------
 * When outputting JSON, we must escape strings safely.
 * This helper prints a JSON string without allocations.
 */
static void json_escape_and_print(FILE *out, const char *s, size_t max_len)
{
    fputc('"', out);
    for (size_t i = 0; i < max_len && s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '\\': fputs("\\\\", out); break;
            case '"':  fputs("\\\"", out); break;
            case '\b': fputs("\\b", out);  break;
            case '\f': fputs("\\f", out);  break;
            case '\n': fputs("\\n", out);  break;
            case '\r': fputs("\\r", out);  break;
            case '\t': fputs("\\t", out);  break;
            default:
                if (c < 0x20) {
                    fprintf(out, "\\u%04x", c);
                } else {
                    fputc(c, out);
                }
        }
    }
    fputc('"', out);
}

/*
 * Ring buffer callback:
 * - Runs in user space, called by libbpf when an event is received
 * - Must be fast (avoid heavy work here on busy nodes)
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(struct event))
        return 0;

    struct event e = *(const struct event *)data;

    /* Convert monotonic -> wall clock */
    __u64 wall_ns = realtime_minus_monotonic_ns + e.ts_ns;
    time_t sec = (time_t)(wall_ns / 1000000000ULL);
    long nsec = (long)(wall_ns % 1000000000ULL);

    struct tm tm;
    localtime_r(&sec, &tm);

    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

    /* Improve readability of args */
    prettify_args(e.args, sizeof(e.args));

    const char *file = e.filename[0] ? e.filename : "-";
    const char *args = e.args[0] ? e.args : "-";

    if (!g_json_output) {
        /* Human-friendly line output (default) */
        fprintf(stdout,
            "exec time=%s.%03ld uid=%u pid=%u ppid=%u comm=%s cgroup=%llu file=%s args=\"%s\"\n",
            tbuf,
            nsec / 1000000L,
            e.uid,
            e.pid,
            e.ppid,
            e.comm,
            (unsigned long long)e.cgroup_id,
            file,
            args);
    } else {
        /* JSONL output (one JSON object per line), useful for Loki/Grafana */
        fputs("{", stdout);

        fputs("\"time\":", stdout);
        fprintf(stdout, "\"%s.%03ld\",", tbuf, nsec / 1000000L);

        fprintf(stdout, "\"uid\":%u,", e.uid);
        fprintf(stdout, "\"pid\":%u,", e.pid);
        fprintf(stdout, "\"ppid\":%u,", e.ppid);
        fprintf(stdout, "\"cgroup\":%llu,", (unsigned long long)e.cgroup_id);

        fputs("\"comm\":", stdout);
        json_escape_and_print(stdout, e.comm, sizeof(e.comm));
        fputc(',', stdout);

        fputs("\"file\":", stdout);
        json_escape_and_print(stdout, file, sizeof(e.filename));
        fputc(',', stdout);

        fputs("\"args\":", stdout);
        json_escape_and_print(stdout, args, sizeof(e.args));

        fputs("}\n", stdout);
    }

    return 0;
}

/* Read counter map (ARRAY key=0) from BPF into user space. */
static __u64 read_counter_fd(int fd)
{
    __u32 key = 0;
    __u64 val = 0;
    if (fd >= 0 && bpf_map_lookup_elem(fd, &key, &val) == 0)
        return val;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--sample N] [--stats] [--json]\n", prog);
    fprintf(stderr, "  --sample N   Enable sampling for non-root: keep 1/N (N>1). Default off.\n");
    fprintf(stderr, "  --stats      Print stats every ~5 seconds. Default off.\n");
    fprintf(stderr, "  --json       Output events as JSON lines (JSONL). Default off.\n");
}

int main(int argc, char **argv)
{
    int sample_rate = 0; /* sampling OFF by default */

    /* Parse CLI flags */
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "--sample") || !strcmp(argv[i], "-s")) && i + 1 < argc) {
            sample_rate = atoi(argv[++i]);
            if (sample_rate < 0) sample_rate = 0;
        } else if (!strcmp(argv[i], "--stats")) {
            g_stats_enabled = true;
        } else if (!strcmp(argv[i], "--json")) {
            g_json_output = true;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    struct sensor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    int exit_code = 0;

    /*
     * Line-buffer stdout/stderr:
     * Under systemd/journald, stdout can become block-buffered otherwise,
     * making logs appear delayed/batched.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    init_time_offset();

    /* Handle clean shutdown (systemd sends SIGTERM on stop/restart). */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Open the generated BPF skeleton */
    skel = sensor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /*
     * Load BPF object:
     * - creates maps
     * - runs verifier
     * - prepares programs for attach
     */
    err = sensor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF programs: %d\n", err);
        exit_code = 1;
        goto cleanup;
    }

    /*
     * Set sampling config (after load, before attach):
     * We write struct config into cfg map (key=0).
     *
     * This requires:
     * - sensor.bpf.c defines a map named 'cfg'
     * - that map's value is struct config
     */
    {
        __u32 key = 0;
        struct config c = {
            .sample_rate = (unsigned int)sample_rate,
            .pad = 0,
        };

        int fd_cfg = bpf_map__fd(skel->maps.cfg);
        if (fd_cfg >= 0) {
            if (bpf_map_update_elem(fd_cfg, &key, &c, BPF_ANY) != 0) {
                fprintf(stderr, "WARNING: failed to set sample_rate=%d\n", sample_rate);
            }
        } else {
            /* If cfg map isn't present, sampling just won't work. */
            if (sample_rate > 1) {
                fprintf(stderr, "WARNING: cfg map missing, cannot enable sampling\n");
            }
        }

        if (sample_rate > 1)
            fprintf(stderr, "Sampling enabled for non-root: keep 1/%d\n", sample_rate);
    }

    /* Attach programs to their hooks */
    err = sensor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        exit_code = 1;
        goto cleanup;
    }

    /* Create ring buffer reader for rb map */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        exit_code = 1;
        goto cleanup;
    }

    /* Counter map fds (used only if --stats is enabled) */
    int fd_events = bpf_map__fd(skel->maps.events);
    int fd_drops  = bpf_map__fd(skel->maps.drops);

    /* Stats tracking */
    __u64 last_events = 0, last_drops = 0;
    __u64 last_t_ns = get_time_ns(CLOCK_MONOTONIC);
    int tick = 0;

    fprintf(stdout, "Monitoring process exec events...\n");

    /*
     * Main polling loop:
     * ring_buffer__poll() returns:
     *  - number of records processed (>=0)
     *  - -EINTR if interrupted by a signal (normal during SIGTERM)
     *  - other negative values on error
     */
    while (!exiting) {
        err = ring_buffer__poll(rb, 250 /* ms */);
        if (err == -EINTR)
            continue;
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            exit_code = 1;
            break;
        }

        /*
         * Optional stats output:
         * Print every ~5 seconds (20 * 250ms).
         * This is useful on busy nodes to verify whether you're dropping events.
         */
        if (g_stats_enabled && ++tick >= 20) {
            __u64 now_ns = get_time_ns(CLOCK_MONOTONIC);
            double dt = (now_ns > last_t_ns) ? ((now_ns - last_t_ns) / 1e9) : 5.0;

            __u64 ev = read_counter_fd(fd_events);
            __u64 dr = read_counter_fd(fd_drops);

            __u64 dev = ev - last_events;
            __u64 ddr = dr - last_drops;

            fprintf(stderr,
                "stats interval=%.1fs events=%llu (+%llu, %.1f/s) drops=%llu (+%llu, %.2f/s)\n",
                dt,
                (unsigned long long)ev, (unsigned long long)dev, dev / dt,
                (unsigned long long)dr, (unsigned long long)ddr, ddr / dt);

            last_events = ev;
            last_drops = dr;
            last_t_ns = now_ns;
            tick = 0;
        }
    }

cleanup:
    ring_buffer__free(rb);
    sensor_bpf__destroy(skel);

    /* Exit 0 on normal shutdown (SIGTERM/SIGINT), non-zero on real errors. */
    return exit_code;
}

