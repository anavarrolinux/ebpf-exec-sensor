// SPDX-License-Identifier: GPL-2.0
/*
 * sensor.bpf.c
 * ------------
 * Kernel-side eBPF program.
 *
 * Hooks:
 *   - tp/sched/sched_process_exec
 *     A typed tracepoint that fires when a process execs a new program.
 *
 * Output:
 *   - Writes fixed-size event structs into a ring buffer map (rb).
 *
 * Key production properties:
 *   - Bounded memory copies only
 *   - No unbounded loops
 *   - No libc, no printf (BPF can't do that)
 *   - Uses drop counters so you can detect loss under load
 *
 * Rocky Linux 9 / RHEL 9 notes:
 *   - Avoid including kernel headers other than vmlinux.h
 *   - Some RHEL kernels are picky about certain BTF + per-cpu map combos
 *   - Using ARRAY maps for counters is robust
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "interface.h"

/*
 * Ring buffer map:
 * - Efficient kernel->user communication
 * - max_entries is per-CPU
 * - If user space can’t keep up, bpf_ringbuf_reserve() returns NULL (drop)
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* per-CPU; tune based on drop rate */
} rb SEC(".maps");

/*
 * Counter maps:
 * We use MAP_TYPE_ARRAY (key=0) for simplicity and wide kernel compatibility.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");   /* ringbuf_reserve() failed */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} events SEC(".maps");  /* events submitted */

/*
 * Runtime config map (written by user space):
 * Controls optional sampling.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} cfg SEC(".maps");

/*
 * Atomic increment of a u64 stored in an ARRAY map.
 * This is verifier-safe and works well for counters.
 */
static __always_inline void inc_u64(void *map)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/*
 * Read sample_rate from cfg map.
 * If map lookup fails, return 0 (sampling off).
 */
static __always_inline __u32 get_sample_rate(void)
{
    __u32 key = 0;
    struct config *c = bpf_map_lookup_elem(&cfg, &key);
    if (!c)
        return 0;
    return c->sample_rate;
}

/*
 * Copy argv preview from user memory.
 *
 * Where do args live?
 *   Linux stores exec arguments in the process address space (user memory),
 *   accessible via current->mm->arg_start..arg_end.
 *
 * Safety / verifier:
 *   - We read a bounded slice (ARGS_LEN-1 max)
 *   - Use bpf_probe_read_user() for user memory
 *   - Always NUL-terminate
 *
 * Note:
 *   argv is NUL-separated in memory (each arg ends with '\0').
 *   User space will convert embedded NULs to spaces for display.
 */
static __always_inline void copy_args_preview(struct event *e, struct task_struct *task)
{
    struct mm_struct *mm;
    unsigned long arg_start, arg_end;
    __u64 len;

    e->args[0] = '\0';

    mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return;

    arg_start = BPF_CORE_READ(mm, arg_start);
    arg_end   = BPF_CORE_READ(mm, arg_end);
    if (arg_end <= arg_start)
        return;

    len = (__u64)(arg_end - arg_start);
    if (len >= (ARGS_LEN - 1))
        len = (ARGS_LEN - 1);

    if (bpf_probe_read_user(e->args, len, (const void *)arg_start) < 0) {
        e->args[0] = '\0';
        return;
    }
    e->args[len] = '\0';
}

/*
 * Typed tracepoint program:
 * On Rocky 9, trace_event_raw_sched_process_exec contains __data_loc_filename
 * but may not expose a bprm pointer. That's fine.
 *
 * __data_loc fields:
 *   - lower 16 bits: offset from ctx pointer
 *   - upper 16 bits: length
 * We use the offset to locate the kernel-resident filename string.
 */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e;
    __u64 pid_tgid, uid_gid;
    struct task_struct *task;
    __u32 ppid;

    /* Reserve space for event in ring buffer. If full, count drop and return. */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        inc_u64(&drops);
        return 0;
    }

    /*
     * Minimal fields first:
     * We want uid early so we can decide whether to sample.
     */
    pid_tgid = bpf_get_current_pid_tgid(); /* (tgid<<32) | tid */
    uid_gid  = bpf_get_current_uid_gid();  /* (gid<<32) | uid */

    e->pid = (__u32)(pid_tgid >> 32); /* TGID */
    e->uid = (__u32)uid_gid;          /* UID in low 32 bits */

    /*
     * Optional sampling (OFF by default):
     * If enabled (rate > 1), keep 1/rate of non-root events.
     * Root events are always kept because they’re often security-relevant.
     */
    __u32 rate = get_sample_rate();
    if (rate > 1 && e->uid != 0) {
        if ((bpf_get_prandom_u32() % rate) != 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
    }

    /* Now populate the rest of the event */
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /*
     * Correct PPID:
     * Don't confuse TID with PPID.
     * We read current->real_parent->tgid using CO-RE.
     */
    task = (struct task_struct *)bpf_get_current_task_btf();
    ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->ppid = ppid;

    /* filename from tracepoint __data_loc */
    e->filename[0] = '\0';
    {
        __u32 loc = BPF_CORE_READ(ctx, __data_loc_filename);
        __u32 off = loc & 0xFFFF;
        const char *fn = (const char *)ctx + off;

        /* filename is in kernel tracepoint data => read kernel string */
        bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    }

    /* argv preview from user space memory */
    copy_args_preview(e, task);

    /* Count and submit */
    inc_u64(&events);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

