/*
 * eBPF exec sensor (CO-RE)
 *
 * Hook:
 *   tp/sched/sched_process_exec
 *
 * Captures:
 *   - PID / PPID (correct parent TGID)
 *   - UID
 *   - cgroup v2 id
 *   - executable filename
 *   - bounded argv preview
 *
 * Design goals:
 *   - Verifier-safe (bounded copies only)
 *   - No unbounded loops
 *   - Zeroed ringbuf memory to avoid stale data leakage
 *   - Runtime-configurable sampling
 *
 * Tested on Rocky Linux 9 (RHEL9-family kernels).
 */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "interface.h"

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Drop counter */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

/* Event counter */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} events SEC(".maps");

/* Runtime config (sampling) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} cfg SEC(".maps");

static __always_inline void inc_counter(void *map)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline __u32 get_sample_rate(void)
{
    __u32 key = 0;
    struct config *c = bpf_map_lookup_elem(&cfg, &key);
    if (!c)
        return 0;
    return c->sample_rate;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        inc_counter(&drops);
        return 0;
    }

 /* Ring buffer memory is not guaranteed to be zeroed.
  * Clear the event struct to prevent leaking stale bytes.
  */
    __builtin_memset(e, 0, sizeof(*e));

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->pid = pid_tgid >> 32;
    e->uid = uid_gid;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task_btf();

    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

   /* Optional sampling (non-root only).
    *
    * We sample in BPF to reduce ring buffer pressure on busy systems.
    * Root events are always kept since they are typically security-relevant.
    */
    __u32 rate = get_sample_rate();
    if (rate > 1 && e->uid != 0) {
        if ((bpf_get_prandom_u32() % rate) != 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
    }

    /* ----- filename via tracepoint __data_loc ----- */
    {
        __u32 loc = BPF_CORE_READ(ctx, __data_loc_filename);
        __u32 off = loc & 0xFFFF;

        const char *filename = (const char *)ctx + off;

        bpf_probe_read_kernel_str(
            e->filename,
            sizeof(e->filename),
            filename
        );
    }

    /* ----- argv preview from user memory ----- */
    {
        struct mm_struct *mm = BPF_CORE_READ(task, mm);
        if (mm) {
            unsigned long arg_start =
                BPF_CORE_READ(mm, arg_start);
            unsigned long arg_end =
                BPF_CORE_READ(mm, arg_end);

            if (arg_end > arg_start) {
                unsigned long len = arg_end - arg_start;

                if (len > (ARGS_LEN - 1))
                    len = (ARGS_LEN - 1);

                if (bpf_probe_read_user(
                        e->args,
                        len,
                        (void *)arg_start) == 0) {
                    e->args[len] = '\0';
                }
            }
        }
    }

    inc_counter(&events);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
