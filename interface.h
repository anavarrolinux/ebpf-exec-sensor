#ifndef INTERFACE_H
#define INTERFACE_H

/*
 * interface.h
 * -----------
 * This file defines the shared ABI (data contract) between:
 *   - the eBPF program in the kernel (sensor.bpf.c)
 *   - the user-space program (main.c)
 *
 * IMPORTANT RULE (CO-RE / vmlinux.h):
 *   Do NOT include <linux/types.h> or other kernel headers here.
 *   The BPF side already includes vmlinux.h, which defines kernel types.
 *   Including UAPI headers here causes typedef redefinition conflicts.
 *
 * So we define simple fixed-width types ourselves.
 */

typedef unsigned int __u32;
typedef unsigned long long __u64;

/*
 * TASK_COMM_LEN is 16 in the Linux kernel for task comm.
 * Keeping it identical makes output predictable.
 */
#define TASK_COMM_LEN 16

/*
 * These sizes are tradeoffs:
 * - Larger buffers capture more context but increase ringbuf pressure.
 * - Smaller buffers reduce overhead but may truncate.
 *
 * For production, ARGS_LEN=128 is often enough.
 * For learning / richer output, 256 is fine if you watch drops.
 */
#define FILENAME_LEN  256
#define ARGS_LEN      256

/*
 * event
 * -----
 * A single "process exec" event that the BPF program sends to user space.
 *
 * Design goals for BPF friendliness:
 * - Fixed-size fields only (no pointers)
 * - Bounded arrays (no flexible arrays)
 * - Simple POD struct (verifier loves this)
 *
 * ts_ns is monotonic time (ns since boot). We convert to wall clock in user space.
 */
struct event {
    __u32 pid;        /* TGID (process id) */
    __u32 ppid;       /* parent TGID (real PPID) */
    __u32 uid;        /* effective UID */
    __u64 cgroup_id;  /* cgroup v2 id (helps correlate to container/workload) */
    __u64 ts_ns;      /* monotonic timestamp from bpf_ktime_get_ns() */

    char comm[TASK_COMM_LEN];         /* task comm (short name) */
    char filename[FILENAME_LEN];      /* exec filename/path (truncated) */
    char args[ARGS_LEN];              /* argv preview (NUL-separated, then prettified in user space) */
};

/*
 * config
 * ------
 * Runtime configuration that user space can set *without recompiling*.
 *
 * sample_rate:
 *   - 0 or 1 => sampling disabled
 *   - N > 1  => keep 1/N of non-root events (root is still always kept)
 *
 * This is stored in a BPF MAP_TYPE_ARRAY with key=0.
 */
struct config {
    __u32 sample_rate;
    __u32 pad; /* padding / future expansion */
};

#endif /* INTERFACE_H */

