# eBPF Exec Sensor (Rocky Linux 9 / RHEL9-style kernels)

A small **libbpf + CO-RE** eBPF sensor that monitors process **exec** events on **Rocky Linux 9** (and similar RHEL9-family kernels).

It emits:
- wall-clock timestamp
- UID
- PID + **real PPID** (parent TGID)
- comm (task name)
- cgroup id
- executable filename
- bounded argv preview

It supports:
- **JSONL output** (`--json`) for Grafana Loki / Promtail / fluent-bit ingestion
- optional **stats** (`--stats`) showing events/sec and drops/sec
- optional **sampling** (`--sample N`) for non-root execs (default off)

> Why a bounded argv preview?  
> Full argv is unbounded and expensive. A fixed-size preview is a common production compromise.

---

## Files

- `sensor.bpf.c` – kernel-side eBPF program (CO-RE)
- `main.c` – user-space loader and printer (libbpf skeleton)
- `interface.h` – shared ABI between kernel/user space
- `Makefile` – builds CO-RE BPF object + skeleton + user-space binary

---

## Requirements (Rocky Linux 9)

Install dependencies:

```bash
sudo dnf install -y clang llvm bpftool libbpf libbpf-devel elfutils-libelf-devel zlib-devel make gcc
