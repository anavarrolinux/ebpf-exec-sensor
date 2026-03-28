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

Use Cases
 - Detect unexpected shells, LOLBins, suspicious parent/child chains
 - Trace exec activity in KubeVirt nodes / container hosts
 - Feed to Loki and alert on patterns

---
## Files

- `sensor.bpf.c` – kernel-side eBPF program (CO-RE)
- `main.c` – user-space loader and printer (libbpf skeleton)
- `interface.h` – shared ABI between kernel/user space
- `Makefile` – builds CO-RE BPF object + skeleton + user-space binary
- `ebpf-exec-sensor.service` – example of a working Systemd unit file

---

## Installation

```
mkdir /opt/ebpf-exec-sensor
git clone https://github.com/anavarrolinux/ebpf-exec-sensor.git
cd ebpf-exec-sensor/
make
install -m 700 sensor /opt/ebpf-exec-sensor
cp ebpf-exec-sensor.service /etc/systemd/system/
systemctl start ebpf-exec-sensor
```

---

## Requirements (Rocky Linux 9)

Install dependencies:

```bash
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --set-enabled crb
sudo dnf makecache
sudo dnf install -y clang llvm bpftool libbpf libbpf-devel elfutils-libelf-devel zlib-devel make gcc
```
eBPF Sensor Output
<img width="1172" height="563" alt="image" src="https://github.com/user-attachments/assets/c873709c-04e7-4711-94c6-bc646c0978a6" />

eBPF Sensor systemd-analysis security
<img width="1172" height="563" alt="image" src="https://github.com/user-attachments/assets/f8c84954-a4d1-47b0-a177-b89e9d4c2129" />


Initial scaffolding was AI-assisted; functionality, testing, debugging, and final design decisions were implemented through iterative development and validation.
