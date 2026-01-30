# =========================
# Configuration
# =========================

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/')
VMLINUX := /sys/kernel/btf/vmlinux

TARGET := sensor
BPF_OBJ := $(TARGET).bpf.o
SKEL := $(TARGET).skel.h

CFLAGS := -g -O2 -Wall -Wextra
LDFLAGS := -lbpf -lelf -lz

# =========================
# Default target
# =========================

all: $(TARGET)

# =========================
# Generate vmlinux.h (CO-RE)
# =========================

vmlinux.h:
	@if [ ! -e $(VMLINUX) ]; then \
		echo "ERROR: BTF not found at $(VMLINUX)"; \
		exit 1; \
	fi
	$(BPFTOOL) btf dump file $(VMLINUX) format c > vmlinux.h

# =========================
# Compile BPF program
# =========================

$(BPF_OBJ): sensor.bpf.c interface.h vmlinux.h
	$(CLANG) \
		-target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-O2 -g \
		-Wall -Werror \
		-c $< -o $@

	$(LLVM_STRIP) -g $@

# =========================
# Generate skeleton
# =========================

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# =========================
# Compile user-space binary
# =========================

$(TARGET): main.c interface.h $(SKEL)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# =========================
# Cleanup
# =========================

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL) vmlinux.h

.PHONY: all clean
