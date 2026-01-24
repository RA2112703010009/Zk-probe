# ---------- Toolchain ----------
CLANG       ?= clang
LLC         ?= llc
CC          ?= gcc

# ---------- Paths ----------
BPF_DIR     := ebpf
TP_DIR      := $(BPF_DIR)/tracepoints
XDP_DIR     := $(BPF_DIR)/xdp
USR_DIR     := userspace/collector
INC_DIR     := include

# ---------- Output ----------
BUILD_DIR   := build
BPF_OBJ_DIR := $(BUILD_DIR)/bpf
USR_OBJ_DIR := $(BUILD_DIR)/userspace

# ---------- Flags ----------
BPF_CFLAGS  := -O2 -g -Wall -target bpf \
               -D__TARGET_ARCH_x86 \
               -I$(INC_DIR)

USR_CFLAGS  := -O2 -g -Wall
USR_LDFLAGS := -lbpf -lelf -lz

# ---------- Sources ----------
TP_BPF_SRC  := $(TP_DIR)/execve_counter.bpf.c
XDP_BPF_SRC := $(XDP_DIR)/xdp_counter.bpf.c
USR_SRC     := $(USR_DIR)/phase1_loader.c

# ---------- Objects ----------
TP_BPF_OBJ  := $(BPF_OBJ_DIR)/execve_counter.bpf.o
XDP_BPF_OBJ := $(BPF_OBJ_DIR)/xdp_counter.bpf.o
USR_BIN     := $(USR_OBJ_DIR)/phase1_loader

# ---------- Targets ----------
.PHONY: all clean dirs

all: dirs $(TP_BPF_OBJ) $(XDP_BPF_OBJ) $(USR_BIN)

dirs:
	@mkdir -p $(BPF_OBJ_DIR)
	@mkdir -p $(USR_OBJ_DIR)

# ---------- BPF programs ----------
$(TP_BPF_OBJ): $(TP_BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(XDP_BPF_OBJ): $(XDP_BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ---------- Userspace loader ----------
$(USR_BIN): $(USR_SRC)
	$(CC) $(USR_CFLAGS) $< -o $@ $(USR_LDFLAGS)

# ---------- Cleanup ----------
clean:
	rm -rf $(BUILD_DIR)
