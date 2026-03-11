CLANG   ?= clang-15
BPFTOOL ?= bpftool
CC      ?= gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I./bpf -Wall
USER_CFLAGS := -g -O2 -Wall -I./bpf
USER_LDFLAGS:= -lbpf -lelf -lpthread -lz

.PHONY: all clean

all: mlsandbox
	@echo ""
	@echo "Build OK!  Run: sudo ./mlsandbox <model.pkl>"

bpf/mlsandbox_lsm.bpf.o: bpf/mlsandbox_lsm.bpf.c bpf/vmlinux.h bpf/mlsandbox_lsm.bpf.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[bpf] $@"

bpf/mlsandbox_lsm.skel.h: bpf/mlsandbox_lsm.bpf.o
	$(BPFTOOL) gen skeleton $< > $@
	@echo "[skel] $@"

mlsandbox: userspace/mlsandbox.c bpf/mlsandbox_lsm.skel.h bpf/mlsandbox_lsm.bpf.h
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)
	@echo "[user] $@"

clean:
	rm -f bpf/mlsandbox_lsm.bpf.o bpf/mlsandbox_lsm.skel.h mlsandbox
