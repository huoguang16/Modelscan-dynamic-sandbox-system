#!/bin/bash
# MLSandbox 一键修复和重新编译脚本
# 从当前目录复制修复后的文件到项目目录，然后编译
set -euo pipefail

PROJECT="/opt/mlsandbox"
SRC="$PROJECT/src"

echo "============================================"
echo "  MLSandbox 一键修复脚本"
echo "============================================"
echo ""

# ---- 步骤 1: 写入修复后的 BPF 头文件 ----
echo "[1/6] 写入 mlsandbox_lsm.bpf.h ..."
cat > "$SRC/bpf/mlsandbox_lsm.bpf.h" << 'HEADER_EOF'
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MLSANDBOX_LSM_BPF_H
#define __MLSANDBOX_LSM_BPF_H

#define PHASE_INIT         0
#define PHASE_DESERIALIZE  1
#define PHASE_POST_LOAD    2
#define PHASE_INFERENCE    3

#define ACTION_ALLOW  0
#define ACTION_DENY   1
#define ACTION_KILL   2

#define MAX_PATH_LEN  256
#define MAX_THREADS   32
#define MAX_PROCS     4

#define HOOK_FILE_OPEN       1
#define HOOK_SOCKET_CONNECT  2
#define HOOK_SOCKET_CREATE   3
#define HOOK_BPRM_CHECK      4
#define HOOK_MMAP_FILE       5
#define HOOK_TASK_ALLOC      6
#define HOOK_PTRACE          7
#define HOOK_FILE_IOCTL      8
#define HOOK_MPROTECT        9

struct behavior_stats {
    __u64 file_open_cnt;
    __u64 mmap_exec_cnt;
    __u64 clone_thread_cnt;
    __u64 clone_proc_cnt;
    __u64 socket_attempt_cnt;
    __u64 execve_attempt_cnt;
    __u64 denied_cnt;
};

struct proc_info {
    __u32 total_threads;
    __u32 total_procs;
};

struct net_acl_key {
    __u32 ip;
    __u16 port;
    __u16 pad;
};

struct alert_event {
    __u64 cgroup_id;
    __u64 timestamp;
    __u32 pid;
    __u32 hook_id;
    __u32 action;
    __u32 phase;
    __u32 detail_code;
    __u32 _pad;
    char  comm[16];
};

#endif
HEADER_EOF

# ---- 步骤 2: 写入修复后的 BPF 程序 ----
echo "[2/6] 写入 mlsandbox_lsm.bpf.c (无字符串字面量) ..."
cat > "$SRC/bpf/mlsandbox_lsm.bpf.c" << 'BPF_EOF'
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mlsandbox_lsm.bpf.h"

#define O_WRONLY_K      00000001
#define O_RDWR_K        00000002
#define O_CREAT_K       00000100
#define O_TRUNC_K       00001000
#define AF_UNIX_K       1
#define AF_INET_K       2
#define CLONE_THREAD_K  0x00010000
#define PROT_EXEC_K     0x4
#define TIOCSTI_K       0x5412

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u32);
} cgroup_phase_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, struct behavior_stats);
} syscall_counter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u32);
} file_acl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct net_acl_key);
    __type(value, __u32);
} connect_acl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, struct proc_info);
} process_tree_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} alert_ringbuf SEC(".maps");

static __always_inline bool is_sandboxed(__u64 cgid)
{
    return bpf_map_lookup_elem(&cgroup_phase_map, &cgid) != NULL;
}

static __always_inline __u32 get_phase(__u64 cgid)
{
    __u32 *p = bpf_map_lookup_elem(&cgroup_phase_map, &cgid);
    return p ? *p : PHASE_INFERENCE;
}

static __always_inline void emit_alert(__u64 cgid, __u32 hook_id,
                                        __u32 action, __u32 phase,
                                        __u32 detail_code)
{
    struct alert_event *evt = bpf_ringbuf_reserve(&alert_ringbuf,
                                                   sizeof(*evt), 0);
    if (!evt) return;
    evt->cgroup_id   = cgid;
    evt->timestamp   = bpf_ktime_get_ns();
    evt->pid         = bpf_get_current_pid_tgid() >> 32;
    evt->hook_id     = hook_id;
    evt->action      = action;
    evt->phase       = phase;
    evt->detail_code = detail_code;
    evt->_pad        = 0;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_ringbuf_submit(evt, 0);
}

SEC("lsm/file_open")
int BPF_PROG(mlsandbox_file_open, struct file *file)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_sandboxed(cgid)) return 0;
    __u32 phase = get_phase(cgid);

    struct behavior_stats *s = bpf_map_lookup_elem(&syscall_counter_map, &cgid);
    if (s) __sync_fetch_and_add(&s->file_open_cnt, 1);

    char fname[MAX_PATH_LEN];
    __builtin_memset(fname, 0, sizeof(fname));
    struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
    bpf_probe_read_kernel_str(fname, sizeof(fname), BPF_CORE_READ(de, d_name.name));

    unsigned int ff = BPF_CORE_READ(file, f_flags);
    bool is_wr = (ff & (O_WRONLY_K | O_RDWR_K | O_CREAT_K | O_TRUNC_K)) != 0;

    if (phase <= PHASE_DESERIALIZE) {
        if (fname[0]=='s' && fname[1]=='h' && fname[2]=='a' &&
            fname[3]=='d' && fname[4]=='o' && fname[5]=='w' && fname[6]==0) {
            emit_alert(cgid, HOOK_FILE_OPEN, ACTION_KILL, phase, 100);
            bpf_send_signal(9);
            return -1;
        }
        if (is_wr) {
            if (s) __sync_fetch_and_add(&s->denied_cnt, 1);
            emit_alert(cgid, HOOK_FILE_OPEN, ACTION_DENY, phase, 101);
            return -1;
        }
    }
    return 0;
}

SEC("lsm/socket_create")
int BPF_PROG(mlsandbox_socket_create, int family, int type, int protocol, int kern)
{
    if (kern) return 0;
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_sandboxed(cgid)) return 0;
    __u32 phase = get_phase(cgid);
    if (family == AF_UNIX_K) return 0;

    if (phase <= PHASE_POST_LOAD) {
        struct behavior_stats *s = bpf_map_lookup_elem(&syscall_counter_map, &cgid);
        if (s) { __sync_fetch_and_add(&s->socket_attempt_cnt, 1);
                 __sync_fetch_and_add(&s->denied_cnt, 1); }
        emit_alert(cgid, HOOK_SOCKET_CREATE, ACTION_KILL, phase, 200);
        bpf_send_signal(9);
        return -1;
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(mlsandbox_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_sandboxed(cgid)) return 0;
    __u32 phase = get_phase(cgid);

    struct behavior_stats *s = bpf_map_lookup_elem(&syscall_counter_map, &cgid);
    if (s) __sync_fetch_and_add(&s->socket_attempt_cnt, 1);

    if (phase <= PHASE_POST_LOAD) {
        if (s) __sync_fetch_and_add(&s->denied_cnt, 1);
        emit_alert(cgid, HOOK_SOCKET_CONNECT, ACTION_KILL, phase, 201);
        bpf_send_signal(9);
        return -1;
    }
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(mlsandbox_bprm_check, struct linux_binprm *bprm)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_sandboxed(cgid)) return 0;
    __u32 phase = get_phase(cgid);

    struct behavior_stats *s = bpf_map_lookup_elem(&syscall_counter_map, &cgid);
    if (s) __sync_fetch_and_add(&s->execve_attempt_cnt, 1);

    if (phase == PHASE_INIT) return 0;

    if (s) __sync_fetch_and_add(&s->denied_cnt, 1);
    emit_alert(cgid, HOOK_BPRM_CHECK, ACTION_KILL, phase, 300);
    bpf_send_signal(9);
    return -1;
}

SEC("lsm/mmap_file")
int BPF_PROG(mlsandbox_mmap_file, struct file *file,
             unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_sandboxed(cgid)) return 0;
    if (!(prot & PROT_EXEC_K)) return 0;
    __u32 phase = get_phase(cgid);

    struct behavior_stats *s = bpf_map_lookup_elem(&syscall_counter_map, &cgid);
    if (s) __sync_fetch_and_add(&s->mmap_exec_cnt, 1);

    if (!file) {
        if (s) __sync_fetch_and_add(&s->denied_cnt, 1);
        emit_alert(cgid, HOOK_MMAP_FILE, ACTION_KILL, phase, 400);
        bpf_send_signal(9);
        return -1;
    }
    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(mlsandbox_task_alloc, struct task_struct *task,
             unsigned long clone_flags)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_sandboxed(cgid)) return 0;
    __u32 phase = get_phase(cgid);

    struct proc_info *pi = bpf_map_lookup_elem(&process_tree_map, &cgid);
    if (!pi) return 0;
    struct behavior_stats *s = bpf_map_lookup_elem(&syscall_counter_map, &cgid);

    if (clone_flags & CLONE_THREAD_K) {
        __sync_fetch_and_add(&pi->total_threads, 1);
        if (s) __sync_fetch_and_add(&s->clone_thread_cnt, 1);
        if (pi->total_threads > MAX_THREADS) {
            emit_alert(cgid, HOOK_TASK_ALLOC, ACTION_DENY, phase, 500);
            return -1;
        }
    } else {
        __sync_fetch_and_add(&pi->total_procs, 1);
        if (s) __sync_fetch_and_add(&s->clone_proc_cnt, 1);
        if (phase >= PHASE_DESERIALIZE) {
            if (s) __sync_fetch_and_add(&s->denied_cnt, 1);
            emit_alert(cgid, HOOK_TASK_ALLOC, ACTION_KILL, phase, 501);
            bpf_send_signal(9);
            return -1;
        }
        if (pi->total_procs > MAX_PROCS) {
            emit_alert(cgid, HOOK_TASK_ALLOC, ACTION_KILL, phase, 502);
            bpf_send_signal(9);
            return -1;
        }
    }
    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(mlsandbox_ptrace, struct task_struct *child, unsigned int mode)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_sandboxed(cgid)) return 0;
    emit_alert(cgid, HOOK_PTRACE, ACTION_KILL, get_phase(cgid), 600);
    bpf_send_signal(9);
    return -1;
}

SEC("lsm/file_ioctl")
int BPF_PROG(mlsandbox_file_ioctl, struct file *file,
             unsigned int cmd, unsigned long arg)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_sandboxed(cgid)) return 0;
    if (cmd == TIOCSTI_K) {
        emit_alert(cgid, HOOK_FILE_IOCTL, ACTION_KILL, get_phase(cgid), 700);
        bpf_send_signal(9);
        return -1;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
BPF_EOF

# ---- 步骤 3: 写入修复后的 userspace 程序 ----
echo "[3/6] 写入 userspace/mlsandbox.c (兼容旧版 libbpf) ..."
cat > "$SRC/userspace/mlsandbox.c" << 'USER_EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mlsandbox_lsm.skel.h"
#include "mlsandbox_lsm.bpf.h"

#define CGROUP_BASE "/sys/fs/cgroup/mlsandbox"

static volatile sig_atomic_t g_running = 1;
static void sig_handler(int sig) { (void)sig; g_running = 0; }

static const char *detail_str(__u32 code) {
    switch (code) {
    case 100: return "sensitive_file(shadow)";
    case 101: return "write_blocked_deser";
    case 200: return "socket_create_blocked";
    case 201: return "socket_connect_blocked";
    case 300: return "execve_blocked";
    case 400: return "anon_mmap+exec(shellcode)";
    case 401: return "mmap_exec_unknown_file";
    case 500: return "thread_limit";
    case 501: return "fork_blocked_deser";
    case 502: return "fork_bomb";
    case 600: return "ptrace_blocked";
    case 700: return "tiocsti_blocked";
    default:  return "unknown";
    }
}

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int rc = (int)write(fd, data, strlen(data));
    close(fd);
    return rc > 0 ? 0 : -1;
}

static __u64 get_cgroup_id(const char *path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return 0;
    struct { struct file_handle fh; unsigned char pad[128]; } buf;
    int mnt = 0;
    buf.fh.handle_bytes = sizeof(buf.pad);
    if (name_to_handle_at(fd, "", &buf.fh, &mnt, AT_EMPTY_PATH) < 0) {
        struct stat st; fstat(fd, &st); close(fd);
        return (__u64)st.st_ino;
    }
    close(fd);
    __u64 id = 0;
    memcpy(&id, buf.fh.f_handle, sizeof(id));
    return id;
}

static __u64 setup_cgroup(const char *sess, char *out, size_t outsz) {
    mkdir(CGROUP_BASE, 0755);
    write_file("/sys/fs/cgroup/cgroup.subtree_control", "+pids +memory");
    snprintf(out, outsz, "%s/%s", CGROUP_BASE, sess);
    if (mkdir(out, 0755) && errno != EEXIST) { perror("mkdir cg"); return 0; }
    char t[600];
    snprintf(t, sizeof(t), "%s/pids.max", out);   write_file(t, "64");
    snprintf(t, sizeof(t), "%s/memory.max", out);  write_file(t, "8589934592");
    return get_cgroup_id(out);
}

static int cg_add_pid(const char *cg, pid_t pid) {
    char t[600], p[32];
    snprintf(t, sizeof(t), "%s/cgroup.procs", cg);
    snprintf(p, sizeof(p), "%d", pid);
    return write_file(t, p);
}

static int handle_event(void *ctx, void *data, size_t sz) {
    (void)ctx; (void)sz;
    const struct alert_event *e = data;
    const char *acts[] = {"ALLOW","DENY","KILL"};
    const char *phs[]  = {"INIT","DESER","POST","INFER"};
    fprintf(stderr, "\033[1;31m[ALERT]\033[0m hook=%u action=%s phase=%s "
        "pid=%u comm=%s reason=%s\n",
        e->hook_id, acts[e->action<3?e->action:0],
        phs[e->phase<4?e->phase:0],
        e->pid, e->comm, detail_str(e->detail_code));
    return 0;
}

struct rb_ctx { struct ring_buffer *rb; };
static void *rb_thread(void *a) {
    struct rb_ctx *c = a;
    while (g_running) ring_buffer__poll(c->rb, 100);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <model> [-- cmd args...]\n", argv[0]);
        return 1;
    }
    const char *model = argv[1];
    int cmd_start = 0;
    for (int i=2; i<argc; i++)
        if (!strcmp(argv[i],"--")) { cmd_start = i+1; break; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct mlsandbox_lsm_bpf *sk = mlsandbox_lsm_bpf__open();
    if (!sk) { fprintf(stderr, "BPF open fail: %s\n", strerror(errno)); return 1; }

    int err = mlsandbox_lsm_bpf__load(sk);
    if (err) {
        fprintf(stderr, "BPF load fail: %d\n>>> cat /sys/kernel/security/lsm must show 'bpf'\n", err);
        mlsandbox_lsm_bpf__destroy(sk); return 1;
    }
    err = mlsandbox_lsm_bpf__attach(sk);
    if (err) { fprintf(stderr, "BPF attach fail: %d\n", err);
               mlsandbox_lsm_bpf__destroy(sk); return 1; }
    printf("[+] eBPF LSM programs loaded and attached\n");

    int fd_ph = bpf_map__fd(sk->maps.cgroup_phase_map);
    int fd_st = bpf_map__fd(sk->maps.syscall_counter_map);
    int fd_pr = bpf_map__fd(sk->maps.process_tree_map);
    int fd_rb = bpf_map__fd(sk->maps.alert_ringbuf);

    char sid[64]; snprintf(sid, sizeof(sid), "sess_%d", getpid());
    char cgp[512];
    __u64 cgid = setup_cgroup(sid, cgp, sizeof(cgp));
    if (!cgid) { err=1; goto done; }
    printf("[+] Cgroup: %s (id=%llu)\n", cgp, (unsigned long long)cgid);

    { __u32 ph = PHASE_INIT; bpf_map_update_elem(fd_ph, &cgid, &ph, BPF_ANY); }
    { struct behavior_stats z; memset(&z,0,sizeof(z));
      bpf_map_update_elem(fd_st, &cgid, &z, BPF_ANY); }
    { struct proc_info z; memset(&z,0,sizeof(z));
      bpf_map_update_elem(fd_pr, &cgid, &z, BPF_ANY); }
    printf("[+] Maps initialized (phase=INIT)\n");

    struct ring_buffer *rb = ring_buffer__new(fd_rb, handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ringbuf fail\n"); err=1; goto maps; }
    struct rb_ctx rc = { .rb = rb };
    pthread_t tid; pthread_create(&tid, NULL, rb_thread, &rc);

    pid_t ch = fork();
    if (ch == 0) {
        usleep(80000);
        if (cmd_start > 0 && cmd_start < argc)
            execvp(argv[cmd_start], &argv[cmd_start]);
        else
            execlp("python3","python3",
                   "/opt/mlsandbox/scripts/load_model.py", model, NULL);
        perror("exec"); _exit(127);
    }
    if (ch < 0) { perror("fork"); err=1; goto rb_clean; }

    cg_add_pid(cgp, ch);
    { __u32 ph = PHASE_DESERIALIZE; bpf_map_update_elem(fd_ph,&cgid,&ph,BPF_ANY); }
    printf("[+] Phase -> DESERIALIZE (child pid=%d)\n", ch);

    int st = 0; waitpid(ch, &st, 0);
    usleep(200000);

    if (WIFEXITED(st) && WEXITSTATUS(st)==0)
        printf("\033[1;32m[+] Model loaded successfully — SAFE\033[0m\n");
    else if (WIFSIGNALED(st) && WTERMSIG(st)==9) {
        printf("\033[1;31m[!] ATTACK DETECTED — process killed by eBPF\033[0m\n");
        err = 1;
    } else {
        printf("[!] Abnormal exit (code=%d sig=%d)\n",
            WIFEXITED(st)?WEXITSTATUS(st):-1, WIFSIGNALED(st)?WTERMSIG(st):-1);
        err = 1;
    }

    { struct behavior_stats fs;
      if (bpf_map_lookup_elem(fd_st, &cgid, &fs)==0) {
        printf("\n=== Behavioral Summary ===\n");
        printf("  file_open      : %llu\n", (unsigned long long)fs.file_open_cnt);
        printf("  mmap+exec      : %llu\n", (unsigned long long)fs.mmap_exec_cnt);
        printf("  clone(thread)  : %llu\n", (unsigned long long)fs.clone_thread_cnt);
        printf("  clone(process) : %llu\n", (unsigned long long)fs.clone_proc_cnt);
        printf("  socket attempts: %llu\n", (unsigned long long)fs.socket_attempt_cnt);
        printf("  execve attempts: %llu\n", (unsigned long long)fs.execve_attempt_cnt);
        printf("  denied total   : %llu\n", (unsigned long long)fs.denied_cnt);
      }
    }

rb_clean:
    g_running = 0; pthread_join(tid, NULL); ring_buffer__free(rb);
maps:
    bpf_map_delete_elem(fd_ph, &cgid);
    bpf_map_delete_elem(fd_st, &cgid);
    bpf_map_delete_elem(fd_pr, &cgid);
done:
    mlsandbox_lsm_bpf__destroy(sk);
    rmdir(cgp);
    return err ? 1 : 0;
}
USER_EOF

# ---- 步骤 4: 更新 Makefile ----
echo "[4/6] 更新 Makefile ..."
cat > "$SRC/Makefile" << 'MAKE_EOF'
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
MAKE_EOF

# ---- 步骤 5: 确保 load_model.py 存在 ----
echo "[5/6] 确认 scripts/load_model.py ..."
if [ ! -f "$PROJECT/scripts/load_model.py" ]; then
cat > "$PROJECT/scripts/load_model.py" << 'PYEOF'
#!/usr/bin/env python3
import sys, os, time, json

def load_pickle(path):
    import pickle
    with open(path, 'rb') as f:
        return pickle.load(f)

def load_pytorch(path):
    import torch
    return torch.load(path, map_location='cpu', weights_only=False)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: load_model.py <path>", file=sys.stderr); sys.exit(1)
    path = sys.argv[1]
    ext = os.path.splitext(path)[1].lower()
    loaders = {'.pkl': load_pickle, '.pickle': load_pickle,
               '.pt': load_pytorch, '.pth': load_pytorch}
    loader = loaders.get(ext, load_pickle)
    t0 = time.monotonic()
    try:
        model = loader(path)
        dt = time.monotonic() - t0
        print(json.dumps({"status":"success","format":ext,
                           "load_time_ms":round(dt*1000,2),
                           "size":os.path.getsize(path)}))
    except SystemExit: raise
    except Exception as e:
        print(json.dumps({"status":"error","error":str(e)}), file=sys.stderr)
        sys.exit(1)
PYEOF
chmod +x "$PROJECT/scripts/load_model.py"
echo "  Created."
else
echo "  Already exists."
fi

# ---- 步骤 6: 编译 ----
echo "[6/6] 编译..."
cd "$SRC"
make clean
make CLANG=clang-15

echo ""
echo "============================================"
echo "  编译完成！接下来运行测试："
echo ""
echo "  # 测试安全模型"
echo "  sudo ./mlsandbox /opt/mlsandbox/models/safe_model.pkl"
echo ""
echo "  # 测试恶意模型"
echo "  sudo ./mlsandbox /opt/mlsandbox/attacks/a1_reverse_shell.pkl"
echo ""
echo "  # 运行完整测试套件"
echo "  sudo /opt/mlsandbox/scripts/run_tests.sh"
echo "============================================"
