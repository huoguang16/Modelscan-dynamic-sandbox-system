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
