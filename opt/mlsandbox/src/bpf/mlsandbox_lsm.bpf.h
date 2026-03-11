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
