/*
 * MLSandbox Userspace Orchestrator (v3 - fixed exec timing)
 *
 * Key fix: use pipe synchronization so that:
 *   1. Child is moved into cgroup (phase=INIT, execve allowed)
 *   2. Child execs python3 (succeeds because INIT allows execve)
 *   3. Python3 signals "ready" by closing the pipe
 *   4. THEN parent switches phase to DESERIALIZE
 *
 * This eliminates the race where DESERIALIZE was set before
 * the child had a chance to exec python3.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
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
    for (int i = 2; i < argc; i++)
        if (!strcmp(argv[i], "--")) { cmd_start = i + 1; break; }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* ---- 1. Load eBPF ---- */
    struct mlsandbox_lsm_bpf *sk = mlsandbox_lsm_bpf__open();
    if (!sk) { fprintf(stderr, "BPF open fail: %s\n", strerror(errno)); return 1; }

    int err = mlsandbox_lsm_bpf__load(sk);
    if (err) {
        fprintf(stderr, "BPF load fail: %d\n"
            ">>> cat /sys/kernel/security/lsm must show 'bpf'\n", err);
        mlsandbox_lsm_bpf__destroy(sk); return 1;
    }
    err = mlsandbox_lsm_bpf__attach(sk);
    if (err) {
        fprintf(stderr, "BPF attach fail: %d\n", err);
        mlsandbox_lsm_bpf__destroy(sk); return 1;
    }
    printf("[+] eBPF LSM programs loaded and attached\n");

    int fd_ph = bpf_map__fd(sk->maps.cgroup_phase_map);
    int fd_st = bpf_map__fd(sk->maps.syscall_counter_map);
    int fd_pr = bpf_map__fd(sk->maps.process_tree_map);
    int fd_rb = bpf_map__fd(sk->maps.alert_ringbuf);

    /* ---- 2. Create cgroup ---- */
    char sid[64]; snprintf(sid, sizeof(sid), "sess_%d", getpid());
    char cgp[512];
    __u64 cgid = setup_cgroup(sid, cgp, sizeof(cgp));
    if (!cgid) { err = 1; goto done; }
    printf("[+] Cgroup: %s (id=%llu)\n", cgp, (unsigned long long)cgid);

    /* ---- 3. Init maps with INIT phase ---- */
    { __u32 ph = PHASE_INIT; bpf_map_update_elem(fd_ph, &cgid, &ph, BPF_ANY); }
    { struct behavior_stats z; memset(&z, 0, sizeof(z));
      bpf_map_update_elem(fd_st, &cgid, &z, BPF_ANY); }
    { struct proc_info z; memset(&z, 0, sizeof(z));
      bpf_map_update_elem(fd_pr, &cgid, &z, BPF_ANY); }
    printf("[+] Maps initialized (phase=INIT)\n");

    /* ---- 4. Ringbuf consumer thread ---- */
    struct ring_buffer *rb = ring_buffer__new(fd_rb, handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ringbuf fail\n"); err = 1; goto maps; }
    struct rb_ctx rc = { .rb = rb };
    pthread_t tid; pthread_create(&tid, NULL, rb_thread, &rc);

    /* ---- 5. Create synchronization pipes ---- */
    /*
     * Pipe 1 (go_pipe): parent -> child
     *   Parent writes "g" when child is in cgroup and can exec.
     *
     * Pipe 2 (ready_pipe): child -> parent
     *   Child's write end is inherited by python3 via exec.
     *   When python3 starts and load_model.py begins, it closes
     *   the inherited fd. We detect this as EOF = "exec succeeded,
     *   python is running, switch to DESERIALIZE now".
     *
     *   Actually, exec itself closes FD_CLOEXEC fds. So we set
     *   the write end as CLOEXEC. When exec succeeds, the write
     *   end auto-closes, parent sees EOF -> python3 is running.
     */
    int go_pipe[2];    /* parent tells child "proceed with exec" */
    int ready_pipe[2]; /* auto-closes on exec -> parent detects */

    if (pipe(go_pipe) < 0 || pipe(ready_pipe) < 0) {
        perror("pipe"); err = 1; goto rb_clean;
    }

    /* Set ready_pipe write-end as close-on-exec */
    fcntl(ready_pipe[1], F_SETFD, FD_CLOEXEC);

    /* ---- 6. Fork child ---- */
    pid_t ch = fork();
    if (ch == 0) {
        /* ---- CHILD ---- */
        close(go_pipe[1]);     /* close write end of go_pipe */
        close(ready_pipe[0]);  /* close read end of ready_pipe */

        /* Block until parent says "go" */
        char buf;
        if (read(go_pipe[0], &buf, 1) <= 0) {
            /* Parent died or error */
            _exit(126);
        }
        close(go_pipe[0]);

        /*
         * Now exec python3.
         * ready_pipe[1] has FD_CLOEXEC, so it auto-closes when exec succeeds.
         * This signals the parent that python3 is now running.
         */
        if (cmd_start > 0 && cmd_start < argc)
            execvp(argv[cmd_start], &argv[cmd_start]);
        else
            execlp("python3", "python3",
                   "/opt/mlsandbox/scripts/load_model.py", model, NULL);

        /* exec failed */
        perror("exec");
        _exit(127);
    }
    if (ch < 0) { perror("fork"); err = 1; goto rb_clean; }

    /* ---- PARENT ---- */
    close(go_pipe[0]);     /* close read end of go_pipe */
    close(ready_pipe[1]);  /* close write end of ready_pipe */

    /* Move child into sandbox cgroup (phase is INIT = execve allowed) */
    if (cg_add_pid(cgp, ch) < 0) {
        fprintf(stderr, "Warning: could not move pid %d into cgroup\n", ch);
    }
    printf("[+] Child pid=%d moved into cgroup (phase=INIT)\n", ch);

    /* Signal child to proceed with exec */
    write(go_pipe[1], "g", 1);
    close(go_pipe[1]);

    /*
     * Wait for exec to complete:
     * ready_pipe[1] (child's write end) has FD_CLOEXEC.
     * When exec succeeds, that fd is closed, and our read returns 0 (EOF).
     * If exec fails, child exits and fd also closes.
     * Timeout after 5 seconds in case something goes wrong.
     */
    {
        struct pollfd pfd = { .fd = ready_pipe[0], .events = POLLIN };
        int pret = poll(&pfd, 1, 5000 /* 5s timeout */);
        if (pret <= 0) {
            fprintf(stderr, "Warning: timeout waiting for child exec\n");
        }
        /* Read to consume EOF */
        char tmp;
        read(ready_pipe[0], &tmp, 1);
        close(ready_pipe[0]);
    }

    /*
     * Small additional delay to let python3 fully initialize
     * (interpreter startup, import statements in load_model.py)
     * before we tighten the policy.
     */
    usleep(200000); /* 200ms */

    /* ---- 7. NOW switch to DESERIALIZE ---- */
    {
        __u32 ph = PHASE_DESERIALIZE;
        bpf_map_update_elem(fd_ph, &cgid, &ph, BPF_ANY);
    }
    printf("[+] Phase -> DESERIALIZE (enforcement active)\n");

    /* ---- 8. Wait for child ---- */
    int st = 0;
    waitpid(ch, &st, 0);
    usleep(200000); /* let ringbuf drain */

    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        printf("\033[1;32m[+] Model loaded successfully — SAFE\033[0m\n");
    } else if (WIFSIGNALED(st) && WTERMSIG(st) == 9) {
        printf("\033[1;31m[!] ATTACK DETECTED — process killed by eBPF\033[0m\n");
        err = 1;
    } else {
        int ex = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        int sg = WIFSIGNALED(st) ? WTERMSIG(st) : -1;
        printf("[!] Abnormal exit (code=%d signal=%d)\n", ex, sg);
        /* Not necessarily an attack - could be a load error */
        if (sg == 9) err = 1;
    }

    /* ---- 9. Print behavioral summary ---- */
    {
        struct behavior_stats fs;
        if (bpf_map_lookup_elem(fd_st, &cgid, &fs) == 0) {
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
    g_running = 0;
    pthread_join(tid, NULL);
    ring_buffer__free(rb);
maps:
    bpf_map_delete_elem(fd_ph, &cgid);
    bpf_map_delete_elem(fd_st, &cgid);
    bpf_map_delete_elem(fd_pr, &cgid);
done:
    mlsandbox_lsm_bpf__destroy(sk);
    rmdir(cgp);
    return err ? 1 : 0;
}
