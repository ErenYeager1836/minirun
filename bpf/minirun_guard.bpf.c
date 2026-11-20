/*
 * ==============================================================================
 * minirun Guard - eBPF Runtime Security Monitor
 * ==============================================================================
 *
 * PID SEMANTICS:
 *   All `pid`, `tgid`, and `ppid` fields captured by these tracepoints report the
 *   HOST-NAMESPACE PID/TGID (from `bpf_get_current_pid_tgid()`), NOT the virtualized
 *   PID inside the container's PID namespace. `ppid` captures the host-namespace
 *   real_parent->tgid to allow userspace sequence correlation across forks (e.g.
 *   Python script connecting -> sub-forking shell).
 *   Userspace correlates these host PIDs against `/sys/fs/cgroup/.../cgroup.procs`.
 *
 * SECURITY & TOCTOU BOUNDARY NOTE:
 *   User-space pointer reads (via `bpf_probe_read_user_str`) in sys_enter_* probes
 *   are inherently subject to Time-Of-Check to Time-Of-Use (TOCTOU) races if an
 *   untrusted process mutates userspace memory concurrently in another thread.
 *   These probes provide runtime TELEMETRY and heuristics; they are not a hard
 *   kernel security boundary (which would require BPF LSM / seccomp).
 *
 * ZERO-OVERHEAD SCOPING:
 *   Every probe starts by evaluating `bpf_get_current_cgroup_id()` against the
 *   `container_cgroups` map. If the current task does not belong to a monitored
 *   container cgroup v2 hierarchy, the probe returns immediately (0 cycles lost).
 * ==============================================================================
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "guard_event.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/*
 * ==============================================================================
 * BPF Maps
 * ==============================================================================
 */

/* Track active container cgroups: cgroup_id (u64) -> cgroup_config */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct cgroup_config);
} container_cgroups SEC(".maps");

/* 1 MiB Ring Buffer for streaming high-throughput events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

/* Per-CPU drop counter for ring buffer saturation telemetry */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

/* Per-CPU scratch buffer for path resolution (avoids 512-byte stack limit) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[GUARD_MAX_PATH]);
} path_scratch SEC(".maps");

/*
 * ==============================================================================
 * Internal Helper Functions
 * ==============================================================================
 */

static __always_inline void record_drop(void) {
    __u32 key = 0;
    __u64 *drop_cnt = bpf_map_lookup_elem(&drops, &key);
    if (drop_cnt) {
        (*drop_cnt)++;
    }
}

static __always_inline struct guard_event *reserve_event(void) {
    struct guard_event *e = bpf_ringbuf_reserve(&events, sizeof(struct guard_event), 0);
    if (!e) {
        record_drop();
        return NULL;
    }
    /* ringbuf is pre-zeroed by kernel */
    return e;
}

static __always_inline void init_event(struct guard_event *e, __u32 type, __u64 cgid, struct cgroup_config *cfg) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    e->type = type;
    e->severity = GUARD_SEV_INFO;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (__u32)pid_tgid;        /* Host namespace PID */
    e->tgid = (__u32)(pid_tgid >> 32); /* Host namespace TGID */
    e->ppid = BPF_CORE_READ(task, real_parent, tgid); /* Host namespace Parent TGID */
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    e->cgroup_id = cgid;
    e->container_idx = cfg->container_idx;
    e->flags = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/*
 * Check if path matches sensitive container breakout or host tampering targets.
 * Only emits events for these sensitive targets; all other paths return 0.
 *
 * In-kernel enforcement split:
 * - /run/docker.sock & /var/run/docker.sock: Unambiguous escape -> is_critical = 1
 * - /proc/sys/kernel/core_pattern: Only critical on write intent ((flags & 3) != 0)
 * - /etc/shadow & /etc/sudoers: Always HIGH, audit-only (never in-kernel kill)
 * - /proc/1/root: Container's own root in private PID userns -> HIGH, audit-only
 */
static __always_inline int is_sensitive_open(const char *p, int flags, int *is_critical) {
    *is_critical = 0;

    /* Check /etc/shadow or /etc/sudoers */
    if (p[0] == '/' && p[1] == 'e' && p[2] == 't' && p[3] == 'c' && p[4] == '/') {
        if (p[5] == 's' && p[6] == 'h' && p[7] == 'a' && p[8] == 'd' && p[9] == 'o' && p[10] == 'w' &&
            (p[11] == '\0' || p[11] == '/')) {
            return 1; /* Sensitive credential store (HIGH, audit only) */
        }
        if (p[5] == 's' && p[6] == 'u' && p[7] == 'd' && p[8] == 'o' && p[9] == 'e' && p[10] == 'r' && p[11] == 's' &&
            (p[12] == '\0' || p[12] == '/')) {
            return 1; /* Privilege escalation config (HIGH, audit only) */
        }
    }

    /* Check /run/docker.sock */
    if (p[0] == '/' && p[1] == 'r' && p[2] == 'u' && p[3] == 'n' && p[4] == '/' &&
        p[5] == 'd' && p[6] == 'o' && p[7] == 'c' && p[8] == 'k' && p[9] == 'e' && p[10] == 'r' &&
        p[11] == '.' && p[12] == 's' && p[13] == 'o' && p[14] == 'c' && p[15] == 'k' &&
        p[16] == '\0') {
        *is_critical = 1; /* Critical container breakout vector */
        return 1;
    }

    /* Check /var/run/docker.sock */
    if (p[0] == '/' && p[1] == 'v' && p[2] == 'a' && p[3] == 'r' && p[4] == '/' &&
        p[5] == 'r' && p[6] == 'u' && p[7] == 'n' && p[8] == '/' &&
        p[9] == 'd' && p[10] == 'o' && p[11] == 'c' && p[12] == 'k' && p[13] == 'e' && p[14] == 'r' &&
        p[15] == '.' && p[16] == 's' && p[17] == 'o' && p[18] == 'c' && p[19] == 'k' &&
        p[20] == '\0') {
        *is_critical = 1; /* Critical container breakout vector */
        return 1;
    }

    /* Check /proc/sys/kernel/core_pattern
     * Note: Harmless to read. Gate the kill on write intent: (flags & 3) != 0.
     * (O_ACCMODE is 3; O_RDONLY is 0. If non-zero, it indicates O_WRONLY or O_RDWR).
     */
    if (p[0] == '/' && p[1] == 'p' && p[2] == 'r' && p[3] == 'o' && p[4] == 'c' && p[5] == '/' &&
        p[6] == 's' && p[7] == 'y' && p[8] == 's' && p[9] == '/' &&
        p[10] == 'k' && p[11] == 'e' && p[12] == 'r' && p[13] == 'n' && p[14] == 'e' && p[15] == 'l' && p[16] == '/' &&
        p[17] == 'c' && p[18] == 'o' && p[19] == 'r' && p[20] == 'e' && p[21] == '_' &&
        p[22] == 'p' && p[23] == 'a' && p[24] == 't' && p[25] == 't' && p[26] == 'e' && p[27] == 'r' && p[28] == 'n' &&
        p[29] == '\0') {
        if ((flags & 3) != 0) {
            *is_critical = 1; /* Kernel crash handler hijack escape on write */
        }
        return 1;
    }

    /* Check /proc/1/root
     * Note: /proc/1/root is the container's own root when using isolated PID namespaces.
     * It is not a host escape; keep severity HIGH and do not trigger in-kernel kill.
     */
    if (p[0] == '/' && p[1] == 'p' && p[2] == 'r' && p[3] == 'o' && p[4] == 'c' && p[5] == '/' &&
        p[6] == '1' && p[7] == '/' &&
        p[8] == 'r' && p[9] == 'o' && p[10] == 'o' && p[11] == 't' &&
        (p[12] == '\0' || p[12] == '/')) {
        return 1;
    }

    return 0;
}

/*
 * Check if an AF_UNIX socket path points to docker.sock
 */
static __always_inline int is_docker_sock_unix(const char *p) {
    if ((p[0] == '/' && p[1] == 'r' && p[2] == 'u' && p[3] == 'n' && p[4] == '/' &&
         p[5] == 'd' && p[6] == 'o' && p[7] == 'c' && p[8] == 'k' && p[9] == 'e' && p[10] == 'r' &&
         p[11] == '.' && p[12] == 's' && p[13] == 'o' && p[14] == 'c' && p[15] == 'k' &&
         p[16] == '\0') ||
        (p[0] == '/' && p[1] == 'v' && p[2] == 'a' && p[3] == 'r' && p[4] == '/' &&
         p[5] == 'r' && p[6] == 'u' && p[7] == 'n' && p[8] == '/' &&
         p[9] == 'd' && p[10] == 'o' && p[11] == 'c' && p[12] == 'k' && p[13] == 'e' && p[14] == 'r' &&
         p[15] == '.' && p[16] == 's' && p[17] == 'o' && p[18] == 'c' && p[19] == 'k' &&
         p[20] == '\0')) {
        return 1;
    }
    return 0;
}

/*
 * Classify executed binary and command name heuristics.
 * NOTE: Busybox is deliberately treated as MEDIUM at most and NOT as a shell,
 * preventing false-positive alerts on standard Alpine Linux commands.
 */
static __always_inline void classify_exec(struct guard_event *e, const char *path, const char *comm) {
    /* Shell detection (sh, bash, dash, ash, zsh) */
    if ((comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == '\0') ||
        (comm[0] == 's' && comm[1] == 'h' && comm[2] == '\0') ||
        (comm[0] == 'd' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == '\0') ||
        (comm[0] == 'a' && comm[1] == 's' && comm[2] == 'h' && comm[3] == '\0') ||
        (comm[0] == 'z' && comm[1] == 's' && comm[2] == 'h' && comm[3] == '\0')) {
        e->severity = GUARD_SEV_HIGH;
        return;
    }

    /* Busybox invoked generically: MEDIUM severity at most, not a shell */
    if (comm[0] == 'b' && comm[1] == 'u' && comm[2] == 's' && comm[3] == 'y' &&
        comm[4] == 'b' && comm[5] == 'o' && comm[6] == 'x') {
        e->severity = GUARD_SEV_MEDIUM;
        return;
    }

    /* Reconnaissance & transfer tooling (heuristic list) */
    if ((comm[0] == 'n' && comm[1] == 'c' && comm[2] == '\0') ||
        (comm[0] == 'n' && comm[1] == 'c' && comm[2] == 'a' && comm[3] == 't' && comm[4] == '\0') ||
        (comm[0] == 'c' && comm[1] == 'u' && comm[2] == 'r' && comm[3] == 'l' && comm[4] == '\0') ||
        (comm[0] == 'w' && comm[1] == 'g' && comm[2] == 'e' && comm[3] == 't' && comm[4] == '\0') ||
        (comm[0] == 'w' && comm[1] == 'h' && comm[2] == 'o' && comm[3] == 'a' && comm[4] == 'm' && comm[5] == 'i' && comm[6] == '\0')) {
        e->severity = GUARD_SEV_MEDIUM;
        return;
    }

    /* Execution from writable/temporary directories (/tmp, /dev/shm, /var/tmp) */
    if ((path[0] == '/' && path[1] == 't' && path[2] == 'm' && path[3] == 'p' && path[4] == '/') ||
        (path[0] == '/' && path[1] == 'd' && path[2] == 'e' && path[3] == 'v' && path[4] == '/' &&
         path[5] == 's' && path[6] == 'h' && path[7] == 'm' && path[8] == '/') ||
        (path[0] == '/' && path[1] == 'v' && path[2] == 'a' && path[3] == 'r' && path[4] == '/' &&
         path[5] == 't' && path[6] == 'm' && path[7] == 'p' && path[8] == '/')) {
        e->severity = GUARD_SEV_MEDIUM;
        return;
    }

    e->severity = GUARD_SEV_LOW;
}

/*
 * ==============================================================================
 * Probe 1: sched_process_exec (Successful, Resolved Exec Path)
 * ==============================================================================
 */
SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct cgroup_config *cfg = bpf_map_lookup_elem(&container_cgroups, &cgid);
    if (!cfg) {
        return 0; /* Zero overhead on host processes */
    }

    struct guard_event *e = reserve_event();
    if (!e) {
        return 0;
    }

    init_event(e, GUARD_EVENT_EXEC_RESOLVED, cgid, cfg);

    /* Read exec path from tracepoint string dynamic offset */
    unsigned int fname_offset = ctx->__data_loc_filename & 0xffff;
    const void *fname_ptr = (const void *)ctx + fname_offset;
    bpf_probe_read_kernel_str(e->payload.path.path, sizeof(e->payload.path.path), fname_ptr);

    /*
     * INITIAL ENTRYPOINT HANDLING:
     * If the container starts with a shell (e.g. `minirun run rootfs /bin/sh`),
     * the initial exec is expected. We flag it as INIT_EXEC and keep severity INFO
     * so enforce mode does not terminate the container at launch.
     */
    if (!(cfg->flags & CGROUP_FLAG_INIT_EXEC_SEEN)) {
        cfg->flags |= CGROUP_FLAG_INIT_EXEC_SEEN;
        e->flags |= GUARD_FLAG_INIT_EXEC;
        e->severity = GUARD_SEV_INFO;
    } else {
        /* Subsequent executions inside the container undergo security heuristic classification */
        classify_exec(e, e->payload.path.path, e->comm);
    }

    /*
     * NOTE: Per architecture design, "shell exec" and reverse shells are audit
     * signals in the kernel. Enforce termination is performed in userspace via
     * `cgroup.kill` after sequence correlation, preventing false-positive kernel kills.
     */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * ==============================================================================
 * Probe 2: sys_enter_execve (Attempted Exec)
 * ==============================================================================
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct cgroup_config *cfg = bpf_map_lookup_elem(&container_cgroups, &cgid);
    if (!cfg) {
        return 0;
    }

    struct guard_event *e = reserve_event();
    if (!e) {
        return 0;
    }

    init_event(e, GUARD_EVENT_EXEC_ATTEMPT, cgid, cfg);

    /* Read attempted filename argument from userspace (ctx->args[0]) */
    const char *user_fname = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->payload.path.path, sizeof(e->payload.path.path), user_fname);

    e->severity = GUARD_SEV_INFO;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * ==============================================================================
 * Probe 3: sys_enter_connect (Outbound Socket Connect)
 * ==============================================================================
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct cgroup_config *cfg = bpf_map_lookup_elem(&container_cgroups, &cgid);
    if (!cfg) {
        return 0;
    }

    const void *uservaddr = (const void *)ctx->args[1];
    if (!uservaddr) {
        return 0;
    }

    /* Check address family first before reading address contents */
    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), uservaddr) < 0) {
        return 0;
    }

    /* We monitor AF_UNIX (1), AF_INET (2), and AF_INET6 (10) */
    if (family != 1 && family != 2 && family != 10) {
        return 0;
    }

    int is_docker_breakout = 0;
    int killed = 0;
    if (family == 1) {
        /*
         * IN-KERNEL ENFORCEMENT BOUNDARY (Unambiguous container breakout):
         * Connecting to host docker.sock from inside container is unambiguous escape.
         * Note: Abstract sockets (leading NUL) read as empty string and are not matched here.
         * Compute kill decision BEFORE reserve_event() to prevent ring buffer flood evasion.
         * Enforcement takes effect immediately upon return to userspace.
         */
        const char *sun_path_ptr = ((const char *)uservaddr) + 2;
        __u32 zero = 0;
        char *path_buf = bpf_map_lookup_elem(&path_scratch, &zero);
        if (path_buf) {
            path_buf[0] = 0;
            if (bpf_probe_read_user_str(path_buf, sizeof(((struct guard_sock_payload *)0)->sun_path), sun_path_ptr) > 0) {
                if (is_docker_sock_unix(path_buf)) {
                    is_docker_breakout = 1;
                    if (cfg->mode == GUARD_MODE_ENFORCE) {
                        bpf_send_signal(9); /* SIGKILL */
                        killed = 1;
                    }
                }
            }
        }
    }

    struct guard_event *e = reserve_event();
    if (!e) {
        return 0;
    }

    init_event(e, GUARD_EVENT_CONNECT, cgid, cfg);
    e->payload.sock.family = family;
    e->severity = GUARD_SEV_LOW;

    if (family == 2) {
        /* AF_INET (IPv4) */
        struct sockaddr_in sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), uservaddr) == 0) {
            e->payload.sock.dport = sin.sin_port;
            e->payload.sock.daddr_v4 = sin.sin_addr.s_addr;
        }
    } else if (family == 10) {
        /* AF_INET6 (IPv6) */
        struct sockaddr_in6 sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), uservaddr) == 0) {
            e->payload.sock.dport = sin6.sin6_port;
            __builtin_memcpy(e->payload.sock.daddr_v6, &sin6.sin6_addr, 16);
        }
    } else if (family == 1) {
        /* AF_UNIX: Read path as NUL-terminated string starting at offsetof(sun_path) */
        const char *sun_path_ptr = ((const char *)uservaddr) + 2;
        bpf_probe_read_user_str(e->payload.sock.sun_path, sizeof(e->payload.sock.sun_path), sun_path_ptr);

        if (is_docker_breakout) {
            e->severity = GUARD_SEV_CRITICAL;
            if (killed) {
                e->flags |= GUARD_FLAG_IN_KERNEL_KILL;
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * ==============================================================================
 * Shared Open Handler (sys_enter_open, sys_enter_openat, sys_enter_openat2)
 * ==============================================================================
 */
static __always_inline int check_open(struct cgroup_config *cfg, __u64 cgid, const char *user_fname, int dfd, int flags) {
    if (!user_fname) {
        return 0;
    }

    __u32 zero = 0;
    char *buf = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!buf) {
        return 0;
    }

    /* Zero the scratch buffer to prevent stale byte comparison */
    buf[0] = 0;

    long read_bytes = bpf_probe_read_user_str(buf, GUARD_MAX_PATH, user_fname);
    if (read_bytes <= 0) {
        return 0;
    }

    int is_critical = 0;
    if (!is_sensitive_open(buf, flags, &is_critical)) {
        return 0; /* Drop event in-kernel if path is not sensitive */
    }

    /*
     * IN-KERNEL ENFORCEMENT BOUNDARY:
     * Unambiguous breakout: write to core_pattern or access to docker.sock.
     * Execute kill BEFORE reserve_event() to prevent ring buffer flood evasion.
     * Takes effect immediately on return to userspace.
     */
    int killed = 0;
    if (is_critical && cfg->mode == GUARD_MODE_ENFORCE) {
        bpf_send_signal(9); /* SIGKILL */
        killed = 1;
    }

    struct guard_event *e = reserve_event();
    if (!e) {
        return 0;
    }

    init_event(e, GUARD_EVENT_OPENAT, cgid, cfg);
    e->payload.path.dfd = dfd;
    e->payload.path.flags = flags;
    #pragma unroll
    for (int i = 0; i < GUARD_MAX_PATH; i++) { e->payload.path.path[i] = buf[i]; }

    if (is_critical) {
        e->severity = GUARD_SEV_CRITICAL;
        if (killed) {
            e->flags |= GUARD_FLAG_IN_KERNEL_KILL;
        }
    } else {
        e->severity = GUARD_SEV_HIGH;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * Probe 4a: sys_enter_open (Handles musl/Alpine open(2) which bypasses openat on x86_64)
 */
SEC("tracepoint/syscalls/sys_enter_open")
int handle_sys_enter_open(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct cgroup_config *cfg = bpf_map_lookup_elem(&container_cgroups, &cgid);
    if (!cfg) {
        return 0;
    }

    /* args[0]: filename, args[1]: flags */
    return check_open(cfg, cgid, (const char *)ctx->args[0], -100 /* AT_FDCWD */, (int)ctx->args[1]);
}

/*
 * Probe 4b: sys_enter_openat (Standard openat(2))
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct cgroup_config *cfg = bpf_map_lookup_elem(&container_cgroups, &cgid);
    if (!cfg) {
        return 0;
    }

    /* args[0]: dfd, args[1]: filename, args[2]: flags */
    return check_open(cfg, cgid, (const char *)ctx->args[1], (int)ctx->args[0], (int)ctx->args[2]);
}

/*
 * Probe 4c: sys_enter_openat2 (Modern openat2(2))
 */
SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct cgroup_config *cfg = bpf_map_lookup_elem(&container_cgroups, &cgid);
    if (!cfg) {
        return 0;
    }

    /* args[0]: dfd, args[1]: filename, args[2]: struct open_how* */
    return check_open(cfg, cgid, (const char *)ctx->args[1], (int)ctx->args[0], 0);
}

/*
 * ==============================================================================
 * Probe 5: sys_enter_dup2 and sys_enter_dup3 (Reverse Shell File Descriptor Redirection)
 * ==============================================================================
 */
static __always_inline int handle_dup_enter(struct trace_event_raw_sys_enter *ctx, __u32 oldfd, __u32 newfd, __s32 flags) {
    __u64 cgid = bpf_get_current_cgroup_id();
    struct cgroup_config *cfg = bpf_map_lookup_elem(&container_cgroups, &cgid);
    if (!cfg) {
        return 0;
    }

    /* Only emit events when newfd is 0 (stdin), 1 (stdout), or 2 (stderr) */
    if (newfd > 2) {
        return 0;
    }

    struct guard_event *e = reserve_event();
    if (!e) {
        return 0;
    }

    init_event(e, GUARD_EVENT_DUP, cgid, cfg);
    e->payload.dup.oldfd = (__s32)oldfd;
    e->payload.dup.newfd = (__s32)newfd;
    e->payload.dup.flags = flags;
    e->severity = GUARD_SEV_LOW;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int handle_sys_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    return handle_dup_enter(ctx, (__u32)ctx->args[0], (__u32)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int handle_sys_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    return handle_dup_enter(ctx, (__u32)ctx->args[0], (__u32)ctx->args[1], (__s32)ctx->args[2]);
}
