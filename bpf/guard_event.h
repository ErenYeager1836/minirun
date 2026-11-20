#ifndef __GUARD_EVENT_H__
#define __GUARD_EVENT_H__

/*
 * ==============================================================================
 * minirun Guard - Shared Event Definitions & Telemetry Protocol
 * ==============================================================================
 *
 * PID SEMANTICS:
 *   All `pid`, `tgid`, and `ppid` fields captured by eBPF tracepoints report the
 *   HOST-NAMESPACE PID/TGID (from `bpf_get_current_pid_tgid()`), NOT the virtualized
 *   PID inside the container's PID namespace (where the root process is PID 1).
 *   `ppid` captures the host-namespace real_parent->tgid via BPF_CORE_READ.
 *   Userspace correlates these PIDs against `/sys/fs/cgroup/.../cgroup.procs`.
 *
 * SECURITY & TOCTOU BOUNDARY NOTE:
 *   User-space pointer reads (e.g. `bpf_probe_read_user_str` in sys_enter_* probes)
 *   are inherently prone to Time-Of-Check to Time-Of-Use (TOCTOU) races if an
 *   attacker modifies memory concurrently in another thread. These probes provide
 *   high-fidelity runtime TELEMETRY and heuristics; they are not a hard kernel
 *   security perimeter (which would require BPF LSM / seccomp).
 * ==============================================================================
 */

#define GUARD_MAX_PATH 256
#define GUARD_TASK_COMM_LEN 16
#define GUARD_UNIX_PATH_MAX 108

/* Event Type Identifiers */
enum guard_event_type {
    GUARD_EVENT_EXEC_ATTEMPT  = 1, /* sys_enter_execve (attempted binary execution) */
    GUARD_EVENT_EXEC_RESOLVED = 2, /* sched_process_exec (exec path invoked)        */
    GUARD_EVENT_CONNECT       = 3, /* sys_enter_connect (outbound network attempt)   */
    GUARD_EVENT_OPENAT        = 4, /* sys_enter_open/openat/openat2 (sensitive path) */
    GUARD_EVENT_DUP           = 5, /* sys_enter_dup2/3 (fd redirection to stdin/out) */
};

/* Severity Levels */
enum guard_severity {
    GUARD_SEV_INFO     = 0,
    GUARD_SEV_LOW      = 1,
    GUARD_SEV_MEDIUM   = 2,
    GUARD_SEV_HIGH     = 3,
    GUARD_SEV_CRITICAL = 4,
};

/* Guard Operating Modes */
enum guard_mode {
    GUARD_MODE_NONE    = 0,
    GUARD_MODE_AUDIT   = 1,
    GUARD_MODE_ENFORCE = 2,
};

/* Cgroup Configuration Flags */
#define CGROUP_FLAG_INIT_EXEC_SEEN (1U << 0) /* Initial container entrypoint executed */

/* Event Flags */
#define GUARD_FLAG_IN_KERNEL_KILL  (1U << 0) /* bpf_send_signal(SIGKILL) invoked in-kernel */
#define GUARD_FLAG_INIT_EXEC       (1U << 1) /* Initial container entrypoint execution */

/* Path payload (for exec and open/openat/openat2) */
struct guard_path_payload {
    char path[GUARD_MAX_PATH];
    __s32 flags; /* open flags (e.g. O_RDONLY, O_RDWR) */
    __s32 dfd;   /* directory file descriptor for openat (-100 for AT_FDCWD) */
};

/* Socket payload (for connect) */
struct guard_sock_payload {
    __u16 family; /* 1 = AF_UNIX, 2 = AF_INET, 10 = AF_INET6 */
    __u16 dport;  /* Destination port in network byte order */
    __u32 daddr_v4; /* IPv4 destination in network byte order */
    __u8  daddr_v6[16]; /* IPv6 destination address */
    char  sun_path[GUARD_UNIX_PATH_MAX]; /* AF_UNIX socket path */
};

/* Dup payload (for dup2 / dup3) */
struct guard_dup_payload {
    __s32 oldfd;
    __s32 newfd; /* 0 = stdin, 1 = stdout, 2 = stderr */
    __s32 flags;
};

/* Event Payload Union */
union guard_payload {
    struct guard_path_payload path;
    struct guard_sock_payload sock;
    struct guard_dup_payload  dup;
};

/*
 * Fixed-size, verifier-friendly event structure streamed through BPF ring buffer
 */
struct guard_event {
    __u32 type;        /* enum guard_event_type */
    __u32 severity;    /* enum guard_severity */
    __u64 ts_ns;       /* Monotonic timestamp in nanoseconds */
    __u32 pid;         /* Host-namespace thread PID */
    __u32 tgid;        /* Host-namespace process TGID */
    __u32 ppid;        /* Host-namespace parent process TGID (real_parent->tgid) */
    __u32 uid;         /* Process UID */
    __u32 gid;         /* Process GID */
    __u64 cgroup_id;   /* 64-bit Linux cgroup v2 ID */
    char  comm[GUARD_TASK_COMM_LEN]; /* Command name */
    __u32 flags;       /* GUARD_FLAG_* */
    __u32 container_idx; /* Identifier mapping to container metadata in userspace */
    union guard_payload payload;
};

/*
 * Value stored in container_cgroups hash map
 */
struct cgroup_config {
    __u32 container_idx;
    __u32 mode;  /* enum guard_mode (AUDIT or ENFORCE) */
    __u32 flags; /* CGROUP_FLAG_* */
};

#endif /* __GUARD_EVENT_H__ */
