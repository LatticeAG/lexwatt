"""Workload syscall and resource policy (spec §2.3).

This module is the policy model enforced inside the sandbox by the
generated seccomp filter, the namespace image, and the broker.  The
conformance harness exercises these decisions directly.
"""

from __future__ import annotations

# The complete unconditional x86_64 syscall-name allowlist, verbatim from
# spec §2.3.  Everything not listed returns EPERM; clone3 returns ENOSYS.
ALLOWED_SYSCALLS: frozenset[str] = frozenset(
    """
read write readv writev pread64 pwrite64 close close_range lseek fstat newfstatat stat lstat statx
open openat openat2 access faccessat faccessat2 readlink readlinkat getdents getdents64
mmap mprotect munmap mremap madvise msync brk mincore
rt_sigaction rt_sigprocmask rt_sigreturn rt_sigpending rt_sigtimedwait rt_sigsuspend sigaltstack
poll ppoll select pselect6 epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait epoll_pwait2
eventfd eventfd2 pipe pipe2 dup dup2 dup3 fcntl flock fsync fdatasync ftruncate truncate
getpid getppid gettid getuid geteuid getgid getegid getgroups getcwd chdir fchdir
mkdir mkdirat rmdir unlink unlinkat rename renameat renameat2 link linkat symlink symlinkat
chmod fchmod fchmodat umask utime utimes utimensat getrandom uname sysinfo
clock_gettime clock_getres gettimeofday time nanosleep clock_nanosleep
futex set_tid_address set_robust_list get_robust_list rseq membarrier
sched_yield sched_getaffinity sched_setaffinity sched_getparam sched_getscheduler
sched_get_priority_max sched_get_priority_min
getrlimit setrlimit prlimit64 getrusage times arch_prctl restart_syscall
wait4 waitid kill tkill tgkill setsid setpgid getpgid getsid execve execveat exit exit_group
sendmsg recvmsg sendto recvfrom shutdown getsockname getpeername getsockopt setsockopt
""".split()
)

# clone() is allowed only for same-process thread creation:
# required CLONE_VM|CLONE_SIGHAND|CLONE_THREAD, zero exit-signal bits, and
# only the listed additional flag bits.
CLONE_REQUIRED = 0x00000100 | 0x00000800 | 0x00010000  # VM|SIGHAND|THREAD
CLONE_EXTRA = (
    0x00000200  # CLONE_FS
    | 0x00000400  # CLONE_FILES
    | 0x00040000  # CLONE_SYSVSEM
    | 0x00080000  # CLONE_SETTLS
    | 0x00100000  # CLONE_PARENT_SETTID
    | 0x00200000  # CLONE_CHILD_CLEARTID
    | 0x01000000  # CLONE_CHILD_SETTID
)
CLONE_ALLOWED_MASK = CLONE_REQUIRED | CLONE_EXTRA

# Paths that do not exist inside the sandbox namespace: open() sees ENOENT.
# A fresh private PID-namespace /proc and private /tmp DO exist; host /run,
# cgroup mounts, powercap controls, container sockets and accelerators do not.
HIDDEN_PATH_PREFIXES = (
    "/sys/fs/cgroup",
    "/sys/class/powercap",
    "/run",
    "/var/run/docker.sock",
    "/var/run/sshd",
)

# Accelerator device nodes are hidden by name prefix: /dev/nvidia0,
# /dev/nvidiactl, /dev/dri/card0, ... — these are not mount components.
HIDDEN_DEVICE_PREFIXES = ("/dev/nvidia", "/dev/dri")

DENIED_SOCKET_FAMILIES = True  # socket/socketpair/connect/bind/listen/accept* all denied


def evaluate_syscall(name: str, flags: int | None = None, pids_current: int = 0, pids_max: int = 0) -> dict:
    """One syscall decision under the workload filter."""
    if name == "clone3":
        return {"errno": "ENOSYS", "allowed": False}
    if name == "clone":
        assert flags is not None
        ok = (flags & CLONE_REQUIRED) == CLONE_REQUIRED and (flags & ~CLONE_ALLOWED_MASK) == 0
        if not ok:
            return {"errno": "EPERM", "allowed": False}
        if pids_current >= pids_max:
            return {"errno": "EAGAIN", "allowed": False}
        return {"errno": None, "allowed": True}
    if name in ("fork", "vfork"):
        return {"errno": "EPERM", "allowed": False}
    if name in (
        "socket",
        "socketpair",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
    ):
        return {"errno": "EPERM", "allowed": False}
    if name in ALLOWED_SYSCALLS:
        return {"errno": None, "allowed": True}
    return {"errno": "EPERM", "allowed": False}


def evaluate_open(path: str, flags: str) -> dict:
    """open() under the private mount namespace: hidden host paths do not
    exist; accelerator devices are absent."""
    norm = path.rstrip("/") or "/"
    for hidden in HIDDEN_PATH_PREFIXES:
        if norm == hidden or norm.startswith(hidden + "/"):
            return {"errno": "ENOENT", "allowed": False}
    for dev in HIDDEN_DEVICE_PREFIXES:
        if norm.startswith(dev):
            return {"errno": "ENOENT", "allowed": False}
    return {"errno": None, "allowed": True}


def evaluate_signal(
    target: str, task_uid: int, target_uid: int, host_pid_visible: bool, same_run_peer: bool
) -> dict:
    """kill() semantics inside the workload PID namespace: the task UID may
    signal only task-UID peers; the privileged reaper answers EPERM; host
    processes are invisible and answer ESRCH."""
    if not host_pid_visible and not same_run_peer:
        return {"errno": "ESRCH", "allowed": False}
    if target_uid != task_uid:
        return {"errno": "EPERM", "allowed": False}
    return {"errno": None, "allowed": True}


def check_frame_length(declared_bytes: int, max_request: int = 65536) -> dict:
    """The reader validates the length before allocating; oversized frames
    close the connection and release no effect."""
    if declared_bytes > max_request or declared_bytes < 0:
        return {
            "connection_closed": True,
            "payload_allocated_bytes": 0,
            "effects_released": 0,
        }
    return {
        "connection_closed": False,
        "payload_allocated_bytes": declared_bytes,
        "effects_released": 0,
    }
