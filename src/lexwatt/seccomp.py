"""Pinned workload seccomp filter (spec §2.3) as a real cBPF program.

The allowlist is arch-pinned to x86_64: an architecture mismatch is fatal
(SECCOMP_RET_KILL_PROCESS), x32 is denied by that same check, clone3 returns
ENOSYS, clone() is admitted only for the thread-creation flag combination,
and every unlisted syscall returns EPERM.

The program is installed with prctl(PR_SET_NO_NEW_PRIVS) +
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER); no libseccomp dependency.
"""

from __future__ import annotations

import ctypes
import struct

from .sandbox import ALLOWED_SYSCALLS, CLONE_ALLOWED_MASK, CLONE_REQUIRED

# --- BPF -------------------------------------------------------------------
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ = 0x15
BPF_JMP_JSET = 0x45
BPF_ALU_AND_K = 0x54
BPF_RET_K = 0x06

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
EPERM = 1
ENOSYS = 38

AUDIT_ARCH_X86_64 = 0xC000003E

OFF_NR = 0
OFF_ARCH = 4
OFF_ARGS0_LO = 16  # args[0] low 32 bits (little-endian)

# Canonical x86_64 syscall numbers (asm/unistd_64.h).  Only names referenced
# by the profile are listed; socket-family and fork-family calls are absent
# because the default action is EPERM.
X86_64_SYSCALLS = {
    "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
    "lstat": 6, "poll": 7, "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11,
    "brk": 12, "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15,
    "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20, "access": 21,
    "pipe": 22, "select": 23, "sched_yield": 24, "mremap": 25, "msync": 26,
    "mincore": 27, "madvise": 28, "dup": 32, "dup2": 33, "nanosleep": 35,
    "getpid": 39, "socket": 41, "connect": 42, "accept": 43, "sendto": 44,
    "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "shutdown": 48, "bind": 49,
    "listen": 50, "getsockname": 51, "getpeername": 52, "socketpair": 53,
    "setsockopt": 54, "getsockopt": 55, "clone": 56, "fork": 57, "vfork": 58,
    "execve": 59, "exit": 60, "wait4": 61, "kill": 62, "uname": 63,
    "fcntl": 72, "flock": 73, "fsync": 74, "fdatasync": 75, "truncate": 76,
    "ftruncate": 77, "getdents": 78, "getcwd": 79, "chdir": 80, "fchdir": 81,
    "rename": 82, "mkdir": 83, "rmdir": 84, "link": 86, "unlink": 87,
    "symlink": 88, "readlink": 89, "chmod": 90, "fchmod": 91, "umask": 95,
    "gettimeofday": 96, "getrlimit": 97, "getrusage": 98, "sysinfo": 99,
    "times": 100, "getuid": 102, "getgid": 104, "geteuid": 107, "getegid": 108,
    "setpgid": 109, "getppid": 110, "setsid": 112, "getgroups": 115,
    "getpgid": 121, "getsid": 124, "rt_sigpending": 127, "rt_sigtimedwait": 128,
    "rt_sigsuspend": 130, "sigaltstack": 131, "utime": 132, "mknod": 133,
    "statfs": 137, "personality": 135, "prctl": 157, "arch_prctl": 158,
    "setrlimit": 160, "gettid": 186, "tkill": 200, "time": 201, "futex": 202,
    "sched_setaffinity": 203, "sched_getaffinity": 204, "epoll_create": 213,
    "getdents64": 217, "set_tid_address": 218, "restart_syscall": 219,
    "clock_gettime": 228, "clock_getres": 229, "clock_nanosleep": 230,
    "exit_group": 231, "epoll_wait": 232, "epoll_ctl": 233, "tgkill": 234,
    "utimes": 235, "waitid": 247, "openat": 257, "mkdirat": 258,
    "newfstatat": 262, "unlinkat": 263, "renameat": 264, "linkat": 265,
    "symlinkat": 266, "readlinkat": 267, "fchmodat": 268, "faccessat": 269,
    "pselect6": 270, "ppoll": 271, "set_robust_list": 273, "get_robust_list": 274,
    "utimensat": 280, "epoll_pwait": 281, "eventfd": 284, "accept4": 288,
    "eventfd2": 290, "epoll_create1": 291, "dup3": 292, "pipe2": 293,
    "prlimit64": 302, "renameat2": 316, "getrandom": 318, "execveat": 322,
    "membarrier": 324, "statx": 332, "rseq": 334, "clone3": 435,
    "close_range": 436, "openat2": 437, "faccessat2": 439, "epoll_pwait2": 441,
}


def _stmt(code: int, k: int) -> bytes:
    return struct.pack("<HBBI", code, 0, 0, k)


def _jump(code: int, k: int, jt: int, jf: int) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


def _ret(k: int) -> bytes:
    return _stmt(BPF_RET_K, k)


def build_filter() -> bytes:
    """Return the cBPF program bytes for the workload profile."""
    allowed_nrs = sorted(
        X86_64_SYSCALLS[name] for name in ALLOWED_SYSCALLS if name != "clone"
    )
    prog: list[bytes] = []
    # 0: load arch; fatal on mismatch (also denies x32 which reports a
    # different arch value to seccomp)
    prog.append(_stmt(BPF_LD_W_ABS, OFF_ARCH))
    prog.append(_jump(BPF_JMP_JEQ, AUDIT_ARCH_X86_64, 1, 0))
    prog.append(_ret(SECCOMP_RET_KILL_PROCESS))
    # 3: load nr
    prog.append(_stmt(BPF_LD_W_ABS, OFF_NR))
    # compare chain; destinations patched after layout is known
    compares: list[tuple[int, int]] = []  # (index, nr) for allowed
    special_clone: list[int] = []
    special_clone3: list[int] = []
    for nr in allowed_nrs:
        compares.append((len(prog), nr))
        prog.append(b"")
    clone_idx = len(prog)
    prog.append(_jump(BPF_JMP_JEQ, X86_64_SYSCALLS["clone"], 0, 0))
    clone3_idx = len(prog)
    prog.append(_jump(BPF_JMP_JEQ, X86_64_SYSCALLS["clone3"], 0, 0))
    deny_idx = len(prog)
    prog.append(_ret(SECCOMP_RET_ERRNO | EPERM))
    # clone3 -> ENOSYS
    enosys_idx = len(prog)
    prog.append(_ret(SECCOMP_RET_ERRNO | ENOSYS))
    # clone flag check: (flags & ~MASK) -> EPERM; (flags & REQUIRED) != REQUIRED -> EPERM
    clone_block = len(prog)
    prog.append(_stmt(BPF_LD_W_ABS, OFF_ARGS0_LO))
    jset_idx = len(prog)
    prog.append(b"")  # JSET ~MASK -> EPERM
    prog.append(_stmt(BPF_ALU_AND_K, CLONE_REQUIRED))
    jeq_idx = len(prog)
    prog.append(b"")  # JEQ REQUIRED -> ALLOW else EPERM
    allow_idx = len(prog)
    prog.append(_ret(SECCOMP_RET_ALLOW))

    def fwd(src: int, dst: int) -> int:
        d = dst - src - 1
        if not (0 <= d <= 255):
            raise AssertionError("BPF jump out of range")
        return d

    for idx, nr in compares:
        prog[idx] = _jump(BPF_JMP_JEQ, nr, fwd(idx, allow_idx), 0)
    prog[clone_idx] = _jump(
        BPF_JMP_JEQ, X86_64_SYSCALLS["clone"], fwd(clone_idx, clone_block), 0
    )
    prog[clone3_idx] = _jump(
        BPF_JMP_JEQ, X86_64_SYSCALLS["clone3"], fwd(clone3_idx, enosys_idx), 0
    )
    prog[jset_idx] = _jump(
        BPF_JMP_JSET, (~CLONE_ALLOWED_MASK) & 0xFFFFFFFF, fwd(jset_idx, deny_idx), 0
    )
    prog[jeq_idx] = _jump(
        BPF_JMP_JEQ, CLONE_REQUIRED, fwd(jeq_idx, allow_idx), fwd(jeq_idx, deny_idx)
    )
    return b"".join(prog)


def instruction_count() -> int:
    return len(build_filter()) // 8


def install() -> None:
    """Install the filter on the current process (real enforcement).

    Requires nothing but no_new_privs; must run inside the workload's
    namespace setup immediately before exec.
    """
    prog = build_filter()

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("pad", ctypes.c_ushort * 3),
                    ("filter", ctypes.c_void_p)]

    buf = ctypes.create_string_buffer(prog)
    fprog = SockFprog(len=instruction_count(), filter=ctypes.cast(buf, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_NO_NEW_PRIVS = 38
    PR_SET_SECCOMP = 22
    SECCOMP_MODE_FILTER = 2
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS)")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_SECCOMP)")
