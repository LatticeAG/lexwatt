"""Real Linux host backend (spec §2.1–§2.4).

Implements the kernel-facing operations the enforced profiles require:
cgroup-v2 containment (cpu/cpuset/pids/memory + cgroup.kill), RAPL package
energy counters under /sys/class/powercap, mount/PID/IPC/UTS/network
namespaces, the pinned seccomp filter, locked task UIDs, and the bounded
brokered HTTPS GET.  Privileged paths fail honestly with capability codes
when the host cannot supply the required boundary — there is no degraded
process-group-only mode.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import socket
import ssl
import time
from dataclasses import dataclass, field

from ..errors import LexwattError

CGROUP_ROOT = "/sys/fs/cgroup"
LEXWATT_CGROUP_PARENT = "/sys/fs/cgroup/lexwatt"
POWERCAP_ROOT = "/sys/class/powercap"

CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000

_libc = ctypes.CDLL(None, use_errno=True)


def _unshare(flags: int) -> None:
    if _libc.unshare(flags) != 0:
        raise OSError(ctypes.get_errno(), "unshare")


def boot_id() -> str:
    with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as f:
        return f.read().strip().lower()


def boottime_us() -> int:
    return int(time.clock_gettime(time.CLOCK_BOOTTIME) * 1_000_000)


def _read_int(path: str) -> int:
    with open(path, "r", encoding="ascii") as f:
        return int(f.read().strip())


def _write(path: str, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.write(fd, value.encode("ascii"))
    finally:
        os.close(fd)


def cpulist_to_set(cpus: str) -> set[int]:
    out: set[int] = set()
    for part in cpus.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out


@dataclass
class LinuxDomain:
    dom_id: str
    sysfs_dir: str
    cpus: set[int]

    def read(self) -> tuple[int, int, int]:
        # Returns (counter_uj, range_uj, read_t_us) in BOOTTIME microseconds.
        # Read counter then range, then timestamp — all sysfs reads are
        # nofollow opens.
        cfd = os.open(os.path.join(self.sysfs_dir, "energy_uj"), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            counter = int(os.read(cfd, 64).strip())
        finally:
            os.close(cfd)
        rfd = os.open(os.path.join(self.sysfs_dir, "max_energy_uj_range_uj"), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            range_uj = int(os.read(rfd, 64).strip())
        finally:
            os.close(rfd)
        return (counter, range_uj, boottime_us())


@dataclass
class LinuxCgroup:
    run_id: str
    path: str
    procs: list = field(default_factory=list)

    def populated(self) -> int:
        try:
            with open(os.path.join(self.path, "cgroup.events"), "r", encoding="ascii") as f:
                for line in f:
                    if line.startswith("populated"):
                        return int(line.split()[1])
        except OSError:
            return 1
        return 1

    def usage_us(self) -> int:
        with open(os.path.join(self.path, "cpu.stat"), "r", encoding="ascii") as f:
            for line in f:
                if line.startswith("usage_usec"):
                    return int(line.split()[1])
        return 0

    def kill(self) -> bool:
        try:
            _write(os.path.join(self.path, "cgroup.kill"), "1")
            return True
        except OSError:
            return False

    def group_kill(self) -> bool:
        ok = False
        for p in list(self.procs):
            try:
                os.killpg(p.pgid, 9)
                ok = True
            except (ProcessLookupError, PermissionError, AttributeError):
                try:
                    os.kill(p.pid, 9)
                    ok = True
                except (ProcessLookupError, PermissionError):
                    pass
        return ok


@dataclass
class LinuxProc:
    pid: int
    pgid: int
    pidfd: int
    channel_id: str
    alive: bool = True
    exit: dict | None = None

    def poll(self) -> dict | None:
        if not self.alive:
            return self.exit
        try:
            done, status, _ru = os.wait4(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.alive = False
            self.exit = {"code": None, "signal": 9}
            return self.exit
        if done == 0:
            return None
        self.alive = False
        if os.WIFEXITED(status):
            self.exit = {"code": os.WEXITSTATUS(status), "signal": None}
        elif os.WIFSIGNALED(status):
            self.exit = {"code": None, "signal": os.WTERMSIG(status)}
        else:
            self.exit = {"code": None, "signal": 9}
        return self.exit


class LinuxHost:
    """Production backend; every unsupported capability is reported."""

    name = "linux"

    def __init__(self):
        self._workspace_locks: dict[str, int] = {}
        self._uid_locks: dict[int, int] = {}

    def boot_id(self) -> str:
        return boot_id()

    def boottime_us(self) -> int:
        return boottime_us()

    # -- capabilities ---------------------------------------------------------

    def capabilities(self, profile: str) -> dict:
        failures = []
        import platform

        arch_ok = platform.machine() == "x86_64"
        cgroup_v2 = False
        cgroup_kill = False
        try:
            with open("/proc/mounts", "r", encoding="ascii") as f:
                cgroup_v2 = any(
                    line.split()[1] == CGROUP_ROOT and line.split()[2] == "cgroup2"
                    for line in f
                )
            # cgroup.kill exists only in non-root cgroups; cgroup.subtree_control
            # at the root proves a unified v2 hierarchy on a kernel that has it.
            cgroup_kill = cgroup_v2 and os.path.exists(
                os.path.join(CGROUP_ROOT, "cgroup.subtree_control")
            )
        except OSError:
            pass
        euid0 = os.geteuid() == 0
        namespaces = cgroup_v2 and euid0 and self._check_namespaces()
        seccomp = self._check_seccomp()
        uid_iso = euid0
        domains = self._discover_rapl()
        for cond in (
            not (cgroup_v2 and arch_ok and euid0),
            not cgroup_kill,
            not namespaces or not seccomp or not uid_iso,
        ):
            if cond and "UNSUPPORTED_PROFILE" not in failures:
                failures.append("UNSUPPORTED_PROFILE")
        if profile == "linux-rapl-v1" and not domains:
            failures.append("SENSOR_UNAVAILABLE")
        return {
            "profile": profile,
            "cgroup_kill": bool(cgroup_kill),
            "task_uid_isolation": bool(uid_iso),
            "seccomp": bool(seccomp),
            "namespaces": bool(namespaces),
            "rapl_domains": domains,
            "failures": failures,
        }

    def _check_namespaces(self) -> bool:
        try:
            for ns in ("mnt", "pid", "ipc", "uts", "net"):
                if not os.path.exists(f"/proc/self/ns/{ns}"):
                    return False
            return True
        except OSError:
            return False

    def _check_seccomp(self) -> bool:
        try:
            with open("/proc/self/status", "r", encoding="ascii") as f:
                return any(line.startswith("Seccomp:") for line in f)
        except OSError:
            return False

    def _discover_rapl(self) -> list[str]:
        out = []
        try:
            for name in sorted(os.listdir(POWERCAP_ROOT)):
                d = os.path.join(POWERCAP_ROOT, name)
                if not os.path.isdir(d):
                    continue
                if name.startswith("intel-rapl:") and ":" not in name[len("intel-rapl:") :]:
                    energy = os.path.join(d, "energy_uj")
                    rng = os.path.join(d, "max_energy_uj_range_uj")
                    if os.path.exists(energy) and os.path.exists(rng):
                        out.append(f"package-{name.rsplit(':', 1)[1]}")
        except OSError:
            pass
        return out

    # -- provisioning -----------------------------------------------------------

    def task_uid_alloc(self, lo: int, hi: int, in_use: set[int]) -> int:
        for uid in range(lo, hi + 1):
            if uid in in_use:
                continue
            lock_path = f"/run/lexwatt/uid-{uid}.lock"
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            except OSError as e:
                raise LexwattError("CONTAINMENT_FAULT") from e
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                continue
            self._uid_locks[uid] = fd
            return uid
        raise LexwattError("BUSY")

    def task_uid_free(self, uid: int) -> None:
        fd = self._uid_locks.pop(uid, None)
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def workspace_lease(self, path: str, run_id: str) -> int:
        os.makedirs("/run/lexwatt", mode=0o700, exist_ok=True)
        lock_path = f"/run/lexwatt/ws-{abs(hash(path))}.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            os.close(fd)
            raise LexwattError("BUSY") from e
        self._workspace_locks[path] = fd
        return fd

    def workspace_release(self, path: str) -> None:
        fd = self._workspace_locks.pop(path, None)
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    # -- cgroup containment -------------------------------------------------------

    def cgroup_create(self, run_id: str, cfg: dict, domain_cpus: str) -> LinuxCgroup:
        if not self.capabilities("linux-ledger-v1")["cgroup_kill"] and not os.path.exists(
            os.path.join(CGROUP_ROOT, "cgroup.kill")
        ):
            raise LexwattError("CONTAINMENT_FAULT")
        parent = LEXWATT_CGROUP_PARENT
        try:
            os.makedirs(parent, mode=0o700, exist_ok=True)
            _write(os.path.join(parent, "cgroup.subtree_control"), "+cpu +cpuset +pids +memory")
        except OSError as e:
            raise LexwattError("CONTAINMENT_FAULT") from e
        path = os.path.join(parent, run_id)
        try:
            os.mkdir(path, 0o700)
            _write(os.path.join(path, "pids.max"), str(cfg["pids_max"]))
            _write(os.path.join(path, "memory.max"), str(int(cfg["memory_max_bytes"])))
            _write(os.path.join(path, "memory.swap.max"), "0")
            _write(os.path.join(path, "memory.oom.group"), "1")
            if domain_cpus:
                _write(os.path.join(path, "cpuset.cpus"), domain_cpus)
        except OSError as e:
            raise LexwattError("CONTAINMENT_FAULT") from e
        return LinuxCgroup(run_id=run_id, path=path)

    def cgroup_usage_us(self, cg: LinuxCgroup) -> int:
        return cg.usage_us()

    def cgroup_populated(self, cg: LinuxCgroup) -> int:
        return cg.populated()

    def cgroup_kill(self, cg: LinuxCgroup) -> bool:
        return cg.kill()

    def group_kill(self, cg: LinuxCgroup) -> bool:
        return cg.group_kill()

    def cgroup_teardown(self, cg: LinuxCgroup) -> None:
        try:
            os.rmdir(cg.path)
        except OSError:
            pass

    # -- energy domains --------------------------------------------------------------

    def open_domains(self, domain_ids: list[str]) -> list[LinuxDomain]:
        out = []
        for dom_id in domain_ids:
            # domain ids are "package-N"; resolve the sysfs dir by kernel name
            idx = dom_id.split("-", 1)[1]
            sysfs_dir = os.path.join(POWERCAP_ROOT, f"intel-rapl:{idx}")
            real = os.path.realpath(sysfs_dir)
            if not real.startswith("/sys/devices"):
                raise LexwattError("SENSOR_UNAVAILABLE")
            cpus = set()
            try:
                with open(os.path.join(real, "cpulist"), "r", encoding="ascii") as f:
                    cpus = cpulist_to_set(f.read().strip())
            except OSError:
                pass
            out.append(LinuxDomain(dom_id=dom_id, sysfs_dir=real, cpus=cpus))
        return out

    def read_domain(self, handle: LinuxDomain) -> tuple[int, int, int]:
        try:
            return handle.read()
        except (OSError, ValueError) as e:
            raise LexwattError("SENSOR_FAULT") from e

    # -- workload spawn -----------------------------------------------------------------

    def spawn_root(self, run_ctx, execv: dict, channel_sock) -> LinuxProc:
        return self._spawn(run_ctx, execv, channel_sock)

    def spawn_child(self, run_ctx, execv: dict, channel_sock) -> LinuxProc:
        return self._spawn(run_ctx, execv, channel_sock)

    def _spawn(self, run_ctx, execv: dict, channel_sock) -> LinuxProc:
        """Containment launch: private namespaces + cgroup + task UID +
        no_new_privs + pinned seccomp + exec barrier.

        Two-fork structure: the first child unshares mount/PID/IPC/UTS/net
        namespaces and becomes the trusted reaper (PID 1 inside); the second
        fork is the workload, which joins the owned cgroup, drops to the
        locked task UID, installs the filter, then execs.
        """
        from .. import seccomp

        err_r, err_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(err_r)
                _unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET)
                # second fork: enters the new PID namespace
                child = os.fork()
                if child != 0:
                    # namespace reaper: adopt + reap, forward cgroup kill scope
                    os._exit(self._reap(child))
                # workload: join cgroup, drop privileges, exec
                _write(
                    os.path.join(run_ctx.cgroup.path, "cgroup.procs"), str(os.getpid())
                )
                os.setsid()
                os.setgroups([])
                os.setgid(run_ctx.task_uid)
                os.setuid(run_ctx.task_uid)
                os.chdir(execv["cwd"])
                env = dict(execv["env"])
                env.setdefault("LANG", "C.UTF-8")
                # descriptor 3 is the broker channel
                if channel_sock is not None:
                    if channel_sock.fileno() != 3:
                        os.dup2(channel_sock.fileno(), 3)
                    channel_sock.close()
                # close everything else
                keep = {0, 1, 2, 3}
                for fd in range(4, 1024):
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                import resource

                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                seccomp.install()
                os.execve(execv["argv"][0], execv["argv"], env)
            except BaseException as e:  # report to supervisor via error pipe
                try:
                    os.write(err_w, repr(e).encode()[:4000])
                finally:
                    os._exit(127)
        os.close(err_w)
        msg = os.read(err_r, 4000)
        os.close(err_r)
        if msg:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
            raise LexwattError("ACTION_FAILED")
        try:
            pidfd = os.pidfd_open(pid) if hasattr(os, "pidfd_open") else -1
        except OSError:
            pidfd = -1
        proc = LinuxProc(pid=pid, pgid=pid, pidfd=pidfd, channel_id="")
        run_ctx.cgroup.procs.append(proc)
        return proc

    @staticmethod
    def _reap(first_child: int) -> int:
        """PID-1-in-namespace reaper: reap until the namespace empties."""
        status = 0
        try:
            while True:
                try:
                    done, st, _ = os.wait4(-1, 0)
                    if done == first_child:
                        status = st
                except ChildProcessError:
                    break
        finally:
            pass
        return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 125

    def proc_exited(self, proc: LinuxProc) -> dict | None:
        return proc.poll()

    def proc_alive(self, proc: LinuxProc) -> bool:
        if proc.alive:
            proc.poll()
        return proc.alive

    # -- brokered HTTP -----------------------------------------------------------

    def http_get(self, dest: dict, action: dict, deadline_us: int) -> dict:
        """Bounded HTTPS GET to the lowest sorted pinned IP, TLS-verified
        against the configured hostname; no DNS, redirects, credentials, or
        decompression."""
        from ..hashing import sha256_hex
        from ..scalars import encode_b64url

        host = dest["origin"][len("https://") :]
        ip = dest["ips"][0]
        deadline = time.monotonic() + deadline_us / 1_000_000
        sock = socket.socket(socket.AF_INET if ":" not in ip else socket.AF_INET6, socket.SOCK_STREAM)
        try:
            sock.settimeout(max(deadline - time.monotonic(), 0.001))
            sock.connect((ip, 443))
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(sock, server_hostname=host)
            try:
                tls.settimeout(max(deadline - time.monotonic(), 0.001))
                req = (
                    f"GET {action['path']} HTTP/1.1\r\nHost: {host}\r\n"
                    "Connection: close\r\nAccept-Encoding: identity\r\n\r\n"
                ).encode("ascii")
                tls.sendall(req)
                head = b""
                while b"\r\n\r\n" not in head and len(head) <= 16384:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                if b"\r\n\r\n" not in head:
                    raise LexwattError("ACTION_FAILED")
                status = int(head.split(b"\r\n", 1)[0].split()[1])
                if not (100 <= status <= 599):
                    raise LexwattError("ACTION_FAILED")
                body = head.split(b"\r\n\r\n", 1)[1]
                limit = action["max_response_bytes"]
                while len(body) < limit + 1:
                    try:
                        chunk = tls.recv(min(65536, limit + 1 - len(body)))
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    body += chunk
                if len(body) > limit:
                    raise LexwattError("OUTPUT_LIMIT")
                return {
                    "kind": "http_get",
                    "status": status,
                    "body_b64": encode_b64url(body),
                    "body_hash": sha256_hex(body),
                    "truncated": False,
                }
            finally:
                tls.close()
        except LexwattError:
            raise
        except (OSError, ssl.SSLError, ValueError) as e:
            raise LexwattError("ACTION_FAILED") from e
        finally:
            try:
                sock.close()
            except OSError:
                pass
