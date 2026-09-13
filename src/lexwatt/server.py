"""Local API transport (spec §6).

Frame format: four-byte unsigned big-endian payload length followed by
canonical JSON.  Requests <= 65536 bytes; responses <= 1048576 bytes.  The
owner control stream and the workload fd-3 socketpair share the identical
format and envelope.  Control connections authenticate by SO_PEERCRED
UID 0; workload channels authenticate by descriptor identity.
"""

from __future__ import annotations

import os
import socket
import struct
import threading

from . import jcs
from .errors import LexwattError
from .schema import check_request

MAX_REQUEST_BYTES = 65536
MAX_RESPONSE_BYTES = 1048576
MAX_QUEUED_PER_CONN = 16


def read_frame(sock: socket.socket, max_bytes: int) -> bytes | None:
    """Read one frame; returns None on clean EOF.  Oversized/malformed
    frames raise LexwattError — the caller closes the connection."""
    hdr = _read_exactly(sock, 4)
    if hdr is None:
        return None
    declared = struct.unpack(">I", hdr)[0]
    if declared > max_bytes:
        raise LexwattError("INVALID_INPUT")  # close without releasing effects
    payload = _read_exactly(sock, declared)
    if payload is None:
        raise LexwattError("INVALID_INPUT")  # partial frame is never a request
    return payload


def write_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_RESPONSE_BYTES:
        raise LexwattError("OUTPUT_LIMIT")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _read_exactly(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (ConnectionError, OSError):
            raise LexwattError("INVALID_INPUT")
        if not chunk:
            if not buf:
                return None
            raise LexwattError("INVALID_INPUT")
        buf += chunk
    return buf


def peer_uid(sock: socket.socket) -> int:
    """SO_PEERCRED of a connected Unix socket (Linux)."""
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", creds)
    return uid


class ControlServer:
    """Root-owned 0600 control socket under /run/lexwatt/<run_id>/."""

    def __init__(self, launcher, run_id: str, runtime_root: str):
        self.launcher = launcher
        self.run_id = run_id
        self.dir = os.path.join(runtime_root, run_id)
        self.path = os.path.join(self.dir, "control.sock")
        self._sock = None
        self._thread = None
        self._closed = threading.Event()

    def start(self) -> None:
        os.makedirs(self.dir, mode=0o700)
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.path)
        os.chmod(self.path, 0o600)
        self._sock.listen(16)
        self._sock.settimeout(0.25)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._closed.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if peer_uid(conn) != 0:
                    conn.close()
                    continue
            except OSError:
                conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            while True:
                try:
                    payload = read_frame(conn, MAX_REQUEST_BYTES)
                except LexwattError:
                    break  # framing violation closes the connection
                if payload is None:
                    break
                try:
                    req = jcs.loads(payload)
                    check_request(req)
                except LexwattError:
                    break  # no validated request ID: close, no invented ID
                try:
                    resp = self.launcher.control(req, owner_uid=0)
                except LexwattError as e:
                    resp = e.to_response(req["id"])
                write_frame(conn, jcs.dumps(resp))
        finally:
            conn.close()

    def stop(self) -> None:
        self._closed.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        try:
            os.unlink(self.path)
        except OSError:
            pass


class ChannelServer:
    """Serves one workload channel (the supervisor end of the fd-3
    socketpair) — identical frame format and envelope."""

    def __init__(self, launcher, channel_id: str, sock: socket.socket):
        self.launcher = launcher
        self.channel_id = channel_id
        self.sock = sock
        self._closed = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        try:
            while not self._closed.is_set():
                try:
                    payload = read_frame(self.sock, MAX_REQUEST_BYTES)
                except LexwattError:
                    break
                if payload is None:
                    break
                try:
                    req = jcs.loads(payload)
                    check_request(req)
                except LexwattError:
                    break
                try:
                    resp = self.launcher.workload(self.channel_id, req)
                except LexwattError as e:
                    resp = e.to_response(req["id"])
                write_frame(self.sock, jcs.dumps(resp))
        finally:
            try:
                self.sock.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._closed.set()
