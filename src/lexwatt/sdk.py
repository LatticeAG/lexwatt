"""Python SDK: request(method, params) clients plus the pure helpers
(spec §8.3).  One nanoid request ID is generated per logical mutation and
retained across transport retries.
"""

from __future__ import annotations

import socket
import time

from . import jcs
from .errors import LexwattError
from .ids import IdGenerator
from .server import read_frame, write_frame


class Client:
    """Framed request client for the control stream or a workload channel."""

    def __init__(self, sock: socket.socket, ids: IdGenerator | None = None):
        self.sock = sock
        self.ids = ids or IdGenerator()

    @classmethod
    def connect(cls, path: str) -> "Client":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        return cls(s)

    @classmethod
    def from_fd(cls, fd: int = 3) -> "Client":
        return cls(socket.socket(fileno=fd))

    def request(self, method: str, params: dict, request_id: str | None = None, retries: int = 3) -> dict:
        """One logical call: a stable request ID across transport retries.
        Returns the response envelope; raises LexwattError on error replies."""
        rid = request_id or self.ids.new("request")
        req = {"v": 1, "id": rid, "method": method, "params": params}
        payload = jcs.dumps(req)
        last_err: Exception | None = None
        for _ in range(retries):
            try:
                write_frame(self.sock, payload)
                raw = read_frame(self.sock, 1048576)
                if raw is None:
                    raise LexwattError("INVALID_INPUT")
                resp = jcs.loads(raw)
            except LexwattError as e:
                last_err = e
                continue
            if resp.get("ok") is False:
                err = resp["error"]
                e = LexwattError(err["code"], err.get("retryable", False))
                if e.code == "BUSY":
                    time.sleep(0.05)
                    last_err = e
                    continue  # BUSY retries keep the same request ID
                raise e
            return resp
        raise last_err or LexwattError("INVALID_INPUT")


def workload_channel(fd: int = 3) -> Client:
    """The workload-side SDK bound to descriptor 3."""
    return Client.from_fd(fd)
