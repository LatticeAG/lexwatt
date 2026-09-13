"""Per-run SQLite journal and the global launch index (spec §10.2).

One database per run, one writer; every mutation is a single
BEGIN IMMEDIATE transaction that appends signed events, updates
projections/object state, and stores the idempotent reply.
"""

from __future__ import annotations

import os
import sqlite3

from .errors import LexwattError

JOURNAL_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS run (id TEXT PRIMARY KEY, state TEXT NOT NULL, config_hash TEXT NOT NULL, projection BLOB NOT NULL, last_seq INTEGER NOT NULL, last_hash TEXT NOT NULL, stop_reason TEXT);
CREATE TABLE IF NOT EXISTS event (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, hash TEXT NOT NULL UNIQUE, canonical_entry BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS request (principal TEXT NOT NULL, id TEXT NOT NULL, digest TEXT NOT NULL, canonical_response BLOB NOT NULL, PRIMARY KEY(principal,id));
CREATE TABLE IF NOT EXISTS token (id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, state TEXT NOT NULL, action_hash TEXT NOT NULL, expires_us TEXT NOT NULL, canonical_token BLOB NOT NULL, canonical_action BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS action (id TEXT PRIMARY KEY, token_id TEXT NOT NULL UNIQUE REFERENCES token(id), channel_id TEXT NOT NULL, state TEXT NOT NULL, canonical_view BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS compute (id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, canonical_reservation BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
"""

LAUNCH_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS launch (owner_uid INTEGER NOT NULL, request_id TEXT NOT NULL, digest TEXT NOT NULL, config_hash TEXT NOT NULL, run_id TEXT NOT NULL UNIQUE, response BLOB, PRIMARY KEY(owner_uid,request_id));
"""

STORAGE_MAJOR = "1"


class AuditFault(LexwattError):
    def __init__(self):
        super().__init__("AUDIT_FAULT")


class Journal:
    """One run's journal database."""

    def __init__(self, path: str):
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            self.db = sqlite3.connect(path, isolation_level=None)
            self.db.executescript(JOURNAL_SCHEMA)
            os.chmod(path, 0o600)
        except (OSError, sqlite3.Error) as e:
            raise AuditFault() from e

    def close(self) -> None:
        self.db.close()

    def begin(self) -> None:
        try:
            self.db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as e:
            raise AuditFault() from e

    def commit(self) -> None:
        try:
            self.db.execute("COMMIT")
        except sqlite3.Error as e:
            raise AuditFault() from e

    def rollback(self) -> None:
        try:
            self.db.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    # -- metadata -----------------------------------------------------------

    def meta_set(self, key: str, value: bytes) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)", (key, value)
        )

    def meta_get(self, key: str) -> bytes | None:
        row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    # -- run row --------------------------------------------------------------

    def run_insert(self, run_id: str, state: str, config_hash: str, projection: bytes) -> None:
        self.db.execute(
            "INSERT INTO run(id,state,config_hash,projection,last_seq,last_hash,stop_reason) VALUES(?,?,?,?,?,?,?)",
            (run_id, state, config_hash, projection, 0, "0" * 64, None),
        )

    def run_update(
        self,
        run_id: str,
        state: str,
        projection: bytes,
        last_seq: int,
        last_hash: str,
        stop_reason: str | None,
    ) -> None:
        self.db.execute(
            "UPDATE run SET state=?,projection=?,last_seq=?,last_hash=?,stop_reason=? WHERE id=?",
            (state, projection, last_seq, last_hash, stop_reason, run_id),
        )

    def run_row(self, run_id: str):
        return self.db.execute(
            "SELECT id,state,config_hash,projection,last_seq,last_hash,stop_reason FROM run WHERE id=?",
            (run_id,),
        ).fetchone()

    # -- events ---------------------------------------------------------------

    def event_append(self, seq: int, event_id: str, hash_: str, canonical_entry: bytes) -> None:
        self.db.execute(
            "INSERT INTO event(seq,id,hash,canonical_entry) VALUES(?,?,?,?)",
            (seq, event_id, hash_, canonical_entry),
        )

    def event_head(self) -> tuple[int, str]:
        row = self.db.execute(
            "SELECT seq,hash FROM event ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (0, "0" * 64)

    def events_after(self, after_seq: int, limit: int) -> list[bytes]:
        rows = self.db.execute(
            "SELECT canonical_entry FROM event WHERE seq>? ORDER BY seq LIMIT ?",
            (after_seq, limit),
        ).fetchall()
        return [r[0] for r in rows]

    def event_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM event").fetchone()[0]

    def journal_bytes(self) -> int:
        """Allocated bytes across the journal + WAL (for the log budget)."""
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = self.db.execute("PRAGMA database_list").fetchone()[2] + suffix
            try:
                total += os.path.getsize(p)
            except OSError:
                pass
        return total

    # -- idempotent request table ----------------------------------------------

    def request_get(self, principal: str, req_id: str):
        return self.db.execute(
            "SELECT digest,canonical_response FROM request WHERE principal=? AND id=?",
            (principal, req_id),
        ).fetchone()

    def request_put(self, principal: str, req_id: str, digest: str, response: bytes) -> None:
        self.db.execute(
            "INSERT INTO request(principal,id,digest,canonical_response) VALUES(?,?,?,?)",
            (principal, req_id, digest, response),
        )

    # -- tokens / actions / compute --------------------------------------------

    def token_put(self, token: dict, state: str, action: dict, canonical_token: bytes, canonical_action: bytes) -> None:
        self.db.execute(
            "INSERT INTO token(id,channel_id,state,action_hash,expires_us,canonical_token,canonical_action) VALUES(?,?,?,?,?,?,?)",
            (
                token["body"]["token_id"],
                token["body"]["channel_id"],
                state,
                token["body"]["action_hash"],
                token["body"]["expires_us"],
                canonical_token,
                canonical_action,
            ),
        )

    def token_state(self, token_id: str) -> str | None:
        row = self.db.execute("SELECT state FROM token WHERE id=?", (token_id,)).fetchone()
        return row[0] if row else None

    def token_set_state(self, token_id: str, state: str) -> None:
        self.db.execute("UPDATE token SET state=? WHERE id=?", (state, token_id))

    def token_row(self, token_id: str):
        return self.db.execute(
            "SELECT id,channel_id,state,action_hash,expires_us,canonical_token,canonical_action FROM token WHERE id=?",
            (token_id,),
        ).fetchone()

    def action_put(self, action_id: str, token_id: str, channel_id: str, state: str, view: bytes) -> None:
        self.db.execute(
            "INSERT INTO action(id,token_id,channel_id,state,canonical_view) VALUES(?,?,?,?,?)",
            (action_id, token_id, channel_id, state, view),
        )

    def action_set(self, action_id: str, state: str, view: bytes) -> None:
        self.db.execute(
            "UPDATE action SET state=?,canonical_view=? WHERE id=?", (state, view, action_id)
        )

    def action_row(self, action_id: str):
        return self.db.execute(
            "SELECT id,token_id,channel_id,state,canonical_view FROM action WHERE id=?",
            (action_id,),
        ).fetchone()

    def compute_put(self, compute_id: str, channel_id: str, reservation: bytes) -> None:
        self.db.execute(
            "INSERT INTO compute(id,channel_id,canonical_reservation) VALUES(?,?,?)",
            (compute_id, channel_id, reservation),
        )

    def compute_set(self, compute_id: str, reservation: bytes) -> None:
        self.db.execute(
            "UPDATE compute SET canonical_reservation=? WHERE id=?", (reservation, compute_id)
        )

    def compute_row(self, compute_id: str):
        return self.db.execute(
            "SELECT id,channel_id,canonical_reservation FROM compute WHERE id=?",
            (compute_id,),
        ).fetchone()


class LaunchIndex:
    """launches.sqlite: run.start idempotency index (spec §10.2)."""

    def __init__(self, path: str):
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            self.db = sqlite3.connect(path, isolation_level=None)
            self.db.executescript(LAUNCH_SCHEMA)
        except (OSError, sqlite3.Error) as e:
            raise AuditFault() from e

    def close(self) -> None:
        self.db.close()

    def begin(self) -> None:
        self.db.execute("BEGIN IMMEDIATE")

    def commit(self) -> None:
        self.db.execute("COMMIT")

    def rollback(self) -> None:
        self.db.execute("ROLLBACK")

    def get(self, owner_uid: int, request_id: str):
        return self.db.execute(
            "SELECT digest,config_hash,run_id,response FROM launch WHERE owner_uid=? AND request_id=?",
            (owner_uid, request_id),
        ).fetchone()

    def reserve(self, owner_uid: int, request_id: str, digest: str, config_hash: str, run_id: str) -> None:
        self.db.execute(
            "INSERT INTO launch(owner_uid,request_id,digest,config_hash,run_id,response) VALUES(?,?,?,?,?,NULL)",
            (owner_uid, request_id, digest, config_hash, run_id),
        )

    def store_response(self, owner_uid: int, request_id: str, response: bytes) -> None:
        self.db.execute(
            "UPDATE launch SET response=? WHERE owner_uid=? AND request_id=?",
            (response, owner_uid, request_id),
        )
