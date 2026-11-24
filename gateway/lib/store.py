"""What the gateway remembers between calls, in one small database: used nonces, pupils seen, calls waiting.

Each step that must happen once is one database transaction, so two calls at the same instant cannot both win.
One gateway process owns the file.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

NONCE_LIFE = 900         # longer than the oldest request the gateway accepts (300s)
HOLD_LIFE = 8 * 3600     # a school day
HOLD_RETENTION = 24 * 3600
MAX_WAITING = 20         # calls one job may have waiting, so nobody is worn down into approving

TABLES = """
CREATE TABLE IF NOT EXISTS nonces(who TEXT, nonce TEXT, ts REAL, PRIMARY KEY(who, nonce));
CREATE TABLE IF NOT EXISTS seen(meter TEXT, pupil TEXT, PRIMARY KEY(meter, pupil));
CREATE TABLE IF NOT EXISTS holds(id TEXT PRIMARY KEY, body TEXT, principal TEXT, agent_id TEXT, root TEXT,
                                 state TEXT, created REAL, expires REAL, reason TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS control_versions(name TEXT PRIMARY KEY, version INTEGER, digest TEXT);
CREATE TABLE IF NOT EXISTS helper_slots(root TEXT, idx INTEGER, child_jkt TEXT, child_jti TEXT,
                                        PRIMARY KEY(root, idx));
CREATE TABLE IF NOT EXISTS rates(bucket TEXT, window INTEGER, count INTEGER, PRIMARY KEY(bucket, window));
"""


class Full(Exception):
    """A limit would be passed. `detail` is safe to show the agent."""

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=10)
        if str(path) != ":memory:" and os.name != "nt":
            os.chmod(path, 0o600)
        self.lock = threading.RLock()
        self.db.executescript(TABLES)
        self._transaction(self._digest_old_nonces)
        # whatever was running when the gateway stopped: nobody can say if it happened, so it is never tried again
        self.db.execute("UPDATE holds SET state = 'unknown' WHERE state IN ('running', 'collecting')")
        self._transaction(lambda: self._expire_holds(time.time()))

    def close(self) -> None:
        self.db.close()

    def _transaction(self, work):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                out = work()
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
            self.db.execute("COMMIT")
            return out

    # ------------------------------------------------------------ nonces

    def _digest_old_nonces(self) -> None:
        """Upgrade raw nonce rows once, without opening a replay window during deployment."""
        if self.db.execute("PRAGMA user_version").fetchone()[0] >= 1:
            return
        rows = self.db.execute("SELECT who, nonce, ts FROM nonces").fetchall()
        self.db.execute("DELETE FROM nonces")
        self.db.executemany(
            "INSERT OR IGNORE INTO nonces VALUES (?, ?, ?)",
            [(who, hashlib.sha256(nonce.encode()).hexdigest(), ts) for who, nonce, ts in rows],
        )
        self.db.execute("PRAGMA user_version = 1")

    def use_nonce(self, who: str, nonce: str) -> bool:
        """True the first time `who` uses this nonce."""
        now, digest = time.time(), hashlib.sha256(nonce.encode()).hexdigest()

        def work():
            self.db.execute("DELETE FROM nonces WHERE ts < ?", (now - NONCE_LIFE,))
            return self.db.execute("INSERT OR IGNORE INTO nonces VALUES (?, ?, ?)", (who, digest, now)).rowcount == 1

        return self._transaction(work)

    # ------------------------------------------------------------ monotonic control files and helper slots

    def accept_control(self, name: str, version: int, digest: str) -> bool:
        """Accept a signed control snapshot only if it does not roll back or change at the same version."""

        def work():
            row = self.db.execute("SELECT version, digest FROM control_versions WHERE name = ?", (name,)).fetchone()
            if row is not None and (version < row[0] or (version == row[0] and digest != row[1])):
                return False
            if row is None or version > row[0]:
                self.db.execute(
                    "INSERT INTO control_versions VALUES (?, ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET version = excluded.version, digest = excluded.digest",
                    (name, version, digest),
                )
            return True

        return self._transaction(work)

    def bind_helper_slot(self, root: str, idx: int, child_jkt: str, child_jti: str) -> bool:
        """Bind a reserved helper number to its first child key and id, durably and atomically."""

        def work():
            row = self.db.execute(
                "SELECT child_jkt, child_jti FROM helper_slots WHERE root = ? AND idx = ?", (root, idx)
            ).fetchone()
            if row is None:
                self.db.execute("INSERT INTO helper_slots VALUES (?, ?, ?, ?)", (root, idx, child_jkt, child_jti))
                return True
            return row == (child_jkt, child_jti)

        return self._transaction(work)

    def allow_rate(self, bucket: str, limit: int, period: int, now: float | None = None) -> bool:
        """Consume one request from a fixed, durable rate window."""
        now = time.time() if now is None else now
        window = int(now // period)

        def work():
            self.db.execute("DELETE FROM rates WHERE window < ?", (window - 2,))
            row = self.db.execute("SELECT count FROM rates WHERE bucket = ? AND window = ?", (bucket, window)).fetchone()
            if row is not None and row[0] >= limit:
                return False
            self.db.execute(
                "INSERT INTO rates VALUES (?, ?, 1) "
                "ON CONFLICT(bucket, window) DO UPDATE SET count = count + 1",
                (bucket, window),
            )
            return True

        return self._transaction(work)

    # ------------------------------------------------------------ pupil budgets

    def spend(self, meters: list[tuple[str, int]], pupils: set[str]) -> None:
        """Add pupils to every meter, or to none of them."""

        def work():
            for meter, limit in meters:
                seen = {r[0] for r in self.db.execute("SELECT pupil FROM seen WHERE meter = ?", (meter,))}
                if len(seen | pupils) > limit:
                    raise Full(f"this {meter.split(':')[0]} may see {limit} pupils and has seen {len(seen)}")
            for meter, _ in meters:
                self.db.executemany("INSERT OR IGNORE INTO seen VALUES (?, ?)", [(meter, p) for p in sorted(pupils)])

        self._transaction(work)

    def used(self, meter: str) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM seen WHERE meter = ?", (meter,)).fetchone()[0]

    # ------------------------------------------------------------ calls waiting for a person

    def _expire_holds(self, now: float) -> None:
        self.db.execute(
            "UPDATE holds SET state = 'lapsed', body = '{}', result = NULL "
            "WHERE state = 'waiting' AND expires <= ?",
            (now,),
        )
        self.db.execute(
            "UPDATE holds SET body = '{}', result = NULL "
            "WHERE state != 'waiting' AND expires <= ?",
            (now - HOLD_RETENTION,),
        )

    def hold(self, body: dict, *, principal: str, agent_id: str, root: str, until: float) -> str:
        now, hold_id = time.time(), secrets.token_urlsafe(16)

        def work():
            self._expire_holds(now)
            waiting = self.db.execute(
                "SELECT COUNT(*) FROM holds WHERE root = ? AND state = 'waiting' AND expires > ?", (root, now)
            ).fetchone()[0]
            if waiting >= MAX_WAITING:
                raise Full(f"{waiting} calls are already waiting for a person")
            self.db.execute(
                "INSERT INTO holds VALUES (?, ?, ?, ?, ?, 'waiting', ?, ?, '', NULL)",
                (hold_id, json.dumps(body), principal, agent_id, root, now, min(until, now + HOLD_LIFE)),
            )

        self._transaction(work)
        return hold_id

    def get_hold(self, hold_id: str) -> dict | None:
        def work():
            self._expire_holds(time.time())
            cur = self.db.execute("SELECT * FROM holds WHERE id = ?", (hold_id,))
            return cur.description, cur.fetchone()

        description, row = self._transaction(work)
        if row is None:
            return None
        hold = dict(zip([c[0] for c in description], row, strict=True))
        hold["body"] = json.loads(hold["body"])
        hold["result"] = json.loads(hold["result"]) if hold["result"] else None
        return hold

    def waiting_for(self, principal: str) -> list[dict]:
        def work():
            now = time.time()
            self._expire_holds(now)
            ids = [
                r[0]
                for r in self.db.execute(
                    "SELECT id FROM holds WHERE principal = ? AND state = 'waiting' AND expires > ? ORDER BY created",
                    (principal, now),
                )
            ]
            return ids

        ids = self._transaction(work)
        return [self.get_hold(i) for i in ids]

    def leave_waiting(self, hold_id: str, state: str, reason: str = "") -> bool:
        """True for exactly one caller. A hold leaves 'waiting' once and never goes back."""

        def work():
            return (
                self.db.execute(
                    "UPDATE holds SET state = ?, reason = ? WHERE id = ? AND state = 'waiting' AND expires > ?",
                    (state, reason, hold_id, time.time()),
                ).rowcount
                == 1
            )

        return self._transaction(work)

    def finish(self, hold_id: str, state: str, result=None, reason: str = "") -> None:
        """Only from 'running'. A hold still 'running' after a crash stays there: unknown, and never tried again."""
        self._transaction(
            lambda: self.db.execute(
                "UPDATE holds SET state = ?, result = ?, reason = ? WHERE id = ? AND state = 'running'",
                (state, json.dumps(result) if result is not None else None, reason, hold_id),
            )
        )

    def claim_result(self, hold_id: str, agent_id: str, root: str) -> dict | None:
        """Atomically claim one completed result. A concurrent collector can never receive the same data."""

        def work():
            self._expire_holds(time.time())
            cur = self.db.execute(
                "SELECT * FROM holds WHERE id = ? AND agent_id = ? AND root = ?", (hold_id, agent_id, root)
            )
            row = cur.fetchone()
            if row is None:
                return None
            description = cur.description
            hold = dict(zip([c[0] for c in description], row, strict=True))
            claimed = False
            if hold["state"] == "done" and hold["result"] is not None:
                changed = self.db.execute(
                    "UPDATE holds SET state = 'collecting' WHERE id = ? AND state = 'done' AND result IS NOT NULL",
                    (hold_id,),
                ).rowcount
                if changed != 1:
                    return None
                claimed = True
            hold["body"] = json.loads(hold["body"])
            hold["result"] = json.loads(hold["result"]) if claimed and hold["result"] else None
            return hold

        return self._transaction(work)

    def forget_result(self, hold_id: str) -> None:
        """Results hold pupil data, so they go once collected, and the request with them."""
        self._transaction(
            lambda: self.db.execute(
                "UPDATE holds SET result = NULL, body = '{}', "
                "state = CASE WHEN state = 'collecting' THEN 'collected' ELSE state END WHERE id = ?",
                (hold_id,),
            )
        )
