"""What the gateway remembers between calls, in one small database: used nonces, pupils seen, calls waiting.

Each step that must happen once is one database transaction, so two calls at the same instant cannot both win.
One gateway process owns the file.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time

NONCE_LIFE = 900         # longer than a request can stay fresh: 300s either side of now
HOLD_LIFE = 8 * 3600     # a school day
MAX_WAITING = 20         # calls one job may have waiting, so nobody is worn down into approving

TABLES = """
CREATE TABLE IF NOT EXISTS nonces(who TEXT, nonce TEXT, ts REAL, PRIMARY KEY(who, nonce));
CREATE TABLE IF NOT EXISTS seen(meter TEXT, pupil TEXT, PRIMARY KEY(meter, pupil));
CREATE TABLE IF NOT EXISTS holds(id TEXT PRIMARY KEY, body TEXT, principal TEXT, agent_id TEXT, root TEXT,
                                 state TEXT, created REAL, expires REAL, reason TEXT, result TEXT);
"""


class Full(Exception):
    """A limit would be passed. `detail` is safe to show the agent."""

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=10)
        self.lock = threading.RLock()
        self.db.executescript(TABLES)
        # whatever was running when the gateway stopped: nobody can say if it happened, so it is never tried again
        self.db.execute("UPDATE holds SET state = 'unknown' WHERE state = 'running'")

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

    def use_nonce(self, who: str, nonce: str) -> bool:
        """True the first time `who` uses this nonce."""
        now = time.time()

        def work():
            self.db.execute("DELETE FROM nonces WHERE ts < ?", (now - NONCE_LIFE,))
            return self.db.execute("INSERT OR IGNORE INTO nonces VALUES (?, ?, ?)", (who, nonce, now)).rowcount == 1

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

    def hold(self, body: dict, *, principal: str, agent_id: str, root: str, until: float) -> str:
        now, hold_id = time.time(), secrets.token_urlsafe(16)

        def work():
            # nothing personal is kept for a request that lapsed
            self.db.execute("UPDATE holds SET body = '{}' WHERE state = 'waiting' AND expires <= ?", (now,))
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
        with self.lock:
            cur = self.db.execute("SELECT * FROM holds WHERE id = ?", (hold_id,))
            row = cur.fetchone()
        if row is None:
            return None
        hold = dict(zip([c[0] for c in cur.description], row, strict=True))
        if hold["state"] == "waiting" and hold["expires"] <= time.time():
            hold["state"] = "lapsed"
        hold["body"] = json.loads(hold["body"])
        hold["result"] = json.loads(hold["result"]) if hold["result"] else None
        return hold

    def waiting_for(self, principal: str) -> list[dict]:
        with self.lock:
            ids = [
                r[0]
                for r in self.db.execute(
                    "SELECT id FROM holds WHERE principal = ? AND state = 'waiting' AND expires > ? ORDER BY created",
                    (principal, time.time()),
                )
            ]
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

    def forget_result(self, hold_id: str) -> None:
        """Results hold pupil data, so they go once collected, and the request with them."""
        self._transaction(
            lambda: self.db.execute("UPDATE holds SET result = NULL, body = '{}' WHERE id = ?", (hold_id,))
        )
