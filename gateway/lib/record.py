"""The record of what was asked and what was released (questions 14 and 16).

Written before anything is released. Says whose data and what kind, never the values. Each entry holds the hash of
the one before it and is signed by the gateway, so a change in the middle breaks everything after it. Only an anchor,
the latest hash held by somebody else, can show that the end was cut off.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

from .common import canonical, sha256_hex, sign_bytes, verify_bytes

log = logging.getLogger(__name__)
REDACTED = {"value", "reason"}   # a correction's new value can be special category data, and its reason is free text
HASHED = {"query", "pupil_id", "pupil_ids"}  # names, free text and identifiers do not belong in request arguments
UNATTRIBUTED_PER_MINUTE = 60     # beyond this, requests with no genuine mandate are counted, not written
NOBODY = "unattributed"


def safe_text(s: str, longest: int = 100) -> str:
    s = s.encode("utf-8", "replace").decode("utf-8")
    return s if len(s) <= longest else s[:longest] + "..."


def safe_arguments(arguments: dict) -> dict:
    """Enough to recognise a call by, without the data it carried and without letting a caller fill the disk."""

    def clean(v, depth=0):
        if isinstance(v, str):
            return safe_text(v)
        if isinstance(v, bool) or v is None:
            return v
        if isinstance(v, (int, float)):
            return v if abs(v) < 1e15 else "large"
        if depth < 2 and isinstance(v, list):
            return [clean(x, depth + 1) for x in v[:60]]
        if depth < 2 and isinstance(v, dict):
            return {safe_text(str(k), 40): clean(x, depth + 1) for k, x in list(v.items())[:20]}
        return "..."

    cleaned = clean(arguments)
    return {
        k: "(not recorded)" if k in REDACTED else sha256_hex(canonical(v)) if k in HASHED else v
        for k, v in cleaned.items()
    }


class Record:
    def __init__(self, path: Path, key):
        self.path, self.key, self.lock = Path(path), key, threading.Lock()
        self.last = {"seq": 0, "hash": "start"}
        self._minute, self._junk = 0, 0
        if self.path.exists():
            if os.name != "nt":
                os.chmod(self.path, 0o600)
            found = check(self.path, key.public_key())
            if found != "ok":
                msg = f"the record {self.path} is {found}. Keep that file, move it aside, and find out why"
                raise RuntimeError(msg)
            lines = self.path.read_text(encoding="utf-8").splitlines()
            if lines:
                self.last = json.loads(lines[-1])

    def append(self, **event) -> dict:
        """If this raises, the caller must release nothing."""
        with self.lock:
            if event.get("principal", NOBODY) == NOBODY:
                minute = int(time.time() // 60)
                self._minute, self._junk = minute, (self._junk + 1 if minute == self._minute else 1)
                if self._junk > UNATTRIBUTED_PER_MINUTE:
                    if self._junk == UNATTRIBUTED_PER_MINUTE + 1:
                        log.warning("many requests with no genuine mandate; not recording more this minute")
                    return self.last
            entry = {"seq": self.last["seq"] + 1, "prev": self.last["hash"], "ts": time.time(), **event}
            entry["hash"] = sha256_hex(canonical(entry))
            entry["sig"] = sign_bytes(self.key, entry["hash"].encode())
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as f:
                if hasattr(os, "fchmod"):
                    os.fchmod(f.fileno(), 0o600)
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.last = entry
            return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines()]


def check(path: Path, gateway_pub, anchor: tuple[int, str] | None = None) -> str:
    """'ok', or what is wrong. anchor = (seq, hash) that somebody else wrote down earlier."""
    prev, seen = "start", {}
    lines = Path(path).read_text(encoding="utf-8").splitlines() if Path(path).exists() else []
    for n, line in enumerate(lines, 1):
        try:
            e = json.loads(line)
            body = {k: v for k, v in e.items() if k not in ("hash", "sig")}
            genuine = (
                e["prev"] == prev
                and e["seq"] == n
                and sha256_hex(canonical(body)) == e["hash"]
                and verify_bytes(gateway_pub, e["hash"].encode(), e["sig"])
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            genuine = False
        if not genuine:
            return f"broken at entry {n}"
        prev = seen[n] = e["hash"]
    if anchor and anchor[0] and seen.get(anchor[0]) != anchor[1]:
        return f"entry {anchor[0]} is missing or was replaced"
    return "ok"


def summary(entries: list[dict], principal: str, levels: dict[str, int], root: str | None = None) -> dict:
    """What one person's agents were given, over everything or over one job."""
    mine = [
        e
        for e in entries
        if e["principal"] == principal
        and e["decision"] == "ALLOW"
        and e["reason"] not in ("PERSON_LOOKUP", "COLLECTED")  # the person's own, and an answer already counted
        and (root is None or e.get("root") == root)
    ]
    columns = {c for e in mine for c in e.get("columns", [])}
    return {
        "requests": len(mine),
        "pupils": sorted({p for e in mine for p in e.get("pupils", [])}),
        "columns": sorted(columns),
        "special": sorted(c for c in columns if levels.get(c, 4) >= 4),
    }
