"""One spelling per file (question 4).

The gateway compares and forwards the same cleaned path, so what was checked is what is opened. Only harmless
differences are cleaned away. Anything a server could read as a different file is refused, because the gateway does
not know which rules the server's system follows: Windows also opens a\\b, "file.csv." and "file.csv::$DATA".
"""
from __future__ import annotations

import re

# letters, digits and a few marks. No backslash, colon, control character, space, or anything outside ASCII
PLAIN = re.compile(r"[A-Za-z0-9_\-./]+")


def clean(path) -> str | None:
    """The path with "./" and doubled slashes removed, or None if it must be refused."""
    if not isinstance(path, str) or not PLAIN.fullmatch(path) or path.startswith("/") or path.endswith("/"):
        return None
    parts = [p for p in path.split("/") if p not in ("", ".")]
    if not parts or any(p.endswith(".") for p in parts):  # ".." ends with a dot too
        return None
    return "/".join(parts)
