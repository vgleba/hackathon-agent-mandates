"""Start local servers that stop when this process does. Shared by the lab and by Desk."""

import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# runs a server that exits when its parent does, however the parent ends: the pipe on its stdin closes
CHILD = """
import os, sys, threading
threading.Thread(target=lambda: (sys.stdin.read(), os._exit(0)), daemon=True).start()
import uvicorn
uvicorn.run(sys.argv[1], host="127.0.0.1", port=int(sys.argv[2]), log_level="warning")
"""
# the data server's settings need these to exist; a local .env may not
DATA_ENV = {
    "APP_URL": "http://localhost",
    "APP_NAME": "lab",
    "AWS_REGION": "local",
    "REPO": "lab",
    "ENVIRONMENT": "local",
}


def fresh_dir(name: str) -> Path:
    """An empty .tmp/<name>. Only ever clears a folder of ours."""
    work = ROOT / ".tmp" / name
    if not name.isalpha() or work.resolve().parent != (ROOT / ".tmp").resolve():
        msg = f"refusing to clear {work}"
        raise RuntimeError(msg)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    return work


def require_free_ports(ports: dict[str, int], name: str) -> None:
    for what, port in ports.items():
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                sys.exit(f"port {port} ({what}) is in use. Is {name} already running?")


def _start(app: str, port: int, cwd: Path, env: dict[str, str]) -> subprocess.Popen:
    # PYTHONPATH could import another copy of the gateway; GATEWAY_DEMO is left off, as it is by default
    inherited = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "GATEWAY_DEMO"}}
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", CHILD, app, str(port)], cwd=cwd, env={**inherited, **env}, stdin=subprocess.PIPE
    )


def _wait_until_up(app: str, url: str, child: subprocess.Popen, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if child.poll() is not None:
            sys.exit(f"{app} stopped while starting (exit code {child.returncode})")
        try:
            with urllib.request.urlopen(url, timeout=2):  # noqa: S310
                return
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    sys.exit(f"{app} did not start within {seconds}s")


@contextmanager
def servers(data_port: int, gateways: list[tuple[int, Path]], state: Path):
    """The data server, and a gateway for each (port, folder to run its code from), all on 127.0.0.1."""
    gateway_env = {
        "MCP_SERVERS": f"pupil-data=http://127.0.0.1:{data_port}/mcp/",
        "GATEWAY_STATE_DIR": str(state),
    }
    wanted = [("mcp_server.main:app", data_port, ROOT, DATA_ENV, "/api/healthcheck")]
    wanted += [("gateway.main:app", port, cwd, gateway_env, "/healthcheck") for port, cwd in gateways]
    children = []
    try:
        for app, port, cwd, env, path in wanted:
            children.append(_start(app, port, cwd, env))
            _wait_until_up(f"{app} on {port}", f"http://127.0.0.1:{port}{path}", children[-1])
        yield
    finally:
        for child in children:
            child.stdin.close()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
