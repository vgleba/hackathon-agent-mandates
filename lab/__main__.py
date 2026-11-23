"""The gateway before and after, side by side.

    python -m lab        # then open http://127.0.0.1:8184, and Ctrl+C to stop everything

Starts the data server, the original gateway (exported from git) and the gateway in this working tree, then the page.
Everything listens on 127.0.0.1 and uses its own issuer, keys and mandates in .tmp/lab, made afresh on every start,
so nothing here reads or writes gateway/state. Restart it to pick up a change to the gateway.
"""

import io
import logging
import shutil
import subprocess
import sys
import tarfile

import uvicorn

from gateway import cli
from gateway import eval as ev
from lab import launch, server

log = logging.getLogger("lab")


def export_baseline() -> None:
    """The gateway as it was before our changes, straight from git, so "before" cannot drift."""
    tar = subprocess.run(  # noqa: S603
        ["git", "archive", "--format=tar", server.BASELINE, "gateway"],  # noqa: S607
        cwd=server.ROOT,
        capture_output=True,
        check=False,
    )
    if tar.returncode:
        sys.exit(f"could not export commit {server.BASELINE}: {tar.stderr.decode().strip()}")
    with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as t:
        t.extractall(server.WORK / "before", filter="data")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    launch.require_free_ports(server.PORTS, "the lab")
    launch.fresh_dir("lab")
    export_baseline()
    cli.main(["--state", str(server.STATE), "init"])
    ev.main(["build", "--state", str(server.STATE), "-o", str(server.PACK)])
    # a page for experimenting with: its own people are not held to a day's limit
    for principal in ("officer:jsmith", "eval:runner"):
        cli.set_person(server.STATE, principal, daily_pupils=1_000_000)
    ports = server.PORTS
    gateways = [(ports["after"], server.ROOT), (ports["before"], server.WORK / "before")]
    with launch.servers(ports["data server"], gateways, server.STATE):
        log.info("\nOpen http://127.0.0.1:%d   (Ctrl+C stops everything)\n", ports["page"])
        uvicorn.run(server.app, host="127.0.0.1", port=ports["page"], log_level="warning")
    shutil.rmtree(server.STATE, ignore_errors=True)  # keys from this run are no use to the next


if __name__ == "__main__":
    main()
