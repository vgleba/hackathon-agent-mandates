"""Desk, for school staff.

    python -m desk       # then open one of the sign-in links it prints. Ctrl+C stops everything

Everything listens on 127.0.0.1 and starts afresh each time, in .tmp/desk: its own issuer, people and record.
"""

import logging

import uvicorn

from desk import server
from gateway import cli
from lab import launch

log = logging.getLogger("desk")
JSMITH, PRIYA = "officer:jsmith", "officer:priya"


def set_up() -> dict[str, str]:
    """Two people, to show that neither can see, approve or take back the other's. Returns their sign-in links."""
    cli.main(["--state", str(server.STATE), "init"])
    cli.set_person(server.STATE, JSMITH, name="J Smith", successor=PRIYA)
    cli.set_person(
        server.STATE, PRIYA, name="Priya", status="active", urns=["SCH04", "SCH05"], clearance=4, daily_pupils=300
    )
    return {p: server.desk.add_person(p) for p in (JSMITH, PRIYA)}


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    launch.require_free_ports(server.PORTS, "Desk")
    launch.fresh_dir("desk")
    links = set_up()
    ports = server.PORTS
    with launch.servers(ports["data server"], [(ports["gateway"], server.ROOT)], server.STATE):
        log.info("\nSign in (each link works once):")
        log.info("  J Smith, all 12 schools        %s", links[JSMITH])
        log.info("  Priya, Dunmore and Elmwood     %s\n", links[PRIYA])
        uvicorn.run(server.app, host="127.0.0.1", port=ports["page"], log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
