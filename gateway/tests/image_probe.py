"""The gateway as the production image has it: without gateway/demo.py, which .dockerignore leaves out (ADR-0001).

Run in an interpreter of its own, so that the test process keeps its gateway with the demo in it:

    python -m gateway.tests.image_probe <state dir> <call as JSON> <agent private key>

Prints one line of JSON: the status of each /demo route, and the status and decision of the call.
"""

import json
import os
import sys
from pathlib import Path

DEMO_ROUTES = [
    ("GET", "/demo/issuer", None),
    ("GET", "/demo/trust", None),
    ("POST", "/demo/mandate", {"urn": "SCH07", "tools": ["pupil"], "deny": []}),
    ("POST", "/demo/revoke", {"idx": 0}),
    ("POST", "/demo/call", {"tool": "pupil", "arguments": {"pupil_id": "P0586", "urn": "SCH07"}}),
]


def probe() -> None:
    state_dir, call = sys.argv[1], json.loads(sys.argv[2])
    sys.modules["gateway.demo"] = None  # importing it now fails as it does when the file is not there
    os.environ["GATEWAY_DEMO"] = "1"  # switched on, as a deploy might: there must be nothing to switch on
    os.environ["GATEWAY_STATE_DIR"] = state_dir

    from fastapi.testclient import TestClient  # noqa: PLC0415  (only once the demo is blocked)

    from gateway import cli, main  # noqa: PLC0415
    from gateway.lib.common import priv_from_pem  # noqa: PLC0415
    from mcp_server.api.routes_mcp import mcp  # noqa: PLC0415

    main.MCP_SERVERS["pupil-data"] = mcp
    with TestClient(main.app, raise_server_exceptions=False) as client:
        # Model an external agent signing after this process starts. The key path is supplied by the test harness;
        # it is not present in the production image whose contents this probe checks.
        call = cli.sign_request(
            priv_from_pem(Path(sys.argv[3]).read_bytes()),
            server=call["server"],
            tool=call["tool"],
            arguments=call["arguments"],
            mandate=call["mandate"],
        )
        demo = {
            f"{method} {path}": client.request(method, path, json=body).status_code
            for method, path, body in DEMO_ROUTES
        }
        reply = client.post("/tools/call", json=call)
    seen = {"demo": demo, "call": [reply.status_code, reply.json()["decision"]["decision"]]}
    sys.stdout.write(json.dumps(seen) + "\n")


if __name__ == "__main__":
    probe()
