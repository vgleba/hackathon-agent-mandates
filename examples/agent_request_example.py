import json
import urllib.error
import urllib.request
from pathlib import Path

from gateway.cli import sign_request
from gateway.lib.common import priv_from_pem

KEY = priv_from_pem(Path("gateway/state/agent.pem").read_bytes())
MANDATE = Path("gateway/state/mandate.jwt").read_text().strip()


def call(tool: str, arguments: dict) -> dict:
    body = sign_request(KEY, server="pupil-data", tool=tool, arguments=arguments, mandate=MANDATE)
    req = urllib.request.Request(
        "http://localhost:8082/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as r:  # noqa: S310  (the caller chooses its gateway URL)
            return json.load(r)
    except urllib.error.HTTPError as e:  # a 403 still carries the decision
        return json.load(e)


print(call("search", {"query": "P0004", "urn": "SCH01", "limit": 1}))  # noqa: T201  (runnable example)
