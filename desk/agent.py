"""The assistant: one process per job, following a fixed list of steps. It is not a model.

It makes its own key in memory, says only the public half, is handed a mandate for that key, does the job through the
gateway and stops. The key is never written down and dies with the process. It is given no other key, so a copied
mandate is no use to anyone, and nothing here can grant itself anything.

Talks in lines of JSON. It says {"jwk"}, is told {"mandate", "gateway", "job", "choice"}, then says what it is doing.
A model could take this file's place: it would get the same one mandate and the same refusals.
"""
# ruff: noqa: N818  (a refusal carries a code to match on; text shown to people has real apostrophes)

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

from desk import jobs
from gateway.cli import delegate_mandate, sign_request
from gateway.lib.common import generate_keypair, jwk_to_pub, pub_to_jwk

ALLOWED, HELD = 200, 202


class Stopped(Exception):
    """The gateway said no. The reason is passed on to the person, and nothing else is tried."""


def say(**event) -> None:
    sys.stdout.write(json.dumps(event) + "\n")
    sys.stdout.flush()


class Assistant:
    def __init__(self):
        self.key, pub = generate_keypair()
        say(jwk=pub_to_jwk(pub))
        told = json.loads(sys.stdin.readline())
        self.mandate, self.url, self.job, self.choice = (told[k] for k in ("mandate", "gateway", "job", "choice"))

    def send(self, tool: str, arguments: dict, server: str = "pupil-data") -> tuple[int, dict]:
        body = sign_request(self.key, server=server, tool=tool, arguments=arguments, mandate=self.mandate)
        req = urllib.request.Request(  # noqa: S310
            f"{self.url}/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e) if e.headers.get_content_type() == "application/json" else {}

    def ask(self, tool: str, arguments: dict):
        status, reply = self.send(tool, arguments)
        if status == HELD:
            return self.wait_for_person(reply["hold_id"])
        if status != ALLOWED:
            raise Stopped(reply.get("decision", {}).get("reason_code", "FAILED"))
        return reply["result"]

    def wait_for_person(self, hold_id: str):
        say(waiting=hold_id)
        while True:
            time.sleep(1)
            status, reply = self.send("held", {"id": hold_id}, server="gateway")
            if status != ALLOWED:
                raise Stopped(reply.get("decision", {}).get("reason_code", "FAILED"))
            state = reply["held"]["state"]
            if state == "done":
                return reply.get("result")
            if state not in {"waiting", "running"}:
                raise Stopped({"refused": "REFUSED_BY_PERSON", "lapsed": "LAPSED"}.get(state, state.upper()))

    # ------------------------------------------------------------ the jobs

    def run(self) -> None:
        if self.job == "letters" and self.choice.get("helper") and len(self.choice["pupils"]) > 1:
            result = self.letters_with_a_helper()
        else:
            steps = jobs.calls(self.job, self.choice)
            result = []
            for n, (tool, arguments) in enumerate(steps, 1):
                if len(steps) > 1:
                    say(doing=f"{n} of {len(steps)}")
                found = self.ask(tool, arguments)
                result += found if isinstance(found, list) else [found]
        say(result=result)

    def letters_with_a_helper(self) -> list:
        """Half each. The helper is another process with its own key, handed a narrower mandate (question 7)."""
        ids = list(self.choice["pupils"])
        mine, theirs = ids[: len(ids) // 2], ids[len(ids) // 2 :]
        helper = start()
        jwk = json.loads(helper.stdout.readline())["jwk"]
        scope = [
            {
                "server": "pupil-data",
                "tools": ["draft"],
                "constraints": {
                    "urn": [self.choice["school"]],
                    "kind": [self.choice["kind"]],
                    "pupil_ids": theirs,
                },
            }
        ]
        child = delegate_mandate(self.mandate, self.key, jwk_to_pub(jwk), scope=scope, ttl=jobs.SCHOOL_DAY)
        say(helper=len(theirs))
        half = {**self.choice, "helper": False, "pupils": {i: self.choice["pupils"][i] for i in theirs}}
        tell(helper, mandate=child, gateway=self.url, job="letters", choice=half)
        status, reply = self.send("draft", {"urn": half["school"], "kind": half["kind"], "pupil_ids": mine})
        if status != HELD:
            raise Stopped(reply.get("decision", {}).get("reason_code", "FAILED"))
        own, theirs_found = None, None
        stopped = None
        try:
            own = self.wait_for_person(reply["hold_id"])
        except Stopped as e:
            stopped = e
        for line in helper.stdout:
            event = json.loads(line)
            if "result" in event:
                theirs_found = event["result"]
            elif "stopped" in event:
                say(helper_stopped=event["stopped"])
        helper.wait()
        if stopped and theirs_found is None:
            raise stopped
        return [*(own or []), *(theirs_found or [])]


def start() -> subprocess.Popen:
    """Another assistant process. It inherits nothing but what it needs to run."""
    return subprocess.Popen(
        [sys.executable, "-m", "desk.agent"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8"
    )


def tell(process: subprocess.Popen, **message) -> None:
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()


def main() -> None:
    try:
        Assistant().run()
    except Stopped as e:
        say(stopped=str(e))
    except Exception as e:  # noqa: BLE001  the person is told it stopped, whatever went wrong
        say(stopped="FAILED", kind=type(e).__name__)
    say(done=True)


if __name__ == "__main__":
    main()
