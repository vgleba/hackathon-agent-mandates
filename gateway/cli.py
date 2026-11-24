"""Hand an agent part of your access, then use it.

A mandate is a signed note from an issuer to an agent. It says what the agent may do, what it must
never do, and until when. The gateway checks the note on every call. The issuer can cancel it at any time.

    python -m gateway.cli init                                      # issuer: one-off setup
    python -m gateway.cli keygen -o agent.pem                       # agent: make a key, send the printed JWK
    python -m gateway.cli issue --agent-key team.jwk -o mandate.jwt # issuer: write a mandate for that key
    python -m gateway.cli discover --url http://localhost:8082      # agent: see what a gateway offers
    python -m gateway.cli revoke --idx 0                            # issuer: cancel mandate 0
    python -m gateway.cli decode mandate.jwt                        # anyone: read what a mandate says
    python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem \\
        --server pupil-data --tool search --args '{"query": "P0004", "urn": "SCH01"}'

Keys and mandates live in $GATEWAY_STATE_DIR (default gateway/state). It holds private keys: never commit it.
"""

import argparse
import json
import os
import re
import secrets
import sys
import time
import urllib.request
import uuid
from pathlib import Path

import jwt

from gateway.lib.common import (
    b64u,
    b64u_decode,
    canonical,
    generate_keypair,
    jwk_to_pub,
    priv_from_pem,
    priv_to_pem,
    pub_from_pem,
    pub_to_jwk,
    pub_to_pem,
    sign_bytes,
)
from gateway.lib.delegation import CHILD_TYP
from gateway.lib.gateway_verify import Request
from gateway.lib.mandate_issuer import MandateIssuer
from gateway.lib.people_policy import issue_people_policy
from gateway.lib.record import check as check_record
from gateway.lib.status_list import StatusListIssuer

# search pupils of SCH01 only; get only the two files that hold no pupil data. Also the Day 2 attack mandate.
DEFAULT_SCOPE = [
    {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}},
    {
        "server": "pupil-data",
        "tools": ["get"],
        "constraints": {"path": ["synthetic/synthetic_schools.csv", "synthetic/synthetic_manifest.json"]},
    },
]
DEFAULT_DENY = ["*.write", "pii.*"]
DEFAULT_PROFILE = {"clearance": 3, "purpose_code": "scope_only", "budget": {"pupils": 50}}
RUNTIME_CONFIG_FILES = ("trusted_list.json", "status_list.json", "status_list.jwt", "people.jwt")
# who may grant access, checked on every call (question 13). The eval and the default mandate use these two
DEFAULT_PEOPLE = {
    "officer:jsmith": {
        "name": "J Smith",
        "status": "active",
        "urns": "*",
        "clearance": 4,
        "daily_pupils": 300,
    },
    "eval:runner": {"name": "Eval", "status": "active", "urns": "*", "clearance": 3, "daily_pupils": 300},
}
AUTHORITY_FIELDS = {"status", "urns", "clearance", "daily_pupils", "jwk", "successor"}


def replace_text(path: Path, text: str) -> None:
    """All of the new text or all of the old, never half: the gateway reads these files on every request."""
    new = path.with_name(f"{path.name}.{secrets.token_hex(4)}.new")
    new.write_text(text, encoding="utf-8")
    for attempt in range(50):
        try:
            new.replace(path)
        except PermissionError:  # Windows, while somebody is reading it
            if attempt == 49:  # noqa: PLR2004
                raise
            time.sleep(0.02)
        else:
            return


def ensure_audience(state: Path, meta: dict | None = None) -> str:
    """Give state made before mandate v2 one stable gateway audience without replacing any key."""
    trusted_path, status_path = state / "trusted_list.json", state / "status_list.json"
    trusted = json.loads(trusted_path.read_text(encoding="utf-8"))
    meta = json.loads(status_path.read_text(encoding="utf-8")) if meta is None else meta
    audience = trusted.get("gateway_audience") or meta.get("audience") or f"urn:hack:gateway:{uuid.uuid4()}"
    if trusted.get("gateway_audience") != audience:
        trusted["gateway_audience"] = audience
        replace_text(trusted_path, json.dumps(trusted, indent=2))
    if meta.get("audience") != audience:
        meta["audience"] = audience
        replace_text(status_path, json.dumps(meta, indent=2))
    else:
        meta["audience"] = audience
    return audience


def _load_status(state: Path) -> tuple[StatusListIssuer, dict]:
    meta = json.loads((state / "status_list.json").read_text())
    ensure_audience(state, meta)
    issuer = StatusListIssuer(
        meta["issuer"],
        meta["uri"],
        priv_from_pem((state / "issuer_key.pem").read_bytes()),
        sequence=meta.get("sequence", 0),
    )
    issuer.bits = bytearray(b64u_decode(meta["bits_b64u"]))
    issuer._next = meta["next"]  # noqa: SLF001
    return issuer, meta


def _save_status(state: Path, issuer: StatusListIssuer, meta: dict) -> None:
    issuer.sequence += 1
    meta.update(next=issuer._next, bits_b64u=b64u(bytes(issuer.bits)), sequence=issuer.sequence)  # noqa: SLF001
    replace_text(state / "status_list.json", json.dumps(meta, indent=2))
    # a week: the gateway fails closed on a stale list and nothing republishes between CLI runs
    replace_text(state / "status_list.jwt", issuer.publish(ttl=7 * 86400))
    publish_runtime(state)


def _normal_people(people: dict) -> dict:
    if (
        not isinstance(people, dict)
        or not people
        or not all(isinstance(principal, str) and isinstance(person, dict) for principal, person in people.items())
    ):
        msg = "people.json must be a non-empty object of people"
        raise ValueError(msg)
    return {principal: {**person, "authz_epoch": person.get("authz_epoch", 1)} for principal, person in people.items()}


def save_people(state: Path, people: dict) -> dict:
    """Write the issuer's working copy and the signed, monotonic policy consumed by the gateway."""
    people = _normal_people(people)
    if not all(type(person["authz_epoch"]) is int and person["authz_epoch"] >= 1 for person in people.values()):
        msg = "every person needs a positive authorization epoch"
        raise ValueError(msg)
    meta = json.loads((state / "status_list.json").read_text(encoding="utf-8"))
    ensure_audience(state, meta)
    sequence_path = state / "people_sequence.json"
    if sequence_path.exists():
        sequence = json.loads(sequence_path.read_text(encoding="utf-8"))["sequence"]
    elif (state / "people.jwt").exists():
        sequence = jwt.decode((state / "people.jwt").read_text(), options={"verify_signature": False}).get("seq", 0)
    else:
        sequence = 0
    if type(sequence) is not int or sequence < 0:
        msg = "people policy sequence is invalid"
        raise ValueError(msg)
    sequence += 1
    token = issue_people_policy(
        people,
        issuer=meta["issuer"],
        kid=meta["kid"],
        priv=priv_from_pem((state / "issuer_key.pem").read_bytes()),
        sequence=sequence,
    )
    replace_text(state / "people.json", json.dumps(people, indent=2))
    replace_text(sequence_path, json.dumps({"sequence": sequence}, indent=2))
    replace_text(state / "people.jwt", token)
    publish_runtime(state)
    return people


def load_people(state: Path) -> dict:
    """Everyone who may grant access. The CLI keeps this working copy; the gateway reads only people.jwt."""
    path = state / "people.json"
    if not path.exists():
        return save_people(state, DEFAULT_PEOPLE)
    raw = json.loads(path.read_text(encoding="utf-8"))
    people = _normal_people(raw)
    if people != raw or not (state / "people.jwt").exists():
        return save_people(state, people)
    return people


def write_private(path: Path, data: bytes) -> None:
    """A private key, readable by its owner only, even where the file was already there with looser rights."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        if hasattr(os, "fchmod"):  # not on Windows, which does not keep these bits anyway
            os.fchmod(f.fileno(), 0o600)
        f.write(data)


def publish_runtime(state: Path) -> Path:
    """Publish only the files a gateway may receive, separated from issuer and agent secrets."""
    runtime = state / "runtime"
    config, secrets_dir, data_dir = runtime / "config", runtime / "secrets", runtime / "data"
    config.mkdir(parents=True, exist_ok=True)
    secrets_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        state.chmod(0o700)
        runtime.chmod(0o700)
        config.chmod(0o750)
        secrets_dir.chmod(0o700)
        data_dir.chmod(0o700)
        for private in [*state.glob("*.pem"), state / "gateway.db", state / "record.jsonl"]:
            if private.exists():
                private.chmod(0o600)
    allowed_config = set(RUNTIME_CONFIG_FILES)
    for published in config.iterdir():
        if published.name not in allowed_config:
            if published.is_dir() and not published.is_symlink():
                msg = f"unexpected directory in runtime config: {published}"
                raise ValueError(msg)
            published.unlink()
    for name in RUNTIME_CONFIG_FILES:
        source = state / name
        if source.exists():
            replace_text(config / name, source.read_text(encoding="utf-8"))
        else:
            (config / name).unlink(missing_ok=True)
    gateway_key = state / "gateway_key.pem"
    if gateway_key.exists():
        write_private(secrets_dir / "gateway_key.pem", gateway_key.read_bytes())
    else:
        (secrets_dir / "gateway_key.pem").unlink(missing_ok=True)
    return runtime


def load_or_create_key(path: Path):
    if path.exists():
        return priv_from_pem(path.read_bytes())
    priv, _ = generate_keypair()
    write_private(path, priv_to_pem(priv))
    return priv


def load_agent_pub(path: Path):
    """Public key from a JWK JSON file, a public PEM or a private PEM; creates a private PEM if missing."""
    if not path.exists():
        return load_or_create_key(path).public_key()
    raw = path.read_bytes()
    if raw.lstrip().startswith(b"{"):
        return jwk_to_pub(json.loads(raw))
    if b"PRIVATE" in raw:
        return priv_from_pem(raw).public_key()
    return pub_from_pem(raw)


def scope_warnings(scope: list[dict]) -> list[str]:
    """Scope entries add up: the gateway allows a call if any one entry accepts it, and an entry only restricts
    the arguments it names. Entries for one tool that constrain different arguments are usually a mistake."""
    seen: dict[tuple[str, str], set[frozenset]] = {}
    for entry in scope:
        for tool in entry["tools"]:
            seen.setdefault((entry["server"], tool), set()).add(frozenset(entry.get("constraints", {})))
    return [
        f"warning: {server}.{tool} has entries constraining different arguments "
        f"({', '.join(str(sorted(k)) for k in sorted(keys, key=sorted))}); each entry is a separate grant, "
        "so the tool is as wide as its loosest entry"
        for (server, tool), keys in seen.items()
        if len(keys) > 1
    ]


def issue_mandate(
    state: Path,
    agent_pub,
    *,
    scope: list[dict],
    deny: list[str],
    ttl: int,
    purpose: str,
    principal: str,
    org: str,
    extra: dict | None = None,
    helpers: int = 0,
) -> tuple[str, int]:
    """Issue a mandate from the state dir's issuer key. Returns (jwt, status-list index).

    `helpers` sets aside that many revocation numbers, so the agent may hand part of this on and each can be stopped.
    """
    for warning in scope_warnings(scope):
        print(warning, file=sys.stderr)
    people = load_people(state)
    if principal not in people:
        msg = f"{principal} is not in people.json. Add them first: cli person --principal {principal} --urns ..."
        raise ValueError(msg)
    status, meta = _load_status(state)
    profile = {**DEFAULT_PROFILE, **(extra or {})}
    if helpers:
        profile |= {"may_delegate": 1, "helpers": [status.allocate() for _ in range(helpers)]}
    idx = status._next  # noqa: SLF001
    token = MandateIssuer(meta["issuer"], meta["kid"], status.priv, status).issue(
        delegator={"principal": principal, "org": org, "authority": "hackathon"},
        delegate_pub=agent_pub,
        purpose=purpose,
        scope=scope,
        deny=deny,
        audience=meta["audience"],
        principal_epoch=people[principal]["authz_epoch"],
        ttl=ttl,
        extra=profile,
    )
    _save_status(state, status, meta)
    return token, idx


def revoke_mandate(state: Path, idx: int) -> None:
    status, meta = _load_status(state)
    status.revoke(idx)
    _save_status(state, status, meta)


def delegate_mandate(parent: str, parent_priv, helper_pub, *, scope: list[dict], ttl: int, helper: int = 0) -> str:
    """Hand part of a mandate on to a helper's key. Needs no issuer: the parent agent's own key signs it."""
    claims = jwt.decode(parent, options={"verify_signature": False})
    child = {
        "jti": f"urn:uuid:{uuid.uuid4()}",
        "exp": min(int(time.time()) + ttl, claims["exp"]),
        "cnf": {"jwk": pub_to_jwk(helper_pub)},
        "scope": scope,
        "helper_idx": claims["helpers"][helper],
        "parent": parent,
    }
    return jwt.encode(child, priv_to_pem(parent_priv), algorithm="EdDSA", headers={"typ": CHILD_TYP})


def person_message(principal: str, do: str, nonce: str, ts: int, fields: dict) -> bytes:
    """What a person signs with their own key. `do` is part of it, so a signature is good for one kind of thing."""
    return canonical({"principal": principal, "do": do, "nonce": nonce, "ts": ts, "fields": fields})


def sign_as_person(key, principal: str, do: str, **fields) -> dict:
    nonce, ts = secrets.token_urlsafe(16), int(time.time())
    sig = sign_bytes(key, person_message(principal, do, nonce, ts, fields))
    return {"principal": principal, "nonce": nonce, "ts": ts, "sig": sig, **fields}


def set_person(state: Path, principal: str, **fields) -> None:
    people = load_people(state)
    previous = people.get(principal)
    current = {**(previous or {}), **fields}
    epoch = previous.get("authz_epoch", 1) if previous else 1
    if previous and any(name in fields and previous.get(name) != current.get(name) for name in AUTHORITY_FIELDS):
        epoch += 1
    people[principal] = {**current, "authz_epoch": epoch}
    save_people(state, people)


def person_key(state: Path, principal: str):
    """A person's own key, kept apart from any agent's. In real use it stays on their own device."""
    key = load_or_create_key(state / f"person_{re.sub(r'[^a-z0-9]+', '_', principal.lower())}.pem")
    jwk = pub_to_jwk(key.public_key())
    owners = [name for name, person in load_people(state).items() if name != principal and person.get("jwk") == jwk]
    if owners:
        msg = f"principal key filename collides with {owners}; choose a distinct principal identifier"
        raise ValueError(msg)
    set_person(state, principal, jwk=jwk)
    return key


def sign_request(agent_priv, *, server: str, tool: str, arguments: dict, mandate: str) -> dict:
    req = Request(
        server=server,
        tool=tool,
        arguments=arguments,
        mandate=mandate,
        nonce=secrets.token_urlsafe(16),
        ts=int(time.time()),
        sig="",
    )
    req.sig = sign_bytes(agent_priv, req.signing_input())
    return req.__dict__


def cmd_init(a) -> None:
    state = a.state
    if (state / "trusted_list.json").exists() and not a.force:
        sys.exit(f"{state} already initialised; pass --force to overwrite")
    state.mkdir(parents=True, exist_ok=True)
    issuer_priv, issuer_pub = generate_keypair()
    gateway_priv, gateway_pub = generate_keypair()
    write_private(state / "issuer_key.pem", priv_to_pem(issuer_priv))
    write_private(state / "gateway_key.pem", priv_to_pem(gateway_priv))
    (state / "gateway.pub").write_bytes(pub_to_pem(gateway_pub))
    audience = a.audience or f"urn:hack:gateway:{uuid.uuid4()}"
    trusted = {"gateway_audience": audience, "issuers": {a.issuer: {a.kid: pub_to_jwk(issuer_pub)}}}
    (state / "trusted_list.json").write_text(json.dumps(trusted, indent=2))
    meta = {
        "issuer": a.issuer,
        "kid": a.kid,
        "audience": audience,
        "uri": f"{a.issuer}/status/1",
        "next": 0,
        "bits_b64u": "",
    }
    _save_status(state, StatusListIssuer(a.issuer, meta["uri"], issuer_priv), meta)
    save_people(state, DEFAULT_PEOPLE)
    person_key(state, "officer:jsmith")
    print(f"initialised {state}")


def cmd_issue(a) -> None:
    token, idx = issue_mandate(
        a.state,
        load_agent_pub(a.agent_key),
        scope=json.loads(a.scope),
        deny=json.loads(a.deny),
        ttl=a.ttl,
        purpose=a.purpose,
        principal=a.principal,
        org=a.org,
        extra=json.loads(a.claims),
        helpers=a.helpers,
    )
    if a.out:
        a.out.write_text(token)
        print(f"wrote mandate (status idx {idx}) to {a.out}")
    else:
        print(token)


def cmd_delegate(a) -> None:
    token = delegate_mandate(
        a.mandate.read_text().strip(),
        priv_from_pem(a.agent_key.read_bytes()),
        load_agent_pub(a.to),
        scope=json.loads(a.scope),
        ttl=a.ttl,
        helper=a.helper,
    )
    a.out.write_text(token)
    print(f"wrote a narrower mandate for the helper to {a.out}")


def cmd_person(a) -> None:
    given = {"name": a.name, "status": a.status, "clearance": a.clearance, "daily_pupils": a.daily_pupils}
    given["successor"] = a.successor
    if a.urns:
        given["urns"] = "*" if a.urns == "*" else a.urns.split(",")
    if a.principal not in load_people(a.state):  # missing means least
        given = {"status": "active", "urns": [], "clearance": 1, "daily_pupils": 0} | {
            k: v for k, v in given.items() if v is not None
        }
    set_person(a.state, a.principal, **{k: v for k, v in given.items() if v is not None})
    if a.key:
        person_key(a.state, a.principal)
    print(json.dumps({a.principal: load_people(a.state)[a.principal]}, indent=2))


def cmd_sign_people(a) -> None:
    """Migrate or republish an issuer working copy as the signed runtime policy."""
    save_people(a.state, json.loads((a.state / "people.json").read_text(encoding="utf-8")))
    print(f"signed people policy at {a.state / 'people.jwt'}")


def cmd_publish_runtime(a) -> None:
    runtime = publish_runtime(a.state)
    print(f"published gateway runtime state at {runtime}")


def cmd_log_anchor(a) -> None:
    runtime_record = a.state / "runtime" / "data" / "record.jsonl"
    path = runtime_record if runtime_record.exists() else a.state / "record.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    last = json.loads(lines[-1])
    print(f"{last['seq']}:{last['hash']}")


def cmd_log_check(a) -> None:
    anchor = None
    if a.anchor:
        seq, hashed = a.anchor.split(":", 1)
        anchor = (int(seq), hashed)
    runtime_record = a.state / "runtime" / "data" / "record.jsonl"
    path = runtime_record if runtime_record.exists() else a.state / "record.jsonl"
    found = check_record(path, pub_from_pem((a.state / "gateway.pub").read_bytes()), anchor)
    if found != "ok":
        sys.exit(found)
    print(found)


def cmd_keygen(a) -> None:
    if a.out.exists():
        sys.exit(f"{a.out} already exists")
    priv = load_or_create_key(a.out)
    print(json.dumps(pub_to_jwk(priv.public_key())))


def cmd_discover(a) -> None:
    with urllib.request.urlopen(f"{a.url}/describe") as resp:  # noqa: S310
        print(json.dumps(json.load(resp), indent=2))


def cmd_revoke(a) -> None:
    revoke_mandate(a.state, a.idx)
    print(f"revoked idx {a.idx}")


def cmd_decode(a) -> None:
    # reads the claims only: the signature is not checked here, the gateway does that on every call
    payload = (a.mandate or a.state / "mandate.jwt").read_text().split(".")[1]
    print(json.dumps(json.loads(b64u_decode(payload)), indent=2))


def cmd_call(a) -> None:
    body = sign_request(
        priv_from_pem(a.agent_key.read_bytes()),
        server=a.server,
        tool=a.tool,
        arguments=json.loads(a.args),
        mandate=a.mandate.read_text().strip(),
    )
    req = urllib.request.Request(  # noqa: S310
        f"{a.url}/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            status, text = resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    print(status)
    print(json.dumps(json.loads(text), indent=2))


def main(argv: list[str] | None = None) -> None:  # noqa: PLR0915  (one block per command)
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--state",
        type=Path,
        default=Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state")),
        help="folder holding keys and mandates",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="become an issuer: make the keys that sign mandates (run once)")
    s.add_argument("--issuer", default="https://issuer.hack.local", help="your name as an issuer")
    s.add_argument("--kid", default="issuer-2026-11", help="label for this signing key")
    s.add_argument("--audience", help="gateway audience (default: a new unique urn:hack:gateway UUID)")
    s.add_argument("--force", action="store_true", help="replace existing keys")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("keygen", help="make an agent key; prints the public half for the issuer")
    s.add_argument("-o", "--out", type=Path, default=Path("agent.pem"), help="where to save the private key")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("discover", help="show what a gateway offers and how to sign a call")
    s.add_argument("--url", default="http://localhost:8082", help="gateway address")
    s.set_defaults(fn=cmd_discover)

    s = sub.add_parser("issue", help="write a mandate for an agent key")
    s.add_argument("--agent-key", type=Path, required=True, help="the agent's public key (JWK or PEM)")
    s.add_argument("--scope", default=json.dumps(DEFAULT_SCOPE), help="what the agent may do (JSON)")
    s.add_argument("--deny", default=json.dumps(DEFAULT_DENY), help="what it must never do (JSON)")
    s.add_argument("--ttl", type=int, default=7200, help="seconds until it expires")
    s.add_argument("--purpose", default="Pupil-data lookups for school SCH01", help="why the agent needs it")
    s.add_argument("--principal", default="officer:jsmith", help="the person handing over access")
    s.add_argument("--org", default="school:SCH01", help="who that person acts for")
    s.add_argument("--claims", default="{}", help="claims of your own to sign in, e.g. '{\"clearance\": 2}' (JSON)")
    s.add_argument("--helpers", type=int, default=0, help="how many helpers the agent may hand part of this on to")
    s.add_argument("-o", "--out", type=Path, help="file to write to (default: print it)")
    s.set_defaults(fn=cmd_issue)

    s = sub.add_parser("delegate", help="agent: hand part of your mandate on to a helper, narrower")
    s.add_argument("--mandate", type=Path, required=True, help="your own mandate, issued with --helpers")
    s.add_argument("--agent-key", type=Path, required=True, help="your own private key")
    s.add_argument("--to", type=Path, required=True, help="the helper's public key (JWK or PEM)")
    s.add_argument("--scope", required=True, help="the part to hand on (JSON)")
    s.add_argument("--ttl", type=int, default=900, help="seconds until it expires, never later than your own")
    s.add_argument("--helper", type=int, default=0, help="which of the helpers set aside for you: 0, 1, ...")
    s.add_argument("-o", "--out", type=Path, required=True, help="file to write to")
    s.set_defaults(fn=cmd_delegate)

    s = sub.add_parser("person", help="add or change someone who may grant access; takes effect on the next call")
    s.add_argument("--principal", required=True, help="their id, e.g. officer:priya")
    s.add_argument("--name", help="their name")
    s.add_argument("--status", choices=["active", "away", "left"], help="anything but active pauses all their agents")
    s.add_argument("--urns", help="schools they cover, e.g. SCH04,SCH05, or * for all")
    s.add_argument("--clearance", type=int, choices=[1, 2, 3, 4], help="the most sensitive data they may see")
    s.add_argument("--daily-pupils", type=int, help="different pupils their agents may see in a day")
    s.add_argument("--successor", help="who may start their jobs afresh when they leave")
    s.add_argument(
        "--key", action="store_true", help="make them a key of their own, to approve and read their log with"
    )
    s.set_defaults(fn=cmd_person)

    s = sub.add_parser("sign-people", help="sign people.json for the gateway (migrates older state)")
    s.set_defaults(fn=cmd_sign_people)

    s = sub.add_parser("publish-runtime", help="publish only gateway config and its own audit key")
    s.set_defaults(fn=cmd_publish_runtime)

    s = sub.add_parser("log-anchor", help="print the latest entry's number and hash, for somebody else to keep")
    s.set_defaults(fn=cmd_log_anchor)

    s = sub.add_parser("log-check", help="check that the record has not been changed, or cut off since an anchor")
    s.add_argument("--anchor", help="what log-anchor printed earlier")
    s.set_defaults(fn=cmd_log_check)

    s = sub.add_parser("revoke", help="cancel a mandate; takes effect on the next call")
    s.add_argument("--idx", type=int, required=True, help="number printed when it was issued")
    s.set_defaults(fn=cmd_revoke)

    s = sub.add_parser("decode", help="print a mandate's claims as JSON, without checking its signature")
    s.add_argument("mandate", type=Path, nargs="?", help="the mandate file (default: mandate.jwt in --state)")
    s.set_defaults(fn=cmd_decode)

    s = sub.add_parser("call", help="ask the gateway to run a tool, using a mandate")
    s.add_argument("--mandate", type=Path, required=True, help="the mandate file")
    s.add_argument("--agent-key", type=Path, required=True, help="private key the mandate was issued to")
    s.add_argument("--server", default="pupil-data", help="which data server behind the gateway")
    s.add_argument("--tool", required=True, help="tool name, e.g. search")
    s.add_argument("--args", default="{}", help="tool arguments (JSON)")
    s.add_argument("--url", default="http://localhost:8082", help="gateway address")
    s.set_defaults(fn=cmd_call)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
