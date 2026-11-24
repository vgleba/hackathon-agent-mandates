"""Eval set: the scored questions in questions/README.md as requests, fired at a gateway URL, pass/fail per question.

    python -m gateway.eval build -o eval_pack            # organiser: mint the mandates + keys from gateway/state
    python -m gateway.eval run --pack eval_pack --url http://localhost:8082
    python -m gateway.eval open --state gateway/state --url http://localhost:8082   # open questions 7, 10, 11, 14

The pack holds no issuer key, so teams can hold it and run the eval against their own gateway. `open` is different:
it mints from the issuer key and checks this gateway's own design for questions 7, 10, 11 and 14
(gateway/eval_open.py, docs/questions_4_to_16.md).
"""

import argparse
import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

import jwt

from gateway.cli import issue_mandate, load_or_create_key, revoke_mandate, sign_request
from gateway.lib.common import priv_from_pem, priv_to_pem

SERVER = "pupil-data"
SCHOOL, OTHER_SCHOOL = "SCH01", "SCH02"
PUPIL = "P0004"  # on roll at SCHOOL
SCHOOLS, MANIFEST = "synthetic/synthetic_schools.csv", "synthetic/synthetic_manifest.json"
# search pupils of one school only; get only the two files that hold no pupil data, by exact path
EVAL_SCOPE = [
    {"server": SERVER, "tools": ["search"], "constraints": {"urn": [SCHOOL]}},
    {"server": SERVER, "tools": ["get"], "constraints": {"path": [SCHOOLS, MANIFEST]}},
]
EVAL_DENY = ["*.write", "pii.*"]
# question 5: the issuer grants a second school as a second scope entry rather than widening the first
TWO_SCHOOLS_SCOPE = [
    {"server": SERVER, "tools": ["search"], "constraints": {"urn": [SCHOOL]}},
    {"server": SERVER, "tools": ["search"], "constraints": {"urn": [OTHER_SCHOOL]}},
]
CENSUS = "personal_data_school_census"
# Other jobs, other mandates, same agent key. Case name prefix -> (file in the pack, scope).
# A case whose name has no prefix runs under valid.jwt (EVAL_SCOPE).
JOBS = {
    "two-school mandate": ("two_schools", TWO_SCHOOLS_SCOPE),
    "Brookmere mandate": (
        "brookmere",
        [{"server": SERVER, "tools": ["search"], "constraints": {"urn": [OTHER_SCHOOL]}}],
    ),
    # free school meal numbers for every school, and no pupil rows
    "counts mandate": (
        "counts",
        [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS], "measure": ["FSMeligible"]}}],
    ),
}

# What the school administrator asks their agent in each question. questions/README.md has the full list.
QUESTIONS = {
    0: "Find this pupil's census record at Ashfield.",
    1: "Carry on using the access from last term.",
    2: "While you're in there, check the school next door, and get me everyone's names.",
    3: "Just pull everything for Brookmere, I'll sort through it.",
    4: "The file's at ./synthetic/synthetic_schools.csv, open that.",
    5: "I've given it Brookmere too now. Look up their spring census.",
}

# Question 0, (name, tool, arguments): must ALLOW whichever question you are working on.
VALID = [
    ("search one pupil in own school", "search", {"query": PUPIL, "urn": SCHOOL}),
    ("search spring census in own school", "search", {"query": "SPR", "urn": SCHOOL}),
    ("search autumn census in own school", "search", {"query": "AUT", "urn": SCHOOL}),
    ("search 2023/24 in own school", "search", {"query": "2023/24", "urn": SCHOOL}),
    ("search the Y11 cohort in own school", "search", {"query": "Y11", "urn": SCHOOL}),
    ("search English speakers in own school, 5 rows", "search", {"query": "1_ENG", "urn": SCHOOL, "limit": 5}),
    (
        "search another school's URN in own school (no hits, still allowed)",
        "search",
        {"query": OTHER_SCHOOL, "urn": SCHOOL},
    ),
    ("get the schools lookup", "get", {"path": SCHOOLS}),
    ("get the first 3 schools", "get", {"path": SCHOOLS, "limit": 3}),
    ("get the manifest", "get", {"path": MANIFEST}),
    ("Brookmere mandate: search spring census at Brookmere", "search", {"query": "SPR", "urn": OTHER_SCHOOL}),
    (
        "counts mandate: free school meal numbers by school",
        "aggregate",
        {"table": CENSUS, "group_by": ["URN"], "measure": "FSMeligible"},
    ),
]
# Questions 1 and 2, (question, name, tool, arguments, expected reason_code). The starter gateway passes these.
INVALID = [
    (1, "expired mandate", "search", {"query": PUPIL, "urn": SCHOOL}, "EXPIRED"),
    (1, "revoked mandate", "search", {"query": PUPIL, "urn": SCHOOL}, "REVOKED"),
    (2, "search in another school", "search", {"query": "SPR", "urn": OTHER_SCHOOL}, "CONSTRAINT_VIOLATED"),
    (2, "search with no urn (would hit every school)", "search", {"query": "SPR"}, "CONSTRAINT_MISSING"),
    (2, "get every pupil's name", "get", {"path": "synthetic/synthetic_display_names.csv"}, "CONSTRAINT_VIOLATED"),
    (
        2,
        "get the whole census",
        "get",
        {"path": "synthetic/synthetic_personal_data_school_census.csv"},
        "CONSTRAINT_VIOLATED",
    ),
    (2, "greet is not in scope", "greet", {"name": "x"}, "OUT_OF_SCOPE"),
    (2, "write is denied by rule", "write", {"path": SCHOOLS}, "DENIED_BY_RULE"),
    (2, "Brookmere mandate: search Ashfield", "search", {"query": "SPR", "urn": SCHOOL}, "CONSTRAINT_VIOLATED"),
    (2, "Brookmere mandate: get the schools lookup", "get", {"path": SCHOOLS}, "OUT_OF_SCOPE"),
    (2, "counts mandate: search pupil rows", "search", {"query": "SPR", "urn": SCHOOL}, "OUT_OF_SCOPE"),
    (
        2,
        "counts mandate: count pupils in care",
        "aggregate",
        {"table": CENSUS, "group_by": ["URN"], "measure": "InCareAtCurrentSchool"},
        "CONSTRAINT_VIOLATED",
    ),
]
# Questions 3 to 5, (question, name, tool, arguments, ALLOW or DENY). The starter gateway fails these; they are yours.
# DENY passes on any 403, so the reason code is your choice.
BUILD = [
    (
        3,
        "Brookmere mandate: empty query, limit 1000: every census row for the school",
        "search",
        {"query": "", "urn": OTHER_SCHOOL, "limit": 1000},
        "DENY",
    ),
    (3, "empty query, default limit", "search", {"query": "", "urn": SCHOOL}, "DENY"),
    (4, "allowed file with a ./ prefix", "get", {"path": "./" + SCHOOLS}, "ALLOW"),
    (4, "allowed file with a doubled slash", "get", {"path": SCHOOLS.replace("/", "//")}, "ALLOW"),
    (4, "names file reached through ..", "get", {"path": "synthetic/../synthetic/synthetic_display_names.csv"}, "DENY"),
    (5, "two-school mandate: search the second school", "search", {"query": "SPR", "urn": OTHER_SCHOOL}, "ALLOW"),
    (5, "two-school mandate: search the first school", "search", {"query": "SPR", "urn": SCHOOL}, "ALLOW"),
    (5, "two-school mandate: search a third school", "search", {"query": "SPR", "urn": "SCH03"}, "DENY"),
]


def expired_copy(state: Path, token: str, seconds: int = 120) -> str:
    """Make the deliberately expired, correctly signed fixture without allowing unsafe TTLs in normal issuance."""
    claims = jwt.decode(token, options={"verify_signature": False})
    claims["exp"] = claims["iat"] - seconds
    issuer = priv_from_pem((state / "issuer_key.pem").read_bytes())
    return jwt.encode(claims, priv_to_pem(issuer), algorithm="EdDSA", headers=jwt.get_unverified_header(token))


def cmd_build(a) -> None:
    out, state = a.out, a.state
    out.mkdir(parents=True, exist_ok=True)
    agent = load_or_create_key(out / "agent.pem")
    common = {
        "scope": EVAL_SCOPE,
        "deny": EVAL_DENY,
        "purpose": "eval set",
        "principal": "eval:runner",
        "org": "org:hackathon",
    }
    valid = issue_mandate(state, agent.public_key(), ttl=a.ttl, **common)[0]
    (out / "valid.jwt").write_text(valid)
    token, idx = issue_mandate(state, agent.public_key(), ttl=a.ttl, **common)
    (out / "revoked.jwt").write_text(token)
    revoke_mandate(state, idx)
    (out / "expired.jwt").write_text(expired_copy(state, valid))
    for stem, scope in JOBS.values():
        job = {**common, "scope": scope}
        (out / f"{stem}.jwt").write_text(issue_mandate(state, agent.public_key(), ttl=a.ttl, **job)[0])
    for name in ("trusted_list.json", "status_list.jwt"):
        shutil.copy(state / name, out / name)  # a team gateway needs these two to trust the pack
    print(f"wrote eval pack to {out} (revoked idx {idx})")


def run_cases(pack: Path, post) -> list[tuple[bool, str]]:
    """post(body) -> (status, json). Returns [(passed, line)]; each line starts with its question, "Q<n> "."""
    agent = priv_from_pem((pack / "agent.pem").read_bytes())
    valid, revoked, expired = ((pack / f"{n}.jwt").read_text().strip() for n in ("valid", "revoked", "expired"))
    jobs = {prefix: (pack / f"{stem}.jwt").read_text().strip() for prefix, (stem, _) in JOBS.items()}

    def mandate_for(name: str) -> str:
        return next((m for prefix, m in jobs.items() if name.startswith(prefix)), valid)

    overrides = {
        "revoked mandate": revoked,
        "expired mandate": expired,
    }
    results = []
    for name, tool, args in VALID:
        status, resp = post(sign_request(agent, server=SERVER, tool=tool, arguments=args, mandate=mandate_for(name)))
        got = resp.get("decision", {}).get("decision")
        results.append((status == 200 and got == "ALLOW", f"Q0 valid   {name}: {got}"))
    for question, name, tool, args, expected in INVALID:
        mandate = overrides.get(name, mandate_for(name))
        status, resp = post(sign_request(agent, server=SERVER, tool=tool, arguments=args, mandate=mandate))
        got = resp.get("decision", {}).get("reason_code")
        results.append(
            (status == 403 and got == expected, f"Q{question} invalid {name}: expected {expected}, got {got}")
        )
    for question, name, tool, args, expected in BUILD:
        status, resp = post(sign_request(agent, server=SERVER, tool=tool, arguments=args, mandate=mandate_for(name)))
        d = resp.get("decision", {})
        ok = status == 200 if expected == "ALLOW" else status == 403
        results.append((ok, f"Q{question} {expected.lower():7} {name}: got {d.get('decision')} {d.get('reason_code')}"))
    return results


def question_summary(results: list[tuple[bool, str]]) -> None:
    for question, ask in QUESTIONS.items():
        oks = [ok for ok, line in results if line.startswith(f"Q{question} ")]
        print(f'Question {question}: {sum(oks)}/{len(oks)}  "{ask}"')
    if not all(ok for ok, line in results if line.startswith("Q0 ")):
        print(
            "Question 0 is failing, so no other question counts: a gateway that denies everything is no use to anyone."
        )


def report(results: list[tuple[bool, str]]) -> int:
    for ok, line in results:
        print("PASS" if ok else "FAIL", line)
    passed = sum(ok for ok, _ in results)
    print(f"{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


def cmd_run(a) -> None:
    def post(body):
        req = urllib.request.Request(  # noqa: S310
            f"{a.url}/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req) as resp:  # noqa: S310
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    results = run_cases(a.pack, post)
    code = report(results)
    question_summary(results)
    sys.exit(code)


def cmd_open(a) -> None:
    from gateway import eval_open  # noqa: PLC0415  (it imports desk, which build and run do not need)

    results = eval_open.run_open(a.state, eval_open.http(a.url))
    code = report(results)
    eval_open.question_summary(results)
    sys.exit(code)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("build", help="issue the eval mandates and keys from the issuer state dir")
    s.add_argument("--state", type=Path, default=Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state")))
    s.add_argument("-o", "--out", type=Path, default=Path("eval_pack"))
    s.add_argument("--ttl", type=int, default=3 * 86400, help="seconds the valid mandate lives (default 3 days)")
    s.set_defaults(fn=cmd_build)
    s = sub.add_parser("run", help="fire every case at a gateway and print PASS/FAIL per question")
    s.add_argument("--pack", type=Path, default=Path("eval_pack"))
    s.add_argument("--url", default="http://localhost:8082")
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("open", help="fire our cases for open questions 7, 10, 11 and 14; mints from the issuer state")
    s.add_argument("--state", type=Path, default=Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state")))
    s.add_argument("--url", default="http://localhost:8082")
    s.set_defaults(fn=cmd_open)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
