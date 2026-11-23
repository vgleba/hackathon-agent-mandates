"""Question 14: what did it see? And the memory every other check relies on."""

import json

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway.lib import record
from gateway.lib.common import priv_from_pem

from .conftest import JSMITH, entry

SEARCH = entry("search", urn=["SCH01"])


def pub(world):
    return priv_from_pem((world.state / "gateway_key.pem").read_bytes()).public_key()


def check(world, anchor=None):
    return record.check(world.state / "record.jsonl", pub(world), anchor)


def some_calls(world, n=5):
    m = world.mandate(SEARCH)
    for _ in range(n):
        world.call("search", m, query="P0004", urn="SCH01")


# ------------------------------------------------------------ what goes in


def test_an_allowed_call_records_whose_data_and_what_kind(world):
    m = world.mandate(SEARCH)
    assert world.call("search", m, query="P0004", urn="SCH01")[0] == 200
    e = world.entries()[-1]
    assert (e["decision"], e["reason"], e["principal"]) == ("ALLOW", "IN_SCOPE", JSMITH)
    assert e["pupils"] == ["P0004"]
    assert "FSMeligible" in e["columns"]
    assert e["rows"] == 5
    assert e["tool"] == "pupil-data.search"


def test_values_are_never_recorded(world):
    m = world.mandate(SEARCH)
    _, resp = world.call("search", m, query="P0004", urn="SCH01")
    text = (world.state / "record.jsonl").read_text()
    shown = {v for row in resp["result"] for k, v in row.items() if k in {"Language", "Gender"}}
    assert shown
    assert not any(f'"{v}"' in text for v in shown)


def test_a_refusal_is_recorded_too(world):
    m = world.mandate(SEARCH)
    world.call("search", m, query="SPR", urn="SCH02")
    e = world.entries()[-1]
    assert (e["decision"], e["reason"], e["pupils"]) == ("DENY", "CONSTRAINT_VIOLATED", [])


def test_free_text_and_new_values_are_redacted(world):
    m = world.mandate(entry("write", urn=["SCH01"]), clearance=4)
    world.call(
        "write", m, pupil_id="P0004", urn="SCH01", column="Ethnicity", value="SECRETVALUE", reason="PRIVATEREASON"
    )
    text = (world.state / "record.jsonl").read_text()
    assert "SECRETVALUE" not in text
    assert "PRIVATEREASON" not in text
    assert "Ethnicity" in text


def test_long_arguments_are_cut(world):
    m = world.mandate(SEARCH)
    world.call("search", m, query="x" * 50_000, urn="SCH01")
    assert len((world.state / "record.jsonl").read_text()) < 10_000


def test_nothing_is_kept_from_a_request_with_no_genuine_mandate(world):
    body = world.sign("search", "not-a-mandate", query="PLANTED", urn="SCH01")
    world.post({**body, "tool": "PLANTEDTOOL"})
    e = world.entries()[-1]
    assert e["principal"] == "unattributed"
    assert "PLANTED" not in json.dumps(e)


def test_junk_cannot_fill_the_disk(world):
    for i in range(300):
        world.post({**world.sign("search", "junk"), "nonce": str(i)})
    assert len(world.entries()) < 120


# ------------------------------------------------------------ whose record it is


def test_wrong_key_expired_and_revoked_use_is_tied_to_the_person(world):
    m, idx = world.issue(SEARCH)
    old = world.mandate(SEARCH, ttl=-120)
    thief = world.new_key()
    assert world.reason("search", m, key=thief, query="P0004", urn="SCH01") == "POP_FAILED"
    assert world.reason("search", old, query="P0004", urn="SCH01") == "EXPIRED"
    cli.revoke_mandate(world.state, idx)
    assert world.reason("search", m, query="P0004", urn="SCH01") == "REVOKED"
    assert [(e["reason"], e["principal"]) for e in world.entries()] == [
        ("POP_FAILED", JSMITH),
        ("EXPIRED", JSMITH),
        ("REVOKED", JSMITH),
    ]


def test_an_edited_mandate_is_not_tied_to_anyone(world):
    h, p, s = world.mandate(SEARCH).split(".")
    claims = json.loads(cli.b64u_decode(p))
    claims["delegator"]["principal"] = "officer:victim"
    forged = ".".join([h, cli.b64u(json.dumps(claims).encode()), s])
    assert world.reason("search", forged, query="P0004", urn="SCH01") == "SIG_INVALID"
    assert world.entries()[-1]["principal"] == "unattributed"


# ------------------------------------------------------------ recorded before release


def test_if_the_record_cannot_be_written_nothing_is_released(world, monkeypatch):
    m = world.mandate(SEARCH)

    def broken(*_a, **_k):
        raise OSError

    monkeypatch.setattr(main.state["record"], "append", broken)
    status, resp = world.call("search", m, query="P0004", urn="SCH01")
    assert status == 403
    assert "result" not in resp


# ------------------------------------------------------------ noticing changes


def test_an_untouched_record_checks_out(world):
    some_calls(world)
    assert check(world) == "ok"


@pytest.mark.parametrize("field", ["decision", "pupils", "principal", "ts"])
def test_editing_an_entry_is_noticed(world, field):
    some_calls(world)
    path = world.state / "record.jsonl"
    lines = path.read_text().splitlines()
    e = json.loads(lines[2])
    e[field] = "changed"
    path.write_text("\n".join([*lines[:2], json.dumps(e), *lines[3:]]) + "\n")
    assert check(world) == "broken at entry 3"


def test_deleting_from_the_middle_is_noticed(world):
    some_calls(world)
    path = world.state / "record.jsonl"
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    assert check(world).startswith("broken at entry")


def test_a_genuine_entry_from_another_record_does_not_fit(world, tmp_path):
    # signed by the same gateway and with the right number: only the chain shows it does not belong here
    key = priv_from_pem((world.state / "gateway_key.pem").read_bytes())
    other = record.Record(tmp_path / "other.jsonl", key)
    for _ in range(4):
        other.append(decision="DENY", reason="NOTHING", principal=JSMITH)
    some_calls(world)
    path = world.state / "record.jsonl"
    lines, spare = path.read_text().splitlines(), (tmp_path / "other.jsonl").read_text().splitlines()
    path.write_text("\n".join([*lines[:2], spare[2], *lines[3:]]) + "\n")
    assert check(world) == "broken at entry 3"


def test_cutting_off_the_end_needs_the_anchor(world):
    some_calls(world, 6)
    last = world.entries()[-1]
    path = world.state / "record.jsonl"
    path.write_text("\n".join(path.read_text().splitlines()[:4]) + "\n")
    assert check(world) == "ok"  # nothing inside the file can show that its end is missing
    assert check(world, (last["seq"], last["hash"])) == "entry 6 is missing or was replaced"


def test_rewriting_the_record_with_another_key_is_noticed(world):
    some_calls(world)
    path = world.state / "record.jsonl"
    entries = world.entries()
    path.unlink()
    forger = record.Record(path, world.new_key())
    for e in entries:
        forger.append(**{k: v for k, v in e.items() if k not in {"seq", "prev", "ts", "hash", "sig"}})
    assert check(world) == "broken at entry 1"


def test_the_gateway_will_not_start_on_a_broken_record(world):
    some_calls(world)
    path = world.state / "record.jsonl"
    path.write_text(path.read_text().replace("ALLOW", "DENY", 1))
    with pytest.raises(RuntimeError, match="record"):
        main.load_state(world.state)


# ------------------------------------------------------------ memory that survives a restart


def test_a_captured_request_is_still_a_replay_after_a_restart(world):
    body = world.sign("search", world.mandate(SEARCH), query="P0004", urn="SCH01")
    assert world.post(body)[0] == 200
    with TestClient(main.app, raise_server_exceptions=False) as restarted:
        r = restarted.post("/tools/call", json=body)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "POP_FAILED")


def test_one_agents_nonce_does_not_block_anothers(world):
    other = world.new_key()
    a = cli.sign_request(world.key, server="pupil-data", tool="search", arguments={}, mandate=world.mandate(SEARCH))
    m = world.mandate(SEARCH, key=other)
    req = main.Request(
        server="pupil-data",
        tool="search",
        arguments={"query": "P0004", "urn": "SCH01"},
        mandate=m,
        nonce=a["nonce"],
        ts=a["ts"],
        sig="",
    )
    req.sig = cli.sign_bytes(other, req.signing_input())
    world.post(a)
    assert world.post(req.__dict__)[0] == 200


# ------------------------------------------------------------ in plain words


def test_summary_reads_like_a_sentence(world):
    some_calls(world, 3)
    levels = dict.fromkeys(world.entries()[-1]["columns"], 2) | {"Ethnicity": 4}
    s = record.summary(world.entries(), JSMITH, levels)
    assert s["requests"] == 3
    assert s["pupils"] == ["P0004"]
    assert s["special"] == (["Ethnicity"] if "Ethnicity" in s["columns"] else [])
    assert "NewColumn" in record.summary([{**world.entries()[-1], "columns": ["NewColumn"]}], JSMITH, levels)["special"]
