"""Question 7: can access be handed on narrower, and never wider?"""

import itertools
import json
import time

import jwt
import pytest

from gateway import cli
from gateway.lib.common import priv_to_pem, pub_to_jwk

from .conftest import TERM, entry

ROSTER = entry("roster", urn=["SCH04"], year_group=[10, 11], **TERM)
DRAFT = entry("draft", urn=["SCH04"], kind=["absence"])
CHILD = [entry("roster", urn=["SCH04"], year_group=[11], **TERM)]
YEAR_11 = {"urn": "SCH04", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}


class Pair:
    """A parent agent with two helpers allowed, and a helper with its own key."""

    def __init__(self, world, **claims):
        self.world, self.helper = world, world.new_key()
        claims = {"clearance": 2, "budget": {"pupils": 60}, "purpose_code": "absence_letters", **claims}
        self.parent, self.idx = world.issue(ROSTER, DRAFT, reserve=2, **claims)
        self.claims = jwt.decode(self.parent, options={"verify_signature": False})

    def child(self, scope=None, *, signer=None, headers=None, parent=None, **over):
        claims = {
            "jti": "urn:uuid:child",
            "exp": self.claims["exp"] - 10,
            "cnf": {"jwk": pub_to_jwk(self.helper.public_key())},
            "scope": CHILD if scope is None else scope,
            "helper_idx": self.claims["helpers"][0],
            "parent": parent or self.parent,
            **over,
        }
        claims = {k: v for k, v in claims.items() if v is not ...}
        return jwt.api_jws.encode(
            json.dumps(claims).encode(),
            priv_to_pem(signer or self.world.key),
            algorithm="EdDSA",
            headers={"typ": "mandate-child+jwt", **(headers or {})},
        )

    def call(self, token, tool="roster", **args):
        return self.world.call(tool, token, key=self.helper, **(args or YEAR_11))

    def reason(self, token, tool="roster", **args):
        status, resp = self.call(token, tool, **args)
        return resp["decision"]["reason_code"] if status != 200 else "IN_SCOPE"


@pytest.fixture
def pair(world):
    return Pair(world)


# ------------------------------------------------------------ what works


def test_a_helper_gets_the_year_11_list(pair):
    status, resp = pair.call(pair.child())
    assert status == 200
    assert len(resp["result"]) == 41


def test_the_cli_makes_the_same_thing(pair):
    token = cli.delegate_mandate(pair.parent, pair.world.key, pair.helper.public_key(), scope=CHILD, ttl=300)
    assert pair.reason(token) == "IN_SCOPE"


def test_the_helper_cannot_use_what_was_not_handed_on(pair):
    assert pair.reason(pair.child(), "draft", urn="SCH04", pupil_ids=["P1017"], kind="absence") == "OUT_OF_SCOPE"
    assert pair.reason(pair.child(), **{**YEAR_11, "year_group": 10}) == "CONSTRAINT_VIOLATED"


def test_only_the_helpers_key_works_with_it(pair):
    assert pair.world.reason("roster", pair.child(), **YEAR_11) == "POP_FAILED"  # the parent's own key


# ------------------------------------------------------------ never wider

S = "pupil-data"
WIDER = {
    "another school": [entry("roster", urn=["SCH04", "SCH01"], year_group=[11], **TERM)],
    "another year group": [entry("roster", urn=["SCH04"], year_group=[11, 12], **TERM)],
    "another academic year": [entry("roster", urn=["SCH04"], year_group=[11], academic_year=["2021/22"], term=["SPR"])],
    "another tool": [entry("roster", "pupil", urn=["SCH04"], year_group=[11], **TERM)],
    "a limit left out": [entry("roster", urn=["SCH04"], **TERM)],
    "every limit left out": [entry("roster")],
    "no constraints key": [{"server": S, "tools": ["roster"]}],
    "another server": [{**CHILD[0], "server": "gateway"}],
    "an extra field in an entry": [{**CHILD[0], "extra": True}],
    "one narrow entry and one wide": [CHILD[0], entry("search")],
    "mixing two parent entries": [entry("roster", "draft", urn=["SCH04"], kind=["absence"])],
    "a limit that is text, not a list": [entry("roster", urn="SCH04", year_group=[11], **TERM)],
    "a limit that is an object": [entry("roster", urn={"SCH04": 1}, year_group=[11], **TERM)],
    "tools as text": [{**CHILD[0], "tools": "roster"}],
    "a wildcard": [entry("*", urn=["SCH04"], year_group=[11], **TERM)],
    "no entries": [],
    "not a list": {"server": S},
    "an entry that is not an object": ["roster"],
}


@pytest.mark.parametrize("name", WIDER)
def test_a_wider_scope_is_refused(pair, name):
    assert pair.reason(pair.child(WIDER[name])) in {"CHILD_WIDER", "MALFORMED_REQUEST"}


@pytest.mark.parametrize(
    "claim",
    [
        {"clearance": 4},
        {"clearance": 1},
        {"purpose_code": "safeguarding_review"},
        {"budget": {"pupils": 10_000}},
        {"delegator": {"principal": "eval:runner", "org": "x"}},
        {"may_delegate": 1},
        {"helpers": [0, 1, 2]},
        {"iss": "https://issuer.hack.local"},
        {"status": {"status_list": {"uri": "x", "idx": 0}}},
        {"scopes": [[entry("search")]]},
        {"root": "another-job"},
        {"shown": "x"},
        {"nbf": 0},
    ],
)
def test_a_helper_cannot_set_anything_else(pair, claim):
    assert pair.reason(pair.child(**claim)) == "CHILD_WIDER"


def test_a_helper_cannot_outlive_its_parent(pair):
    assert pair.reason(pair.child(exp=pair.claims["exp"] + 1)) == "CHILD_WIDER"
    assert pair.reason(pair.child(exp=int(time.time()) - 120)) == "EXPIRED"


@pytest.mark.parametrize("exp", [None, "soon", True, 1e300, ...])
def test_a_helper_needs_a_proper_expiry(pair, exp):
    assert pair.call(pair.child(exp=exp))[0] == 403


def test_a_helper_inherits_the_parents_deny_rules(world):
    pair = Pair(world)
    parent, _ = world.issue(ROSTER, DRAFT, reserve=1, deny=["*.roster"], clearance=2)
    idx = jwt.decode(parent, options={"verify_signature": False})["helpers"][0]
    assert pair.reason(pair.child(parent=parent, helper_idx=idx, deny=[])) == "DENIED_BY_RULE"


def test_a_helper_can_add_its_own_deny_rules(pair):
    assert pair.reason(pair.child(deny=["*.roster"])) == "DENIED_BY_RULE"


def test_both_scopes_are_enforced_even_if_the_narrower_check_had_a_hole(pair, monkeypatch):
    from gateway.lib import delegation  # noqa: PLC0415

    monkeypatch.setattr(delegation, "narrower", lambda *_: True)
    wide = pair.child([entry("roster", "search", "pupil")])
    assert pair.reason(wide, **{**YEAR_11, "urn": "SCH01"}) == "CONSTRAINT_VIOLATED"
    assert pair.reason(wide, "search", query="SPR", urn="SCH04") == "OUT_OF_SCOPE"


# ------------------------------------------------------------ where it came from


def test_only_the_parents_own_key_can_make_a_helper(pair):
    assert pair.reason(pair.child(signer=pair.helper)) == "CHILD_SIG_INVALID"
    assert pair.reason(pair.child(signer=pair.world.new_key())) == "CHILD_SIG_INVALID"


def test_a_parent_the_issuer_never_signed_is_no_parent(pair):
    h, p, s = pair.parent.split(".")
    claims = json.loads(cli.b64u_decode(p))
    claims["scope"] = [entry("search", "pupil")]
    forged = ".".join([h, cli.b64u(json.dumps(claims).encode()), s])
    assert pair.reason(pair.child([entry("search")], parent=forged)) == "SIG_INVALID"


def test_another_agents_mandate_cannot_be_the_parent(pair):
    other = pair.world.new_key()
    parent = pair.world.mandate(entry("search", urn=["SCH01"]), key=other, reserve=1)
    assert (
        pair.call(pair.child([entry("search", urn=["SCH01"])], parent=parent), "search", query="SPR", urn="SCH01")[0]
        == 403
    )


def test_a_parent_must_have_been_allowed_to_hand_on(pair):
    plain = pair.world.mandate(ROSTER, DRAFT, clearance=2)
    assert pair.reason(pair.child(parent=plain)) == "DELEGATION_NOT_ALLOWED"


@pytest.mark.parametrize(
    "claims",
    [
        {"may_delegate": 0, "helpers": [9]},
        {"may_delegate": True, "helpers": [9]},
        {"may_delegate": "1", "helpers": [9]},
        {"may_delegate": 1},
        {"may_delegate": 1, "helpers": []},
        {"may_delegate": 1, "helpers": 9},
        {"helpers": [9]},
    ],
)
def test_half_a_permission_is_none(pair, claims):
    parent = pair.world.mandate(ROSTER, clearance=2, **claims)
    assert pair.reason(pair.child(parent=parent, helper_idx=9)) == "DELEGATION_NOT_ALLOWED"


def test_a_helper_cannot_make_helpers(pair):
    grandchild_key = pair.world.new_key()
    child = pair.child()
    token = pair.child(parent=child, signer=pair.helper, cnf={"jwk": pub_to_jwk(grandchild_key.public_key())})
    status, resp = pair.world.call("roster", token, key=grandchild_key, **YEAR_11)
    assert (status, resp["decision"]["reason_code"]) == (403, "DELEGATION_NOT_ALLOWED")


def test_a_very_deep_chain_is_refused_quickly(pair):
    token = pair.parent
    for _ in range(12):
        token = pair.child(parent=token)
    start = time.time()
    assert pair.call(token)[0] in {403, 422}  # the HTTP field cap may refuse it before JWT decoding
    assert time.time() - start < 2


@pytest.mark.parametrize("parent", ["", "x", "a.b.c", 5, None, [], {}])
def test_a_parent_that_is_not_a_mandate(pair, parent):
    token = pair.child()
    claims = jwt.decode(token, options={"verify_signature": False})
    claims["parent"] = parent
    token = jwt.api_jws.encode(
        json.dumps(claims).encode(),
        priv_to_pem(pair.world.key),
        algorithm="EdDSA",
        headers={"typ": "mandate-child+jwt"},
    )
    assert pair.call(token)[0] == 403


# ------------------------------------------------------------ taking it back


def test_revoking_the_parent_stops_the_helper(pair):
    token = pair.child()
    assert pair.reason(token) == "IN_SCOPE"
    cli.revoke_mandate(pair.world.state, pair.idx)
    assert pair.reason(token) == "REVOKED"


def test_one_helper_can_be_stopped_alone(pair):
    first, second = pair.child(), pair.child(helper_idx=pair.claims["helpers"][1])
    cli.revoke_mandate(pair.world.state, pair.claims["helpers"][0])
    assert pair.reason(first) == "REVOKED"
    assert pair.reason(second) == "IN_SCOPE"
    assert pair.world.call("roster", pair.parent, **YEAR_11)[0] == 200


def test_one_reserved_slot_cannot_be_reused_for_another_child(pair):
    assert pair.reason(pair.child()) == "IN_SCOPE"
    other = pair.world.new_key()
    second = pair.child(jti="urn:uuid:another-child", cnf={"jwk": pub_to_jwk(other.public_key())})
    status, reply = pair.world.call("roster", second, key=other, **YEAR_11)
    assert (status, reply["decision"]["reason_code"]) == (403, "DELEGATION_NOT_ALLOWED")


@pytest.mark.parametrize("idx", [0, 999, -1, None, "3", True, [0], ...])
def test_a_helper_must_use_a_number_the_person_set_aside(pair, idx):
    # otherwise a helper could pick a number nobody will ever revoke
    if idx == 0:
        idx = pair.idx  # its parent's own
    assert pair.call(pair.child(helper_idx=idx))[0] == 403


# ------------------------------------------------------------ everything else still applies


def test_a_helper_spends_its_parents_budget(world):
    pair = Pair(world, budget={"pupils": 41})
    assert pair.reason(pair.child()) == "IN_SCOPE"
    assert world.reason("roster", pair.parent, **{**YEAR_11, "year_group": 11}) == "IN_SCOPE"
    parent, _ = world.issue(entry("search", urn=["SCH04"]), reserve=1, budget={"pupils": 2})
    idx = jwt.decode(parent, options={"verify_signature": False})["helpers"][0]
    token = pair.child([entry("search", urn=["SCH04"])], parent=parent, helper_idx=idx)
    assert world.call("search", parent, query="P1017", urn="SCH04")[0] == 200
    assert pair.call(token, "search", query="P1018", urn="SCH04")[0] == 200
    assert pair.reason(token, "search", query="P1019", urn="SCH04") == "BUDGET_EXCEEDED"
    assert world.reason("search", parent, query="P1020", urn="SCH04") == "BUDGET_EXCEEDED"


def test_a_helper_is_recorded_under_the_person_and_the_job(pair):
    pair.call(pair.child())
    e = pair.world.entries()[-1]
    assert e["principal"] == "officer:jsmith"
    assert e["root"] == pair.claims["jti"]
    assert e["agent_id"] != pair.claims["agent_id"]


def test_the_purpose_and_person_still_apply_to_a_helper(pair):
    pair.world.person("officer:jsmith", status="left")
    assert pair.reason(pair.child()) == "PERSON_PAUSED"


def test_no_helper_reaches_data_its_parent_cannot(pair):
    """Every combination of school, year and tool, through many shapes of child: never more than the parent gets."""
    shapes = [CHILD, *[w for w in WIDER.values() if isinstance(w, list)]]
    for shape, urn, year in itertools.product(shapes, ("SCH01", "SCH04"), (10, 11)):
        args = {**YEAR_11, "urn": urn, "year_group": year}
        status, _ = pair.call(pair.child(shape), **args)
        if status == 200:
            assert pair.world.call("roster", pair.parent, **args)[0] == 200, (shape, args)
