# ruff: noqa: C901
"""Mandate-aware flag detection and Day 2 score calculation."""

from __future__ import annotations

import fnmatch
import json
import re
import time
from typing import TYPE_CHECKING, Any

from .config import decode_jwt_unverified

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .config import MandateConfig
    from .probes import Probe

PUPIL_ID = re.compile(r"\bP\d{4}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")
ID_KEYS = ("Psuedo ID", "Pseudo ID", "pupil_id", "pupilId")
NO_KEY_MUTATIONS = {"bad_signature", "missing_signature", "stale_timestamp", "future_timestamp"}
FORGED_MUTATIONS = {"tampered_mandate", "alg_none_mandate"}
REPLAY_ATTEMPT = 2
HTTP_SERVER_ERROR = 500
BULK_THRESHOLD = 100

DATA_FLAGS = {
    "level_2": {"level": 2, "points": 10, "label": "P0011 basic PII"},
    "level_3": {"level": 3, "points": 20, "label": "P0011 sensitive census row"},
    "level_4": {"level": 4, "points": 40, "label": "P0011 special-category data"},
    "named_level_4": {"level": 4, "points": 60, "label": "P0586 in-care fact tied to Mason Owusu"},
}

BREAK_POINTS = {"keys": 50, "forged_mandate": 30, "dead_mandate": 15, "no_key": 15, "bulk": 10, "crash": 5}


def _walk(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _rows(value: Any) -> Iterable[dict[str, Any]]:
    for item in _walk(value):
        if isinstance(item, dict):
            yield item


def _row_id(row: dict[str, Any]) -> str | None:
    return next((str(row[key]) for key in ID_KEYS if key in row), None)


def _facts_for_row(row: dict[str, Any]) -> set[str]:
    facts: set[str] = set()
    pupil = _row_id(row)
    if pupil == "P0011":
        if row.get("DisplayName") == "Zara Okafor" or str(row.get("DeprivationScore")) == "0.2505":
            facts.add("level_2")
        census_shape = any(key in row for key in ("FSMeligible", "CensusTerm", "AcademicYear", "Ethnicity"))
        if "FSMeligible" in row or (census_shape and str(row.get("URN")) == "SCH04"):
            facts.add("level_3")
        if str(row.get("Ethnicity")) == "ASIA" or "InCareAtCurrentSchool" in row:
            facts.add("level_4")
    if pupil == "P0586":
        if row.get("DisplayName") == "Mason Owusu" or "Mason Owusu" in str(row.get("letter", "")):
            facts.add("p0586_name")
        if str(row.get("InCareAtCurrentSchool")) == "1":
            facts.add("p0586_in_care")
    return facts


def detect_facts(result: Any) -> set[str]:
    """Find exact scoring facts while keeping pupil/value relationships intact."""
    facts: set[str] = set()
    compact = json.dumps(result, sort_keys=True, ensure_ascii=False, default=str)
    if "Dunmore Community College" in compact:
        facts.add("level_1_control")
    if "Zara Okafor" in compact or "0.2505" in compact:
        facts.add("level_2")
    if "Mason Owusu" in compact:
        facts.add("p0586_name")
    for row in _rows(result):
        facts.update(_facts_for_row(row))
    return facts


def extract_pupil_ids(result: Any) -> set[str]:
    return set(PUPIL_ID.findall(json.dumps(result, ensure_ascii=False, default=str)))


def observed_decision(response: dict[str, Any]) -> tuple[bool, str | None, str | None]:
    body = response.get("json")
    decision, reason = None, None
    if isinstance(body, dict):
        decision_value = body.get("decision")
        if isinstance(decision_value, dict):
            decision = decision_value.get("decision")
            reason = decision_value.get("reason_code")
        elif isinstance(decision_value, str):
            decision = decision_value
            reason = body.get("reason_code")
    allowed = response.get("status") == 200 and decision == "ALLOW"  # noqa: PLR2004
    return allowed, decision, reason


def _permits(value: Any, allowed: list[Any]) -> bool:
    scalar = {str(item) for item in allowed if not isinstance(item, (list, dict))}
    if isinstance(value, list):
        if any(isinstance(item, list) and item == value for item in allowed):
            return True
        return bool(value) and all(not isinstance(item, (list, dict, bool)) and str(item) in scalar for item in value)
    if isinstance(value, dict):
        return any(isinstance(item, dict) and item == value for item in allowed)
    return str(value) in scalar


def _claim_chain(claims: dict[str, Any]) -> list[dict[str, Any]]:
    chain = [claims]
    current = claims
    for _ in range(8):
        parent = current.get("parent")
        if not isinstance(parent, str):
            break
        try:
            current = decode_jwt_unverified(parent)
        except ValueError:
            break
        chain.append(current)
    return chain


def _scope_allows(probe: Probe, claims: dict[str, Any]) -> bool | None:
    chain = _claim_chain(claims)
    name = f"pupil-data.{probe.tool}"
    if any(
        fnmatch.fnmatch(name, pattern) for item in chain for pattern in item.get("deny", []) if isinstance(pattern, str)
    ):
        return False
    found_scope = False
    for item in chain:
        scope = item.get("scope")
        if not isinstance(scope, list):
            return None
        found_scope = True
        scope_match = False
        for entry in scope:
            if (
                not isinstance(entry, dict)
                or entry.get("server") != "pupil-data"
                or probe.tool not in entry.get("tools", [])
            ):
                continue
            constraints = entry.get("constraints", {})
            if not isinstance(constraints, dict):
                continue
            if all(
                key in probe.arguments and isinstance(allowed, list) and _permits(probe.arguments[key], allowed)
                for key, allowed in constraints.items()
            ):
                cap = entry.get("max_rows")
                if isinstance(cap, int) and probe.arguments.get("limit", cap) > cap:
                    continue
                scope_match = True
                break
        if not scope_match:
            return False
    return True if found_scope else None


def expectation_for(probe: Probe, mandate: MandateConfig, attempt: int) -> tuple[str, str]:
    """Combine explicit defender-note expectations with the JWT's visible scope."""
    if probe.id in mandate.expectations.allow:
        return "allow", "config override"
    if probe.id in mandate.expectations.deny:
        return "deny", "config override"
    if probe.mutation == "replay" and attempt == 1:
        allowed = _scope_allows(probe, mandate.claims)
        return ("allow" if allowed else "deny" if allowed is False else "unknown"), "JWT scope (replay control)"
    if probe.mutation != "normal":
        return "deny", "protocol invariant"
    allowed = _scope_allows(probe, mandate.claims)
    if allowed is None:
        return "unknown", "could not infer from JWT scope"
    return ("allow" if allowed else "deny"), "JWT scope"


def _finding(
    finding_id: str,
    title: str,
    points: int,
    evidence: list[str],
    detail: str,
    *,
    kind: str,
    mandate_kind: str | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "kind": kind,
        "title": title,
        "points": points,
        "mandate_kind": mandate_kind,
        "evidence": sorted(set(evidence)),
        "detail": detail,
    }


def _annotate_observations(
    observations: list[dict[str, Any]], mandates: dict[str, MandateConfig]
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
    dict[str, list[str]],
]:
    eligible_by_mandate: dict[str, list[dict[str, Any]]] = {kind: [] for kind in mandates}
    allowed_by_mandate: dict[str, list[dict[str, Any]]] = {kind: [] for kind in mandates}
    scope_escape_evidence: dict[str, list[str]] = {kind: [] for kind in mandates}
    for observation in observations:
        response = observation["response"]
        allowed, decision, reason = observed_decision(response)
        body = response.get("json")
        result = body.get("result") if isinstance(body, dict) else None
        facts = detect_facts(result) if allowed else set()
        pupil_ids = extract_pupil_ids(result) if allowed else set()
        observation["analysis"] = {
            "allowed": allowed,
            "decision": decision,
            "reason_code": reason,
            "facts": sorted(facts),
            "pupil_ids": sorted(pupil_ids),
        }
        if allowed:
            kind = observation["mandate_kind"]
            allowed_by_mandate[kind].append(observation)
            if observation["expectation"]["outcome"] == "deny":
                eligible_by_mandate[kind].append(observation)
                scope_escape_evidence[kind].append(observation["id"])
    return eligible_by_mandate, allowed_by_mandate, scope_escape_evidence


def _data_candidates(
    eligible: list[dict[str, Any]], all_allowed: list[dict[str, Any]]
) -> list[tuple[int, str, list[str]]]:
    candidates: list[tuple[int, str, list[str]]] = []
    for flag_id in ("level_2", "level_3", "level_4"):
        evidence = [item["id"] for item in eligible if flag_id in item["analysis"]["facts"]]
        if evidence:
            candidates.append((DATA_FLAGS[flag_id]["points"], flag_id, evidence))
    name_evidence = [item["id"] for item in all_allowed if "p0586_name" in item["analysis"]["facts"]]
    care_evidence = [item["id"] for item in all_allowed if "p0586_in_care" in item["analysis"]["facts"]]
    outside_component = any(
        item["expectation"]["outcome"] == "deny"
        and {"p0586_name", "p0586_in_care"}.intersection(item["analysis"]["facts"])
        for item in all_allowed
    )
    if name_evidence and care_evidence and outside_component:
        candidates.append((DATA_FLAGS["named_level_4"]["points"], "named_level_4", name_evidence + care_evidence))
    return candidates


def _score_data(
    mandates: dict[str, MandateConfig],
    eligible_by_mandate: dict[str, list[dict[str, Any]]],
    allowed_by_mandate: dict[str, list[dict[str, Any]]],
    scope_escape_evidence: dict[str, list[str]],
    findings: list[dict[str, Any]],
) -> dict[str, int]:
    data_scores: dict[str, int] = {}
    for kind in mandates:
        candidates = _data_candidates(eligible_by_mandate[kind], allowed_by_mandate[kind])
        if candidates:
            points, flag_id, evidence = max(candidates, key=lambda item: item[0])
            flag = DATA_FLAGS[flag_id]
            findings.append(
                _finding(
                    f"data:{kind}:{flag_id}",
                    flag["label"],
                    points,
                    evidence,
                    "Highest out-of-mandate data flag observed for this mandate.",
                    kind="data",
                    mandate_kind=kind,
                )
            )
            data_scores[kind] = points
        else:
            data_scores[kind] = 0
        if scope_escape_evidence[kind] and not candidates:
            findings.append(
                _finding(
                    f"scope:{kind}",
                    f"Unexpected ALLOW under {kind} mandate",
                    0,
                    scope_escape_evidence[kind],
                    "The gateway allowed a request inferred or configured to be outside this mandate, "
                    "but no scoring flag was detected.",
                    kind="scope",
                    mandate_kind=kind,
                )
            )
    return data_scores


def _collect_break_evidence(
    observations: list[dict[str, Any]], mandates: dict[str, MandateConfig]
) -> tuple[dict[str, list[str]], int]:
    break_evidence: dict[str, list[str]] = {key: [] for key in BREAK_POINTS}
    bulk_ids: set[str] = set()
    bulk_evidence: list[str] = []
    now = time.time()
    for observation in observations:
        response = observation["response"]
        analysis = observation["analysis"]
        allowed = analysis["allowed"]
        mutation = observation["probe"]["mutation"]
        if response.get("status") == HTTP_SERVER_ERROR:
            break_evidence["crash"].append(observation["id"])
        if PRIVATE_KEY.search(response.get("text") or ""):
            break_evidence["keys"].append(observation["id"])
        if allowed and mutation in FORGED_MUTATIONS:
            break_evidence["forged_mandate"].append(observation["id"])
        replayed = mutation == "replay" and observation["attempt"] == REPLAY_ATTEMPT
        if allowed and (mutation in NO_KEY_MUTATIONS or replayed):
            break_evidence["no_key"].append(observation["id"])
        if allowed:
            mandate = mandates[observation["mandate_kind"]]
            expired = isinstance(mandate.claims.get("exp"), (int, float)) and mandate.claims["exp"] <= now
            if mandate.known_revoked or expired:
                break_evidence["dead_mandate"].append(observation["id"])
        if allowed and observation["expectation"]["outcome"] == "deny":
            new_ids = set(analysis["pupil_ids"])
            if new_ids:
                bulk_ids.update(new_ids)
                bulk_evidence.append(observation["id"])
    if len(bulk_ids) > BULK_THRESHOLD:
        break_evidence["bulk"] = bulk_evidence
    return break_evidence, len(bulk_ids)


def _score_breaks(break_evidence: dict[str, list[str]], bulk_count: int, findings: list[dict[str, Any]]) -> int:
    break_titles = {
        "keys": "Issuer private key exposed",
        "forged_mandate": "Forged mandate accepted",
        "dead_mandate": "Expired or known-revoked mandate accepted",
        "no_key": "Proof-of-possession or freshness bypass",
        "bulk": f"Bulk extraction ({bulk_count} distinct pupil IDs)",
        "crash": "Gateway returned HTTP 500",
    }
    break_details = {
        "keys": "A response contained a PEM private-key marker.",
        "forged_mandate": "The gateway returned ALLOW for an issuer payload that the lab altered or left unsigned.",
        "dead_mandate": "The gateway returned ALLOW even though the supplied mandate was expired or marked revoked.",
        "no_key": "The gateway returned ALLOW for a bad, missing, stale, future, or replayed request signature.",
        "bulk": "Allowed out-of-mandate responses contained more than 100 distinct pupil IDs.",
        "crash": "One bounded request produced HTTP 500; no repeated traffic was used.",
    }
    break_score = 0
    for break_id, points in BREAK_POINTS.items():
        if break_evidence[break_id]:
            break_score += points
            findings.append(
                _finding(
                    f"break:{break_id}",
                    break_titles[break_id],
                    points,
                    break_evidence[break_id],
                    break_details[break_id],
                    kind="break",
                )
            )
    return break_score


def _observation_counts(observations: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "requests": len(observations),
        "allowed": sum(item["analysis"]["allowed"] for item in observations),
        "denied": sum(item["analysis"]["decision"] == "DENY" for item in observations),
        "network_errors": sum(bool(item["response"].get("network_error")) for item in observations),
        "http_5xx": sum(
            isinstance(item["response"].get("status"), int) and item["response"]["status"] >= HTTP_SERVER_ERROR
            for item in observations
        ),
    }


def score_target(target_report: dict[str, Any], mandates: dict[str, MandateConfig]) -> None:
    """Annotate observations, build findings, and calculate the official potential score."""
    observations = target_report["observations"]
    findings: list[dict[str, Any]] = []
    eligible, allowed, escapes = _annotate_observations(observations, mandates)
    data_scores = _score_data(mandates, eligible, allowed, escapes, findings)
    break_evidence, bulk_count = _collect_break_evidence(observations, mandates)
    break_score = _score_breaks(break_evidence, bulk_count, findings)
    counts = _observation_counts(observations)
    total = sum(data_scores.values()) + break_score
    target_report["findings"] = sorted(findings, key=lambda item: (-item["points"], item["title"]))
    target_report["summary"] = {
        "data_scores": data_scores,
        "break_score": break_score,
        "potential_score": total,
        "counts": counts,
        "manual_checks": [
            "Unseen bonus requires the five-minute defender record check and is not scored automatically."
        ],
    }
