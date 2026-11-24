"""Sequential, bounded execution of attack-lab probes."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gateway.lib.common import priv_from_pem

from . import SCHEMA_VERSION, VERSION
from .probes import PROBES_BY_ID, Probe, select_probes
from .scoring import expectation_for, observed_decision, score_target
from .wire import WireResponse, build_request_bodies, post_gateway

if TYPE_CHECKING:
    from .config import LabConfig, MandateConfig, TargetConfig

Progress = Callable[[dict[str, Any]], None]


def _iso_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _mandate_metadata(mandate: MandateConfig) -> dict[str, Any]:
    claims = mandate.claims
    source = "inline" if mandate.source == "inline" else Path(mandate.source).name
    return {
        "source": source,
        "note": mandate.note,
        "known_revoked": mandate.known_revoked,
        "token_sha256": hashlib.sha256(mandate.token.encode()).hexdigest(),
        "claims": claims,
        "expect": {
            "allow": sorted(mandate.expectations.allow),
            "deny": sorted(mandate.expectations.deny),
        },
    }


def _probe_metadata(probe: Probe) -> dict[str, Any]:
    return {
        "id": probe.id,
        "title": probe.title,
        "category": probe.category,
        "description": probe.description,
        "mutation": probe.mutation,
        "score_hint": probe.score_hint,
    }


def _planned_response() -> dict[str, Any]:
    return {
        "status": None,
        "headers": {},
        "json": None,
        "text": "",
        "elapsed_ms": 0,
        "truncated": False,
        "network_error": None,
        "planned": True,
    }


def _observation(
    target: TargetConfig,
    mandate: MandateConfig,
    probe: Probe,
    body: dict[str, Any],
    *,
    attempt: int,
    response: WireResponse | None,
) -> dict[str, Any]:
    outcome, source = expectation_for(probe, mandate, attempt)
    payload = _planned_response() if response is None else response.to_dict()
    return {
        "id": f"{target.id}:{mandate.kind}:{probe.id}:{attempt}",
        "target_id": target.id,
        "mandate_kind": mandate.kind,
        "probe": _probe_metadata(probe),
        "attempt": attempt,
        "request": body,
        "expectation": {"outcome": outcome, "source": source},
        "response": payload,
    }


def _validate_filters(config: LabConfig, target_ids: set[str] | None, only_probes: set[str] | None) -> None:
    available_targets = {target.id for target in config.targets}
    unknown_targets = (target_ids or set()) - available_targets
    if unknown_targets:
        msg = f"unknown target ids: {', '.join(sorted(unknown_targets))}"
        raise ValueError(msg)
    unknown_probes = (only_probes or set()) - PROBES_BY_ID.keys()
    if unknown_probes:
        msg = f"unknown probe ids: {', '.join(sorted(unknown_probes))}"
        raise ValueError(msg)
    configured_probe_ids = {
        probe_id
        for target in config.targets
        for mandate in target.mandates.values()
        for probe_id in mandate.expectations.allow | mandate.expectations.deny
    }
    unknown_configured = configured_probe_ids - PROBES_BY_ID.keys()
    if unknown_configured:
        msg = f"config expectations name unknown probes: {', '.join(sorted(unknown_configured))}"
        raise ValueError(msg)


def run_lab(
    config: LabConfig,
    *,
    profile: str = "quick",
    target_ids: set[str] | None = None,
    only_probes: set[str] | None = None,
    timeout_seconds: float | None = None,
    delay_seconds: float | None = None,
    dry_run: bool = False,
    progress: Progress | None = None,
) -> dict[str, Any]:
    """Run all selected probes one at a time and return a serializable report."""
    _validate_filters(config, target_ids, only_probes)
    timeout = config.timeout_seconds if timeout_seconds is None else timeout_seconds
    delay = config.delay_seconds if delay_seconds is None else delay_seconds
    if not 1 <= timeout <= 60:  # noqa: PLR2004
        msg = "timeout_seconds must be between 1 and 60"
        raise ValueError(msg)
    if not 0 <= delay <= 10:  # noqa: PLR2004
        msg = "delay_seconds must be between 0 and 10"
        raise ValueError(msg)
    private_key = priv_from_pem(config.agent_key.read_bytes())
    started = _iso_now()
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "lab_version": VERSION,
        "run": {
            "id": str(uuid.uuid4()),
            "started_at": started,
            "finished_at": None,
            "profile": profile,
            "dry_run": dry_run,
            "timeout_seconds": timeout,
            "delay_seconds": delay,
            "agent_key": config.agent_key.name,
        },
        "targets": [],
        "summary": {},
    }
    selected_targets = [target for target in config.targets if not target_ids or target.id in target_ids]
    for target in selected_targets:
        target_report: dict[str, Any] = {
            "id": target.id,
            "name": target.name,
            "gateway_url": target.gateway_url,
            "mandates": {kind: _mandate_metadata(mandate) for kind, mandate in target.mandates.items()},
            "observations": [],
            "findings": [],
            "summary": {},
        }
        for kind, mandate in target.mandates.items():
            probes = select_probes(profile, kind, only_probes)
            total = sum(2 if probe.mutation == "replay" else 1 for probe in probes)
            completed = 0
            for probe in probes:
                bodies = build_request_bodies(probe, mandate.token, private_key)
                for attempt, body in enumerate(bodies, start=1):
                    completed += 1
                    if progress:
                        progress(
                            {
                                "phase": "start",
                                "target": target.name,
                                "target_id": target.id,
                                "mandate": kind,
                                "probe": probe.title,
                                "probe_id": probe.id,
                                "attempt": attempt,
                                "completed": completed,
                                "total": total,
                            }
                        )
                    response = None if dry_run else post_gateway(target.gateway_url, body, timeout)
                    observation = _observation(
                        target,
                        mandate,
                        probe,
                        body,
                        attempt=attempt,
                        response=response,
                    )
                    target_report["observations"].append(observation)
                    if progress:
                        allowed, decision, reason = observed_decision(observation["response"])
                        progress(
                            {
                                "phase": "finish",
                                "target": target.name,
                                "target_id": target.id,
                                "mandate": kind,
                                "probe": probe.title,
                                "probe_id": probe.id,
                                "attempt": attempt,
                                "completed": completed,
                                "total": total,
                                "status": observation["response"]["status"],
                                "allowed": allowed,
                                "decision": decision,
                                "reason": reason,
                                "network_error": observation["response"]["network_error"],
                                "dry_run": dry_run,
                            }
                        )
                    if not dry_run and delay and not (probe is probes[-1] and attempt == len(bodies)):
                        time.sleep(delay)
        score_target(target_report, target.mandates)
        report["targets"].append(target_report)
    report["run"]["finished_at"] = _iso_now()
    report["summary"] = {
        "targets": len(report["targets"]),
        "requests": sum(target["summary"]["counts"]["requests"] for target in report["targets"]),
        "findings": sum(len(target["findings"]) for target in report["targets"]),
        "potential_score": sum(target["summary"]["potential_score"] for target in report["targets"]),
        "targets_with_network_errors": sum(
            target["summary"]["counts"]["network_errors"] > 0 for target in report["targets"]
        ),
    }
    return report


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def write_report(report: dict[str, Any], output: Path | None = None) -> tuple[Path, Path]:
    """Write an immutable timestamped report and an atomically refreshed latest.json."""
    reports_dir = Path(__file__).resolve().parents[1] / "local"
    if output is None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        output = reports_dir / f"attack-lab-report-{stamp}.json"
    else:
        output = output.expanduser().resolve()
    _atomic_json(output, report)
    latest = reports_dir / "attack-lab-latest.json"
    if output != latest:
        _atomic_json(latest, report)
    return output, latest
