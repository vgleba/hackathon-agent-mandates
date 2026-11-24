"""Command line entry point for the Day 2 attack lab."""

# ruff: noqa: T201

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .config import ConfigError, load_config
from .probes import PROBES
from .runner import run_lab, write_report
from .serve import serve_report

DEFAULT_CONFIG = Path(__file__).resolve().parent / "targets.local.json"
DEFAULT_REPORT = Path(__file__).resolve().parents[1] / "local" / "attack-lab-latest.json"


def _progress(event: dict) -> None:
    if event["phase"] != "finish":
        return
    prefix = f"[{event['target_id']}/{event['mandate']}] {event['completed']:02}/{event['total']:02}"
    if event.get("dry_run"):
        outcome = "PLANNED"
    elif event.get("network_error"):
        outcome = f"NETWORK ERROR: {event['network_error']}"
    else:
        decision = event.get("decision") or "NO DECISION"
        reason = f" {event['reason']}" if event.get("reason") else ""
        outcome = f"HTTP {event['status']} {decision}{reason}"
    print(f"{prefix} {event['probe_id']}: {outcome}")


def _run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    report = run_lab(
        config,
        profile=args.profile,
        target_ids=set(args.target) if args.target else None,
        only_probes=set(args.probe) if args.probe else None,
        timeout_seconds=args.timeout,
        delay_seconds=args.delay,
        dry_run=args.dry_run,
        progress=_progress,
    )
    output, latest = write_report(report, args.output)
    print()
    print("Target scorecard")
    for target in report["targets"]:
        scores = target["summary"]["data_scores"]
        print(
            f"  {target['name']}: default={scores.get('default', 0)}, feature={scores.get('feature', 0)}, "
            f"breaks={target['summary']['break_score']}, total={target['summary']['potential_score']}"
        )
    print(f"Report: {output}")
    if latest != output:
        print(f"Dashboard data: {latest}")
    if args.fail_on_findings and report["summary"]["potential_score"]:
        return 1
    return 0


def _list_probes(args: argparse.Namespace) -> int:
    rows = [
        {
            "id": probe.id,
            "category": probe.category,
            "profiles": sorted(probe.profiles),
            "mandates": sorted(probe.mandate_kinds),
            "title": probe.title,
        }
        for probe in PROBES
        if not args.profile or args.profile in probe.profiles
    ]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(f"{row['id']:<34} {row['category']:<20} {row['title']}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    serve_report(args.report, host=args.host, port=args.port, open_browser=args.open)
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Run bounded Day 2 attacks against posted mandate gateways.")
    sub = root.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run probes and write a JSON evidence report")
    run.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    run.add_argument("--profile", choices=("quick", "full"), default="quick")
    run.add_argument("--target", action="append", help="target id to run (repeatable)")
    run.add_argument("--probe", action="append", help="probe id to run (repeatable)")
    run.add_argument("--timeout", type=float, help="per-request timeout in seconds (1-60)")
    run.add_argument("--delay", type=float, help="delay between requests in seconds (0-10)")
    run.add_argument("--output", type=Path, help="write the timestamped report here")
    run.add_argument("--dry-run", action="store_true", help="build and report requests without sending them")
    run.add_argument("--fail-on-findings", action="store_true", help="exit 1 when the potential score is non-zero")
    run.set_defaults(function=_run)

    listing = sub.add_parser("list-probes", help="show the built-in probe catalogue")
    listing.add_argument("--profile", choices=("quick", "full"))
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(function=_list_probes)

    serve = sub.add_parser("serve", help="serve a report dashboard on localhost")
    serve.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8185)
    serve.add_argument("--open", action="store_true", help="open the dashboard in the default browser")
    serve.set_defaults(function=_serve)
    return root


def main(argv: list[str] | None = None) -> int:
    root = parser()
    args = root.parse_args(argv)
    try:
        return args.function(args)
    except (ConfigError, FileNotFoundError, ValueError) as exc:
        root.exit(2, f"attack-lab: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
