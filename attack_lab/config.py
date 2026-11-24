# ruff: noqa: EM101, EM102, TRY003
"""Strict configuration loading for the attack lab."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from gateway.lib.common import b64u_decode, jwk_thumbprint, priv_from_pem, pub_to_jwk

TARGET_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
MANDATE_KINDS = ("default", "feature")


class ConfigError(ValueError):
    """A configuration is unsafe or cannot be used."""


@dataclass(frozen=True)
class Expectations:
    allow: frozenset[str] = field(default_factory=frozenset)
    deny: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class MandateConfig:
    kind: str
    token: str
    source: str
    note: str
    expectations: Expectations
    known_revoked: bool
    claims: dict[str, Any]


@dataclass(frozen=True)
class TargetConfig:
    id: str
    name: str
    gateway_url: str
    mandates: dict[str, MandateConfig]


@dataclass(frozen=True)
class LabConfig:
    source: Path
    agent_key: Path
    targets: tuple[TargetConfig, ...]
    timeout_seconds: float
    delay_seconds: float


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    """Decode only for planning; the remote gateway remains responsible for verification."""
    parts = token.split(".")
    if len(parts) != 3:  # noqa: PLR2004
        raise ConfigError("mandate is not a three-part compact JWT")
    try:
        claims = json.loads(b64u_decode(parts[1]))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ConfigError("mandate JWT payload is not readable JSON") from exc
    if not isinstance(claims, dict):
        raise ConfigError("mandate JWT payload must be an object")
    return claims


def _number(value: Any, name: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be a number")
    number = float(value)
    if not minimum <= number <= maximum:
        raise ConfigError(f"{name} must be between {minimum:g} and {maximum:g}")
    return number


def _path(base: Path, value: Any, name: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{name} must be a non-empty path")
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def _gateway_url(value: Any, target_id: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"target {target_id}: gateway_url must be a string")
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigError(f"target {target_id}: gateway_url must be an http(s) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError(f"target {target_id}: gateway_url cannot contain credentials, a query, or a fragment")
    path = parsed.path.rstrip("/")
    if path.endswith("/tools/call"):
        path = path.removesuffix("/tools/call")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _string_set(value: Any, name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ConfigError(f"{name} must be a list of probe ids")
    return frozenset(value)


def _load_mandate(base: Path, kind: str, value: Any, target_id: str) -> MandateConfig:  # noqa: C901
    if isinstance(value, str):
        value = {"file": value}
    if not isinstance(value, dict):
        raise ConfigError(f"target {target_id}: {kind} mandate must be a file path or object")
    has_file, has_token = "file" in value, "token" in value
    if has_file == has_token:
        raise ConfigError(f"target {target_id}: {kind} mandate needs exactly one of file or token")
    if has_file:
        source_path = _path(base, value["file"], f"target {target_id}: {kind} mandate file")
        try:
            token = source_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"target {target_id}: cannot read {kind} mandate file {source_path}") from exc
        source = str(source_path)
    else:
        token = value["token"]
        if not isinstance(token, str) or not token.strip():
            raise ConfigError(f"target {target_id}: {kind} mandate token must be a non-empty string")
        token, source = token.strip(), "inline"
    expectations = value.get("expect", {})
    if not isinstance(expectations, dict):
        raise ConfigError(f"target {target_id}: {kind}.expect must be an object")
    allow = _string_set(expectations.get("allow"), f"target {target_id}: {kind}.expect.allow")
    deny = _string_set(expectations.get("deny"), f"target {target_id}: {kind}.expect.deny")
    if overlap := allow & deny:
        raise ConfigError(f"target {target_id}: probes cannot be both allowed and denied: {', '.join(sorted(overlap))}")
    note = value.get("note", "")
    if not isinstance(note, str):
        raise ConfigError(f"target {target_id}: {kind}.note must be a string")
    revoked = value.get("known_revoked", False)
    if not isinstance(revoked, bool):
        raise ConfigError(f"target {target_id}: {kind}.known_revoked must be true or false")
    return MandateConfig(
        kind=kind,
        token=token,
        source=source,
        note=note,
        expectations=Expectations(allow, deny),
        known_revoked=revoked,
        claims=decode_jwt_unverified(token),
    )


def load_config(path: Path) -> LabConfig:  # noqa: C901, PLR0912, PLR0915
    """Load a config and refuse ambiguous authorization or key/mandate pairings."""
    path = path.expanduser().resolve()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config root must be an object")
    base = path.parent
    key_path = _path(base, raw.get("agent_key"), "agent_key")
    try:
        private_key = priv_from_pem(key_path.read_bytes())
    except OSError as exc:
        raise ConfigError(f"cannot read agent private key {key_path}") from exc
    except (TypeError, ValueError, AssertionError) as exc:
        raise ConfigError(f"agent_key is not an Ed25519 private PEM: {key_path}") from exc
    expected_jkt = jwk_thumbprint(pub_to_jwk(private_key.public_key()))

    defaults = raw.get("defaults", {})
    if not isinstance(defaults, dict):
        raise ConfigError("defaults must be an object")
    timeout = _number(defaults.get("timeout_seconds", 10), "defaults.timeout_seconds", minimum=1, maximum=60)
    delay = _number(defaults.get("delay_seconds", 0.2), "defaults.delay_seconds", minimum=0, maximum=10)

    raw_targets = raw.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ConfigError("targets must be a non-empty list")
    targets: list[TargetConfig] = []
    seen: set[str] = set()
    for raw_target in raw_targets:
        if not isinstance(raw_target, dict):
            raise ConfigError("each target must be an object")
        target_id = raw_target.get("id")
        if not isinstance(target_id, str) or not TARGET_ID.fullmatch(target_id):
            raise ConfigError("each target id must match [a-z0-9][a-z0-9_-]{0,63}")
        if target_id in seen:
            raise ConfigError(f"duplicate target id {target_id}")
        seen.add(target_id)
        if raw_target.get("authorized") is not True:
            raise ConfigError(f"target {target_id}: set authorized to true only for its posted hackathon gateway")
        name = raw_target.get("name", target_id)
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"target {target_id}: name must be a non-empty string")
        raw_mandates = raw_target.get("mandates")
        if not isinstance(raw_mandates, dict) or "default" not in raw_mandates:
            raise ConfigError(f"target {target_id}: mandates.default is required")
        unknown_kinds = set(raw_mandates) - set(MANDATE_KINDS)
        if unknown_kinds:
            raise ConfigError(f"target {target_id}: unknown mandate kinds: {', '.join(sorted(unknown_kinds))}")
        mandates = {kind: _load_mandate(base, kind, value, target_id) for kind, value in raw_mandates.items()}
        for kind, mandate in mandates.items():
            try:
                actual_jkt = jwk_thumbprint(mandate.claims["cnf"]["jwk"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ConfigError(f"target {target_id}: {kind} mandate has no usable cnf.jwk") from exc
            if actual_jkt != expected_jkt:
                raise ConfigError(f"target {target_id}: {kind} mandate was not issued to agent_key {key_path.name}")
        targets.append(
            TargetConfig(
                id=target_id,
                name=name.strip(),
                gateway_url=_gateway_url(raw_target.get("gateway_url"), target_id),
                mandates=mandates,
            )
        )
    return LabConfig(path, key_path, tuple(targets), timeout, delay)
