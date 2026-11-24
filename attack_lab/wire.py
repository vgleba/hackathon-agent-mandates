"""Build signed attack requests and send them without leaving the posted gateway origin."""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from gateway.lib.common import b64u, b64u_decode, sign_bytes
from gateway.lib.gateway_verify import Request

if TYPE_CHECKING:
    from .probes import Probe

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
USER_AGENT = "mandate-attack-lab/0.1"


@dataclass(frozen=True)
class WireResponse:
    status: int | None
    headers: dict[str, str]
    json: Any
    text: str
    elapsed_ms: int
    truncated: bool
    network_error: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not risk forwarding a mandate or signed body to a different origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002, PLR0917
        return None


def _json_segment(value: dict[str, Any]) -> str:
    return b64u(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())


def _broadened_payload(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    header_segment, payload_segment, signature_segment = token.split(".")
    header = json.loads(b64u_decode(header_segment))
    claims = json.loads(b64u_decode(payload_segment))
    claims["scope"] = [
        {
            "server": "pupil-data",
            "tools": ["search", "get", "pupil", "roster", "aggregate", "classification", "draft"],
            "constraints": {},
        }
    ]
    return header, claims, signature_segment


def mutate_mandate(token: str, mutation: str) -> str:
    """Create a deliberately invalid forged token without ever using an issuer key."""
    header, claims, signature = _broadened_payload(token)
    if mutation == "tampered_mandate":
        return f"{_json_segment(header)}.{_json_segment(claims)}.{signature}"
    if mutation == "alg_none_mandate":
        header["alg"] = "none"
        return f"{_json_segment(header)}.{_json_segment(claims)}."
    msg = f"unsupported mandate mutation {mutation}"
    raise ValueError(msg)


def _corrupt_signature(signature: str) -> str:
    if not signature:
        return "A"
    return ("A" if signature[0] != "A" else "B") + signature[1:]


def build_request_bodies(probe: Probe, mandate: str, private_key, *, now: int | None = None) -> list[dict[str, Any]]:
    """Build one request, or the same request twice for the bounded replay probe."""
    now = int(time.time()) if now is None else now
    token = mandate
    if probe.mutation in {"tampered_mandate", "alg_none_mandate"}:
        token = mutate_mandate(mandate, probe.mutation)
    timestamp = now
    if probe.mutation == "stale_timestamp":
        timestamp -= 3600
    elif probe.mutation == "future_timestamp":
        timestamp += 600
    request = Request(
        server="pupil-data",
        tool=probe.tool,
        arguments=probe.arguments,
        mandate=token,
        nonce=secrets.token_urlsafe(16),
        ts=timestamp,
        sig="",
    )
    request.sig = sign_bytes(private_key, request.signing_input())
    if probe.mutation == "bad_signature":
        request.sig = _corrupt_signature(request.sig)
    elif probe.mutation == "missing_signature":
        request.sig = ""
    body = asdict(request)
    return [body, dict(body)] if probe.mutation == "replay" else [body]


def _decode_response(raw: bytes, *, truncated: bool) -> tuple[Any, str]:
    text = raw.decode("utf-8", "replace")
    if truncated:
        return None, text
    try:
        return json.loads(text), text
    except json.JSONDecodeError:
        return None, text


def _read_wire_response(response, started: float, status: int) -> WireResponse:
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(raw) > MAX_RESPONSE_BYTES
    if truncated:
        raw = raw[:MAX_RESPONSE_BYTES]
    parsed, text = _decode_response(raw, truncated=truncated)
    allowed_headers = {"content-type", "x-request-id", "x-correlation-id"}
    headers = {key.lower(): value for key, value in response.headers.items() if key.lower() in allowed_headers}
    return WireResponse(status, headers, parsed, text, round((time.monotonic() - started) * 1000), truncated, None)


def post_gateway(gateway_url: str, body: dict[str, Any], timeout: float) -> WireResponse:
    """POST only to /tools/call and never follow a redirect."""
    endpoint = f"{gateway_url.rstrip('/')}/tools/call"
    request = urllib.request.Request(  # noqa: S310
        endpoint,
        data=json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode(),
        headers={"content-type": "application/json", "user-agent": USER_AGENT, "accept": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirect)
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            return _read_wire_response(response, started, response.status)
    except urllib.error.HTTPError as exc:
        return _read_wire_response(exc, started, exc.code)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return WireResponse(None, {}, None, "", round((time.monotonic() - started) * 1000), False, str(reason))
