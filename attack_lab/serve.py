"""Local-only static report server."""

from __future__ import annotations

import json
import logging
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlsplit

log = logging.getLogger(__name__)
WEB_ROOT = Path(__file__).resolve().parent / "web"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}


class ReportHandler(BaseHTTPRequestHandler):
    """Serve a fixed asset allowlist and one selected report."""

    report_path: ClassVar[Path]

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header(
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _route(self) -> tuple[int, str, bytes]:
        path = urlsplit(self.path).path
        if path == "/report.json":
            try:
                raw = self.report_path.read_bytes()
                json.loads(raw)
            except (OSError, json.JSONDecodeError):
                return 500, "application/json", b'{"error":"report is unavailable or invalid"}'
            return 200, "application/json; charset=utf-8", raw
        if path == "/healthcheck":
            return 200, "application/json", b'{"status":"ok"}'
        asset = STATIC_FILES.get(path)
        if asset is None:
            return 404, "application/json", b'{"error":"not found"}'
        filename, content_type = asset
        try:
            return 200, content_type, (WEB_ROOT / filename).read_bytes()
        except OSError:
            return 500, "application/json", b'{"error":"UI asset is unavailable"}'

    def do_GET(self) -> None:
        self._send(*self._route())

    def do_HEAD(self) -> None:
        self._send(*self._route())

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        log.info("report UI: %s", format % args)


def serve_report(report: Path, *, host: str = "127.0.0.1", port: int = 8185, open_browser: bool = False) -> None:
    report = report.expanduser().resolve()
    if not report.is_file():
        msg = f"report not found: {report}; run the lab first"
        raise FileNotFoundError(msg)
    try:
        json.loads(report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"report is not valid JSON: {report}"
        raise ValueError(msg) from exc
    ReportHandler.report_path = report
    server = ThreadingHTTPServer((host, port), ReportHandler)
    url = f"http://{host}:{server.server_port}/"
    log.warning("Attack Lab report UI: %s", url)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
