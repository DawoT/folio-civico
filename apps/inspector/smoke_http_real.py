"""Real HTTP smoke with the patched scanner, no network, and synthetic PDFs.

Run only inside the isolated Docker validation container. Authentication uses
synthetic credentials that are NOT production secrets. Never logs PDF content.
"""
from __future__ import annotations

import hashlib
import http.client
from http.server import HTTPServer
import json
import os
from threading import Thread

from fixtures import native_pdf
from inspector import InspectorHandler

SAMPLE_TOKEN = "folio-synthetic-http-token-" * 2
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def request(port: int, method: str, path: str, *, body: bytes | None = None,
            headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=35)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        result = connection.getresponse()
        return result.status, result.read(MAX_RESPONSE_BYTES + 1)
    finally:
        connection.close()


def run_smoke() -> dict[str, str]:
    os.environ["FOLIO_INSPECTOR_SERVICE_TOKEN"] = SAMPLE_TOKEN
    os.environ["FOLIO_INSPECTOR_OUTPUT_MODE"] = "unsigned"
    os.environ["CLAMAV_DB_DIR"] = "/opt/clamdb"
    # The loopback HTTPServer lives only inside --network none Docker.
    # Never publish ports or spawn a second network listener.
    server = HTTPServer(("127.0.0.1", 0), InspectorHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = request(server.server_port, "GET", "/health")
        if status != 200 or body:
            raise AssertionError("Patched inspector did not pass health check")
        pdf = native_pdf()
        headers = {
            "Content-Type": "application/pdf",
            "X-Folio-Document-Version": "synthetic_http_v1",
            "X-Folio-Source-Sha256": hashlib.sha256(pdf).hexdigest(),
            "X-Folio-Inspector-Token": SAMPLE_TOKEN,
        }
        status, body = request(
            server.server_port, "POST", "/inspect",
            body=pdf, headers={**headers, "X-Folio-Inspector-Token": "wrong"}
        )
        if status != 403 or body:
            raise AssertionError("Inspector accepted unauthorized request")
        status, body = request(server.server_port, "POST", "/inspect",
                               body=pdf, headers=headers)
        if status != 200 or len(body) > MAX_RESPONSE_BYTES:
            raise AssertionError("Inspector rejected valid synthetic PDF")
        result: dict = json.loads(body)
        if (set(result) != {"manifest"}
                or result["manifest"]["scanVerdict"] != "clean"
                or result["manifest"]["documentVersionId"] != "synthetic_http_v1"
                or result["manifest"]["sourceSha256"] != headers["X-Folio-Source-Sha256"]
                or len(result["manifest"]["pages"]) != 1
                or "EXPEDIENTE" not in result["manifest"]["pages"][0]["text"]):
            raise AssertionError("Unsigned manifest not bound to source document")
        status, body = request(
            server.server_port, "POST", "/inspect",
            body=pdf, headers={**headers, "X-Folio-Source-Sha256": "f" * 64}
        )
        if status != 422 or body:
            raise AssertionError("Inspector accepted a forged source hash")
        return {
            "health": "passed", "unauthorized": "rejected",
            "unsigned_manifest": "passed", "forged_sha256": "rejected"
        }
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def main() -> int:
    try:
        checks = run_smoke()
    except Exception:
        # Do not expose parser exceptions, untrusted bytes or scanner paths.
        print(json.dumps({"ready": False, "reason": "http_smoke_failed"}))
        return 1
    print(json.dumps({"ready": True, "checks": checks}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
