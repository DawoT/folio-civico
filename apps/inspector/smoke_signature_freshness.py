"""Non-destructive ClamAV signature freshness smoke for a running image.

Called in an offline read-only container via python3 -c. Never changes the
container clock, writes databases, or considers a stale scanner to be clean.
"""
from __future__ import annotations

import json
from pathlib import Path
import time

from inspector import MAX_SIGNATURE_AGE, ScannerUnavailable, require_fresh_signatures


def validate_signature_lifecycle(directory: Path, now: float) -> dict:
    require_fresh_signatures(directory, now=now)
    try:
        # Simulate lifecycle expiry by injecting a later logical clock only.
        require_fresh_signatures(directory, now=now + MAX_SIGNATURE_AGE + 3600)
    except ScannerUnavailable:
        return {
            "ready": True,
            "fresh": "passed",
            "synthetic_expired": "blocked",
            "threshold_hours": MAX_SIGNATURE_AGE // 3600,
        }
    raise AssertionError("Expired signatures were admitted")


def main() -> int:
    try:
        result = validate_signature_lifecycle(Path("/opt/clamdb"), time.time())
    except (OSError, ScannerUnavailable, AssertionError):
        print(json.dumps({"ready": False, "reason": "signature_lifecycle_failed"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
