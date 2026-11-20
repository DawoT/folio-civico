"""Verify official Talos 1.5.5 signed .deb and hash its native payload.

Downloaded bytes, detached signature and temporary GPG keyring are discarded
after the comparison. The package is NOT installed, and no user documents
are uploaded. Exact pinned vendor URL and independent primary fingerprint.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

TALOS_FINGERPRINT = "5BADCA2665EF59DCF8A23D8B707F0DB480836771"
VERSION = "1.5.5-1"
DEB_NAME = "clamav-1.5.5.linux.x86_64.deb"
URL = (
    "https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.5/"
    + DEB_NAME
)
KEY_URL = ("https://raw.githubusercontent.com/Cisco-Talos/"
           "clamav-documentation/main/src/manual/cisco-talos.gpg")
CODE_ROOTS = ("/usr/local/bin/", "/usr/local/sbin/", "/usr/local/lib/")
CODE_SHA = re.compile(r"^[a-f0-9]{64}$")


def _run(argv: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Signed vendor artifact prerequisite unavailable") from error
    if result.returncode:
        raise ValueError("Signed vendor artifact prerequisite failed")
    return result


def _curl(url: str, output: Path, max_seconds: int) -> None:
    _run([
        "curl", "--fail", "--silent", "--show-error", "--location",
        "--proto", "=https", "--proto-redir", "=https", "--retry", "2",
        "--connect-timeout", "15", "--max-time", str(max_seconds),
        url, "--output", str(output),
    ], timeout=max_seconds + 30)
    if not output.is_file() or output.stat().st_size == 0:
        raise ValueError("Signed vendor download empty")


def _package_field(path: Path, field: str) -> str:
    result = _run(["dpkg-deb", "--field", str(path), field], timeout=20)
    return result.stdout.strip()


def code_files_from_tar(stream: tarfile.TarFile) -> list[dict]:
    """Hash regular ELF and ar archives in the official signed package stream.

    Never extracts untrusted archive members or follows symlink targets.
    Each selected member is hashed on the fly with fixed-size buffers.
    """
    files: dict[str, str] = {}
    for entry in stream:
        name = entry.name.removeprefix("./")
        # Reject ambiguous relative/traversal candidates: no disk writes.
        if name.startswith("/") or any(part in ("..", ".") for part in name.split("/")):
            raise ValueError("Vendor package contains noncanonical path")
        path = "/" + name
        if not any(path.startswith(root) for root in CODE_ROOTS) or not entry.isfile():
            continue
        handle = stream.extractfile(entry)
        if handle is None:
            raise ValueError("Compiled package payload could not be read")
        with handle:
            first = handle.read(8)
            if not (first.startswith(b"\x7fELF") or
                    (path.endswith(".a") and first == b"!<arch>\n")):
                continue
            if path in files:
                raise ValueError("Duplicate installed native code path in vendor archive")
            digest = hashlib.sha256()
            digest.update(first)
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
            files[path] = digest.hexdigest()
        if len(files) > 200:
            raise ValueError("Unexpectedly large vendor code-bearing manifest")
    result = [{"path": path, "sha256": digest} for path, digest in sorted(files.items())]
    names = {row["path"] for row in result}
    for item in (
        "/usr/local/bin/clamscan",
        "/usr/local/sbin/clamd",
        "/usr/local/lib/libclamav.so.12.1.0",
        "/usr/local/lib/libclamav_rust.a",
    ):
        if item not in names:
            raise ValueError("Core signed ClamAV native code missing")
    return result


def vendor_evidence() -> dict:
    # Release verification works on a clean host with gpg/curl/dpkg-deb.
    # No files from an untrusted PDF or institutional storage are involved.
    with tempfile.TemporaryDirectory(prefix="folio-clamav-vendor-") as scratch:
        directory = Path(scratch)
        deb = directory / DEB_NAME
        signature = directory / (DEB_NAME + ".sig")
        key = directory / "talos.gpg"
        keyring = directory / "talos-keyring.gpg"
        _curl(KEY_URL, key, 45)
        _curl(URL + ".sig", signature, 90)
        _curl(URL, deb, 240)

        gpg_args = [
            "gpg", "--batch", "--no-default-keyring", "--keyring", str(keyring)
        ]
        _run(gpg_args + ["--import", str(key)], timeout=20)
        fprs = _run(gpg_args + ["--with-colons", "--list-keys"], timeout=20).stdout
        primary = next(
            (row.split(":")[9] for row in fprs.splitlines()
             if row.startswith("fpr:")), None
        )
        if primary != TALOS_FINGERPRINT:
            raise ValueError("Talos primary signing key fingerprint mismatch")
        result = _run(gpg_args + [
            "--status-fd", "1", "--verify", str(signature), str(deb),
        ], timeout=60)
        good = [
            line.split() for line in result.stdout.splitlines()
            if line.startswith("[GNUPG:] VALIDSIG ")
        ]
        if (len(good) != 1 or
            not (good[0][2] == TALOS_FINGERPRINT or
                 good[0][-1] == TALOS_FINGERPRINT) or
            not any(x.startswith("[GNUPG:] GOODSIG ") for x in result.stdout.splitlines())):
            raise ValueError("Detached GPG signature not tied to pinned Talos identity")
        pkg = _package_field(deb, "Package")
        version = _package_field(deb, "Version")
        arch = _package_field(deb, "Architecture")
        if (pkg, version, arch) != ("clamav", VERSION, "amd64"):
            raise ValueError("Unexpected Talos Debian package metadata")
        digest = hashlib.sha256()
        with deb.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)

        # Stream the signed package's filesystem tar, no unsafe extraction.
        try:
            process = subprocess.Popen(
                ["dpkg-deb", "--fsys-tarfile", str(deb)],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
        except OSError as error:
            raise ValueError("Vendor .deb data stream inaccessible") from error
        try:
            assert process.stdout is not None
            with tarfile.open(fileobj=process.stdout, mode="r|") as payload:
                files = code_files_from_tar(payload)
            if process.wait(timeout=90) != 0:
                raise ValueError("Incomplete vendor package payload")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)

        return {
            "source": "talos-detached-debian-package-v1",
            "signature_verified": True,
            "signer_fingerprint": TALOS_FINGERPRINT,
            "package": pkg,
            "package_version": version,
            "architecture": arch,
            "signed_deb_sha256": digest.hexdigest(),
            "files": files,
            "vendor_patched_floor": "1.5.3",
            "release_authorized": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor", action="store_true", required=True)
    args = parser.parse_args()
    try:
        result = vendor_evidence()
    except (ValueError, OSError, tarfile.TarError, subprocess.TimeoutExpired):
        print(json.dumps({"status": "error",
                          "reason": "signed_talos_package_not_independently_verified"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
