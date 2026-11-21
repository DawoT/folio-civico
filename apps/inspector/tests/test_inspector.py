import hashlib
import hmac
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from png_fixtures import rgb_png
from pdfimages_fixtures import EMPTY_REPORT
from qpdf_visual_fixtures import visual_qpdf_report

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("folio_inspector", ROOT / "inspector.py")
assert SPEC is not None and SPEC.loader is not None
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)

PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF"
SHA = hashlib.sha256(PDF).hexdigest()
KEY = b"test-protocol-key-" * 3


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.signatures = Path(self.temp.name)
        for database in ("daily.cld", "main.cvd", "bytecode.cvd"):
            (self.signatures / database).write_bytes(b"synthetic fixture")
        self.called = []

    def tearDown(self):
        self.temp.cleanup()

    def fake_runner(self, argv, cwd):
        self.called.append(argv[0])
        command = argv[0]
        if command == "clamscan" and "--version" in argv:
            return "ClamAV 1.5.5/28187/2026-11-18"
        if command == "qpdf" and argv[1] == "--is-encrypted":
            return "not_encrypted"
        if command == "qpdf" and argv[1] == "--json":
            return visual_qpdf_report(argv, count=2)
        if command == "pdfdetach":
            return "0 embedded files\n"
        if command == "pdfinfo":
            if "-box" in argv:
                page = int(argv[argv.index("-f") + 1])
                return ("Pages: 2\nEncrypted: no\n"
                        f"Page {page} size: 595 x 842 pts (A4)\n"
                        f"Page {page} rot: 0\n"
                        f"Page {page} MediaBox: 0 0 595 842\n"
                        f"Page {page} CropBox: 0 0 595 842\n")
            return "Pages: 2\nEncrypted: no\n"
        if command == "pdfimages":
            return EMPTY_REPORT
        if command == "pdftotext":
            page = int(argv[argv.index("-f") + 1])
            return f"Expediente de obras página {page}"
        return ""

    def test_qpdf_encryption_status_is_fail_closed_and_does_not_leak_metadata(self):
        from subprocess import CompletedProcess
        args = ["qpdf", "--is-encrypted", "synthetic.pdf"]
        for status, expected_error in (
            (0, inspector.ReviewRequired),
            (1, inspector.ScannerUnavailable),
            (3, inspector.ScannerUnavailable),
            (-11, inspector.ScannerUnavailable),
        ):
            with self.subTest(status=status), patch.object(
                inspector.subprocess, "run",
                return_value=CompletedProcess(args, status, b"", b""),
            ), self.assertRaises(expected_error):
                inspector.command(args, self.signatures)
        with patch.object(
            inspector.subprocess, "run",
            return_value=CompletedProcess(args, 2, b"", b""),
        ):
            self.assertEqual(inspector.command(args, self.signatures), "not_encrypted")
        self.assertEqual(list(self.signatures.glob("tmp*")), [])

    def test_encryption_gate_precedes_any_poppler_or_qpdf_structure_probe(self):
        invocations = []
        def capture(argv, cwd):
            invocations.append(tuple(argv))
            return self.fake_runner(argv, cwd)
        self.assertEqual(
            inspector.inspect_pdf(PDF, "ver_a", SHA,
                                  signatures=self.signatures, run=capture)["scanVerdict"],
            "clean",
        )
        tools = [args[0] for args in invocations]
        preflight = next(index for index, args in enumerate(invocations)
                         if args[:2] == ("qpdf", "--is-encrypted"))
        self.assertLess(tools.index("clamscan"), preflight)
        self.assertLess(preflight, next(index for index, args in enumerate(invocations)
                                      if args[:2] == ("qpdf", "--check")))
        self.assertLess(preflight, tools.index("pdfdetach"))
        self.assertLess(preflight, tools.index("pdfinfo"))

        def encrypted(argv, cwd):
            invocations.append(tuple(argv))
            if argv[:2] == ["qpdf", "--is-encrypted"]:
                raise inspector.ReviewRequired("Encrypted PDF is not supported")
            if argv[0] in {"pdfdetach", "pdfinfo", "pdftotext", "pdfimages", "pdftoppm"}:
                self.fail("Poppler must never inspect an encrypted document")
            return self.fake_runner(argv, cwd)
        invocations.clear()
        with self.assertRaises(inspector.ReviewRequired):
            inspector.inspect_pdf(PDF, "ver_a", SHA,
                                  signatures=self.signatures, run=encrypted)
        self.assertNotIn("pdfdetach", [args[0] for args in invocations])
        self.assertFalse(any(args[:2] == ("qpdf", "--check") for args in invocations))

    def test_encryption_preflight_requires_an_explicit_unencrypted_verdict(self):
        for unexpected in ("", "encrypted", "not_encrypted\\n", "not_encrypted "):
            def unreliable(argv, cwd):
                if argv[:2] == ["qpdf", "--is-encrypted"]:
                    return unexpected
                if argv[0] in ("pdfdetach", "pdfinfo", "pdftotext", "pdfimages", "pdftoppm"):
                    self.fail("No Poppler calls without exact qpdf verdict")
                return self.fake_runner(argv, cwd)
            with self.subTest(verdict=unexpected), self.assertRaises(
                inspector.ScannerUnavailable
            ):
                inspector.inspect_pdf(PDF, "ver_a", SHA,
                                      signatures=self.signatures, run=unreliable)

    def test_parser_children_receive_only_immutable_allowlisted_environment(self):
        """A memory-disclosure CVE in a PDF/AV parser must not expose service keys."""
        from subprocess import CompletedProcess
        poison = {
            "FOLIO_INSPECTOR_SERVICE_TOKEN": "synthetic-private-token-" * 3,
            "FOLIO_INSPECTOR_HMAC_KEY": "synthetic-hmac-key-" * 4,
            "LD_PRELOAD": "/tmp/malicious.so",
            "LD_LIBRARY_PATH": "/tmp/untrusted-libs",
            "FONTCONFIG_FILE": "/tmp/attacker-fonts.xml",
            "FONTCONFIG_PATH": "/tmp/attacker-fontconfig",
            "FONTCONFIG_SYSROOT": "/tmp/attacker-root",
            "XDG_CONFIG_HOME": "/tmp/user-font-config",
            "XDG_CACHE_HOME": "/tmp/user-font-cache",
            "HOME": "/tmp/attacker-home",
            "TESSDATA_PREFIX": "/tmp/attacker-tessdata",
            "PATH": "/tmp/attacker-bin",
            "PYTHONPATH": "/tmp/attacker-py",
        }
        with patch.dict(os.environ, poison), patch.object(
            inspector.subprocess, "run",
            return_value=CompletedProcess(["clamscan", "--version"], 0, b"", b""),
        ) as invoked:
            inspector.command(["clamscan", "--version"], self.signatures)
        child = invoked.call_args.kwargs["env"]
        self.assertEqual(child, {
            "PATH": "/opt/folio-poppler/bin:/opt/folio-ocr/bin:/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TESSDATA_PREFIX": "/usr/share/tesseract-ocr/5/tessdata",
            "FONTCONFIG_FILE": "/etc/fonts/fonts.conf",
            "FONTCONFIG_PATH": "/etc/fonts",
            "HOME": "/nonexistent",
            "XDG_CONFIG_HOME": "/nonexistent",
            "XDG_CACHE_HOME": "/nonexistent",
        })
        for secret in poison.values():
            self.assertNotIn(secret, child.values())
        self.assertEqual(set(child), set(inspector.engine_environment()))

    def test_real_child_inherits_no_service_credentials_or_custom_fontconfig(self):
        """Direct child-process contract, not merely an inspected mock call."""
        with patch.dict(os.environ, {
            "FOLIO_INSPECTOR_SERVICE_TOKEN": "private-test-token",
            "FOLIO_INSPECTOR_HMAC_KEY": "private-test-hmac",
            "FONTCONFIG_FILE": "/tmp/injected-fonts.conf",
            "XDG_CONFIG_HOME": "/tmp/injected-xdg",
            "LD_LIBRARY_PATH": "/tmp/injected-library",
        }):
            raw = inspector.command(
                [sys.executable, "-c",
                 "import json,os;print(json.dumps(dict(os.environ),sort_keys=True))"],
                self.signatures,
            )
        self.assertEqual(json.loads(raw), inspector.engine_environment())

    def test_security_patch_version_policy_rejects_outdated_clamav(self):
        for raw in ("ClamAV 1.4.6", "ClamAV 1.5.4/28185/Mon Nov 16 2026",
                    "", "ClamAV unknown", "ClamAV 1.5.4-masquerade"):
            with self.subTest(raw=raw):
                with self.assertRaises(inspector.ScannerUnavailable):
                    inspector.verify_clamav_version(raw)
        for raw in ("ClamAV 1.5.5", "ClamAV 1.5.5/28187/Nov 18",
                    "ClamAV 1.5.6/28188/Nov 19"):
            with self.subTest(raw=raw):
                inspector.verify_clamav_version(raw)

    def test_clean_pdf_extracts_two_contiguous_pages(self):
        result = inspector.inspect_pdf(PDF, "ver_a", SHA,
                                       signatures=self.signatures,
                                       run=self.fake_runner)
        self.assertEqual(result["scanVerdict"], "clean")
        self.assertEqual(len(result["pages"]), 2)
        self.assertEqual([p["page"] for p in result["pages"]], [1, 2])
        self.assertIn("clamscan", self.called)
        self.assertIn("qpdf", self.called)
        self.assertIn("pdfdetach", self.called)
        self.assertIn("pdftotext", self.called)
        self.assertEqual(result["sourceSha256"], SHA)

    def test_scanner_failure_cannot_be_treated_as_clean(self):
        def failing(argv, cwd):
            if argv[0] == "clamscan" and "--version" not in argv:
                raise inspector.ReviewRequired("synthetic virus match")
            return self.fake_runner(argv, cwd)

        with self.assertRaises(inspector.ReviewRequired):
            inspector.inspect_pdf(PDF, "ver_a", SHA, signatures=self.signatures,
                                  run=failing)
        self.assertNotIn("pdftotext", self.called)

    def test_missing_or_stale_signature_database_fails_closed(self):
        (self.signatures / "daily.cld").unlink()
        with self.assertRaises(inspector.ScannerUnavailable):
            inspector.inspect_pdf(PDF, "ver_a", SHA,
                                  signatures=self.signatures, run=self.fake_runner)
        signature = self.signatures / "main.cvd"
        signature.write_bytes(b"fixture")
        old = time.time() - 4 * 86400
        os.utime(signature, (old, old))
        with self.assertRaises(inspector.ScannerUnavailable):
            inspector.require_fresh_signatures(self.signatures)

    def test_core_signatures_must_all_be_present_current_and_unambiguous(self):
        current = time.time()
        inspector.require_fresh_signatures(self.signatures,now=current)
        for name in ("daily.cld","main.cvd","bytecode.cvd"):
            with self.subTest(missing=name):
                original=(self.signatures/name).read_bytes()
                (self.signatures/name).unlink()
                with self.assertRaises(inspector.ScannerUnavailable):
                    inspector.require_fresh_signatures(self.signatures,now=current)
                (self.signatures/name).write_bytes(original)
            with self.subTest(stale=name):
                os.utime(self.signatures/name,(current-72*3600-1,current-72*3600-1))
                with self.assertRaises(inspector.ScannerUnavailable):
                    inspector.require_fresh_signatures(self.signatures,now=current)
                os.utime(self.signatures/name,(current,current))
        (self.signatures/"daily.cvd").write_bytes(b"duplicate database")
        with self.assertRaises(inspector.ScannerUnavailable):
            inspector.require_fresh_signatures(self.signatures,now=current)

    def test_signature_timestamp_must_not_be_future_or_symlinked(self):
        current=time.time()
        original=self.signatures/"daily.cld"
        os.utime(original,(current+3600,current+3600))
        with self.assertRaises(inspector.ScannerUnavailable):
            inspector.require_fresh_signatures(self.signatures,now=current)
        original.unlink()
        target=self.signatures/"unsafe.txt"
        target.write_bytes(b"synthetic")
        original.symlink_to(target)
        with self.assertRaises(inspector.ScannerUnavailable):
            inspector.require_fresh_signatures(self.signatures,now=current)

    def test_signature_expiration_returns_http_503_not_healthy(self):
        from http.client import HTTPConnection
        from http.server import HTTPServer
        from threading import Thread
        with patch.dict(os.environ,{
            "FOLIO_INSPECTOR_SERVICE_TOKEN":"synthetic" * 6,
            "FOLIO_INSPECTOR_OUTPUT_MODE":"unsigned",
            "CLAMAV_DB_DIR":str(self.signatures)
        }),patch.object(inspector.shutil,"which",return_value="/usr/bin/fake"),\
            patch.object(inspector,"command",return_value="ClamAV 1.5.5"):
            service=HTTPServer(("127.0.0.1",0),inspector.InspectorHandler)
            thread=Thread(target=service.serve_forever,daemon=True)
            thread.start()
            try:
                def health():
                    connection=HTTPConnection("127.0.0.1",service.server_port,timeout=3)
                    connection.request("GET","/health")
                    response=connection.getresponse()
                    result=(response.status,response.read())
                    connection.close()
                    return result
                self.assertEqual(health(),(200,b""))
                stale=time.time()-inspector.MAX_SIGNATURE_AGE-1
                os.utime(self.signatures/"daily.cld",(stale,stale))
                self.assertEqual(health(),(503,b""))
            finally:
                service.shutdown()
                thread.join(timeout=3)
                service.server_close()

    def test_encrypted_embedded_and_overlong_docs_are_rejected(self):
        cases = [
            ("pdfinfo", "Pages: 1\nEncrypted: yes\n"),
            ("pdfdetach", "1 embedded files\n"),
            ("pdfinfo", "Pages: 101\nEncrypted: no\n"),
        ]
        for engine, response in cases:
            def fake(argv, cwd, engine=engine, response=response):
                return response if argv[0] == engine else self.fake_runner(argv, cwd)
            with self.subTest(engine=engine, response=response):
                with self.assertRaises(inspector.ReviewRequired):
                    inspector.inspect_pdf(PDF, "ver_a", SHA,
                                          signatures=self.signatures, run=fake)

    def test_bytes_mismatch_and_invalid_header_rejected_before_scan(self):
        with self.assertRaises(inspector.ReviewRequired):
            inspector.inspect_pdf(PDF, "ver_a", "f" * 64,
                                  signatures=self.signatures, run=self.fake_runner)
        with self.assertRaises(inspector.ReviewRequired):
            inspector.inspect_pdf(b"<not a pdf>extra", "ver_a", SHA,
                                  signatures=self.signatures, run=self.fake_runner)
        self.assertEqual(self.called, [])

    def test_fallback_to_ocr_only_if_text_empty(self):
        def fake(argv, cwd):
            if argv[0] == "pdftotext":
                return ""
            if argv[0] == "pdftoppm":
                (cwd / "ocr-page.png").write_bytes(rgb_png(500, 500))
            if argv[0] == "tesseract":
                return "Página recuperada con OCR"
            return self.fake_runner(argv, cwd)

        result = inspector.inspect_pdf(PDF, "ver_a", SHA,
                                       signatures=self.signatures, run=fake)
        self.assertIn("OCR", result["pages"][0]["text"])

    def test_empty_ocr_or_oversized_extraction_is_not_clean(self):
        for value in ("", "X" * 8001, "<script>\u202eevil</script>"):
            def fake(argv, cwd, value=value):
                if argv[0] == "pdftotext":
                    return value
                return self.fake_runner(argv, cwd)
            with self.subTest(value_len=len(value)):
                with self.assertRaises(inspector.ReviewRequired):
                    inspector.inspect_pdf(PDF, "ver_a", SHA,
                                          signatures=self.signatures, run=fake)

    def test_golden_hmac_vector_interoperates_with_typescript(self):
        vector = {
            "documentVersionId":"test_ver_1",
            "sourceSha256":"a" * 64,
            "scanVerdict":"clean",
            "scanner":"folio-isolated-clamav-poppler-v1",
            "scannerReportId":"scan_123456789",
            "scannedAt":"2026-11-18T17:30:00.000Z",
            "pages":[{"page":1,"text":"Órdenes de compra — obra Código 01"}]
        }
        signed = json.loads(inspector.signed_result(vector, ("synthetic" * 6).encode()))
        self.assertEqual(signed["signature"],
                         "db780f659b237992a32d3b78ea3318b6001df6e013ce6ce51026cd7dcd160ca9")

    def test_signatures_bind_page_text_version_and_original_hash(self):
        manifest = inspector.inspect_pdf(PDF, "ver_a", SHA,
                                         signatures=self.signatures, run=self.fake_runner)
        signed = json.loads(inspector.signed_result(manifest, KEY))
        canonical = json.dumps(manifest, ensure_ascii=False,
                               separators=(",", ":")).encode("utf-8")
        expected = hmac.new(KEY, canonical, hashlib.sha256).hexdigest()
        self.assertEqual(signed["signature"], expected)
        self.assertNotIn("original.pdf", json.dumps(signed))
        changed = dict(manifest, sourceSha256="f" * 64)
        different = json.loads(inspector.signed_result(changed, KEY))
        self.assertNotEqual(different["signature"], expected)

    def test_engine_output_is_disk_backed_and_rejected_above_two_mib(self):
        script = ("import sys; "
                  "sys.stdout.buffer.write(b'X' * (2 * 1024 * 1024 + 1))")
        with self.assertRaises(inspector.ReviewRequired):
            inspector.command([sys.executable, "-c", script], self.signatures)
        self.assertEqual(list(self.signatures.glob("tmp*")), [])

    def test_engine_output_requires_strict_utf8(self):
        script = "import sys;sys.stdout.buffer.write(bytes([255,254,0]))"
        with self.assertRaises(inspector.ReviewRequired):
            inspector.command([sys.executable, "-c", script], self.signatures)

    def test_clamav_engine_error_is_not_mistaken_for_a_virus_detection(self):
        from subprocess import CompletedProcess
        with patch.object(inspector.subprocess, "run",
                          return_value=CompletedProcess(["clamscan"], 2, b"", b"")):
            with self.assertRaises(inspector.ScannerUnavailable):
                inspector.command(["clamscan", "/tmp/sample.pdf"], self.signatures)

    def test_total_wall_time_budget_fails_closed(self):
        with patch.object(inspector, "MAX_TOTAL_SECONDS", -1):
            with self.assertRaises(inspector.ScannerUnavailable):
                inspector.inspect_pdf(PDF, "ver_a", SHA,
                                      signatures=self.signatures, run=self.fake_runner)

    def test_missing_engines_fail_closed_and_never_emit_report(self):
        def unavailable(argv, cwd):
            raise inspector.ScannerUnavailable("not installed")
        with self.assertRaises(inspector.ScannerUnavailable):
            inspector.inspect_pdf(PDF, "ver_a", SHA,
                                  signatures=self.signatures, run=unavailable)

    def test_cloudflare_container_env_secrets_are_supported_without_files(self):
        with patch.dict(os.environ, {
            "FOLIO_INSPECTOR_SERVICE_TOKEN": "synthetic" * 6,
            "FOLIO_INSPECTOR_HMAC_KEY": "synthetic-hmac" * 4,
        }):
            self.assertEqual(inspector.secret_file("FOLIO_INSPECTOR_TOKEN_FILE"),
                             ("synthetic" * 6).encode())
            self.assertEqual(inspector.secret_file("FOLIO_INSPECTOR_HMAC_FILE"),
                             ("synthetic-hmac" * 4).encode())

    def test_container_readiness_rejects_missing_engines_or_stale_signatures(self):
        with patch.dict(os.environ, {
            "FOLIO_INSPECTOR_SERVICE_TOKEN": "synthetic" * 6,
            "FOLIO_INSPECTOR_HMAC_KEY": "synthetic-hmac" * 4,
            "CLAMAV_DB_DIR": str(self.signatures),
        }):
            with patch.object(inspector.shutil, "which", return_value=None):
                with self.assertRaises(inspector.ScannerUnavailable):
                    inspector.inspection_ready()
            with patch.object(inspector.shutil, "which", return_value="/usr/bin/fake"), \
                 patch.object(inspector, "command", return_value="ClamAV 1.5.5"):
                inspector.inspection_ready()
                (self.signatures / "daily.cld").unlink()
                with self.assertRaises(inspector.ScannerUnavailable):
                    inspector.inspection_ready()

    def test_missing_pdfimages_blocks_readiness_before_document_admission(self):
        with patch.dict(os.environ, {
            "FOLIO_INSPECTOR_SERVICE_TOKEN": "synthetic" * 6,
            "FOLIO_INSPECTOR_HMAC_KEY": "synthetic-hmac" * 4,
            "CLAMAV_DB_DIR": str(self.signatures),
        }), patch.object(
            inspector.shutil, "which",
            side_effect=lambda binary: None if binary == "pdfimages" else "/synthetic/bin",
        ), patch.object(inspector, "command", return_value="ClamAV 1.5.5"):
            with self.assertRaises(inspector.ScannerUnavailable):
                inspector.inspection_ready()

    def test_readiness_and_direct_admission_reject_vulnerable_scanner(self):
        with patch.dict(os.environ, {
            "FOLIO_INSPECTOR_SERVICE_TOKEN": "synthetic" * 6,
            "FOLIO_INSPECTOR_HMAC_KEY": "synthetic-hmac" * 4,
            "CLAMAV_DB_DIR": str(self.signatures),
        }), patch.object(inspector.shutil, "which", return_value="/usr/bin/fake"), \
             patch.object(inspector, "command", return_value="ClamAV 1.5.4"):
            with self.assertRaises(inspector.ScannerUnavailable):
                inspector.inspection_ready()
        def outdated_runner(argv, cwd):
            if "--version" in argv:
                return "ClamAV 1.4.6"
            self.fail("A vulnerable scanner must not process the PDF")
        with self.assertRaises(inspector.ScannerUnavailable):
            inspector.inspect_pdf(PDF, "ver_a", SHA, signatures=self.signatures,
                                  run=outdated_runner)

    def test_gateway_health_is_private_and_fails_when_inspector_unavailable(self):
        from http.client import HTTPConnection
        from http.server import HTTPServer
        from threading import Thread
        service = HTTPServer(("127.0.0.1", 0), inspector.InspectorHandler)
        thread = Thread(target=service.serve_forever, daemon=True)
        thread.start()
        def health():
            connection = HTTPConnection("127.0.0.1", service.server_port, timeout=3)
            connection.request("GET", "/health")
            response = connection.getresponse()
            status, content = response.status, response.read()
            connection.close()
            return status, content
        try:
            with patch.object(inspector, "inspection_ready",
                              side_effect=inspector.ScannerUnavailable("not ready")):
                self.assertEqual(health(), (503, b""))
            with patch.object(inspector, "inspection_ready", return_value=None):
                self.assertEqual(health(), (200, b""))
        finally:
            service.shutdown()
            thread.join(timeout=3)
            service.server_close()

    def test_cloudflare_unsigned_mode_keeps_hmac_out_of_parser_environment(self):
        from http.client import HTTPConnection
        from http.server import HTTPServer
        from threading import Thread

        manifest = {
            "documentVersionId": "ver_a", "sourceSha256": SHA,
            "scanVerdict": "clean", "scanner": "isolated-scanner-v1",
            "scannerReportId": "report_test_87654321",
            "scannedAt": "2026-11-18T19:00:00.000Z",
            "pages": [{"page": 1, "text": "Referencia sintética"}]
        }
        with patch.dict(os.environ, {
            "FOLIO_INSPECTOR_OUTPUT_MODE": "unsigned",
            "FOLIO_INSPECTOR_SERVICE_TOKEN": ("synthetic" * 6),
            "CLAMAV_DB_DIR": str(self.signatures)
        }, clear=True):
            with patch.object(inspector.shutil, "which", return_value="/usr/bin/fake"), \
                 patch.object(inspector, "command", return_value="ClamAV 1.5.5"):
                inspector.inspection_ready()  # No HMAC secret required.
            server = HTTPServer(("127.0.0.1", 0), inspector.InspectorHandler)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with patch.object(inspector, "inspect_pdf", return_value=manifest) as mocked:
                    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                    connection.request("POST", "/inspect", body=PDF, headers={
                        "Content-Type": "application/pdf",
                        "X-Folio-Document-Version": "ver_a",
                        "X-Folio-Source-Sha256": SHA,
                        "X-Folio-Inspector-Token": "synthetic" * 6
                    })
                    response = connection.getresponse()
                    raw = response.read()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(raw), {"manifest": manifest})
                    self.assertNotIn(b"signature", raw)
                    mocked.assert_called_once()
                    connection.close()
            finally:
                server.shutdown()
                thread.join(timeout=3)
                server.server_close()

    def test_inspector_rejects_unexpected_signing_mode(self):
        with patch.dict(os.environ, {"FOLIO_INSPECTOR_OUTPUT_MODE": "unverified"}):
            with self.assertRaises(inspector.ScannerUnavailable):
                inspector.inspection_output_mode()

    def test_http_service_authenticates_and_bounds_binary_input(self):
        from http.client import HTTPConnection
        from http.server import HTTPServer
        from threading import Thread

        token = self.signatures / "token"
        signing = self.signatures / "signing"
        token.write_bytes(KEY)
        signing.write_bytes(KEY)
        with patch.dict(os.environ, {
            "FOLIO_INSPECTOR_TOKEN_FILE": str(token),
            "FOLIO_INSPECTOR_HMAC_FILE": str(signing)
        }):
            service = HTTPServer(("127.0.0.1", 0), inspector.InspectorHandler)
            thread = Thread(target=service.serve_forever, daemon=True)
            thread.start()
            def request(secret, data=PDF):
                connection = HTTPConnection("127.0.0.1", service.server_port, timeout=3)
                connection.request(
                    "POST", "/inspect", body=data,
                    headers={
                        "Content-Type": "application/pdf",
                        "X-Folio-Document-Version": "ver_a",
                        "X-Folio-Source-Sha256": SHA,
                        "X-Folio-Inspector-Token": secret.decode()
                    }
                )
                response = connection.getresponse()
                status, body = response.status, response.read()
                connection.close()
                return status, body
            try:
                self.assertEqual(request(b"incorrect-service-token")[0], 403)
                manifest = {
                    "documentVersionId":"ver_a", "sourceSha256":SHA, "scanVerdict":"clean",
                    "scanner":"isolated-scanner-v1", "scannerReportId":"report_test_012345",
                    "scannedAt":"2026-11-18T17:00:00.000Z",
                    "pages":[{"page":1,"text":"Texto sintético"}]
                }
                with patch.object(inspector, "inspect_pdf", return_value=manifest) as fake:
                    status, body = request(KEY)
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(body)["manifest"]["pages"][0]["page"],1)
                    fake.assert_called_once()
            finally:
                service.shutdown()
                thread.join(timeout=3)
                service.server_close()


if __name__ == "__main__":
    unittest.main()
