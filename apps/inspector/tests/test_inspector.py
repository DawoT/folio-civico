import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

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
        (self.signatures / "daily.cld").write_bytes(b"synthetic fixture")
        self.called = []

    def tearDown(self):
        self.temp.cleanup()

    def fake_runner(self, argv, cwd):
        self.called.append(argv[0])
        command = argv[0]
        if command == "pdfdetach":
            return "0 embedded files\n"
        if command == "pdfinfo":
            return "Pages: 2\nEncrypted: no\n"
        if command == "pdftotext":
            page = int(argv[argv.index("-f") + 1])
            return f"Expediente de obras página {page}"
        return ""

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
            if argv[0] == "clamscan":
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
                (cwd / "ocr-page.png").write_bytes(b"synthetic raster")
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
