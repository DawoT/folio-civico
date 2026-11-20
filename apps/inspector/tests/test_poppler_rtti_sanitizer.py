"""R1.15: fail-closed metadata parity and target-scoped sanitizer exception."""
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poppler_isolated_sanitizer import (
    PDFINFO_FIXTURES, TEST_ANNOTATION_URI,
    inspect_pdfinfo_reports, linked_annotation_pdf,
)


def make_reports(directory: Path) -> None:
    for name in PDFINFO_FIXTURES:
        (directory / f"pdfinfo-{name}.txt").write_text(
            "Pages:          1\n"
            "Encrypted:      no\n"
            "PDF version:    1.4\n",
            encoding="utf-8",
        )
    (directory / "linked-urls.txt").write_text(
        "Page  Type          URL\n"
        f"1     Annotation    {TEST_ANNOTATION_URI}\n",
        encoding="utf-8",
    )


class PopplerRTTISanitizerTests(unittest.TestCase):
    def test_synthetic_annotation_is_deterministic_and_offline(self):
        first, second = linked_annotation_pdf(), linked_annotation_pdf()
        self.assertEqual(first, second)
        self.assertTrue(first.startswith(b"%PDF-"))
        self.assertLess(len(first), 4096)
        self.assertEqual(first.count(TEST_ANNOTATION_URI.encode()), 1)
        self.assertIn(b"/Subtype /Link", first)
        self.assertIn(b"/Annots [5 0 R]", first)

    def test_five_reports_and_one_link_require_complete_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_reports(root)
            report = inspect_pdfinfo_reports(root)
            self.assertEqual(set(report), set(PDFINFO_FIXTURES) | {"linked_uri_report"})
            for digest in report.values():
                self.assertEqual(len(digest), 64)
            self.assertEqual(
                report["linked_uri_report"],
                hashlib.sha256((root / "linked-urls.txt").read_bytes()).hexdigest(),
            )

    def test_missing_duplicate_or_incorrect_metadata_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_reports(root)
            path = root / "pdfinfo-native.txt"
            original = path.read_text()
            for mutation in (
                "", original + "Pages:          1\n",
                original.replace("Encrypted:      no", "Encrypted:      yes"),
                original.replace("PDF version:    1.4", "PDF version:    1.7"),
            ):
                path.write_text(mutation)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    inspect_pdfinfo_reports(root)
            path.write_text(original)
            path.unlink()
            with self.assertRaises(ValueError):
                inspect_pdfinfo_reports(root)

    def test_link_requires_exact_expected_uri_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_reports(root)
            links = root / "linked-urls.txt"
            original = links.read_text()
            for mutation in (
                original.replace(TEST_ANNOTATION_URI, "https://example.invalid/changed"),
                original + original,
                original.replace("Annotation", "Unverified"),
            ):
                links.write_text(mutation)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    inspect_pdfinfo_reports(root)

    def test_symlinks_and_oversized_reports_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_reports(root)
            report = root / "pdfinfo-linked.txt"
            report.unlink()
            report.symlink_to(root / "pdfinfo-native.txt")
            with self.assertRaises(ValueError):
                inspect_pdfinfo_reports(root)
            report.unlink()
            report.write_bytes(b"x" * 20000)
            with self.assertRaises(ValueError):
                inspect_pdfinfo_reports(root)
            make_reports(root)
            links = root / "linked-urls.txt"
            links.unlink()
            links.symlink_to(root / "pdfinfo-native.txt")
            with self.assertRaises(ValueError):
                inspect_pdfinfo_reports(root)

    def test_vptr_exception_is_target_scoped_in_research_script(self):
        root = Path(__file__).resolve().parents[1]
        script = (root / "research_patches" / "build_sanitized_poppler.sh").read_text()
        self.assertIn(
            "target_compile_options(pdfinfo PRIVATE -fno-sanitize=vptr)", script
        )
        self.assertNotIn("target_compile_options(poppler PRIVATE -fno-sanitize=vptr)", script)
        self.assertIn("-fsanitize=address,undefined", script)
        self.assertIn("--target pdftotext pdftoppm pdfinfo", script)


if __name__ == "__main__":
    unittest.main()
