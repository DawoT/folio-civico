"""The signature lifecycle smoke must reject expired real database metadata."""
from pathlib import Path
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inspector import MAX_SIGNATURE_AGE
from smoke_signature_freshness import validate_signature_lifecycle, main


class SignatureLifecycleSmokeTests(unittest.TestCase):
    def test_fresh_files_pass_and_simulated_expiry_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            now=time.time()
            for name in ("daily","main","bytecode"):
                path=root/(name+".cvd")
                path.write_bytes(b"synthetic fixture")
                os.utime(path,(now,now))
            result=validate_signature_lifecycle(root,now)
            self.assertTrue(result["ready"])
            self.assertEqual(result["synthetic_expired"],"blocked")
            self.assertEqual(result["threshold_hours"],72)

    def test_missing_or_already_stale_database_is_never_admitted(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            now=time.time()
            for name in ("daily","main","bytecode"):
                p=root/(name+".cvd")
                p.write_bytes(b"synthetic fixture")
                os.utime(p,(now-MAX_SIGNATURE_AGE-1,now-MAX_SIGNATURE_AGE-1))
            from inspector import ScannerUnavailable
            with self.assertRaises(ScannerUnavailable):
                validate_signature_lifecycle(root,now)
        with patch("smoke_signature_freshness.validate_signature_lifecycle",
                   side_effect=AssertionError("secret/file.pdf")), \
             patch("builtins.print") as output:
            self.assertEqual(main(),3)
            self.assertNotIn("secret/file.pdf",output.call_args.args[0])


if __name__=="__main__":
    unittest.main()
