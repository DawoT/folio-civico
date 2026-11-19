"""Offline checks for selected fixes in an exact SHA-pinned Tesseract tarball."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tesseract_source_patch_probe import PATCH_MARKERS, probe_archive, main


def archive(overrides=None):
    sources={path:"\n".join(patterns) for path,patterns in PATCH_MARKERS.items()}
    sources.update(overrides or {})
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode="w:gz") as obj:
        for path,source in sources.items():
            body=source.encode("utf-8")
            info=tarfile.TarInfo("tesseract-5.5.4/"+path)
            info.size=len(body)
            obj.addfile(info,io.BytesIO(body))
    return stream.getvalue()


class SourcePatchProbeTests(unittest.TestCase):
    def test_selected_source_markers_are_present_without_declaring_runtime_safe(self):
        data=archive()
        result=probe_archive(data,expected_sha256=hashlib.sha256(data).hexdigest())
        self.assertEqual(result["status"],"source_markers_verified")
        self.assertEqual(result["release_version"],"5.5.4")
        self.assertEqual(result["selected_checks"],4)
        self.assertEqual(set(result["checks"]),{
            "CVE-2026-119338","CVE-2026-119339",
            "CVE-2026-119340","CVE-2026-119341",
        })
        self.assertTrue(all(s == "source_marker_present" for s in result["checks"].values()))
        self.assertFalse(result["binary_patch_verified"])
        self.assertFalse(result["complete_source_advisory_coverage"])
        self.assertFalse(result["release_authorized"])

    def test_modified_tar_digest_and_missing_marker_are_hard_errors(self):
        data=archive()
        with self.assertRaisesRegex(ValueError,"digest"):
            probe_archive(data,expected_sha256="0"*64)
        with self.assertRaisesRegex(ValueError,"patch markers"):
            damaged=archive({"src/lstm/weightmatrix.cpp":"vulnerable path"})
            probe_archive(damaged,expected_sha256=hashlib.sha256(damaged).hexdigest())
        with self.assertRaises(ValueError):
            probe_archive(b"not-a-tarball",expected_sha256=hashlib.sha256(b"not-a-tarball").hexdigest())

    def test_duplicate_source_file_and_symlink_are_not_treated_as_verified(self):
        data=archive()
        # Duplicate path means the inspected contents are ambiguous.
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode="w:gz") as obj:
            for path,patterns in PATCH_MARKERS.items():
                for repeat in (range(2) if "pagerenderer" in path else range(1)):
                    body="\n".join(patterns).encode()
                    item=tarfile.TarInfo("source/"+path)
                    item.size=len(body)
                    obj.addfile(item,io.BytesIO(body))
        duplicate=stream.getvalue()
        with self.assertRaises(ValueError):
            probe_archive(duplicate,expected_sha256=hashlib.sha256(duplicate).hexdigest())
        symlink=io.BytesIO()
        with tarfile.open(fileobj=symlink,mode="w:gz") as obj:
            for path,patterns in PATCH_MARKERS.items():
                info=tarfile.TarInfo("source/"+path)
                if "pagerenderer.cpp" in path:
                    info.type=tarfile.SYMTYPE
                    info.linkname="other.cpp"
                    obj.addfile(info)
                else:
                    body="\n".join(patterns).encode()
                    info.size=len(body)
                    obj.addfile(info,io.BytesIO(body))
        broken=symlink.getvalue()
        with self.assertRaises(ValueError):
            probe_archive(broken,expected_sha256=hashlib.sha256(broken).hexdigest())

    def test_cli_is_offline_and_fails_closed_for_wrong_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/"synthetic.tar.gz"
            file.write_bytes(archive())
            with patch.object(sys,"argv",["tesseract_source_patch_probe.py","--archive",str(file)]), \
                 patch("builtins.print") as emitted:
                self.assertEqual(main(),3)
                self.assertEqual(json.loads(emitted.call_args.args[0]),
                                 {"status":"error","reason":"source_fix_evidence_incomplete"})


if __name__ == "__main__":
    unittest.main()
