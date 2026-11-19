"""Unit proof that source-built ELF components cannot become invisible to the gate."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from source_inventory import (
    inventory, inspect_component, sha256_elf, TESSERACT_METADATA,
    POPPLER_METADATA, SOURCE,
)


def provision(root: Path, name: str):
    if name == "tesseract":
        base=root/"opt/folio-ocr"
        exe=base/"bin/tesseract"
        lib=base/"lib/libtesseract.so.5.5.4"
        metadata=TESSERACT_METADATA
    else:
        base=root/"opt/folio-poppler"
        exe=base/"bin/pdfinfo"
        lib=base/"lib/libpoppler.so.147"
        metadata=POPPLER_METADATA
    tools=[exe,lib]
    if name == "poppler":
        tools.extend(base/"bin"/n for n in (
            "pdftotext","pdftoppm","pdfdetach","pdfattach"
        ))
    for path in tools:
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(b"\x7fELF" + bytes(64))
    (base/"source-provenance.json").write_text(json.dumps(metadata),encoding="utf-8")
    if name == "tesseract":
        models = root / "usr/share/tesseract-ocr/5/tessdata"
        models.mkdir(parents=True, exist_ok=True)
        models.chmod(0o755)
        for language in ("eng", "spa"):
            file = models / f"{language}.traineddata"
            file.write_bytes(
                (b"synthetic-official-model-placeholder-" + language.encode()) * 4
            )
            file.chmod(0o644)
    return exe,lib


def checked_version(argv, **_kwargs):
    if argv[0] == "ldd":
        return subprocess.CompletedProcess(argv,0,stdout=(
            "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00000001)\n"
        ),stderr="")
    if argv[0].endswith("/tesseract"):
        output="tesseract 5.5.4\n"
    elif argv[0].endswith("/pdfinfo"):
        output="pdfinfo version 25.03.0\n"
    else:
        raise AssertionError("Unexpected binary executed in provenance check")
    return subprocess.CompletedProcess(argv,0,stdout=output,stderr="")


class SourceInventoryTests(unittest.TestCase):
    def test_real_elf_hashes_source_version_and_flags_are_attested(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            provision(root,"tesseract")
            provision(root,"poppler")
            with patch("source_inventory.subprocess.run",side_effect=checked_version):
                value=inventory("experiment",root=root)
            self.assertEqual(value["source"],SOURCE)
            self.assertEqual(value["source_cve_coverage"],"unassessed")
            self.assertEqual([x["name"] for x in value["components"]],
                             ["tesseract","poppler"])
            for row in value["components"]:
                self.assertEqual(len(row["executable_sha256"]),64)
                self.assertEqual(len(row["library_sha256"]),64)
                self.assertEqual(len(row["provenance_sha256"]),64)
                self.assertEqual(row["cve_assessment"],"required")
                self.assertEqual(row["automated_cve_coverage"],"not_verified")
                if row["name"] == "tesseract":
                    self.assertEqual(set(row["model_sha256"]), {"eng", "spa"})
                    self.assertTrue(all(len(value) == 64
                                        for value in row["model_sha256"].values()))
                if row["name"] == "poppler":
                    self.assertEqual(row["model_sha256"], {})
                    self.assertEqual(set(row["tool_sha256"]),{
                        "pdfinfo","pdftotext","pdftoppm","pdfdetach","pdfattach"
                    })
                    self.assertTrue(all(len(x) == 64 for x in row["tool_sha256"].values()))
                self.assertNotIn(str(root),json.dumps(row))

    def test_models_are_required_regular_nonwritable_files_with_bounded_size(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            provision(root,"tesseract")
            models=root/"usr/share/tesseract-ocr/5/tessdata"
            with patch("source_inventory.subprocess.run",side_effect=checked_version):
                normal=inspect_component(root,"tesseract")
                self.assertEqual(len(normal["model_sha256"]),2)
                # Changes are detectable even when the filename is unchanged.
                original=normal["model_sha256"]["spa"]
                (models/"spa.traineddata").write_bytes(b"different-synthetic-model")
                (models/"spa.traineddata").chmod(0o644)
                updated=inspect_component(root,"tesseract")
                self.assertNotEqual(updated["model_sha256"]["spa"],original)
                # Each mutation runs against a fresh fixture.
                for failure in ("missing", "extra", "world_writable", "empty", "symlink",
                                "mutable_directory"):
                    with tempfile.TemporaryDirectory() as scratch:
                        candidate=Path(scratch)
                        provision(candidate,"tesseract")
                        model_dir=candidate/"usr/share/tesseract-ocr/5/tessdata"
                        file=model_dir/"spa.traineddata"
                        if failure == "missing":
                            file.unlink()
                        elif failure == "extra":
                            (model_dir/"fra.traineddata").write_bytes(b"extra")
                        elif failure == "world_writable":
                            file.chmod(0o666)
                        elif failure == "empty":
                            file.write_bytes(b"")
                        elif failure == "symlink":
                            file.unlink()
                            file.symlink_to(model_dir/"eng.traineddata")
                        elif failure == "mutable_directory":
                            model_dir.chmod(0o777)
                        with self.subTest(failure=failure),self.assertRaises(ValueError):
                            inspect_component(candidate,"tesseract")

    def test_required_component_missing_or_unexpected_component_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with self.assertRaises(ValueError):
                inventory("experiment",root=root)
            with self.assertRaises(ValueError):
                inventory("candidate",root=root)
            provision(root,"tesseract")
            provision(root,"poppler")
            with self.assertRaises(ValueError):
                inventory("candidate",root=root)
            with patch("source_inventory.subprocess.run",side_effect=checked_version):
                self.assertEqual(len(inventory("validation",root=root)["components"]),2)
            with self.assertRaises(ValueError):
                inventory("unexpected",root=root)

    def test_metadata_tampering_and_symlink_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as other:
            root=Path(folder)
            exe,_=provision(root,"tesseract")
            metadata=root/"opt/folio-ocr/source-provenance.json"
            value=json.loads(metadata.read_text())
            value["archive"]=True
            metadata.write_text(json.dumps(value))
            with patch("source_inventory.subprocess.run",side_effect=checked_version):
                with self.assertRaises(ValueError):
                    inspect_component(root,"tesseract")
            metadata.write_text(json.dumps(TESSERACT_METADATA))
            exe.unlink()
            outside=Path(other)/"payload"
            outside.write_bytes(b"\x7fELF" + bytes(100))
            exe.symlink_to(outside)
            with patch("source_inventory.subprocess.run",side_effect=checked_version):
                with self.assertRaises(ValueError):
                    inspect_component(root,"tesseract")

    def test_non_elf_and_wrong_executable_version_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            exe,_=provision(root,"tesseract")
            exe.write_text("fake")
            with self.assertRaises(ValueError):
                sha256_elf(root,"opt/folio-ocr/bin/tesseract")
            exe.write_bytes(b"\x7fELF" + bytes(10))
            result=subprocess.CompletedProcess([str(exe)],0,stdout="tesseract 4.0.0",stderr="")
            with patch("source_inventory.subprocess.run",return_value=result):
                with self.assertRaises(ValueError):
                    inspect_component(root,"tesseract")

    def test_unresolved_or_forbidden_native_linkage_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            provision(root,"tesseract")
            for bad in (
                "libxml2.so.2 => /lib/libxml2.so.2 (0x1)",
                "libarchive.so.13 => /lib/libarchive.so.13 (0x1)",
                "libsomething.so => not found",
            ):
                def runner(argv,**kwargs):
                    if argv[0] == "ldd":
                        return subprocess.CompletedProcess(argv,0,stdout=bad,stderr="")
                    return checked_version(argv,**kwargs)
                with self.subTest(linkage=bad),patch(
                    "source_inventory.subprocess.run",side_effect=runner
                ),self.assertRaises(ValueError):
                    inspect_component(root,"tesseract")

    def test_missing_source_built_poppler_utility_blocks_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            provision(root,"tesseract")
            provision(root,"poppler")
            (root/"opt/folio-poppler/bin/pdftotext").unlink()
            with patch("source_inventory.subprocess.run",side_effect=checked_version), self.assertRaises(ValueError):
                inventory("experiment",root=root)

    def test_plain_old_validation_does_not_invent_native_binaries(self):
        with tempfile.TemporaryDirectory() as folder:
            value=inventory("validation",root=Path(folder))
        self.assertEqual(value["components"],[])
        self.assertEqual(value["source_cve_coverage"],"not_applicable")


if __name__=="__main__":
    unittest.main()
