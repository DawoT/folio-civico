"""R1.42 TDD: source-level guard ordering and private evidence must fail closed."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))
import tesseract_554_guard_landmarks as m


def source_fixture() -> dict[str, str]:
    """Small synthetic C++ fixtures, not snippets fetched from the network."""
    return {
        "src/classify/adaptive.cpp": """
ADAPT_CLASS_STRUCT::ADAPT_CLASS_STRUCT() { }
ADAPT_CLASS_STRUCT::~ADAPT_CLASS_STRUCT() {
    for (int i = 0; i < MAX_NUM_CONFIGS; i++) { }
    FreeBitVector(PermProtos);
    FreeBitVector(PermConfigs);
}
ADAPT_TEMPLATES_STRUCT::~ADAPT_TEMPLATES_STRUCT() {
    if (Templates != nullptr) {
        for (unsigned i = 0; i < (Templates)->NumClasses && i < MAX_NUM_CLASSES; i++) {
            delete Class[i];
        }
    }
}
ADAPT_CLASS_STRUCT *ReadAdaptedClass(TFile *fp) {
    Class = new ADAPT_CLASS_STRUCT;
    FreeBitVector(Class->PermProtos);
    FreeBitVector(Class->PermConfigs);
    fp->FRead(Class, sizeof(ADAPT_CLASS_STRUCT), 1);
    Class->TempProtos = NIL_LIST;
    for (i = 0; i < MAX_NUM_CONFIGS; i++) {
       Class->Config[i].Temp = nullptr;
    }
    Class->PermProtos = NewBitVector(MAX_NUM_PROTOS);
    if (test_bit(Class->PermConfigs, i)) {
        Class->Config[i].Perm = nullptr;
    }
    if (NumTempProtos < 0 || NumTempProtos > MAX_NUM_PROTOS) {
        delete Class;
        return nullptr;
    }
}
ADAPT_TEMPLATES_STRUCT *Classify::ReadAdaptedTemplates(TFile *fp) {
    const size_t ReadCount = fp->FRead(Templates, sizeof(ADAPT_TEMPLATES_STRUCT), 1);
    Templates->Templates = nullptr;
    for (unsigned i = 0; i < MAX_NUM_CLASSES; i++) {
        Templates->Class[i] = nullptr;
    }
    if (ReadCount != 1) {
        delete Templates;
    }
    Templates->Templates = ReadIntTemplates(fp);
    if (Templates->Templates == nullptr) {
        delete Templates;
    }
}
""",
        "src/classify/adaptive.h": """
#include <array>
struct ADAPT_CLASS_STRUCT {
  std::array<ADAPTED_CONFIG, MAX_NUM_CONFIGS> Config{};
};
class ADAPT_TEMPLATES_STRUCT {
  ADAPT_TEMPLATES_STRUCT() : Templates(nullptr), NumNonEmptyClasses(0) {}
  std::array<ADAPT_CLASS_STRUCT *, MAX_NUM_CLASSES> Class{};
};
""",
        "src/classify/adaptmatch.cpp": """
ADAPT_TEMPLATES_STRUCT *Classify::NewAdaptedTemplates() {
  if (unicharset.size() > static_cast<size_t>(MAX_NUM_CLASSES)) {
    return nullptr;
  }
}
bool Classify::InitAdaptiveClassifier(TessdataManager *mgr) {
  PreTrainedTemplates = ReadIntTemplates(&fp);
  if (PreTrainedTemplates == nullptr) { return false; }
  AdaptedTemplates = ReadAdaptedTemplates(&fp);
  if (AdaptedTemplates == nullptr) {
    AdaptedTemplates = NewAdaptedTemplates();
  }
  if (AdaptedTemplates == nullptr) { return false; }
}
""",
        "src/ccmain/tessedit.cpp": """
bool init_tesseract = tessedit_ocr_engine_mode != OEM_LSTM_ONLY;
if (!program_editup(textbase, init_tesseract ? mgr : nullptr)) {
   return -1;
}
""",
        "src/ccutil/unicharset.cpp": """
bool UNICHARSET::load_from_file(FILE *f) {
  bool success = load_via_fgets(fgets_cb, skip_fragments);
}
bool UNICHARSET::load_from_file(TFile *f) {
  bool success = load_via_fgets(fgets_cb, skip_fragments);
}
bool UNICHARSET::load_via_fgets(
  const std::function<char *(char *, int)> &fgets_cb, bool skip_fragments) {
  if (sscanf(buffer, "%d", &unicharset_size) != 1) { return false; }
  if (unicharset_size <= 0) { return false; }
  if (unicharset_size > MAX_NUM_CLASSES) { return false; }
  for (UNICHAR_ID id = 0; id < unicharset_size; ++id) {
     this->unichar_insert_backwards_compatible(unichar);
     if (size() != static_cast<size_t>(id) + 1) { return false; }
     this->set_isalpha(id, properties & ISALPHA_MASK);
     this->unichars[id].properties.enabled = true;
  }
}
""",
        "src/ccutil/serialis.h": """
size_t RemainingBytes() const {
  return data_ != nullptr && offset_ < data_->size() ? data_->size() - offset_ : 0;
}
""",
        "src/dict/dawg.cpp": """
bool SquishedDawg::read_squished_dawg(TFile *file) {
  if (num_edges_ == 0) { return false; }
  if (num_edges_ > 50000000) { return false; }
  if (num_edges_ > file->RemainingBytes() / sizeof(EDGE_RECORD)) { return false; }
  Dawg::init(unicharset_size);
  edges_ = new EDGE_RECORD[num_edges_];
  for (uint32_t i = 0; i < num_edges_; ++i) {
    if (forward_edge(i)) {
      bool terminated = false;
      uint32_t j = i;
      do {
        NODE_REF nj = next_node_from_edge_rec(edges_[j]);
        if (nj != 0 && static_cast<uint32_t>(nj) >= num_edges_) {
          return false;
        }
        if (last_edge(j)) {
          terminated = true;
        }
        ++j;
      } while (j < num_edges_);
      if (!terminated) { return false; }
    }
  }
  return true;
}
""",
    }


class GuardLandmarkTDD(unittest.TestCase):
    def test_all_four_source_guard_groups_present_in_synthetic_fixture(self):
        rows = m.guard_landmarks(source_fixture())
        self.assertEqual(set(rows), set(m.CVE_IDS))
        for key, item in rows.items():
            self.assertTrue(item["source_guard_landmarks_present"], key)
            self.assertTrue(all(item["checks"].values()), key)
            self.assertFalse(item["runtime_exploit_regression_executed"])
            self.assertFalse(item["binary_remediation_attested"])

    def test_all_four_guard_groups_fail_if_their_critical_check_is_removed(self):
        attacks = [
            ("CVE-2026-119341", "src/classify/adaptive.cpp",
             "Class->TempProtos = NIL_LIST;", "Class->TempProtos = raw_pointer;"),
            ("CVE-2026-73067", "src/dict/dawg.cpp",
             "if (!terminated) { return false; }",
             "if (!terminated) { /* no rejection */ }"),
            ("CVE-2026-88052", "src/ccutil/unicharset.cpp",
             "if (size() != static_cast<size_t>(id) + 1) { return false; }",
             "if (size() != static_cast<size_t>(id) + 1) { /* no rejection */ }"),
            ("CVE-2026-88053", "src/classify/adaptmatch.cpp",
             "if (AdaptedTemplates == nullptr) { return false; }",
             "if (AdaptedTemplates == nullptr) { /* missing abort */ }"),
        ]
        for cve, path, before, after in attacks:
            with self.subTest(cve=cve):
                src = source_fixture()
                src[path] = src[path].replace(before, after)
                self.assertFalse(
                    m.guard_landmarks(src)[cve]["source_guard_landmarks_present"]
                )

    def test_early_return_before_pointer_cleanup_is_not_a_proven_guard(self):
        source = source_fixture()
        needle = "    Templates->Templates = nullptr;"
        source["src/classify/adaptive.cpp"] = source[
            "src/classify/adaptive.cpp"
        ].replace(needle, "    delete Templates;\n" + needle)
        # This evidence inspector is scoped and ordered: a new early delete
        # is a separate data-flow question, not automatically cleared.
        # A strict guard requires no pre-neutralization delete in the scope.
        report = m.guard_landmarks(source)
        self.assertFalse(report["CVE-2026-119341"][
            "source_guard_landmarks_present"])

    def test_malformed_source_scope_fails_closed(self):
        fixture = source_fixture()
        fixture["src/dict/dawg.cpp"] = "void unrelated() { }"
        with self.assertRaises(ValueError):
            m.guard_landmarks(fixture)
        fixture = source_fixture()
        fixture["src/dict/dawg.cpp"] += fixture["src/dict/dawg.cpp"]
        with self.assertRaises(ValueError):
            m.guard_landmarks(fixture)

    def test_comments_cannot_fake_guard_tokens(self):
        fixture = source_fixture()
        fixture["src/dict/dawg.cpp"] = fixture["src/dict/dawg.cpp"].replace(
            "if (!terminated) { return false; }",
            "/* if (!terminated) { return false; } */",
        )
        self.assertFalse(m.guard_landmarks(fixture)[
            "CVE-2026-73067"]["source_guard_landmarks_present"])

    def test_embedded_strings_do_not_truncate_function_scope(self):
        content = """bool Sample::f() {
            const char *a = "brace { }";
            if (!valid) { return false; }
            return true;
        }
        """
        scope = m._scope(content, "bool Sample::f()")
        self.assertIn("returntrue;", scope)

    def test_exact_private_excerpt_hash_pins_prevent_forged_source(self):
        fixture = source_fixture()
        packed = m._pack_sources(fixture)
        with self.assertRaisesRegex(ValueError, "independently pinned"):
            m._unpack_sources(packed)
        modified = copy.deepcopy(packed)
        name = m.FILES[0]
        payload = "mismatched proof".encode()
        modified[name]["zlib_base64"] = base64.b64encode(
            zlib.compress(payload)
        ).decode()
        modified[name]["sha256"] = hashlib.sha256(payload).hexdigest()
        with self.assertRaises(ValueError):
            m._unpack_sources(modified)

    def test_malformed_private_source_archive_fails_closed(self):
        with self.assertRaises(ValueError):
            m._load_sources(b"not a tarball")

    def test_absent_and_forged_release_claim_rejected(self):
        fixture = source_fixture()
        with patch.object(
            m, "PINNED_FILE_SHA",
            {name: hashlib.sha256(value.encode()).hexdigest()
             for name, value in fixture.items()},
        ):
            result = {
                "status": "source_guard_landmarks_research_release_blocked",
                "source_version": "5.5.4",
                "source_url": m.SOURCE_URL,
                "source_tarball_sha256": m.SOURCE_SHA,
                "source_evidence": m._pack_sources(fixture),
                "cve_results": m.guard_landmarks(fixture),
                "source_cve_paths_accounted_for": True,
                "full_cve_runtime_exploit_tests": False,
                "compiled_elf_bound_to_source_by_reproducible_build": False,
                "source_based_CVE_remediation_certified": False,
                "complete_source_advisory_coverage": False,
                "security_gate": "blocked",
                "vex": "not_issued",
                "release_authorized": False,
            }
            self.assertFalse(m.verify_report(result)["release_authorized"])
            for bad_key in (
                "release_authorized", "full_cve_runtime_exploit_tests",
                "source_based_CVE_remediation_certified",
                "compiled_elf_bound_to_source_by_reproducible_build",
                "complete_source_advisory_coverage",
            ):
                changed = copy.deepcopy(result)
                changed[bad_key] = True
                with self.assertRaises(ValueError):
                    m.verify_report(changed)

    def test_host_root_and_remote_docker_are_rejected(self):
        with patch.object(m.os, "geteuid", return_value=0):
            with self.assertRaises(ValueError):
                m.host_capture()
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote:2375"}):
            with self.assertRaises(ValueError):
                m.host_capture()


if __name__ == "__main__":
    unittest.main()
