"""R1.42: inspect *ordered guard landmarks* in hash-pinned Tesseract 5.5.4.

Separate from R1.41 upstream postimage comparison. The source downloaded
inside a disposable unprivileged container is admitted by tarball SHA-256.
Selected actual C++ sources are retained compressed in a PRIVATE report,
allowing --verify-only to recompute the exact guards without Docker/network.

Guard landmarks are not a full C++ data-flow proof, exploit regression,
source-to-ELF build attestation, VEX, or permission to release. Exit 2 on
complete research evidence, even if guards are present. Fail closed otherwise.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
from urllib.request import Request, urlopen
import zlib

SOURCE_URL = "https://deb.debian.org/debian/pool/main/t/tesseract/tesseract_5.5.4.orig.tar.gz"
SOURCE_SHA = "a8dbf8b8c8ee427ff6ad1d99116502feaf59440af1adb893caf60a6576826cf4"
CVE_IDS = (
    "CVE-2026-119341", "CVE-2026-73067",
    "CVE-2026-88052", "CVE-2026-88053",
)
FILES = (
    "src/classify/adaptive.cpp",
    "src/classify/adaptive.h",
    "src/classify/adaptmatch.cpp",
    "src/ccmain/tessedit.cpp",
    "src/ccutil/unicharset.cpp",
    "src/ccutil/serialis.h",
    "src/dict/dawg.cpp",
)
HOST_PYTHON_IMAGE = "python:3.12-slim"
# Exact source-file content hashes measured from the full SHA-pinned tarball.
# An offline report cannot replace excerpts and recompute self-declared hashes.
PINNED_FILE_SHA = {
    "src/ccmain/tessedit.cpp": "e5078fdf602323408eefdab8f7214b34df3ff7ecdae116eb4c0ae7e5beb10d12",
    "src/ccutil/serialis.h": "819b13fb2ebe796f0d972d2e8845cc1974005028956afdef9ffeff3e7b890af6",
    "src/ccutil/unicharset.cpp": "47add9ee67e40382a0c2c6d0f19d3419997d854156fa5f33d167d21b5167313f",
    "src/classify/adaptive.cpp": "3aa35c0e891410d28ceceb56976fe77b36e11684ee32b586e56bf409d6fab86f",
    "src/classify/adaptive.h": "09a92977cd179f9e91cb2ecc36615200c9673444ad0aed9684459b52b6fd5508",
    "src/classify/adaptmatch.cpp": "01b39ad39e9d765a8ac459ad15fc6761febd8cd54116f15d5ea487262ca889b5",
    "src/dict/dawg.cpp": "c567d932f6095d6f030afe2f5212b08f8ac964a79ec37266ee79c92e2f86a2cb",
}
MAX_FILE = 500_000
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA_RAW = re.compile(r"[0-9a-f]{64}\Z")


def _uncomment(source: str) -> str:
    # This is limited to HASH-VERIFIED source; reject rather than generalize
    # the result to arbitrarily formatted C++ or user-supplied source files.
    return re.sub(r"/\*[\s\S]*?\*/|//[^\n]*",
                  lambda m: "\n" * m.group(0).count("\n"), source)


def _compact(source: str) -> str:
    return re.sub(r"\s+", "", _uncomment(source))


def _scope(source: str, symbol: str) -> str:
    """Require one uniquely named function and return its bounded body."""
    source = _uncomment(source)
    if source.count(symbol) != 1:
        raise ValueError("Ambiguous security-sensitive function: " + symbol)
    start = source.index(symbol)
    opening = source.find("{", start + len(symbol))
    if opening < 0 or opening - start > 650:
        raise ValueError("Missing C++ function body")
    # Guard against braces inside ordinary strings by replacing quoted text.
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        lambda m: " " * len(m.group(0)),
        source[opening:opening + 40_000],
    )
    depth = 0
    for off, c in enumerate(masked):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return re.sub(r"\s+", "", source[opening:opening + off + 1])
    raise ValueError("Unbalanced or unbounded C++ guard scope")


def _ordered(scope: str, *tokens: str) -> bool:
    prev = 0
    for token in tokens:
        piece = re.sub(r"\s+", "", token)
        pos = scope.find(piece, prev)
        if pos < 0:
            return False
        prev = pos + len(piece)
    return True


def _no_unsafe_before(
    scope: str, start: str, checkpoint: str, forbidden: tuple[str, ...],
) -> bool:
    compact_start = re.sub(r"\s+", "", start)
    first = scope.find(compact_start)
    last = scope.find(re.sub(r"\s+", "", checkpoint),
                      first + len(compact_start))
    if first < 0 or last < 0:
        return False
    between = scope[first:last]
    return all(re.sub(r"\s+", "", unsafe) not in between
               for unsafe in forbidden)


def _all(source: str, tokens: tuple[str, ...]) -> bool:
    return all(re.sub(r"\s+", "", t) in _compact(source) for t in tokens)


def guard_landmarks(sources: dict[str, str]) -> dict:
    if set(sources) != set(FILES):
        raise ValueError("Seven source paths are required for guard review")
    a = _scope(sources["src/classify/adaptive.cpp"],
               "ADAPT_CLASS_STRUCT *ReadAdaptedClass(TFile *fp)")
    t = _scope(sources["src/classify/adaptive.cpp"],
               "ADAPT_TEMPLATES_STRUCT *Classify::ReadAdaptedTemplates(TFile *fp)")
    class_ctor = _scope(sources["src/classify/adaptive.cpp"],
                        "ADAPT_CLASS_STRUCT::ADAPT_CLASS_STRUCT()")
    class_dtor = _scope(sources["src/classify/adaptive.cpp"],
                        "ADAPT_CLASS_STRUCT::~ADAPT_CLASS_STRUCT()")
    template_dtor = _scope(sources["src/classify/adaptive.cpp"],
                           "ADAPT_TEMPLATES_STRUCT::~ADAPT_TEMPLATES_STRUCT()")
    new_templates = _scope(sources["src/classify/adaptmatch.cpp"],
                           "ADAPT_TEMPLATES_STRUCT *Classify::NewAdaptedTemplates()")
    classifier = _scope(sources["src/classify/adaptmatch.cpp"],
                        "bool Classify::InitAdaptiveClassifier(TessdataManager *mgr)")
    dawg = _scope(sources["src/dict/dawg.cpp"],
                  "bool SquishedDawg::read_squished_dawg(TFile *file)")
    unichar = _scope(sources["src/ccutil/unicharset.cpp"],
                     "bool UNICHARSET::load_via_fgets(")
    header = _compact(sources["src/classify/adaptive.h"])
    serial = _compact(sources["src/ccutil/serialis.h"])
    tessedit = _compact(sources["src/ccmain/tessedit.cpp"])
    checks = {
        "CVE-2026-119341": {
            "release_bitvectors_before_untrusted_struct_overwrite":
                _ordered(a,
                    "Class = new ADAPT_CLASS_STRUCT;",
                    "FreeBitVector(Class->PermProtos);",
                    "FreeBitVector(Class->PermConfigs);",
                    "fp->FRead(Class, sizeof(ADAPT_CLASS_STRUCT), 1);"),
            "neutralize_pointer_union_before_following_failure_paths":
                _ordered(a,
                    "fp->FRead(Class, sizeof(ADAPT_CLASS_STRUCT), 1);",
                    "Class->TempProtos = NIL_LIST;",
                    "for (i = 0; i < MAX_NUM_CONFIGS; i++) {",
                    "Class->Config[i].Temp = nullptr;",
                    "Class->PermProtos = NewBitVector(MAX_NUM_PROTOS);",
                    "if (test_bit(Class->PermConfigs, i)) {",
                    "Class->Config[i].Perm = nullptr;",
                    "if (NumTempProtos < 0 || NumTempProtos > MAX_NUM_PROTOS)",
                    "delete Class;",
                ) and _no_unsafe_before(a,
                    "fp->FRead(Class, sizeof(ADAPT_CLASS_STRUCT), 1);",
                    "Class->TempProtos = NIL_LIST;", ("delete Class;", "return nullptr;")),
            "neutralize_adapted_templates_before_bad_read_delete":
                _ordered(t,
                    "const size_t ReadCount = fp->FRead(",
                    "Templates->Templates = nullptr;",
                    "for (unsigned i = 0; i < MAX_NUM_CLASSES; i++) {",
                    "Templates->Class[i] = nullptr;",
                    "if (ReadCount != 1)",
                    "delete Templates;",
                ) and _no_unsafe_before(t,
                    "const size_t ReadCount = fp->FRead(",
                    "Templates->Templates = nullptr;",
                    ("delete Templates;", "return nullptr;")),
            "initialized_union_slots_and_bounded_destructor":
                ("std::array<ADAPTED_CONFIG,MAX_NUM_CONFIGS>Config{};" in header
                 and _ordered(class_dtor,
                    "for (int i = 0; i < MAX_NUM_CONFIGS; i++)",
                    "FreeBitVector(PermProtos);",
                    "FreeBitVector(PermConfigs);")),
        },
        "CVE-2026-73067": {
            "remaining_bytes_and_hard_limit_before_allocating_edges":
                ("size_tRemainingBytes()const{" in serial and
                 "offset_<data_->size()?" in serial and
                 _ordered(dawg,
                    "if (num_edges_ == 0)",
                    "if (num_edges_ > 50000000)",
                    "if (num_edges_ > file->RemainingBytes() / sizeof(EDGE_RECORD))",
                    "Dawg::init(unicharset_size);",
                    "edges_ = new EDGE_RECORD[num_edges_];")),
            "forward_edge_runs_must_terminate_within_bounds":
                _ordered(dawg,
                    "for (uint32_t i = 0; i < num_edges_; ++i)",
                    "if (forward_edge(i))",
                    "bool terminated = false;",
                    "uint32_t j = i;",
                    "do {",
                    "if (last_edge(j))",
                    "terminated = true;",
                    "++j;",
                    "} while (j < num_edges_);",
                    "if (!terminated)",
                    "return false;",
                    "return true;"),
            "node_targets_checked_before_success":
                _ordered(dawg,
                    "NODE_REF nj = next_node_from_edge_rec(edges_[j]);",
                    "if (nj != 0 && static_cast<uint32_t>(nj) >= num_edges_)",
                    "return false;",
                    "if (last_edge(j))"),
        },
        "CVE-2026-88052": {
            "unicharset_size_bounded_before_index_loop":
                _ordered(unichar,
                    "sscanf(buffer, \"%d\", &unicharset_size) != 1",
                    "if (unicharset_size <= 0)",
                    "return false;",
                    "if (unicharset_size > MAX_NUM_CLASSES)",
                    "return false;",
                    "for (UNICHAR_ID id = 0; id < unicharset_size; ++id)"),
            "duplicate_or_empty_insertion_detected_before_indexed_writes":
                _ordered(unichar,
                    "this->unichar_insert_backwards_compatible(unichar);",
                    "if (size() != static_cast<size_t>(id) + 1)",
                    "return false;",
                    "this->set_isalpha(id, properties & ISALPHA_MASK);",
                    "this->unichars[id].properties.enabled = true;"),
            "all_file_loaders_funnel_through_checked_parser":
                _compact(sources["src/ccutil/unicharset.cpp"]).count(
                    "boolUNICHARSET::load_from_file(") == 2
                and _compact(sources["src/ccutil/unicharset.cpp"]).count(
                    "boolsuccess=load_via_fgets(fgets_cb,skip_fragments);") == 2,
        },
        "CVE-2026-88053": {
            "template_arrays_value_initialized_and_destructed_with_bound":
                ("std::array<ADAPT_CLASS_STRUCT*,MAX_NUM_CLASSES>Class{};" in header
                 and "ADAPT_TEMPLATES_STRUCT():Templates(nullptr)" in header
                 and _ordered(template_dtor,
                    "if (Templates != nullptr)",
                    "i < (Templates)->NumClasses && i < MAX_NUM_CLASSES",
                    "delete Class[i];")),
            "adapted_loader_resets_untrusted_pointers_before_any_delete":
                _ordered(t,
                    "const size_t ReadCount = fp->FRead(",
                    "Templates->Templates = nullptr;",
                    "Templates->Class[i] = nullptr;",
                    "if (ReadCount != 1)",
                    "delete Templates;",
                    "Templates->Templates = ReadIntTemplates(fp);",
                    "if (Templates->Templates == nullptr)",
                    "delete Templates;"),
            "classifier_rejects_malformed_template_or_oversized_unicharset":
                _ordered(classifier,
                    "PreTrainedTemplates = ReadIntTemplates(&fp);",
                    "if (PreTrainedTemplates == nullptr)",
                    "return false;",
                    "AdaptedTemplates = ReadAdaptedTemplates(&fp);",
                    "if (AdaptedTemplates == nullptr)",
                    "AdaptedTemplates = NewAdaptedTemplates();",
                    "if (AdaptedTemplates == nullptr)",
                    "return false;")
                and _ordered(new_templates,
                    "if (unicharset.size() > static_cast<size_t>(MAX_NUM_CLASSES))",
                    "return nullptr;"),
            "legacy_initialization_error_propagates_to_caller":
                _ordered(tessedit,
                    "bool init_tesseract = tessedit_ocr_engine_mode != OEM_LSTM_ONLY;",
                    "if (!program_editup(textbase,",
                    "return -1;"),
        },
    }
    return {
        cve: {
            "source_guard_landmarks_present": all(row.values()),
            "checks": row,
            "static_evidence_only": True,
            "runtime_exploit_regression_executed": False,
            "binary_remediation_attested": False,
        }
        for cve, row in checks.items()
    }


def _load_sources(data: bytes) -> dict[str, str]:
    if len(data) > 8_000_000 or hashlib.sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError("Tarball does not match Dockerfile pinned source")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            result: dict[str, str] = {}
            for path in FILES:
                names = tar.getmembers()
                matches = [m for m in names if m.name ==
                           "tesseract-5.5.4/" + path]
                if len(matches) != 1 or not matches[0].isfile() or \
                        matches[0].size > MAX_FILE:
                    raise ValueError("Missing or unsafe pinned source file")
                file = tar.extractfile(matches[0])
                if file is None:
                    raise ValueError("Unreadable source member")
                result[path] = file.read().decode("utf-8")
    except (tarfile.TarError, UnicodeError) as error:
        raise ValueError("Invalid upstream source archive") from error
    if (set(result) != set(PINNED_FILE_SHA) or any(
            hashlib.sha256(value.encode("utf-8")).hexdigest() != PINNED_FILE_SHA[name]
            for name, value in result.items())):
        raise ValueError("Pinned source file content differs from reviewed tarball")
    return result


def _pack_sources(sources: dict[str, str]) -> dict:
    return {
        name: {
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
            "zlib_base64": base64.b64encode(
                zlib.compress(code.encode(), level=9)
            ).decode("ascii"),
        }
        for name, code in sources.items()
    }


def _unpack_sources(packed: dict) -> dict[str, str]:
    if not isinstance(packed, dict) or set(packed) != set(FILES):
        raise ValueError("Incomplete private source excerpts")
    values: dict[str, str] = {}
    for name, row in packed.items():
        if not isinstance(row, dict) or set(row) != {"sha256", "zlib_base64"}:
            raise ValueError("Malformed private source excerpt")
        try:
            compressed = base64.b64decode(row["zlib_base64"], validate=True)
            engine = zlib.decompressobj()
            raw = engine.decompress(compressed, MAX_FILE + 1)
            if (not engine.eof or engine.unused_data
                    or engine.unconsumed_tail or len(raw) > MAX_FILE
                    or hashlib.sha256(raw).hexdigest() != row["sha256"]):
                raise ValueError("Private source excerpt SHA mismatch")
            if row["sha256"] != PINNED_FILE_SHA[name]:
                raise ValueError("Source excerpt differs from independently pinned file")
            values[name] = raw.decode("utf-8")
        except (binascii.Error, zlib.error, UnicodeError, TypeError):
            raise ValueError("Unreadable source excerpt") from None
    return values


def _acquire_worker() -> dict:
    with urlopen(Request(
            SOURCE_URL, headers={"User-Agent": "FolioCivico-R142-SourceGuard/1"}),
            timeout=45) as src:
        archive = src.read(8_000_001)
    sources = _load_sources(archive)
    results = guard_landmarks(sources)
    return {
        "status": "source_guard_landmarks_research_release_blocked",
        "source_version": "5.5.4",
        "source_url": SOURCE_URL,
        "source_tarball_sha256": SOURCE_SHA,
        "source_evidence": _pack_sources(sources),
        "cve_results": results,
        "source_cve_paths_accounted_for": all(
            item["source_guard_landmarks_present"] for item in results.values()
        ),
        "full_cve_runtime_exploit_tests": False,
        "compiled_elf_bound_to_source_by_reproducible_build": False,
        "source_based_CVE_remediation_certified": False,
        "complete_source_advisory_coverage": False,
        "security_gate": "blocked",
        "vex": "not_issued",
        "release_authorized": False,
    }


def verify_report(report: dict) -> dict:
    if not isinstance(report, dict):
        raise ValueError("Research report must be a JSON object")
    fixed = {
        "status": "source_guard_landmarks_research_release_blocked",
        "source_version": "5.5.4",
        "source_url": SOURCE_URL,
        "source_tarball_sha256": SOURCE_SHA,
        "full_cve_runtime_exploit_tests": False,
        "compiled_elf_bound_to_source_by_reproducible_build": False,
        "source_based_CVE_remediation_certified": False,
        "complete_source_advisory_coverage": False,
        "security_gate": "blocked",
        "vex": "not_issued",
        "release_authorized": False,
    }
    if any(report.get(k) != v for k, v in fixed.items()):
        raise ValueError("Research report misstates source or release status")
    if set(report.get("cve_results", {})) != set(CVE_IDS):
        raise ValueError("Research CVE set is incomplete")
    reconstructed = guard_landmarks(
        _unpack_sources(report.get("source_evidence"))
    )
    if reconstructed != report["cve_results"] or report.get(
            "source_cve_paths_accounted_for") != all(
            row["source_guard_landmarks_present"]
            for row in reconstructed.values()):
        raise ValueError("Research guard evidence differs from source snippets")
    return {
        "status": "source_guard_excerpts_revalidated_release_blocked",
        "source_tarball_sha256": SOURCE_SHA,
        "guards": {
            cve: {**{"source_guard_landmarks_present":
                     row["source_guard_landmarks_present"]},
                  "failed": sorted(k for k, v in row["checks"].items() if not v)}
            for cve, row in sorted(reconstructed.items())
        },
        "release_authorized": False,
        "security_gate": "blocked",
    }


def _run(argv: list[str], timeout: int = 30, rc: int = 0) -> str:
    try:
        result = subprocess.run(argv, capture_output=True,
                                text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Isolated research worker unavailable") from error
    if result.returncode != rc:
        raise ValueError("Isolated research subprocess failed")
    return result.stdout


def host_capture() -> dict:
    if os.geteuid() == 0:
        raise ValueError("Host root forbidden")
    if (os.environ.get("DOCKER_HOST") and
            not os.environ["DOCKER_HOST"].startswith("unix://")):
        raise ValueError("Remote Docker endpoint forbidden")
    context = _run([
        "docker", "context", "inspect",
        "--format", "{{.Endpoints.docker.Host}}",
    ]).strip()
    if not context.startswith("unix://"):
        raise ValueError("Local Docker socket required")
    image = _run([
        "docker", "image", "inspect", HOST_PYTHON_IMAGE,
        "--format", "{{.Id}}",
    ]).strip()
    if not SHA.fullmatch(image):
        raise ValueError("Python worker image ID is not pinned")
    script = Path(__file__).read_text(encoding="utf-8")
    output = _run([
        "docker", "run", "--rm", "--pull", "never",
        "--network", "bridge", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--pids-limit", "32", "--cpus", "1", "--memory", "768m",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
        "--entrypoint", "python", image, "-I", "-c", script, "--worker",
    ], timeout=180, rc=2)
    try:
        report = json.loads(output)
    except (ValueError, UnicodeError) as error:
        raise ValueError("Malformed private worker source report") from error
    verify_report(report)
    report["worker_image_id"] = image
    report["review_script_sha256"] = hashlib.sha256(script.encode()).hexdigest()
    return report


def private_report(path: Path) -> dict:
    if (not path.is_absolute() or path.parent != Path("/tmp")
            or not re.fullmatch(
                r"folio-r142-tesseract-[a-z0-9_-]{4,80}\.json",
                path.name)
            or path.is_symlink() or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) != 0o600
            or path.stat().st_size > 1_500_000):
        raise ValueError("Missing or insecure research report")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ValueError("Malformed research JSON") from error
    receipt = verify_report(report)
    if (report.get("review_script_sha256") !=
            hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or not isinstance(report.get("worker_image_id"), str)
            or not SHA.fullmatch(report["worker_image_id"])):
        raise ValueError("Research collector identity differs")
    receipt["report_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", type=Path)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.worker:
            result = _acquire_worker()
            print(json.dumps(result, sort_keys=True))
            return 2
        elif args.verify_only:
            result = private_report(args.verify_only)
        else:
            result = host_capture()
            if args.output is not None:
                path = args.output
                if (not path.is_absolute() or path.parent != Path("/tmp")
                        or not re.fullmatch(
                            r"folio-r142-tesseract-[a-z0-9_-]{4,80}\.json",
                            path.name)
                        or path.is_symlink() or path.exists()):
                    raise ValueError("Research destination must be a new /tmp file")
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as out:
                    json.dump(result, out, sort_keys=True, indent=2)
                    out.write("\n")
        print(json.dumps(
            {"status": result["status"], "security_gate": "blocked",
             "release_authorized": False,
             "cve_results": result.get("cve_results",
                                       result.get("guards", {}))},
            sort_keys=True))
        return 2
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({
            "status": "source_guard_evidence_unverified",
            "security_gate": "blocked",
            "release_authorized": False,
        }, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
