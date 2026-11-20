"""R1.41: offline dynamic contract for experimental Poppler image provenance.

Only the orchestration is simulated through Bash functions (BASH_ENV); no
Docker image, network, registry, Git state, or institutional PDF is touched.
The real-engine smokes and Trivy remain separately mandatory.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "apps/inspector/build_poppler_experiment.sh"
BASE = "sha256:" + "a" * 64
EXP = "sha256:" + "b" * 64
ALT = "sha256:" + "c" * 64

FAKE = r"""
python3() {
  printf '{"ready":true}\n'
}
docker() {
  case "$1" in
    image)
      [ "$2" = inspect ] || return 91
      case "$3" in
        folio-civico-inspector@sha256:*)
          if [ "$FAKE_DIGEST_MISMATCH" = 1 ]; then
            printf '%s\n' "$FAKE_ALT"
          else
            printf '%s\n' "$FAKE_BASE"
          fi
          ;;
        folio-civico-inspector:ocr-integrated)
          if [ -f "$FAKE_BASE_SEEN" ] && [ "$FAKE_RETARGET_BASE" = 1 ]; then
            printf '%s\n' "$FAKE_ALT"
          elif [ "$FAKE_BAD_BASE" = 1 ]; then
            printf '%s\n' not-an-image-id
          else
            printf '%s\n' "$FAKE_BASE"
          fi
          : > "$FAKE_BASE_SEEN"
          ;;
        folio-civico-inspector:poppler-experiment)
          if [ -f "$FAKE_EXPERIMENT_SEEN" ] && [ "$FAKE_RETARGET_EXPERIMENT" = 1 ]; then
            printf '%s\n' "$FAKE_ALT"
          elif [ "$FAKE_BAD_EXPERIMENT" = 1 ]; then
            printf '%s\n' not-an-image-id
          else
            printf '%s\n' "$FAKE_EXPERIMENT"
          fi
          : > "$FAKE_EXPERIMENT_SEEN"
          ;;
        *) return 92 ;;
      esac
      ;;
    build)
      printf 'BUILD\n' >> "$FAKE_LOG"
      previous=""
      for arg in "$@"; do
        if [ "$previous" = --build-arg ]; then
          printf 'BUILD_ARG=%s\n' "$arg" >> "$FAKE_LOG"
        fi
        previous="$arg"
      done
      ;;
    run)
      seen=0
      for arg in "$@"; do
        case "$arg" in
          sha256:*)
            printf 'RUN_ID=%s\n' "$arg" >> "$FAKE_LOG"
            seen=$((seen+1))
            ;;
          folio-civico-inspector:poppler-experiment)
            printf 'RUN_TAG\n' >> "$FAKE_LOG"
            ;;
        esac
      done
      [ "$seen" -eq 1 ] || return 93
      ;;
    *) return 94 ;;
  esac
}
"""


class PopplerExperimentImagePinTests(unittest.TestCase):
    def run_script(self, *, base_change=False, experiment_change=False,
                   invalid_base=False, invalid_experiment=False,
                   digest_mismatch=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            init = root / "bash-env"
            init.write_text(FAKE, encoding="utf-8")
            log = root / "calls"
            env = {
                **os.environ,
                "BASH_ENV": str(init),
                "FAKE_LOG": str(log),
                "FAKE_BASE": BASE,
                "FAKE_EXPERIMENT": EXP,
                "FAKE_ALT": ALT,
                "FAKE_BASE_SEEN": str(root / "base-seen"),
                "FAKE_EXPERIMENT_SEEN": str(root / "exp-seen"),
                "FAKE_RETARGET_BASE": str(int(base_change)),
                "FAKE_RETARGET_EXPERIMENT": str(int(experiment_change)),
                "FAKE_BAD_BASE": str(int(invalid_base)),
                "FAKE_BAD_EXPERIMENT": str(int(invalid_experiment)),
                "FAKE_DIGEST_MISMATCH": str(int(digest_mismatch)),
            }
            result = subprocess.run(
                ["bash", str(RUNNER)], cwd=ROOT, env=env,
                capture_output=True, text=True, check=False, timeout=15,
            )
            lines = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            return result.returncode, result.stdout, lines

    def test_build_receives_immutable_candidate_id_and_smokes_experiment_id(self):
        exit_code, stdout, lines = self.run_script()
        self.assertEqual(exit_code, 0, stdout)
        self.assertIn("BUILD", lines)
        self.assertIn("BUILD_ARG=POPPLER_BASE_IMAGE=folio-civico-inspector@" + BASE, lines)
        self.assertEqual(lines.count("RUN_ID=" + EXP), 3)
        self.assertNotIn("RUN_TAG", lines)

    def test_mutated_base_tag_aborts_before_smokes(self):
        code, output, lines = self.run_script(base_change=True)
        self.assertEqual(code, 3)
        self.assertIn("candidate_image_changed", output)
        self.assertFalse(any(x.startswith("RUN_") for x in lines))

    def test_mutated_experiment_tag_aborts_after_smokes(self):
        code, output, lines = self.run_script(experiment_change=True)
        self.assertEqual(code, 3)
        self.assertIn("experiment_image_changed", output)
        self.assertEqual(lines.count("RUN_ID=" + EXP), 3)

    def test_invalid_base_id_aborts_before_build(self):
        code, output, lines = self.run_script(invalid_base=True)
        self.assertEqual(code, 3)
        self.assertIn("invalid_base_image_id", output)
        self.assertNotIn("BUILD", lines)

    def test_repo_digest_resolution_mismatch_aborts_before_build(self):
        code, output, lines = self.run_script(digest_mismatch=True)
        self.assertEqual(code, 3)
        self.assertIn("base_digest_resolution_mismatch", output)
        self.assertNotIn("BUILD", lines)

    def test_invalid_experiment_id_aborts_before_smokes(self):
        code, output, lines = self.run_script(invalid_experiment=True)
        self.assertEqual(code, 3)
        self.assertIn("invalid_experiment_image_id", output)
        self.assertFalse(any(x.startswith("RUN_") for x in lines))


if __name__ == "__main__":
    unittest.main()
