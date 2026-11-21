"""R1.43 offline command-level test for exact Expat prototype ancestry.

Docker and preflight are shadowed by Bash functions. No external calls occur,
no images are built, and real-engine testing remains independent.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "apps/inspector/build_expat_experiment.sh"
BASE_ID = "sha256:0fd737c87ed064bc0cd4b1a0307463caa6e5e335f6214087544b50faf4bbb42f"
EXPERIMENT_ID = "sha256:" + "a" * 64
OTHER_ID = "sha256:" + "b" * 64

FAKE_BASH_ENV = r"""
python3() { printf '{"ready":true}\n'; }
docker() {
  case "$1" in
    image)
      [ "$2" = inspect ] || return 91
      case "$3" in
        folio-civico-inspector:poppler-experiment)
          if [ -f "$FAKE_BASE_SEEN" ] && [ "$FAKE_CHANGE_BASE" = 1 ]; then
            printf '%s\n' "$FAKE_OTHER"
          elif [ "$FAKE_INVALID_BASE" = 1 ]; then
            printf '%s\n' invalid
          else
            printf '%s\n' "$FAKE_BASE"
          fi
          : > "$FAKE_BASE_SEEN"
          ;;
        folio-civico-inspector:expat-source-*)
          if [ "$FAKE_BAD_ALIAS" = 1 ]; then printf '%s\n' "$FAKE_OTHER"
          else printf '%s\n' "$FAKE_BASE"; fi
          ;;
        folio-civico-inspector:expat-experiment)
          if [ "$FAKE_BAD_EXPERIMENT" = 1 ]; then
            printf '%s\n' invalid
          elif [ -f "$FAKE_EXPERIMENT_SEEN" ] && [ "$FAKE_CHANGE_EXPERIMENT" = 1 ]; then
            printf '%s\n' "$FAKE_OTHER"
          else
            printf '%s\n' "$FAKE_EXPERIMENT"
          fi
          : > "$FAKE_EXPERIMENT_SEEN"
          ;;
        *) return 92 ;;
      esac
      ;;
    tag)
      printf 'TAG=%s\n' "$3" >> "$FAKE_LOG"
      ;;
    build)
      printf 'BUILD\n' >> "$FAKE_LOG"
      old=""
      for arg in "$@"; do
        if [ "$old" = --build-arg ]; then
          printf 'BASE_ARG=%s\n' "$arg" >> "$FAKE_LOG"
        fi
        old="$arg"
      done
      ;;
    run)
      id=""
      count=0
      for arg in "$@"; do
        case "$arg" in sha256:*)
          id="$arg"; count=$((count+1));;
        esac
      done
      [ "$count" = 1 ] || return 94
      printf 'RUN=%s\n' "$id" >> "$FAKE_LOG"
      ;;
    *) return 95 ;;
  esac
}
"""

class ExpatPrototypeImagePinTests(unittest.TestCase):
    def invoke(self, *, invalid_base=False, change_base=False,
               bad_alias=False, invalid_exp=False, change_exp=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            init = root / "bash_env"
            init.write_text(FAKE_BASH_ENV, encoding="utf-8")
            log = root / "calls"
            env = {
                **os.environ, "BASH_ENV": str(init),
                "FAKE_LOG": str(log),
                "FAKE_BASE_SEEN": str(root / "base_seen"),
                "FAKE_EXPERIMENT_SEEN": str(root / "exp_seen"),
                "FAKE_BASE": BASE_ID, "FAKE_EXPERIMENT": EXPERIMENT_ID,
                "FAKE_OTHER": OTHER_ID,
                "FAKE_INVALID_BASE": str(int(invalid_base)),
                "FAKE_CHANGE_BASE": str(int(change_base)),
                "FAKE_BAD_ALIAS": str(int(bad_alias)),
                "FAKE_BAD_EXPERIMENT": str(int(invalid_exp)),
                "FAKE_CHANGE_EXPERIMENT": str(int(change_exp)),
            }
            result = subprocess.run(
                ["bash", str(SCRIPT)], cwd=ROOT, env=env, text=True,
                capture_output=True, check=False, timeout=20,
            )
            calls = log.read_text().splitlines() if log.exists() else []
            return result.returncode, result.stdout, calls

    def test_exact_local_base_passed_into_build_and_three_smokes_use_one_id(self):
        code, out, calls = self.invoke()
        self.assertEqual(code, 0, out)
        self.assertIn("BUILD", calls)
        self.assertIn(
            f"BASE_ARG=EXPAT_BASE_IMAGE=folio-civico-inspector:expat-source-{BASE_ID.removeprefix('sha256:')}",
            calls,
        )
        self.assertEqual(calls.count("RUN=" + EXPERIMENT_ID), 3)
        self.assertFalse(any(x.startswith("RUN=") and EXPERIMENT_ID not in x for x in calls))

    def test_refuses_mismatched_or_invalid_base_without_build(self):
        for kwargs in ({"invalid_base": True}, {"bad_alias": True}):
            with self.subTest(kwargs=kwargs):
                code, out, calls = self.invoke(**kwargs)
                self.assertEqual(code, 3, out)
                self.assertNotIn("BUILD", calls)
                self.assertFalse(any(x.startswith("RUN=") for x in calls))

    def test_changed_base_tag_fails_without_smoke(self):
        code, out, calls = self.invoke(change_base=True)
        self.assertEqual(code, 3, out)
        self.assertIn("experimental_base_changed", out)
        self.assertFalse(any(x.startswith("RUN=") for x in calls))

    def test_bad_experiment_id_fails_before_smoke(self):
        code, out, calls = self.invoke(invalid_exp=True)
        self.assertEqual(code, 3, out)
        self.assertFalse(any(x.startswith("RUN=") for x in calls))

    def test_experiment_retarget_after_smokes_fails_closed(self):
        code, out, calls = self.invoke(change_exp=True)
        self.assertEqual(code, 3, out)
        self.assertIn("experiment_image_changed_during_smoke", out)
        self.assertEqual(calls.count("RUN=" + EXPERIMENT_ID), 3)

if __name__ == "__main__":
    unittest.main()
