"""R1.40: offline command-level test of candidate image ID pinning.

Bash functions shadow Docker and the build preflight only inside this unit
test. No images are built, no registry/network calls occur. BASH_ENV makes
the shim work on noexec /tmp mounts in restricted Python 3.12 containers.
All actual engine smokes remain separately mandatory for release review.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "apps/inspector/validate_real_engines.sh"
PINNED = "sha256:" + "a" * 64
RETARGET = "sha256:" + "b" * 64

FAKE_BASH_ENV = r"""
python3() {
  printf '{"ready":true}\n'
}

docker() {
  case "$1" in
    image)
      [ "$2" = inspect ] || return 8
      if [ -f "$FAKE_TAG_SEEN" ] && [ "$FAKE_RETARGET" = 1 ]; then
        printf '%s\n' "$FAKE_RETARGET_ID"
      elif [ "$FAKE_INVALID" = 1 ]; then
        printf '%s\n' invalid-image-identity
      else
        printf '%s\n' "$FAKE_IMAGE_ID"
      fi
      : > "$FAKE_TAG_SEEN"
      ;;
    build)
      printf 'BUILD\n' >> "$FAKE_RUN_LOG"
      ;;
    run)
      shift
      found=0
      for arg in "$@"; do
        case "$arg" in
          sha256:*)
            printf 'RUN_IMAGE=%s\n' "$arg" >> "$FAKE_RUN_LOG"
            found=$((found+1))
            ;;
        esac
      done
      [ "$found" -eq 1 ] || return 9
      ;;
    *)
      return 10
      ;;
  esac
}
"""


class ImagePinHarnessTests(unittest.TestCase):
    def run_fake(self, *, retarget: bool = False, invalid: bool = False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            mock = root / "bash_env"
            mock.write_text(FAKE_BASH_ENV, encoding="utf-8")
            log = root / "calls"
            env = {
                **os.environ,
                "BASH_ENV": str(mock),
                "FAKE_RUN_LOG": str(log),
                "FAKE_TAG_SEEN": str(root / "tag_seen"),
                "FAKE_IMAGE_ID": PINNED,
                "FAKE_RETARGET_ID": RETARGET,
                "FAKE_RETARGET": str(int(retarget)),
                "FAKE_INVALID": str(int(invalid)),
            }
            proc = subprocess.run(
                ["bash", str(RUNNER), "--candidate"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            lines = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            return proc.returncode, proc.stdout, lines

    def test_smokes_use_only_exact_built_image_id(self):
        code, output, calls = self.run_fake()
        self.assertEqual(code, 0, output)
        self.assertEqual(calls[0], "BUILD")
        self.assertEqual(calls[1:], [f"RUN_IMAGE={PINNED}"] * 4)

    def test_mutable_tag_retargeting_causes_nonzero_exit(self):
        code, output, calls = self.run_fake(retarget=True)
        self.assertEqual(code, 3)
        self.assertIn("image_changed_during_smoke", output)
        self.assertEqual(calls[1:], [f"RUN_IMAGE={PINNED}"] * 4)

    def test_invalid_built_id_fails_before_any_smoke(self):
        code, output, calls = self.run_fake(invalid=True)
        self.assertEqual(code, 3)
        self.assertIn("invalid_built_image_id", output)
        self.assertEqual(calls, ["BUILD"])


if __name__ == "__main__":
    unittest.main()
