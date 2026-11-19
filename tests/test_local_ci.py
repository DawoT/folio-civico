"""Contract tests for the local, provider-independent CI entrypoint."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CI_SCRIPT = ROOT / "scripts" / "ci.sh"
EXPECTED = [
    "install --frozen-lockfile",
    "test:local-ci",
    "test",
    "test:inspector",
    "typecheck",
    "build",
    "test:workers",
    "exec wrangler d1 migrations apply folio-civico-preview --local --config apps/api/wrangler.jsonc",
    "exec wrangler d1 migrations apply folio-civico-preview --local --config apps/mcp/wrangler.jsonc",
    "exec wrangler d1 migrations apply folio-civico-preview --local --config apps/processor/wrangler.jsonc",
]


class LocalCiContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="folio-ci-test-")
        self.addCleanup(self.directory.cleanup)
        self.temp = Path(self.directory.name)
        bindir = self.temp / "bin"
        bindir.mkdir()
        fake_pnpm = bindir / "pnpm"
        fake_pnpm.write_text(
            '#!/bin/sh\n'
            'printf "%s\\n" "$*" >> "$CI_FAKE_LOG"\n'
            'if [ "${CI_FAIL_STEP:-}" = "$*" ]; then exit 47; fi\n'
        )
        fake_pnpm.chmod(0o755)
        self.log = self.temp / "calls.log"
        self.env = os.environ.copy()
        self.env["PATH"] = f"{bindir}:{self.env['PATH']}"
        self.env["CI_FAKE_LOG"] = str(self.log)

    def run_ci(self, *args):
        return subprocess.run(
            ["sh", str(CI_SCRIPT), *args],
            cwd=self.temp,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_runs_all_gates_in_order_from_any_cwd(self):
        result = self.run_ci()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), EXPECTED)
        self.assertIn("CI PASSED", result.stdout)

    def test_fails_closed_when_a_gate_fails(self):
        self.env["CI_FAIL_STEP"] = "test:inspector"
        result = self.run_ci()
        self.assertEqual(result.returncode, 47)
        self.assertEqual(self.calls(), EXPECTED[:4])
        self.assertNotIn("CI PASSED", result.stdout)

    def test_rejects_unknown_options_before_running_anything(self):
        result = self.run_ci("--skip-security")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_does_not_perform_remote_migrations_or_deployments(self):
        result = self.run_ci()
        self.assertEqual(result.returncode, 0, result.stderr)
        invocations = self.calls()
        self.assertTrue(all("--local" in call for call in invocations if "d1 migrations" in call))
        self.assertFalse(any("deploy" in call or "--remote" in call for call in invocations))


if __name__ == "__main__":
    unittest.main()
