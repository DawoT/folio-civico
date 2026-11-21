"""Contract tests for the local, provider-independent CI entrypoint."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
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
    "check:frontend-budget",
    "test:performance",
    "test:lighthouse",
    "test:workers",
    "test:browser",
    "test:demo",
    "test:demo:performance",
    "exec wrangler d1 migrations apply folio-civico-preview --local --config apps/api/wrangler.jsonc",
    "exec wrangler d1 migrations apply folio-civico-preview --local --config apps/mcp/wrangler.jsonc",
    "exec wrangler d1 migrations apply folio-civico-preview --local --config apps/processor/wrangler.jsonc",
]


class LocalCiContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="folio-ci-test-")
        self.addCleanup(self.directory.cleanup)
        self.temp = Path(self.directory.name)
        # Contract subprocesses must never acquire the caller's real CI lock.
        # A miniature repository gives them an independent Git common dir.
        self.repo = self.temp / "repo"
        self.repo.mkdir()
        (self.repo / "scripts").mkdir()
        self.ci_script = self.repo / "scripts" / "ci.sh"
        shutil.copy2(CI_SCRIPT, self.ci_script)
        subprocess.run(["git", "init", "--quiet", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "scripts/ci.sh"], check=True)
        subprocess.run([
            "git", "-C", str(self.repo), "-c", "user.name=CI Contract",
            "-c", "user.email=ci-contract@example.invalid", "commit", "-qm", "fixture"
        ], check=True)
        bindir = self.temp / "bin"
        bindir.mkdir()
        fake_pnpm = bindir / "pnpm"
        fake_pnpm.write_text(
            '#!/bin/sh\n'
            'printf "%s\\n" "$*" >> "$CI_FAKE_LOG"\n'
            'if [ "${CI_FAIL_STEP:-}" = "$*" ]; then exit 47; fi\n'
            'if [ "${CI_TEST_WAIT_FIFO:-}" != "" ] && '
            '[ "$*" = "install --frozen-lockfile" ]; then\n'
            '  : > "$CI_TEST_READY_MARKER"\n'
            '  IFS= read -r unused < "$CI_TEST_WAIT_FIFO" || :\n'
            'fi\n'
        )
        fake_pnpm.chmod(0o755)
        # The only directly invoked Python gate is UX-5; keep the fixture
        # synthetic rather than running tests outside this temporary repo.
        fake_python = bindir / "python3"
        fake_python.write_text(
            '#!/bin/sh\n'
            'if [ "$1" = "-m" ] && [ "$2" = "unittest" ] && '
            '[ "$7" = "test_ux5_study.py" ]; then exit 0; fi\n'
            'printf "unexpected Python CI fixture invocation\\n" >&2\n'
            'exit 77\n'
        )
        fake_python.chmod(0o755)
        self.log = self.temp / "calls.log"
        self.env = os.environ.copy()
        self.env["PATH"] = f"{bindir}:{self.env['PATH']}"
        self.env["CI_FAKE_LOG"] = str(self.log)

    def run_ci(self, *args, script=None):
        return subprocess.run(
            ["sh", str(script or self.ci_script), *args],
            cwd=self.temp,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_atomic_lock_excludes_another_git_worktree_and_releases(self):
        """A second worktree fails before the first gate; third succeeds."""
        peer = self.temp / "peer"
        subprocess.run(["git", "-C", str(self.repo), "worktree",
                        "add", "--quiet", "--detach", str(peer)], check=True)
        self.assertEqual(
            subprocess.check_output(["git", "-C", str(peer), "rev-parse",
                                     "--git-common-dir"], text=True).strip(),
            str(self.repo / ".git"),
        )
        fifo = self.temp / "release.fifo"
        os.mkfifo(fifo)
        marker = self.temp / "entered-install"
        first_env = dict(self.env, CI_TEST_WAIT_FIFO=str(fifo),
                         CI_TEST_READY_MARKER=str(marker))
        first = subprocess.Popen(
            ["sh", str(self.ci_script)], cwd=self.temp, env=first_env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and first.poll() is None:
                self.assertLess(time.monotonic(), deadline, "first runner never started")
                time.sleep(0.02)
            self.assertIsNone(first.poll(), "first CI ended before contention test")
            self.assertEqual(self.calls(), EXPECTED[:1])

            blocked = self.run_ci(script=peer / "scripts" / "ci.sh")
            self.assertEqual(blocked.returncode, 75, blocked.stderr)
            self.assertIn("CI BUSY", blocked.stderr)
            self.assertEqual(self.calls(), EXPECTED[:1],
                             "blocked runner must not enter any gate")
            self.assertNotIn("CI PASSED", blocked.stdout)

            with fifo.open("w") as release:
                release.write("go\n")
            out, err = first.communicate(timeout=5)
            self.assertEqual(first.returncode, 0, err)
            self.assertIn("CI PASSED", out)
            self.assertEqual(self.calls(), EXPECTED)

            recovered = self.run_ci(script=peer / "scripts" / "ci.sh")
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertEqual(self.calls(), EXPECTED + EXPECTED)
        finally:
            if first.poll() is None:
                os.killpg(first.pid, signal.SIGKILL)
                first.communicate(timeout=5)

    def test_missing_flock_dependency_fails_closed(self):
        restricted_bin = self.temp / "without-flock"
        restricted_bin.mkdir()
        git_binary = shutil.which("git")
        self.assertIsNotNone(git_binary)
        (restricted_bin / "git").symlink_to(git_binary)
        env = dict(self.env, PATH=str(restricted_bin))
        result = subprocess.run(
            ["/bin/sh", str(self.ci_script)], cwd=self.temp, env=env,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 127)
        self.assertIn("git and flock are required", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_ci_without_git_common_dir_fails_before_all_gates(self):
        outside = self.temp / "outside-repository"
        (outside / "scripts").mkdir(parents=True)
        shutil.copy2(CI_SCRIPT, outside / "scripts" / "ci.sh")
        result = self.run_ci(script=outside / "scripts" / "ci.sh")
        self.assertEqual(result.returncode, 78, result.stderr)
        self.assertIn("cannot resolve the shared Git directory", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_atomic_lock_releases_after_interrupt(self):
        fifo = self.temp / "interrupted.fifo"
        os.mkfifo(fifo)
        marker = self.temp / "entered-install"
        env = dict(self.env, CI_TEST_WAIT_FIFO=str(fifo),
                   CI_TEST_READY_MARKER=str(marker))
        first = subprocess.Popen(
            ["sh", str(self.ci_script)], cwd=self.temp, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and first.poll() is None:
                self.assertLess(time.monotonic(), deadline, "runner never started")
                time.sleep(0.02)
            self.assertIsNone(first.poll())
            os.killpg(first.pid, signal.SIGTERM)
            first.communicate(timeout=5)
            self.assertNotEqual(first.returncode, 0)
            recovered = self.run_ci()
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertIn("CI PASSED", recovered.stdout)
        finally:
            if first.poll() is None:
                os.killpg(first.pid, signal.SIGKILL)
                first.communicate(timeout=5)

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

    def test_frontend_budget_failure_blocks_browser_and_success(self):
        self.env["CI_FAIL_STEP"] = "check:frontend-budget"
        result = self.run_ci()
        self.assertEqual(result.returncode, 47)
        self.assertEqual(self.calls(), EXPECTED[:7])
        self.assertNotIn("CI PASSED", result.stdout)
        self.assertFalse(any("test:browser" in call or "d1 migrations" in call for call in self.calls()))

    def test_performance_lab_failures_block_browser_and_success(self):
        self.env["CI_FAIL_STEP"] = "test:performance"
        result = self.run_ci()
        self.assertEqual(result.returncode, 47)
        self.assertEqual(self.calls(), EXPECTED[:8])
        self.assertNotIn("CI PASSED", result.stdout)
        self.assertFalse(any(call == "test:browser" or "d1 migrations" in call for call in self.calls()))

    def test_performance_lab_never_reuses_previous_preview_or_dev_server(self):
        config = (ROOT / "playwright.performance.config.ts").read_text(encoding="utf-8")
        self.assertIn("reuseExistingServer: false", config)
        self.assertIn("vite preview", config)
        self.assertIn("--strictPort", config)
        self.assertIn("Number(rawPort) < 1024", config)
        self.assertIn("127.0.0.1", config)
        self.assertNotIn("reuseExistingServer: !process.env.CI", config)

    def test_lighthouse_failure_blocks_workerd_browser_and_migrations(self):
        self.env["CI_FAIL_STEP"] = "test:lighthouse"
        result = self.run_ci()
        self.assertEqual(result.returncode, 47)
        self.assertEqual(self.calls(), EXPECTED[:9])
        self.assertNotIn("CI PASSED", result.stdout)
        self.assertNotIn("test:workers", self.calls())
        self.assertNotIn("test:browser", self.calls())
        self.assertFalse(any("d1 migrations" in call for call in self.calls()))

    def test_lighthouse_runner_requires_loopback_and_new_strict_server(self):
        runner = (ROOT / "scripts/run-lighthouse.mjs").read_text(encoding="utf-8")
        self.assertIn("127.0.0.1", runner)
        self.assertIn("--strictPort", runner)
        self.assertIn("CHROME_PATH", runner)
        self.assertIn("--throttling-method=simulate", runner)
        self.assertIn("--only-categories=performance", runner)

    def test_navigation_failures_upload_only_synthetic_trace_and_geometry(self):
        """A failed Chromium anchor click must leave useful, bounded diagnostics."""
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("Preserve synthetic Playwright failure evidence", workflow)
        self.assertIn("if: failure()", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)
        self.assertIn("test-results/task-navigation-*/task-anchor-diagnostics.json", workflow)
        self.assertIn("test-results/task-navigation-*/trace.zip", workflow)
        self.assertIn("retention-days: 3", workflow)
        self.assertNotIn("path: test-results/**", workflow)

    def test_browser_failures_block_database_steps_and_success(self):
        self.env["CI_FAIL_STEP"] = "test:browser"
        result = self.run_ci()
        self.assertEqual(result.returncode, 47)
        self.assertEqual(self.calls(), EXPECTED[:11])
        self.assertNotIn("CI PASSED", result.stdout)
        self.assertFalse(any("d1 migrations" in call for call in self.calls()))

    def test_demo_uses_fresh_server_and_configurable_loopback_port(self):
        """An existing demo process must never satisfy the local CI gate."""
        config = (ROOT / "playwright.demo.config.ts").read_text(encoding="utf-8")
        server = (ROOT / "apps/web/demo-local.mjs").read_text(encoding="utf-8")
        self.assertIn("reuseExistingServer: false", config)
        self.assertIn("resolveDemoPort(process.env.FOLIO_DEMO_PORT)", config)
        self.assertIn("resolveDemoPort(process.env.FOLIO_DEMO_PORT)", server)
        self.assertNotIn("reuseExistingServer: !process.env.CI", config)

    def test_demo_failure_blocks_database_steps_and_success(self):
        self.env["CI_FAIL_STEP"] = "test:demo"
        result = self.run_ci()
        self.assertEqual(result.returncode, 47)
        self.assertEqual(self.calls(), EXPECTED[:12])
        self.assertNotIn("CI PASSED", result.stdout)
        self.assertFalse(any("d1 migrations" in call for call in self.calls()))

    def test_real_api_performance_failure_blocks_migrations_and_success(self):
        self.env["CI_FAIL_STEP"] = "test:demo:performance"
        result = self.run_ci()
        self.assertEqual(result.returncode, 47)
        self.assertEqual(self.calls(), EXPECTED[:13])
        self.assertNotIn("CI PASSED", result.stdout)
        self.assertFalse(any("d1 migrations" in call for call in self.calls()))

    def test_real_api_performance_requires_fresh_signed_demo_and_built_assets(self):
        config = (ROOT / "playwright.demo.performance.config.ts").read_text(encoding="utf-8")
        spec = (ROOT / "tests/demo/real-api.perf.spec.ts").read_text(encoding="utf-8")
        self.assertIn("reuseExistingServer: false", config)
        self.assertIn("real-api.perf.spec.ts", config)
        self.assertIn("loadCompiledWeb", spec)
        self.assertIn('"/api/session"', spec)
        self.assertIn("compiledResponseForPath", spec)
        self.assertIn("route.continue()", spec)

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

    def test_github_actions_installs_real_chromium_before_browser_ci(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        install_deps = "run: pnpm install --frozen-lockfile"
        install_browser = "run: pnpm exec playwright install --with-deps chromium"
        run_ci = "run: sh scripts/ci.sh"
        self.assertIn(install_deps, workflow)
        self.assertIn(install_browser, workflow)
        self.assertLess(workflow.index(install_deps), workflow.index(install_browser))
        self.assertLess(workflow.index(install_browser), workflow.index(run_ci))
        self.assertNotIn("playwright install --with-deps firefox", workflow)
        self.assertNotIn("playwright install --with-deps webkit", workflow)
        self.assertNotIn("wrangler deploy --remote", workflow)

    def test_failed_browser_ci_preserves_short_lived_synthetic_evidence(self):
        """A failed navigation must retain a trace; no permanent data archive."""
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        config = (ROOT / "playwright.config.ts").read_text(encoding="utf-8")
        self.assertIn('trace: "retain-on-failure"', config)
        self.assertIn('screenshot: "only-on-failure"', config)
        # Keep the upload unconditional on the test's outcome (not on the
        # success path), and after the complete CI job so failures still fail.
        self.assertIn("uses: actions/upload-artifact@v4", workflow)
        upload = workflow.split("uses: actions/upload-artifact@v4", 1)
        self.assertEqual(len(upload), 2)
        head, tail = upload
        self.assertIn("if: failure()", head.rsplit("- name:", 1)[-1])
        self.assertLess(head.index("run: sh scripts/ci.sh"), len(head))
        self.assertIn("test-results/", tail)
        self.assertIn("if-no-files-found: ignore", tail)
        self.assertIn("retention-days: 3", tail)
        self.assertNotIn("if: always()", workflow)
        self.assertNotIn("continue-on-error: true", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("playwright-report/", tail)
        self.assertNotIn(".dev.vars", tail)
        self.assertNotIn(".env", tail)

    def test_main_ci_cannot_activate_unapproved_inspector_runtime(self):
        """Main code integration does not grant container/Cloudflare release."""
        import json

        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("branches:", workflow)
        self.assertIn("      - main", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("run: sh scripts/ci.sh", workflow)
        self.assertNotIn("wrangler deploy", workflow)
        self.assertNotIn("docker build", workflow)
        self.assertNotIn("docker push", workflow)

        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        self.assertNotIn("audit:inspector:image", package["scripts"]["build"])
        self.assertNotIn("test:inspector:docker", package["scripts"]["build"])
        for app in ("api", "mcp", "processor", "inspector-gateway"):
            build = json.loads(
                (ROOT / "apps" / app / "package.json").read_text(encoding="utf-8")
            )["scripts"]["build"]
            self.assertEqual(build, "wrangler deploy --dry-run --outdir dist")

        decision = (ROOT / "docs" /
                    "ADR-023-main-code-integration-runtime-release-gate.md")
        policy = decision.read_text(encoding="utf-8")
        for required in (
            "main", "exit 2", "Cloudflare", "Preview", "VEX",
            "sin desplegar", "CVE", "no autoriza",
        ):
            self.assertIn(required, policy)


if __name__ == "__main__":
    unittest.main()
