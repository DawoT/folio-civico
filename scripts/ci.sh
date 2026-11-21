#!/bin/sh
# Reproducible local integration gate. No remote deployments or migrations.
# Run from any working directory: sh scripts/ci.sh
set -eu

if [ "$#" -ne 0 ]; then
  printf 'Usage: sh scripts/ci.sh (no options)\n' >&2
  exit 64
fi

ROOT_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

# Every worktree of a repository shares one Git common directory.
# Reserve the whole local CI run atomically before installs, ports or D1 writes.
# Keep fd 9 open until this shell and its CI descendants have exited; flock
# releases the lock automatically, including after an interrupted CI.
if ! command -v git >/dev/null 2>&1 || ! command -v flock >/dev/null 2>&1; then
  printf 'CI FAILED: git and flock are required for exclusive CI\n' >&2
  exit 127
fi
if ! COMMON_DIR=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null); then
  printf 'CI FAILED: cannot resolve the shared Git directory\n' >&2
  exit 78
fi
original_umask=$(umask)
umask 077
exec 9>>"$COMMON_DIR/folio-ci.lock"
umask "$original_umask"
if ! flock -n 9; then
  printf 'CI BUSY: another worktree holds the shared CI lock (exit 75)\n' >&2
  exit 75
fi

if ! command -v pnpm >/dev/null 2>&1; then
  printf 'CI FAILED: pnpm is required\n' >&2
  exit 127
fi

step() {
  printf '\n==> %s\n' "$1"
}

step 'Install locked dependencies'
pnpm install --frozen-lockfile

step 'Local CI contract tests (fail-closed)'
pnpm test:local-ci

step 'Moderated UX-5 study role, schema and privacy tests (local only)'
python3 -m unittest discover -s tests -p test_ux5_study.py

step 'Unit and integration tests (TypeScript)'
pnpm test

step 'Inspector tests (Python, mocked engines)'
pnpm test:inspector

step 'Static type checks'
pnpm typecheck

step 'React build and Cloudflare Workers dry-runs'
pnpm build

step 'Frontend JS/CSS gzip transfer budget (built artifacts)'
pnpm check:frontend-budget

step 'Chromium lab: production-build FCP/LCP/CLS/TTFB (synthetic API, local only)'
pnpm test:performance

step 'Lighthouse mobile lab (simulated network/CPU, production build, loopback only)'
pnpm test:lighthouse

step 'Cloudflare workerd integration tests (local D1/R2)'
pnpm test:workers

step 'Real Chromium browser E2E and WCAG A/AA checks (synthetic API)'
pnpm test:browser

step 'Loopback guided demo E2E (real API, signed local JWT, SQLite in-memory)'
pnpm test:demo

step 'PERF-005 built frontend + signed local API and SQLite (read-only laboratory)'
pnpm test:demo:performance

for config in \
  apps/api/wrangler.jsonc \
  apps/mcp/wrangler.jsonc \
  apps/processor/wrangler.jsonc
do
  step "Local D1 migrations: $config"
  pnpm exec wrangler d1 migrations apply folio-civico-preview --local --config "$config"
done

printf '\nCI PASSED (local only; NOT an inspector security/deployment approval)\n'
