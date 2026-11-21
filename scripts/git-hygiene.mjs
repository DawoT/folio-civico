#!/usr/bin/env node
/**
 * Read-only inventory of local branches and registered worktrees.
 * The current branch is not assumed to be main; no fetch, delete, prune,
 * checkout, merge, push, network request or filesystem write is performed.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));

function git(root, args) {
  return execFileSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"]
  }).trimEnd();
}

function branches(raw) {
  return raw.split("\n").filter(Boolean).sort();
}

function worktrees(raw) {
  return raw.split("\n\n").filter(Boolean).map((block) => {
    const fields = block.split("\n");
    const value = (name) => fields.find((line) => line.startsWith(name + " "))?.slice(name.length + 1);
    return {
      path: value("worktree"),
      branch: value("branch")?.replace(/^refs\/heads\//, "") ?? null,
      head: value("HEAD"),
      locked: fields.some((line) => line === "locked" || line.startsWith("locked ")),
      prunable: fields.some((line) => line === "prunable" || line.startsWith("prunable "))
    };
  });
}

export function auditRepository(root = DEFAULT_ROOT, base = "origin/main") {
  const repo = resolve(root);
  const baseSha = git(repo, ["rev-parse", "--verify", base + "^{commit}"]);
  const mainSha = git(repo, ["rev-parse", "--verify", "refs/heads/main^{commit}"]);
  const locals = branches(git(repo, ["for-each-ref", "--format=%(refname:short)", "refs/heads"]));
  const merged = new Set(branches(git(repo, ["branch", "--merged", base, "--format=%(refname:short)"])));
  const remote = branches(git(repo, ["for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"]));
  const entries = worktrees(git(repo, ["worktree", "list", "--porcelain"]));
  const [mainAheadCount, mainBehindCount] = git(repo, ["rev-list", "--left-right", "--count", "main..." + base]).split(/\s+/).map(Number);
  const items = entries.map((entry) => {
    // Do not follow prunable entries, which may refer to missing directories.
    const status = entry.prunable ? "" : git(repo, ["-C", entry.path, "status", "--porcelain=v1", "--untracked-files=normal"]);
    const changes = status.split("\n").filter(Boolean);
    return {
      ...entry,
      mergedByAncestry: entry.branch === null ? null : merged.has(entry.branch),
      dirty: changes.length > 0,
      trackedChanges: changes.filter((line) => !line.startsWith("??")).length,
      untrackedChanges: changes.filter((line) => line.startsWith("??")).length
    };
  });
  const diverged = locals.filter((branch) => !merged.has(branch));
  // A merge or cherry-pick can preserve an identical file tree under a
  // different commit SHA. Compare snapshots against the complete reachable
  // base history, not just the current tip; this is evidence, NOT permission
  // to delete branches or discard their separate commit history.
  const baseTrees = new Map();
  if (diverged.length) {
    for (const line of git(repo, ["log", "--format=%H %T", base]).split("\n")) {
      const [commit, tree] = line.split(" ");
      if (commit && tree && !baseTrees.has(tree)) baseTrees.set(tree, commit);
    }
  }
  const divergentBranchSnapshots = diverged.map((branch) => {
    const head = git(repo, ["rev-parse", "--verify", "refs/heads/" + branch + "^{commit}"]);
    const tree = git(repo, ["rev-parse", "--verify", "refs/heads/" + branch + "^{tree}"]);
    return { branch, head, tree, matchingBaseCommit: baseTrees.get(tree) ?? null };
  });
  return {
    base,
    baseSha,
    mainSha,
    mainAheadCount,
    mainBehindCount,
    mainBehindBase: mainBehindCount > 0,
    summary: {
      localBranches: locals.length,
      ancestorBranches: merged.size,
      divergentBranches: diverged.length,
      divergentBranchTreeMatches: divergentBranchSnapshots.filter((branch) => branch.matchingBaseCommit).length,
      remoteBranches: remote.length,
      worktrees: items.length,
      cleanWorktrees: items.filter((item) => !item.dirty && !item.prunable).length,
      dirtyWorktrees: items.filter((item) => item.dirty).length,
      mergedCleanWorktrees: items.filter((item) => item.mergedByAncestry && !item.dirty && !item.prunable).length,
      prunableWorktrees: items.filter((item) => item.prunable).length
    },
    divergentBranches: diverged,
    divergentBranchSnapshots,
    dirtyWorktrees: items.filter((item) => item.dirty),
    worktrees: items
  };
}

export function formatReport(report) {
  const s = report.summary;
  const lines = [
    "Folio Cívico — Git hygiene (read-only)",
    `base: ${report.base} @ ${report.baseSha.slice(0, 12)}`,
    `main: ${report.mainSha.slice(0, 12)}${report.mainBehindBase ? " (behind base)" : ""}`,
    `local branches: ${s.localBranches} (${s.ancestorBranches} ancestor; ${s.divergentBranches} divergent)`,
    `remote branches: ${s.remoteBranches}`,
    `worktrees: ${s.worktrees} (${s.cleanWorktrees} clean; ${s.dirtyWorktrees} dirty; ${s.mergedCleanWorktrees} merged + clean; ${s.prunableWorktrees} prunable)`,
    `divergent snapshots present in base history: ${s.divergentBranchTreeMatches} (still require PR/history review)`,
    "Divergent branches are not proof of unmerged changes: inspect PR history and patch equivalence first.",
    "No branch or worktree is removed by this command."
  ];
  if (report.dirtyWorktrees.length) {
    lines.push("Worktrees with changes:");
    for (const wt of report.dirtyWorktrees) {
      lines.push(`  ${wt.branch ?? "(detached)"}: ${wt.trackedChanges} tracked, ${wt.untrackedChanges} untracked`);
    }
  }
  return lines.join("\n");
}

function cli(argv) {
  const json = argv.includes("--json");
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("Usage: node scripts/git-hygiene.mjs [--json]\n");
    return;
  }
  if (argv.some((arg) => arg !== "--json")) {
    process.stderr.write("Only --json is supported. This command is read-only.\n");
    process.exitCode = 64;
    return;
  }
  try {
    const report = auditRepository();
    process.stdout.write((json ? JSON.stringify(report, null, 2) : formatReport(report)) + "\n");
  } catch (error) {
    process.stderr.write(`Git hygiene audit failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  cli(process.argv.slice(2));
}
