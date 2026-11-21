import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditRepository, formatReport } from "../scripts/git-hygiene.mjs";

const tempRoots = [];
const git = (repo, ...args) => execFileSync("git", ["-C", repo, ...args], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
}).trim();

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "folio-hygiene-"));
  tempRoots.push(root);
  git(root, "init", "--initial-branch=main", "-q");
  git(root, "config", "user.name", "Local Audit Test");
  git(root, "config", "user.email", "local-audit@example.invalid");
  writeFileSync(join(root, "README.md"), "base\n");
  writeFileSync(join(root, ".gitignore"), "/feature-tree/\n/active-tree/\n");
  git(root, "add", "README.md", ".gitignore");
  git(root, "commit", "-qm", "base");
  git(root, "update-ref", "refs/remotes/origin/main", "HEAD");
  return root;
}

afterEach(() => {
  for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("read-only Git hygiene inventory", () => {
  it("distinguishes local ancestry from divergence without changing the repository", () => {
    const root = fixture();
    git(root, "branch", "already-merged");
    const other = join(root, "feature-tree");
    git(root, "worktree", "add", "-qb", "pending-feature", other, "main");
    writeFileSync(join(other, "feature.txt"), "new code\n");
    git(other, "add", "feature.txt");
    git(other, "commit", "-qm", "new feature");

    const before = git(root, "status", "--porcelain");
    const report = auditRepository(root);
    expect(report.summary).toMatchObject({
      localBranches: 3,
      ancestorBranches: 2,
      divergentBranches: 1,
      worktrees: 2,
      dirtyWorktrees: 0,
      mergedCleanWorktrees: 1
    });
    expect(report.divergentBranches).toEqual(["pending-feature"]);
    expect(report.mainBehindCount).toBe(0);
    expect(formatReport(report)).toContain("No branch or worktree is removed");
    expect(git(root, "status", "--porcelain")).toBe(before);
    expect(git(other, "branch", "--show-current")).toBe("pending-feature");
  });

  it("flags tracked and untracked work in linked trees, without deleting or staging", () => {
    const root = fixture();
    const other = join(root, "active-tree");
    git(root, "worktree", "add", "-qb", "active-feature", other, "main");
    writeFileSync(join(other, "README.md"), "modified\n");
    writeFileSync(join(other, "research.txt"), "untracked\n");
    const prior = git(other, "status", "--porcelain");
    const report = auditRepository(root);

    expect(report.summary.dirtyWorktrees).toBe(1);
    expect(report.dirtyWorktrees).toEqual([expect.objectContaining({
      branch: "active-feature",
      dirty: true,
      trackedChanges: 1,
      untrackedChanges: 1
    })]);
    expect(git(other, "status", "--porcelain")).toBe(prior);
  });

  it("reports a stale local main as an integration risk", () => {
    const root = fixture();
    git(root, "branch", "upstream");
    git(root, "switch", "-q", "upstream");
    writeFileSync(join(root, "next.txt"), "new upstream\n");
    git(root, "add", "next.txt");
    git(root, "commit", "-qm", "new upstream");
    git(root, "update-ref", "refs/remotes/origin/main", "HEAD");
    git(root, "switch", "-q", "main");

    const report = auditRepository(root);
    expect(report.mainBehindBase).toBe(true);
    expect(report.mainAheadCount).toBe(0);
    expect(report.mainBehindCount).toBe(1);
  });
});
