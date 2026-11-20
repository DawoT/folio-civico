"""R1.38: source-code guard checks are NOT CVE exploit regressions."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))

from util_linux_folio2_cve_regression import (
    REQUIRED_CVES, SOURCE_NAMES, check_cve_source_guards, inspect_versioned_source
)


class SourceGuards(unittest.TestCase):
    def setUp(self):
        self.files = {
            "libmount/src/context_mount.c": """
static int is_mount_stage_failed(struct libmnt_context *cxt) {
 if (mnt_context_helper_executed(cxt))
  return mnt_context_get_helper_status(cxt) != 0;
 return 0;
}
if (res == 0 && !is_mount_stage_failed(cxt)) {
 rc = mnt_context_call_hooks(cxt, MNT_STAGE_MOUNT_POST);
}
""",
            "sys-utils/nsenter.c": """
cgroup_procs_fd = open(fdpath, O_WRONLY | O_APPEND | O_CLOEXEC);
if (cgroup_procs_fd >= 0) {
 join_into_cgroup();
 close(cgroup_procs_fd);
 cgroup_procs_fd = -1;
}
""",
            "sys-utils/unshare.c": """
fd = open(file, O_WRONLY | O_CLOEXEC);
dirfd = open(binfmt_mnt, O_PATH | O_DIRECTORY | O_CLOEXEC);
fd = openat(dirfd, "register", O_WRONLY | O_CLOEXEC);
""",
            "libmount/src/context.c": """
fd = mnt_open_tree(AT_FDCWD, path, oflg,
 mnt_context_is_restricted(cxt) ? RESOLVE_NO_SYMLINKS : 0);
if (mnt_context_is_restricted(cxt)) {
 if (ul_startswith(src, "/dev/")) {
    path = mnt_resolve_path(src, cache);
 }
}
""",
            "libmount/src/hook_idmap.c": """
fd_tree = mnt_open_tree(AT_FDCWD, target,
 OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC |
 (recursive ? AT_RECURSIVE : 0),
 mnt_context_is_restricted(cxt) ? RESOLVE_NO_SYMLINKS : 0);
""",
            "libmount/src/hook_subdir.c": """
while (*dir == '/')
 dir++;
int sub_fd = mnt_open_tree(fd, subdir,
 AT_NO_AUTOMOUNT | AT_RECURSIVE | OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE,
 RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH);
""",
            "libmount/src/hook_mount.c": """
fd = mnt_open_tree(fd, api->subdir,
 OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE,
 RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH);
""",
        }

    def test_expected_four_cves_and_seven_sources(self):
        self.assertEqual(set(REQUIRED_CVES), {
            "CVE-2026-76642", "CVE-2026-78408",
            "CVE-2026-78409", "CVE-2026-78410",
        })
        self.assertEqual(set(SOURCE_NAMES), set(self.files))

    def test_positive_fixture_guards_only(self):
        status = check_cve_source_guards(self.files)
        self.assertEqual(set(status), set(REQUIRED_CVES))
        self.assertTrue(all(item["source_guard_present"] for item in status.values()))

    def test_post_mount_helper_exit_gate_fail_closed(self):
        bad = dict(self.files)
        bad["libmount/src/context_mount.c"] = bad[
            "libmount/src/context_mount.c"
        ].replace("!is_mount_stage_failed(cxt)", "1")
        self.assertFalse(check_cve_source_guards(bad)[
            "CVE-2026-76642"]["source_guard_present"])

    def test_nsenter_fd_cloexec_and_close_required(self):
        for old, new in (("O_CLOEXEC", "O_NONBLOCK"),
                         ("close(cgroup_procs_fd);", "/* removed */")):
            bad = dict(self.files)
            bad["sys-utils/nsenter.c"] = bad["sys-utils/nsenter.c"].replace(
                old, new
            )
            self.assertFalse(check_cve_source_guards(bad)[
                "CVE-2026-78408"]["source_guard_present"])

    def test_bind_source_must_resolve_without_symlinks(self):
        bad = dict(self.files)
        bad["libmount/src/context.c"] = bad["libmount/src/context.c"].replace(
            "RESOLVE_NO_SYMLINKS", "0"
        )
        self.assertFalse(check_cve_source_guards(bad)[
            "CVE-2026-78410"]["source_guard_present"])

    def test_subdir_must_have_beneath_and_no_intermediate_symlinks(self):
        for old, new in (("RESOLVE_BENEATH", "0"),
                         ("RESOLVE_NO_SYMLINKS", "0"),
                         ("while (*dir == '/')", "if (false)")):
            bad = dict(self.files)
            bad["libmount/src/hook_subdir.c"] = bad[
                "libmount/src/hook_subdir.c"
            ].replace(old, new)
            if old == "RESOLVE_BENEATH" or old == "RESOLVE_NO_SYMLINKS":
                bad["libmount/src/hook_mount.c"] = bad[
                    "libmount/src/hook_mount.c"
                ].replace(old, new)
            self.assertFalse(check_cve_source_guards(bad)[
                "CVE-2026-78409"]["source_guard_present"])

    def test_plain_open_tree_subdir_is_not_safe(self):
        bad = dict(self.files)
        bad["libmount/src/hook_subdir.c"] = bad[
            "libmount/src/hook_subdir.c"
        ].replace("mnt_open_tree(fd, subdir,", "open_tree(fd, subdir,")
        self.assertFalse(check_cve_source_guards(bad)[
            "CVE-2026-78409"]["source_guard_present"])

    def test_source_only_no_repair_claim(self):
        with tempfile.TemporaryDirectory(prefix="folio-r138-fixture-") as tmp:
            root = Path(tmp)
            for rel, body in self.files.items():
                file = root / rel
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(body)
            report = inspect_versioned_source(root)
        self.assertEqual(report["cve_guard_results"]["CVE-2026-78409"][
            "source_guard_present"], True)
        self.assertIs(report["release_authorized"], False)
        self.assertIs(report["cve_remediated"], False)
        self.assertIs(report["runtime_cve_regressions_passed"], False)


if __name__ == "__main__":
    unittest.main()
