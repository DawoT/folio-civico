"""R1.39: scope CVE-2026-78409 by *reachable restricted-user code*, not version string."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "apps/inspector"))
from util_linux_folio2_cve_regression import (
    check_cve_source_guards, inspect_versioned_source, SOURCE_NAMES,
)

# Illustrative C source fragments only, never live mount operations.
LEGACY_PRE = """
static int hook_mount_pre(
    struct libmnt_context *cxt,
    const struct libmnt_hookset *hs,
    void *data __attribute__((__unused__)))
{
    if (mnt_context_target_fd_required(cxt)) {
        DBG(HOOK, ul_debugobj(hs, "subdir mount refused for non-root user"));
        return -ENOTSUP;
    }
    hsd->org_target = strdup(mnt_fs_get_target(cxt->fs));
    if (!rc)
        rc = tmptgt_unshare(hsd);
    if (!rc)
        rc = mnt_context_append_hook(cxt, hs,
                MNT_STAGE_MOUNT_POST, NULL, hook_mount_post);
    return rc;
}
"""
LEGACY_PREPARE = """
static int hook_prepare_target(
    struct libmnt_context *cxt,
    const struct libmnt_hookset *hs,
    void *data __attribute__((__unused__)))
{
    rc = mnt_context_append_hook(cxt, hs,
            MNT_STAGE_MOUNT_PRE,
            NULL, hook_mount_pre);
    return rc;
}
"""
LEGACY_POST = """
static int hook_mount_post(
    struct libmnt_context *cxt,
    const struct libmnt_hookset *hs,
    void *data __attribute__((__unused__)))
{
    rc = do_mount_subdir(cxt, hsd, MNT_PATH_TMPTGT);
    return rc;
}
"""
LEGACY_SUBDIR = """
static int do_mount_subdir(struct libmnt_context *cxt, struct hookset_data *hsd, const char *root)
{
    int fd = open_tree(api->fd_tree, subdir,
        OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE);
    return fd;
}
""" + LEGACY_POST + LEGACY_PRE + LEGACY_PREPARE


def fixture() -> dict[str, str]:
    return {
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
int mnt_context_target_fd_required(struct libmnt_context *cxt)
{
 return mnt_context_is_restricted(cxt);
}
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
        "libmount/src/hook_subdir.c": LEGACY_SUBDIR,
        "libmount/src/hook_mount.c": """\
int create_mount(struct libmnt_context *cxt)
{
 return fsmount(0, 0, 0);
}
""",
    }


class CVEScopeTDD(unittest.TestCase):
    def test_legacy_restricted_user_refusal_is_not_a_missing_patch(self):
        report = check_cve_source_guards(fixture())
        row = report["CVE-2026-78409"]
        self.assertFalse(row["source_guard_present"])
        self.assertTrue(row["legacy_restricted_user_path_rejected"])
        self.assertEqual(row["applicability"], "not_affected_detached_fast_path_absent")
        self.assertFalse(row["affected_detached_fast_path_present"])
        self.assertFalse(row["runtime_exploit_regression_executed"])

    def test_report_always_keeps_security_gate_blocked(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for name, src in data.items():
                f = root / name
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(src)
            report = inspect_versioned_source(root)
        self.assertTrue(report["source_cve_paths_accounted_for"])
        self.assertFalse(report["all_source_guards_present"])
        self.assertEqual(report["unresolved_cve_paths"], [])
        self.assertFalse(report["release_authorized"])
        self.assertFalse(report["cve_remediated"])
        self.assertFalse(report["runtime_cve_regressions_passed"])
        self.assertFalse(report["debian_trixie_abi_validated"])
        self.assertEqual(report["security_gate"], "blocked")

    def test_unsafe_restricted_path_if_refusal_removed(self):
        values = fixture()
        values["libmount/src/hook_subdir.c"] = LEGACY_SUBDIR.replace(
            "return -ENOTSUP;", "return 0;"
        )
        row = check_cve_source_guards(values)["CVE-2026-78409"]
        self.assertEqual(row["applicability"], "unresolved")
        self.assertFalse(row["legacy_restricted_user_path_rejected"])

    def test_missing_pre_mount_registration_is_unresolved(self):
        values = fixture()
        values["libmount/src/hook_subdir.c"] = LEGACY_SUBDIR.replace(
            "MNT_STAGE_MOUNT_PRE", "MNT_STAGE_PREP_TARGET"
        )
        self.assertEqual(check_cve_source_guards(values)[
            "CVE-2026-78409"]["applicability"], "unresolved")

    def test_missing_post_mount_registration_is_unresolved(self):
        values = fixture()
        values["libmount/src/hook_subdir.c"] = LEGACY_SUBDIR.replace(
            "MNT_STAGE_MOUNT_POST", "MNT_STAGE_PREP_TARGET"
        )
        self.assertEqual(check_cve_source_guards(values)[
            "CVE-2026-78409"]["applicability"], "unresolved")

    def test_restricted_context_identity_must_not_be_stubbed(self):
        values = fixture()
        values["libmount/src/context.c"] = values["libmount/src/context.c"].replace(
            "return mnt_context_is_restricted(cxt);", "return 0;"
        )
        self.assertEqual(check_cve_source_guards(values)[
            "CVE-2026-78409"]["applicability"], "unresolved")

    def test_restricted_user_must_be_rejected_before_namespace_change(self):
        values = fixture()
        values["libmount/src/hook_subdir.c"] = LEGACY_SUBDIR.replace(
            "    if (mnt_context_target_fd_required(cxt)) {",
            "    rc = tmptgt_unshare(hsd);\n    if (mnt_context_target_fd_required(cxt)) {"
        )
        self.assertEqual(check_cve_source_guards(values)[
            "CVE-2026-78409"]["applicability"], "unresolved")

    def test_detached_v242_path_is_not_exempted_as_legacy(self):
        values = fixture()
        values["libmount/src/hook_mount.c"] += """
if (fd >= 0 && api->subdir) {
 int sub_fd = open_tree(fd, api->subdir,
   AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW |
   AT_RECURSIVE | OPEN_TREE_CLOEXEC | OPEN_TREE_CLONE);
}
"""
        row = check_cve_source_guards(values)["CVE-2026-78409"]
        self.assertEqual(row["applicability"], "unresolved")
        self.assertTrue(row["affected_detached_fast_path_present"])

    def test_commented_fake_function_cannot_fake_restricted_guard(self):
        values = fixture()
        old = values["libmount/src/context.c"]
        values["libmount/src/context.c"] = (
            "/*\nint mnt_context_target_fd_required(struct libmnt_context *cxt)\n"
            "{\n return mnt_context_is_restricted(cxt);\n}\n*/\n"
            + old.replace("return mnt_context_is_restricted(cxt);", "return 0;")
        )
        self.assertEqual(check_cve_source_guards(values)[
            "CVE-2026-78409"]["applicability"], "unresolved")

    def test_source_input_set_still_fail_closed(self):
        values = fixture()
        values.pop("libmount/src/hook_mount.c")
        with self.assertRaises(ValueError):
            check_cve_source_guards(values)

    def test_legacy_path_other_callers_make_scope_unresolved(self):
        values = fixture()
        values["libmount/src/hook_subdir.c"] += """
static int another_entrypoint(struct libmnt_context *cxt) {
 return do_mount_subdir(cxt, hsd, MNT_PATH_TMPTGT);
}
"""
        row = check_cve_source_guards(values)["CVE-2026-78409"]
        self.assertEqual(row["applicability"], "unresolved")


if __name__ == "__main__":
    unittest.main()
