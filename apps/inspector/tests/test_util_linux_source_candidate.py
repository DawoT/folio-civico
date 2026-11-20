"""R1.32: deterministic source candidate proof, NOT a Debian fix or VEX."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"apps/inspector"))

from util_linux_source_candidate import (
    VERSION, TAR_SHA256, PATCH_SHA256, SIGNER_FINGERPRINT,
    AUTOSIGNER_FINGERPRINT, PATCH_COMMIT, ORIGINAL_NSENTER_SHA256,
    PATCHED_NSENTER_SHA256, CVES, _manifest_digest,
    _assert_primary_key, _valid_signature_status, _patch_identity,
    _assert_cve_source_semantics,
)


def sample_sources():
    return {
        "libmount/src/context_mount.c":"""
            if (res == 0 && !is_mount_stage_failed(cxt)) {
                rc = mnt_context_call_hooks(cxt, MNT_STAGE_MOUNT_POST);
            }
            """,
        "libmount/src/context.c":"""
            mnt_context_is_restricted(cxt) ? RESOLVE_NO_SYMLINKS : 0);
            """,
        "libmount/src/utils.c":"""
            pin_fd = ul_openat_resolve(dirfd, path, O_PATH, 0, resolve);
            """,
        "lib/fileutils.c":"""
            return openat2(dirfd, path, &how, sizeof(how));
            """,
        "sys-utils/unshare.c":"""
            fd = open(file, O_WRONLY | O_CLOEXEC);
            """,
        "sys-utils/nsenter.c":"""
            static int cgroup_procs_fd = -1;
            open_target_fd(&cgroup_fd, "cgroup", optarg);
            close(cgroup_fd);
            cgroup_procs_fd = open(fdpath, O_WRONLY | O_APPEND | O_CLOEXEC);
            if (cgroup_procs_fd >= 0) {
                join_into_cgroup();
                close(cgroup_procs_fd);
                cgroup_procs_fd = -1;
            }
            if (force_gid && setgid(gid) < 0)
                err(EXIT_FAILURE, "gid");
            if (force_uid && setuid(uid) < 0)
                err(EXIT_FAILURE, "uid");
            if (optind < argc)
                execvp(argv[optind], argv + optind);
            """,
    }


class SignedCandidateTDD(unittest.TestCase):
    def test_source_release_and_patch_commit_are_immutably_pinned(self):
        self.assertEqual(VERSION,"2.41.6")
        self.assertEqual(
            TAR_SHA256,
            "e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed",
        )
        self.assertEqual(
            PATCH_SHA256,
            "0b30248db96c77926ab9ad33474003bb1b13d652368dc754a84ac51ec61f7220",
        )
        self.assertEqual(SIGNER_FINGERPRINT,
                         "B0C64D14301CC6EFAEDF60E4E4B71D5EEC39C284")
        self.assertEqual(AUTOSIGNER_FINGERPRINT,
                         "B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1")
        self.assertEqual(PATCH_COMMIT,
                         "485dbb67f1b6bb18e08b1b77f4aa2373ff3a705b")
        self.assertEqual(ORIGINAL_NSENTER_SHA256,
                         "9de70a7aaeebc492ee4eaff3597c82d290aa150bd04f1c91b782f19c5348c390")
        self.assertEqual(PATCHED_NSENTER_SHA256,
                         "070fb7c5fac3dfcebaff3ae008999fac21bf4d1e5e01ee4dfb0aa225555a2d0c")
        self.assertEqual(CVES,(
            "CVE-2026-76642","CVE-2026-78408",
            "CVE-2026-78409","CVE-2026-78410",
        ))

    def test_signed_manifest_rejects_different_hash_and_duplicates(self):
        line=TAR_SHA256+"  util-linux-2.41.6.tar.xz"
        self.assertEqual(_manifest_digest(line+"\n"),TAR_SHA256)
        for bad in (
            "",line+"\n"+line+"\n",
            TAR_SHA256+"  util-linux-2.41.5.tar.xz\n",
            "x"*64+"  util-linux-2.41.6.tar.xz\n",
            "0"*64+"  util-linux-2.41.6.tar.xz\n"+line,
        ):
            with self.subTest(bad=bad[:50]):
                with self.assertRaises(ValueError):
                    _manifest_digest(bad)

    def test_exact_primary_key_fingerprints_from_independent_sources(self):
        good="pub:-:4096:1:A:...\nfpr:::::::::"+SIGNER_FINGERPRINT+":\n"
        self.assertEqual(_assert_primary_key(good,SIGNER_FINGERPRINT),
                         SIGNER_FINGERPRINT)
        for wrong in (good.replace(SIGNER_FINGERPRINT,"0"*40),
                      good+"\npub:-:4096:1:B:...\nfpr:::::::::"+SIGNER_FINGERPRINT+":\n",
                      "sub:-:4096:1:A:\nfpr:::::::::"+SIGNER_FINGERPRINT+":\n"):
            with self.assertRaises(ValueError):
                _assert_primary_key(wrong,SIGNER_FINGERPRINT)

    def test_validsig_not_just_goodsig_or_key_id(self):
        good="[GNUPG:] GOODSIG E4B71D5EEC39C284 Karel Zak\n[GNUPG:] VALIDSIG "+SIGNER_FINGERPRINT+" 2026-09-01 1788260630 0 4 0 1 10 00 "+SIGNER_FINGERPRINT
        self.assertTrue(_valid_signature_status(good,SIGNER_FINGERPRINT))
        for invalid in (
            good.replace("VALIDSIG","BADSIG"),
            good.replace(SIGNER_FINGERPRINT,"0"*40),
            "[GNUPG:] GOODSIG E4B71D5EEC39C284 Karel Zak",
            good+"\n[GNUPG:] BADSIG E4B71D5EEC39C284 Karel Zak",
        ):
            self.assertFalse(_valid_signature_status(invalid,SIGNER_FINGERPRINT))

    def test_patch_requires_exact_commit_and_only_nsenter_file(self):
        patch=("From "+PATCH_COMMIT+" Mon Sep 17 00:00:00 2001\n"
               "Subject: [PATCH] nsenter: close cgroup.procs fd [CVE-2026-78408]\n"
               "diff --git a/sys-utils/nsenter.c b/sys-utils/nsenter.c\n"
               "+close(cgroup_procs_fd);\n")
        _patch_identity(patch,hashlib.sha256(patch.encode()).hexdigest())
        for bad in (
            patch.replace(PATCH_COMMIT,"0"*40),
            patch.replace("CVE-2026-78408","CVE-0000-00000"),
            patch+"diff --git a/sys-utils/unshare.c b/sys-utils/unshare.c\n",
        ):
            with self.assertRaises(ValueError):
                _patch_identity(bad,hashlib.sha256(bad.encode()).hexdigest())
        with self.assertRaises(ValueError):
            _patch_identity(patch,"0"*64)

    def test_cve_source_checks_reject_incomplete_2416_and_patch_tamper(self):
        _assert_cve_source_semantics(sample_sources())
        changes=(
            ("sys-utils/nsenter.c","close(cgroup_procs_fd);",""),
            ("sys-utils/nsenter.c","close(cgroup_fd);",""),
            ("sys-utils/nsenter.c","O_APPEND | O_CLOEXEC","O_APPEND"),
            ("libmount/src/context_mount.c","res == 0 && !is_mount_stage_failed(cxt)","res == 0"),
            ("libmount/src/context.c","RESOLVE_NO_SYMLINKS","0"),
            ("libmount/src/utils.c","ul_openat_resolve","openat"),
            ("sys-utils/unshare.c","O_CLOEXEC","0"),
        )
        for file,before,after in changes:
            with self.subTest(file=file,before=before):
                src=sample_sources()
                src[file]=src[file].replace(before,after)
                with self.assertRaises(ValueError):
                    _assert_cve_source_semantics(src)

    def test_native_compile_probe_is_local_only_and_release_blocked(self):
        script=(ROOT/"apps/inspector/build_util_linux_nsenter_source_smoke.sh").read_text()
        for token in (
            "util_linux_source_candidate.py","--disable-all-programs",
            "--enable-nsenter","--disable-libmount",
            "--disable-libuuid","make","--version","--help",
            "exit 2",
        ):
            self.assertIn(token,script)
        for forbidden in (
            "sudo ","dpkg -i","apt-get install","docker push","wrangler deploy",
            "make install","--ignore-unfixed","--ignorefile",
        ):
            self.assertNotIn(forbidden,script)
        p=subprocess.run(
            ["bash","apps/inspector/build_util_linux_nsenter_source_smoke.sh","--bad"],
            cwd=ROOT,capture_output=True,text=True,timeout=8,
        )
        self.assertEqual(p.returncode,3)

    def test_cli_is_fail_closed_no_artifacts_and_never_release(self):
        with tempfile.TemporaryDirectory() as d:
            result=subprocess.run(
                ["python3","apps/inspector/util_linux_source_candidate.py",
                 "--artifacts-dir",d],
                cwd=ROOT,capture_output=True,text=True,timeout=15,
            )
            self.assertEqual(result.returncode,3)
            self.assertIn("source_candidate_invalid",result.stdout)
        script=(ROOT/"apps/inspector/fetch_util_linux_source_candidate.sh").read_text()
        for expected in (
            "util-linux-2.41.6.tar.xz","sha256sums.asc","485dbb67",
            "util_linux_source_candidate.py","--proto '=https'",
        ):
            self.assertIn(expected,script)
        for forbidden in (
            "docker push","wrangler deploy","apt-get install",
            "dpkg -i","--ignorefile","--ignore-unfixed",
        ):
            self.assertNotIn(forbidden,script)
        p=subprocess.run(
            ["bash","apps/inspector/fetch_util_linux_source_candidate.sh","--bad"],
            cwd=ROOT,capture_output=True,text=True,timeout=8,
        )
        self.assertEqual(p.returncode,3)


if __name__=="__main__":
    unittest.main()
