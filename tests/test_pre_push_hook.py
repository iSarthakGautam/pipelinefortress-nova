"""The pre-push hook refuses pushes that land on main, judged by the refs pushed, not by the
checked-out branch. Runs real `git push` against a local bare remote."""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import install_hooks as ih  # noqa: E402


@unittest.skipUnless(shutil.which("git"), "git not installed")
class TestPrePushHook(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.git("init", "-q", "--bare", "-b", "main", str(self.tmp / "remote.git"), cwd=self.tmp)
        self.work = self.tmp / "work"
        self.git("init", "-q", "-b", "main", str(self.work), cwd=self.tmp)
        self.git("remote", "add", "origin", str(self.tmp / "remote.git"))
        for k, v in (("user.name", "t"), ("user.email", "t@example.invalid"), ("commit.gpgsign", "false")):
            self.git("config", k, v)
        self.git("commit", "-q", "--allow-empty", "-m", "init")
        self.git("push", "-q", "origin", "main")              # seed the remote before the hook exists
        hook = self.work / ".git" / "hooks" / "pre-push"
        hook.write_text(ih.PRE_PUSH, encoding="utf-8", newline="\n")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.git("checkout", "-q", "-b", "feature")
        self.git("commit", "-q", "--allow-empty", "-m", "work")

    def git(self, *args, cwd=None, check=True):
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        p = subprocess.run(["git", *args], cwd=cwd or self.work, capture_output=True, text=True, env=env)
        if check and p.returncode != 0:
            raise AssertionError(f"git {' '.join(args)} failed: {p.stderr}")
        return p

    def push(self, *refspec):
        return self.git("push", "origin", *refspec, check=False)

    def assert_refused(self, p):
        assert p.returncode != 0, p.stderr
        assert "Direct pushes to main are forbidden" in p.stderr

    def test_feature_branch_push_is_allowed(self):
        assert self.push("feature").returncode == 0

    def test_refspec_onto_main_from_a_feature_branch_is_refused(self):
        self.assert_refused(self.push("feature:main"))
        self.assert_refused(self.push("HEAD:refs/heads/main"))

    def test_pushing_main_while_on_another_branch_is_refused(self):
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--ff-only", "feature")
        self.git("checkout", "-q", "feature")
        self.assert_refused(self.push("main"))

    def test_feature_push_while_main_is_checked_out_is_allowed(self):
        self.git("checkout", "-q", "main")
        assert self.push("feature").returncode == 0

    def test_one_main_ref_in_a_multi_ref_push_refuses_all(self):
        self.git("branch", "other")
        self.assert_refused(self.push("other", "feature:main"))
        remote = self.git("ls-remote", "--heads", "origin").stdout
        assert "refs/heads/other" not in remote


if __name__ == "__main__":
    unittest.main()
