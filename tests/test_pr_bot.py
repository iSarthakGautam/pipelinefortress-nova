import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "ai"))

import pr_bot

OLD = '{\n    "name": "x",\n    "dependencies": {\n        "lodash": "4.17.15"\n    }\n}\n'
NEW = OLD.replace("4.17.15", "4.17.21")


class TestPrBot(unittest.TestCase):

    def test_extract_file_strips_a_markdown_fence(self):
        self.assertEqual(pr_bot.extract_file("```json\n" + NEW.rstrip("\n") + "\n```"), NEW)
        self.assertEqual(pr_bot.extract_file(NEW), NEW)
        self.assertIsNone(pr_bot.extract_file("   \n"))

    def test_echoed_data_frame_is_unwrapped_or_refused(self):
        # regression: llama3 echoed <UNTRUSTED_INPUT_DATA>{json}</UNTRUSTED_INPUT_DATA> as the "file", and the garbage
        # diff still passed `git apply --check`, so "applies cleanly" alone proved nothing
        wrapped = '<UNTRUSTED_INPUT_DATA>\n{"content": "a\\nb\\n", "file": "x"}\n</UNTRUSTED_INPUT_DATA>'
        self.assertEqual(pr_bot.extract_file(wrapped), "a\nb\n")
        self.assertIsNone(pr_bot.extract_file("<UNTRUSTED_INPUT_DATA>\nnot json\n</UNTRUSTED_INPUT_DATA>"))
        self.assertIsNone(pr_bot.extract_file("line\n</UNTRUSTED_INPUT_DATA>\n"))

    def test_lines_changed_counts_only_real_changes(self):
        self.assertEqual(pr_bot.lines_changed(pr_bot.make_diff("package.json", OLD, NEW)), 2)

    def test_unchanged_file_yields_no_diff(self):
        self.assertIsNone(pr_bot.make_diff("package.json", OLD, OLD))

    def test_computed_diff_always_applies(self):
        # regression: the model wrote the hunk headers itself and 4 of 4 patches were "corrupt patch"
        diff = pr_bot.make_diff("package.json", OLD, NEW)
        self.assertIn("@@", diff)
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as f:
                f.write(OLD)
            p = subprocess.run(["git", "apply", "-"], input=diff, cwd=d, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(os.path.join(d, "package.json"), encoding="utf-8") as f:
                self.assertEqual(f.read(), NEW)

    def test_draft_pr_end_to_end_with_a_stubbed_model(self):
        reply = {"ok": True, "digest": "sha256:" + "ab" * 32}
        task = {"pr_id": "PR-T", "target": "package.json", "finding": "f", "ask": "bump lodash"}
        fixture = os.path.join(pr_bot.FIXTURES, "package.json")
        with open(fixture, encoding="utf-8") as f:
            real = f.read()
        reply["raw"] = "```\n" + real.replace("4.17.15", "4.17.21").rstrip("\n") + "\n```"
        with mock.patch.object(pr_bot.llm_client, "chat", return_value=reply):
            pr = pr_bot.draft_pr(task, pr_bot.load_patch_prompt(), "m")
        self.assertTrue(pr["applies_cleanly"], pr["apply_error"])
        self.assertEqual(pr["human_review_notes"]["verdict"], "PENDING")   # the bot never reviews its own work
        self.assertEqual(pr["prompt_version"], "patch_draft_v2")

    def test_default_output_dir_does_not_clobber_reviewed_v1(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(pr_bot, "ROOT", d), \
                mock.patch.object(pr_bot, "draft_pr", side_effect=lambda t, p, m: {
                    **t, "model": "m", "prompt_version": "v", "prompt_sha256": "x", "diff": None, "raw_model_output": "",
                    "applies_cleanly": False, "apply_error": "none", "lines_changed": 0, "status": "DRAFT_UNREVIEWED",
                    "human_review_notes": {"reviewer": None, "verdict": "PENDING", "comments": None}}):
            pr_bot.export_prs(model="m")
            self.assertTrue(os.path.isfile(os.path.join(d, "artifacts", "prs", "v2", "PR_REGISTER.md")))
            self.assertFalse(os.path.exists(os.path.join(d, "artifacts", "prs", "PR_REGISTER.md")))


if __name__ == "__main__":
    unittest.main()
