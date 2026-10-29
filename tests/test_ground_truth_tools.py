import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GT = ROOT / "eval" / "ground_truth"
POP = ROOT / "docs/metrics/data/candidate-population-2026-10-29/population.csv"


def run(script, *args):
    return subprocess.run([sys.executable, "-B", str(GT / script), *map(str, args)], capture_output=True, text=True)


class TestGroundTruthTools(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_sample_is_one_row_per_group_and_deterministic(self):
        r = run("sample_population.py", POP, "--out-dir", self.tmp / "s")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = json.loads((self.tmp / "s" / "sampling_manifest.json").read_text())
        self.assertEqual((m["population_findings"], m["duplicate_groups"], m["drawn"]), (264, 98, 98))
        rows = [json.loads(ln) for ln in (self.tmp / "s" / "sample.jsonl").read_text().splitlines()]
        self.assertEqual(len({r["duplicate_group"] for r in rows}), 98)
        run("sample_population.py", POP, "--out-dir", self.tmp / "t", "--n", 40, "--seed", 7)
        run("sample_population.py", POP, "--out-dir", self.tmp / "u", "--n", 40, "--seed", 7)
        self.assertEqual((self.tmp / "t" / "sample.jsonl").read_text(), (self.tmp / "u" / "sample.jsonl").read_text())

    def test_label_sheets_are_separate_and_blank(self):
        run("sample_population.py", POP, "--out-dir", self.tmp / "s")
        for name in ("a", "b"):
            with open(self.tmp / "s" / f"labels_reviewer_{name}.csv", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertTrue(all(not r[f"reviewer_{name}_label"] for r in rows))

    def test_pipeline_sample_to_split_to_kappa(self):
        run("sample_population.py", POP, "--out-dir", self.tmp / "s")
        sheets = {}
        for name in ("a", "b"):
            with open(self.tmp / "s" / f"labels_reviewer_{name}.csv", newline="") as f:
                sheets[name] = list(csv.DictReader(f))
        for i, (ra, rb) in enumerate(zip(sheets["a"], sheets["b"])):
            ra["reviewer_a_label"] = "TRUE_POSITIVE"
            rb["reviewer_b_label"] = "TRUE_POSITIVE" if i % 5 else "FALSE_POSITIVE"
        for name, rows in sheets.items():
            with open(self.tmp / f"{name}.csv", "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=rows[0].keys())
                w.writeheader()
                w.writerows(rows)
        s = self.tmp / "s" / "sample.jsonl"
        r = run("merge_labels.py", self.tmp / "a.csv", self.tmp / "b.csv", "--sample", s, "--out", self.tmp / "gt.jsonl")
        self.assertEqual(r.returncode, 1)               # disagreements, no adjudication: must refuse to freeze
        self.assertIn("needs adjudication", r.stderr)
        with open(self.tmp / "adj.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["finding_id", "adjudicated_label"])
            for ra, rb in zip(sheets["a"], sheets["b"]):
                w.writerow([ra["finding_id"], "FALSE_POSITIVE"])
        r = run("merge_labels.py", self.tmp / "a.csv", self.tmp / "b.csv", "--sample", s, "--out", self.tmp / "gt.jsonl",
                "--adjudicated", self.tmp / "adj.csv")
        self.assertEqual(r.returncode, 0, r.stderr)
        k = run("cohen_kappa.py", self.tmp / "a.csv")
        self.assertNotEqual(k.returncode, 0)             # wrong columns for the default names -> clean failure, not a crash trace
        k = subprocess.run([sys.executable, "-B", str(GT / "cohen_kappa.py"), str(self.tmp / "a.csv"), "--a", "reviewer_a_label",
                            "--b", "reviewer_a_label"], capture_output=True, text=True)
        self.assertIn('"cohens_kappa"', k.stdout)


if __name__ == "__main__":
    unittest.main()
