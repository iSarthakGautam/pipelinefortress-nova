import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "demo" / "index.html").read_text(encoding="utf-8")
SLIDES = re.findall(r'<section class="slide"([^>]*)>(.*?)</section>', HTML, re.S)


class TestDemoDeck(unittest.TestCase):

    def test_twenty_slides_each_with_title_time_and_notes(self):
        self.assertEqual(len(SLIDES), 20)
        titles = []
        for attrs, body in SLIDES:
            titles.append(re.search(r'data-title="([^"]+)"', attrs).group(1))
            self.assertRegex(attrs, r'data-time="\d+"')
            self.assertIn('class="notes"', body, titles[-1])
        self.assertEqual(len(set(titles)), 20)
        self.assertIn('<div id="count">1 / 20</div>', HTML)

    def test_main_path_is_about_nine_minutes(self):
        total = sum(int(re.search(r'data-time="(\d+)"', a).group(1)) for a, _ in SLIDES)
        self.assertTrue(480 <= total <= 540, total)   # DEMO_SCRIPT.md promises 8:40

    def test_team_slide_has_five_empty_name_fields_and_nova_is_on_the_cover(self):
        names = re.findall(r'<input class="name" data-key="(r\d)"([^>]*)>', HTML)
        self.assertEqual([k for k, _ in names], ["r1", "r2", "r3", "r4", "r5"])
        self.assertTrue(all('value=' not in rest for _, rest in names))
        self.assertIn("Team Nova", SLIDES[0][1])

    def test_removed_text_stays_removed(self):
        self.assertNotIn("production-ready", HTML)
        self.assertNotIn('id="hint"', HTML)
        self.assertNotIn("navigate · A attack", HTML)

    def test_pdf_and_fullscreen_buttons_and_print_stylesheet_exist(self):
        self.assertIn('id="btnPdf"', HTML)
        css = (ROOT / "demo/css/style.css").read_text(encoding="utf-8")
        self.assertIn("@media print", css)
        self.assertIn("size: 1280px 720px", css)

    def test_no_external_resources(self):
        # the deck must work offline: no http(s) src/href/url() except plain text
        self.assertEqual(re.findall(r'(?:src|href)="https?://[^"]+"', HTML), [])
        self.assertNotIn("url(http", (ROOT / "demo/css/style.css").read_text(encoding="utf-8"))

    def test_every_autorun_attack_has_a_matching_step(self):
        for attrs, body in SLIDES:
            for n in re.findall(r'data-autorun="(\d+)"', body):
                self.assertTrue(int(n) >= 1)

    def test_script_mentions_every_slide_title_keyword(self):
        script = (ROOT / "demo/DEMO_SCRIPT.md").read_text(encoding="utf-8")
        for n in range(1, 21):
            self.assertRegex(script, rf"###\s+{n}\s+·", n)
        self.assertNotIn("production-ready", script)


class TestResultsPage(unittest.TestCase):

    def test_results_page_builds_from_repo_data(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "results.html"
            r = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/build_demo_results.py"), "--out", str(out)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            page = out.read_text(encoding="utf-8")
            for needle in ("Pre-merge catch rate", "Noise to signal", "bake-off", "Runtime proof", "Team Nova"):
                self.assertIn(needle, page)
            self.assertNotIn("&amp;rarr;", page)    # header escaping bug
            self.assertEqual(re.findall(r'(?:src|href)="https?://', page), [])


if __name__ == "__main__":
    unittest.main()
