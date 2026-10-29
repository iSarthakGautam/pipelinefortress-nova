#!/usr/bin/env python3
"""Assemble the final report from its Markdown parts and, if pandoc is installed, render HTML and PDF.

  python3 scripts/build_report.py            # writes build/report.md (+ build/report.html, build/report.pdf if possible)

Parts live in docs/report/ (R5 integrates; each role owns its sections). The two long role drafts are included as they are.
Prints the word count and an estimated page count so the 14-18 page requirement can be checked.
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARTS = [
    "docs/report/00-executive-summary.md",
    "docs/report/01-problem-and-context.md",
    "docs/report/02-threat-model.md",
    "docs/report/03-architecture.md",
    "docs/REPORT_DRAFT_SECTION_5.md",
    "docs/report/05-container-iac.md",
    "docs/REPORT_DRAFT_SECTIONS_7_9.md",
    "docs/report/10-maturity-self-assessment.md",
    "docs/report/11-limitations.md",
    "docs/report/12-ai-disclosure.md",
    "docs/report/13-future-work.md",
    "docs/BASELINE_VULNERABILITY_REPORT.md",
    "docs/AI_DISCLOSURE.md",
]
TITLE = "---\ntitle: \"PipelineFortress: Secure CI/CD with GenAI-Assisted Triage\"\nsubtitle: \"CAP-DSE-3W, IIT Roorkee x Futurense, DevSecOps Essentials\"\n---\n\n"
WORDS_PER_PAGE = 500


def assemble() -> str:
    out = [TITLE]
    for rel in PARTS:
        path = ROOT / rel
        if not path.is_file():
            sys.exit(f"missing report part: {rel}")
        out.append(path.read_text(encoding="utf-8").strip() + "\n\n\\newpage\n")
    return "\n".join(out)


def main() -> int:
    text = assemble()
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    md = build / "report.md"
    md.write_text(text, encoding="utf-8")
    words = len(text.split())
    print(f"wrote {md.relative_to(ROOT)}: {words} words, about {words / WORDS_PER_PAGE:.0f} pages at {WORDS_PER_PAGE} words/page "
          "(tables and diagrams add more)")
    pandoc = shutil.which("pandoc")
    if not pandoc:
        print("pandoc not installed: only the Markdown was written")
        return 0
    html = build / "report.html"
    subprocess.run([pandoc, str(md), "-o", str(html), "--standalone", "--toc", "--metadata", "pagetitle=PipelineFortress"], check=True)
    print(f"wrote {html.relative_to(ROOT)}")
    pdf = build / "report.pdf"
    r = subprocess.run([pandoc, str(md), "-o", str(pdf), "--toc"], capture_output=True, text=True)
    print(f"wrote {pdf.relative_to(ROOT)}" if r.returncode == 0 else f"PDF skipped (no LaTeX engine?): {r.stderr.strip()[:120]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
