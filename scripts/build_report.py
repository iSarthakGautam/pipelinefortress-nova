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
TITLE = """---
title: "PipelineFortress: Secure CI/CD with GenAI-Assisted Triage"
subtitle: "CAP-DSE-3W, IIT Roorkee × Futurense, DevSecOps Essentials"
author:
  - "Amirdeshwara R"
  - "Inderdeep Singh"
  - "Rajdeep Kaur"
  - "Rohit Singhal"
  - "Sarthak Gautam"
team: "Team Nova"
date: "October 2026"
repository: "https://github.com/iSarthakGautam/pipelinefortress-nova"
---

# PipelineFortress: Secure CI/CD with GenAI-Assisted Triage
**DevSecOps Essentials Capstone Project (CAP-DSE-3W)**  
*IIT Roorkee × Futurense*

**Team Nova:** Amirdeshwara R, Inderdeep Singh, Rajdeep Kaur, Rohit Singhal, Sarthak Gautam  
**Date:** October 2026 | **Repository:** [https://github.com/iSarthakGautam/pipelinefortress-nova](https://github.com/iSarthakGautam/pipelinefortress-nova)

---


"""
WORDS_PER_PAGE = 500


def assemble() -> str:
    out = [TITLE]
    for rel in PARTS:
        path = ROOT / rel
        if not path.is_file():
            sys.exit(f"missing report part: {rel}")
        out.append(path.read_text(encoding="utf-8").strip() + "\n\n\\newpage\n")
    return "\n".join(out)



def sync_to_docs(build: Path, root: Path) -> None:
    docs = root / "docs"
    for src_name, dst_names in [
        ("report.md", ["REPORT.md", "report.md"]),
        ("report.html", ["REPORT.html", "report.html"]),
        ("report.pdf", ["REPORT.pdf", "report.pdf"]),
    ]:
        src = build / src_name
        if src.is_file():
            for d in dst_names:
                shutil.copy2(src, docs / d)
    for img in [
        "01-system-context.svg",
        "02-triage-internals.svg",
        "03-redaction-egress.svg",
        "04-grounding-validator.svg",
        "05-schema-ownership.svg",
        "ci-pipeline-run.png",
        "grafana-pipelinefortress-dashboard.png",
    ]:
        src = build / img
        if src.is_file():
            shutil.copy2(src, docs / img)


def main() -> int:
    text = assemble()
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    md = build / "report.md"
    md.write_text(text, encoding="utf-8")
    words = len(text.split())
    print(f"wrote {md.relative_to(ROOT)}: {words} words, about {words / WORDS_PER_PAGE:.0f} pages at {WORDS_PER_PAGE} words/page "
          "(tables and diagrams add more)")
    demo_dir = ROOT / "docs" / "demo"
    if demo_dir.is_dir():
        for svg in demo_dir.glob("*.svg"):
            shutil.copy2(svg, build / svg.name)
    ci_img = ROOT / "artifacts" / "evidence" / "github-actions-ci-pipeline-run.png"
    if ci_img.is_file():
        shutil.copy2(ci_img, build / "ci-pipeline-run.png")
    grafana_img = ROOT / "artifacts" / "evidence" / "grafana-pipelinefortress-dashboard.png"
    if grafana_img.is_file():
        shutil.copy2(grafana_img, build / "grafana-pipelinefortress-dashboard.png")
    pandoc = shutil.which("pandoc")
    html = build / "report.html"
    pdf = build / "report.pdf"
    if not pandoc:
        chrome_paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            shutil.which("google-chrome"),
            shutil.which("chromium"),
        ]
        chrome = next((p for p in chrome_paths if p and Path(p).is_file()), None)
        if chrome and html.is_file():
            subprocess.run([
                str(chrome), "--headless", "--disable-gpu", "--no-pdf-header-footer",
                f"--print-to-pdf={pdf}", f"file://{html.resolve()}"
            ], capture_output=True)
            if pdf.is_file():
                print(f"wrote {pdf.relative_to(ROOT)} (via headless Chrome)")
        sync_to_docs(build, ROOT)
        print("synced report deliverables (REPORT.md, REPORT.html, REPORT.pdf) to docs/")
        return 0
    subprocess.run([pandoc, str(md), "-o", str(html), "--standalone", "--toc", "--metadata", "pagetitle=PipelineFortress"], check=True)
    print(f"wrote {html.relative_to(ROOT)}")
    r = subprocess.run([pandoc, str(md), "-o", str(pdf), "--toc"], capture_output=True, text=True)
    print(f"wrote {pdf.relative_to(ROOT)}" if r.returncode == 0 else f"PDF skipped (no LaTeX engine?): {r.stderr.strip()[:120]}")
    sync_to_docs(build, ROOT)
    print("synced report deliverables (REPORT.md, REPORT.html, REPORT.pdf) to docs/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
