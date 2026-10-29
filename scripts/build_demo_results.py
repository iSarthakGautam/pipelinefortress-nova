#!/usr/bin/env python3
"""Build demo/results.html: a self-contained "results dashboard" for the live demo, from the repository's real data.

  python3 scripts/build_demo_results.py        # writes demo/results.html (open it in a second window)

Every number is read from a committed file at build time (nothing is typed in by hand except where a panel names its source):
  catch rate     eval/metrics/catch_rate.py on docs/metrics/data/gate-tuning-2026-10-27/findings-main-1bb3381.json
                 (override with --findings <latest CI artifact findings.json>)
  funnel         docs/metrics/data/candidate-population-2026-10-29/population.csv
  bake-off       eval/results/*.jsonl (frozen real model runs)
  runtime proof  artifacts/evidence/runtime/*-runtime-baseline.json
  AI metrics     artifacts/demo/out/metrics.prom (from `make demo-local`)
  PR bot         artifacts/prs/v2/pr_register.json
The page needs no network and no server. Grafana (`make dash`) is the live-dashboard alternative; this is the offline twin.
"""
import argparse
import csv
import html
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "eval" / "metrics"))
sys.path.insert(0, str(ROOT / "ai"))

import catch_rate as cr  # noqa: E402
import run_eval as ev  # noqa: E402
import yaml  # noqa: E402

E = html.escape
SNAP = ROOT / "docs/metrics/data/gate-tuning-2026-10-27/findings-main-1bb3381.json"
POP = ROOT / "docs/metrics/data/candidate-population-2026-10-29/population.csv"
SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COL = {"CRITICAL": "#fb4a68", "HIGH": "#f97316", "MEDIUM": "#fbbf24", "LOW": "#60a5fa"}


def panel(title, body, cls="", sub=""):
    return f'<section class="panel {cls}"><h2>{E(title)}</h2>{f"<p class=sub>{sub}</p>" if sub else ""}{body}</section>'


def table(head, rows, cls=""):
    th = "".join(f"<th>{h}</th>" for h in head)
    tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table>'


def bars(items, width=190):
    top = max((v for _, v, _ in items), default=1) or 1
    out = []
    for label, v, col in items:
        w = max(2, int(width * v / top))
        out.append(f'<div class="bar"><span class="bl">{E(label)}</span><span class="bf" style="width:{w}px;background:{col}"></span><b>{v}</b></div>')
    return "".join(out)


def catch_panel(findings, src):
    planted = yaml.safe_load((ROOT / "ground_truth/planted.yaml").read_text(encoding="utf-8"))["planted_vulnerabilities"]
    rows = cr.evaluate(findings, planted)
    s = cr.summarise(rows)
    body = [f'<div class="kpis"><div class="kpi g"><b>{s["caught"]}/{s["planted"]}</b><span>planted vulns caught pre-merge</span></div>'
            f'<div class="kpi"><b>{s["blocking"]}/{s["planted"]}</b><span>would block the merge (&ge; HIGH)</span></div>'
            f'<div class="kpi"><b>{s["false_alarms"]}/{s["controls"]}</b><span>safe controls flagged</span></div></div>']
    trs = []
    for r in rows:
        ok = r["match"] is not None
        control = r["expected"] == "FALSE_POSITIVE"
        status = ("not flagged (good)" if control and not ok else "FLAGGED (false alarm)" if control else (r["match"] if ok else "<b class=bad>missed</b>"))
        trs.append([E(r["id"]), E(r["name"]), E(r["expected"].replace("_", " ").lower()), status, E(", ".join(r["tools"]) or "-"), E(r["max_severity"] or "-")])
    body.append(table(["ID", "Planted item", "Expected", "Matched as", "Tools", "Max severity"], trs))
    return panel("Pre-merge catch rate vs the planted vulnerabilities", "".join(body), "wide",
                 f"Source: <code>{E(src)}</code> &middot; recall on things <b>we planted</b>, 3 of 10 catalogued after tuning &middot; not a general false-negative rate. On this 2026-10-27 snapshot PLANT-005 (lodash) was not scanned yet and PLANT-012 had moved lines: re-run with <code>--findings</code> on the latest CI artifact")


def funnel_panel():
    rows = list(csv.DictReader(open(POP, newline="", encoding="utf-8")))
    groups = {}
    for r in rows:
        g = groups.setdefault(r["dup_group"], r["severity_norm"])
        if SEV.index(r["severity_norm"]) < SEV.index(g):
            groups[r["dup_group"]] = r["severity_norm"]
    by_tool = Counter(r["tool"] for r in rows)
    sev = Counter(groups.values())
    body = (f'<div class="funnel"><div class="fb f1">{len(rows)} findings</div><span>&rarr;</span><div class="fb f2">{len(groups)} distinct issues</div><span>&rarr;</span><div class="fb f3">gate: only <b>new</b></div></div>'
            + '<div class="two"><div><h3>Findings per tool</h3>' + bars([(t, n, "#22d3ee") for t, n in by_tool.most_common()]) + "</div>"
            + '<div><h3>Distinct issues by severity</h3>' + bars([(s, sev.get(s, 0), SEV_COL[s]) for s in SEV]) + "</div></div>")
    return panel("Noise to signal: why the gate stays usable", body, "", "Source: R2's frozen candidate population (CI run 40762500169)")


def bakeoff_panel():
    records = ev.load_ground_truth()
    trs = []
    m = ev.metrics(ev.heuristic_baseline(records))
    trs.append(["Keyword baseline (no LLM)", m["precision"], m["recall"], m["abstention"], m["confidently_wrong"], "n/a", "n/a"])
    for model in ("llama3:latest", "gemma2:latest"):
        meta, rows = ev.load_rows(model, "full")
        if not rows:
            continue
        m, h = ev.metrics(rows), ev.hallucination(rows)
        trs.append([E(model), m["precision"], m["recall"], m["abstention"], m["confidently_wrong"], f'{h["produced"]} &rarr; <b class=good>{h["reaching_human_with_validator"]}</b>',
                    f'{m["p50_latency_s"]} s'])
    body = table(["Configuration", "Precision", "Recall", "Abstain", "Confidently wrong", "Ungrounded claims produced &rarr; reaching a human", "p50 latency"], trs)
    return panel("LLM triage: bake-off and the validator", body, "wide",
                 "Source: <code>eval/results/*.jsonl</code> (real local runs, temp 0, seed 42) &middot; <b>n = 10 synthetic rows</b>: a smoke set, one row moves a score by 5-10 points")


def runtime_panel():
    f = sorted((ROOT / "artifacts/evidence/runtime").glob("*-runtime-baseline.json"))[-1]
    doc = json.loads(f.read_text(encoding="utf-8"))
    probes = list(doc["runs"].values())[0]
    trs = [[E(p["planted"]), E(p["name"]), E(p["observed"]), '<b class=bad>exploitable</b>' if p["exploitable"] else '<span class=good>safe</span>'] for p in probes]
    return panel("Runtime proof: live probes of our own lab app (loopback)", table(["Planted", "Probe", "Observed", "Result"], trs), "wide",
                 f"Source: <code>{E(str(f.relative_to(ROOT)))}</code> &middot; captured {E(doc['captured'])} &middot; as shipped (DEBUG=1)")


def metrics_panel():
    p = ROOT / "artifacts/demo/out/metrics.prom"
    if not p.is_file():
        return ""
    rows = []
    for ln in p.read_text(encoding="utf-8").splitlines():
        if ln and not ln.startswith("#"):
            name, val = ln.rsplit(" ", 1)
            rows.append([f"<code>{E(name.replace('pipelinefortress_ai_', ''))}</code>", E(val)])
    return panel("AI triage metrics (Prometheus text, as pushed to Grafana)", table(["Metric", "Value"], rows), "",
                 "Source: <code>artifacts/demo/out/metrics.prom</code> (<code>make demo-local</code>). Gauges, not counters: no <code>rate()</code>")


def prs_panel():  # noqa: E501
    p = ROOT / "artifacts/prs/v2/pr_register.json"
    if not p.is_file():
        return ""
    prs = json.loads(p.read_text(encoding="utf-8"))
    trs = [[E(x["pr_id"]), E(x["target"]), "yes" if x["applies_cleanly"] else "<b class=bad>no</b>", str(x.get("lines_changed", "?")), '<span class=warn>PENDING human review</span>'] for x in prs]
    ok = sum(1 for x in prs if x["applies_cleanly"])
    return panel("AI-drafted pull requests (v2: model returns the file, code computes the diff)", f'<div class="kpis"><div class="kpi g"><b>{ok}/{len(prs)}</b><span>apply cleanly (v1 was 0/4)</span></div>'
                 f'<div class="kpi"><b>0/{len(prs)}</b><span>human-reviewed yet</span></div></div>' + table(["PR", "Target", "Applies", "Lines changed", "Review"], trs), "",
                 "&ldquo;Applies cleanly&rdquo; is not &ldquo;correct&rdquo;. Nothing merges without a person.")


CSS = """
:root{--bg:#060a14;--panel:#0f1930;--line:#223457;--text:#e8eefc;--dim:#8fa3c8;--cyan:#22d3ee;--green:#34d399;--red:#fb4a68;--amber:#fbbf24}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#11224a,transparent 60%),var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:28px 36px 60px}
header{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:18px}h1{font-size:28px;margin:0;letter-spacing:-.01em}h1 span{color:var(--cyan)}
.stamp{font:12px ui-monospace,Menlo,monospace;color:var(--dim)}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.panel{min-width:0;overflow-wrap:anywhere}.wide{grid-column:1/-1}
.panel{background:linear-gradient(180deg,#132243,var(--panel));border:1px solid var(--line);border-radius:14px;padding:16px 18px}
h2{font:700 13px ui-monospace,Menlo,monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--cyan);margin:0 0 6px}h3{font-size:13px;color:var(--dim);margin:12px 0 6px}
.sub{color:var(--dim);font-size:12.5px;margin:0 0 10px}code{font:12px ui-monospace,Menlo,monospace;color:#bcd0f5}
table{width:100%;border-collapse:collapse;font-size:13.5px}th{text-align:left;font:700 11px ui-monospace,Menlo,monospace;letter-spacing:.08em;color:var(--dim);text-transform:uppercase;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:6px 8px;border-bottom:1px solid #172745;vertical-align:top}.bad{color:var(--red)}.good{color:var(--green)}.warn{color:var(--amber)}
.kpis{display:flex;gap:12px;margin:6px 0 12px}.kpi{flex:1;border:1px solid var(--line);border-radius:10px;padding:10px 14px;background:#0b1530}.kpi b{display:block;font-size:34px;line-height:1;letter-spacing:-.02em}.kpi.g b{color:var(--green)}.kpi span{color:var(--dim);font-size:12.5px}
.funnel{display:flex;align-items:center;gap:10px;margin:6px 0 10px}.fb{padding:12px 16px;border-radius:10px;font:800 16px ui-monospace,Menlo,monospace;color:#04101c}.f1{background:linear-gradient(90deg,#60a5fa,#22d3ee)}.f2{background:linear-gradient(90deg,#22d3ee,#34d399)}.f3{background:linear-gradient(90deg,#fbbf24,#fb4a68)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:18px}.bar{display:flex;align-items:center;gap:8px;margin:4px 0}.bl{width:78px;font:12px ui-monospace,Menlo,monospace;color:var(--dim)}.bf{height:14px;border-radius:4px;display:inline-block}.bar b{font:700 12px ui-monospace,Menlo,monospace}
footer{margin-top:22px;color:var(--dim);font-size:12.5px}@media print{body{background:#060a14}}
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", default=str(SNAP), help="normalized findings.json for the catch-rate panel (default: the committed 2026-10-27 snapshot)")
    ap.add_argument("--out", default=str(ROOT / "demo/results.html"))
    a = ap.parse_args(argv)
    findings = json.loads(Path(a.findings).read_text(encoding="utf-8"))
    src = str(Path(a.findings).resolve().relative_to(ROOT)) if str(Path(a.findings).resolve()).startswith(str(ROOT)) else a.findings
    panels = [catch_panel(findings, src), funnel_panel(), prs_panel(), bakeoff_panel(), runtime_panel(), metrics_panel()]
    page = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>PipelineFortress: results</title><style>{CSS}</style></head><body>'
            f'<header><h1>Pipeline<span>Fortress</span> &middot; results</h1><div class="stamp">Team Nova &middot; built {time.strftime("%Y-%m-%d %H:%M")} from the repository&rsquo;s own files</div></header>'
            f'<div class="grid">{"".join(panels)}</div>'
            f'<footer>Every number here is computed from a committed file named in its panel. Live twin: <code>make dash</code> (Grafana on http://localhost:3001). Re-run: <code>python3 scripts/build_demo_results.py</code>.</footer></body></html>')
    Path(a.out).write_text(page, encoding="utf-8")
    out = Path(a.out).resolve()
    shown = out.relative_to(ROOT) if str(out).startswith(str(ROOT)) else out
    print(f"wrote {shown} ({len(page) // 1024} KB, {len(panels)} panels)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
