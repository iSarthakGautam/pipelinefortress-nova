#!/usr/bin/env python3
"""Validate a Prometheus text file and push it to a Pushgateway URL."""
import argparse, re, urllib.request
from pathlib import Path
LINE=re.compile(r'^(#.*|[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^{}]*\})?\s+-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|)$')
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('metrics_file'); ap.add_argument('push_url',help='e.g. http://localhost:9091/metrics/job/pipelinefortress_ai'); args=ap.parse_args()
    p=Path(args.metrics_file); body=p.read_text(encoding='utf-8')
    bad=[(i,line) for i,line in enumerate(body.splitlines(),1) if line.strip() and not LINE.match(line)]
    if bad: raise SystemExit(f'Invalid Prometheus text at line {bad[0][0]}: {bad[0][1]!r}')
    req=urllib.request.Request(args.push_url,data=body.encode(),method='PUT',headers={'Content-Type':'text/plain; version=0.0.4; charset=utf-8'})
    with urllib.request.urlopen(req,timeout=10) as response:
        print(f'Pushgateway HTTP {response.status}; bytes={len(body.encode())}; file_sha256={__import__("hashlib").sha256(body.encode()).hexdigest()}')
if __name__=='__main__': main()
