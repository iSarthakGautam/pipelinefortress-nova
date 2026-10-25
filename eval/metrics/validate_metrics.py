#!/usr/bin/env python3
"""Lightweight validation of the project's Prometheus text output and expected metric families."""
import argparse,re
from pathlib import Path
EXPECTED={'pipelinefortress_ai_findings_total','pipelinefortress_ai_clusters_total','pipelinefortress_ai_verdict_total','pipelinefortress_ai_validator_rejections_total','pipelinefortress_ai_outcome_total','pipelinefortress_ai_llm_latency_seconds_sum','pipelinefortress_ai_llm_calls_total'}
LINE=re.compile(r'^[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^{}]*\})?\s+-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$')
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('metrics_file'); args=ap.parse_args(); p=Path(args.metrics_file); text=p.read_text(encoding='utf-8'); families=set(); samples=0; bad=[]
 for n,line in enumerate(text.splitlines(),1):
  if not line.strip() or line.startswith('#'): continue
  if not LINE.match(line): bad.append((n,line)); continue
  families.add(re.split(r'[ {]',line,1)[0]); samples+=1
 missing=EXPECTED-families
 print(f'file={p} samples={samples} families={len(families)}')
 print('families_found='+', '.join(sorted(families)))
 if missing: print('MISSING_EXPECTED_FAMILIES='+', '.join(sorted(missing)))
 if bad: print('INVALID_LINES='+repr(bad[:5]))
 if missing or bad: raise SystemExit(1)
 print('VALIDATION=PASS (format/family check only; not proof of live scrape or semantic correctness)')
if __name__=='__main__': main()
