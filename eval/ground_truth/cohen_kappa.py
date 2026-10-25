#!/usr/bin/env python3
"""Compute Cohen's kappa from two independent categorical label columns in CSV.

Example:
 python3 r5/evaluation/cohen_kappa.py r5/evaluation/labels_template.csv \
   --a reviewer_a_label --b reviewer_b_label --out r5/evaluation/kappa_report.json
Blank labels are excluded and counted. Labels must be independent pre-adjudication labels.
"""
import argparse, csv, json, math
from collections import Counter
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('csv_file')
    ap.add_argument('--a', default='reviewer_a_label')
    ap.add_argument('--b', default='reviewer_b_label')
    ap.add_argument('--out')
    args=ap.parse_args()
    with open(args.csv_file, newline='', encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        if not reader.fieldnames or args.a not in reader.fieldnames or args.b not in reader.fieldnames:
            raise SystemExit(f'Missing columns. Found: {reader.fieldnames}; requested {args.a}, {args.b}')
        pairs=[]; excluded=0
        for row in reader:
            a=(row.get(args.a) or '').strip(); b=(row.get(args.b) or '').strip()
            if not a or not b:
                excluded+=1; continue
            pairs.append((a,b))
    n=len(pairs)
    if not n: raise SystemExit('No paired nonblank labels; kappa is not calculable.')
    ca=Counter(a for a,b in pairs); cb=Counter(b for a,b in pairs)
    observed=sum(a==b for a,b in pairs)/n
    labels=sorted(set(ca)|set(cb))
    expected=sum((ca[x]/n)*(cb[x]/n) for x in labels)
    kappa=None if math.isclose(1-expected,0.0,abs_tol=1e-12) else (observed-expected)/(1-expected)
    report={'n_paired':n,'n_excluded_blank_or_unpaired':excluded,'labels':labels,'reviewer_a_distribution':dict(ca),'reviewer_b_distribution':dict(cb),'raw_agreement':round(observed,6),'expected_agreement_by_chance':round(expected,6),'cohens_kappa':None if kappa is None else round(kappa,6),'interpretation_note':'Report class distribution and raw agreement alongside kappa. Kappa is undefined when expected agreement is 1.0. This calculation does not adjudicate disagreements.'}
    print(json.dumps(report,indent=2))
    if args.out: Path(args.out).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__': main()
