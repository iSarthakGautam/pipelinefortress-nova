#!/usr/bin/env python3
"""Create chronological development/test JSONL files and a SHA-256 freeze manifest.

Requires each JSON object to contain a trustworthy ISO-8601 timestamp field. The cutoff
is exclusive for development (< cutoff) and inclusive for test (>= cutoff). Related
records should be grouped before use; this script refuses duplicate group IDs spanning
splits. It cannot create a valid split from the current timestamp-free 10-row smoke set.
"""
import argparse, hashlib, json
from datetime import datetime, timezone
from pathlib import Path

def parse_dt(s):
    dt=datetime.fromisoformat(s.replace('Z','+00:00'))
    if dt.tzinfo is None: raise ValueError(f'Timestamp must include timezone: {s}')
    return dt.astimezone(timezone.utc)
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('input_jsonl'); ap.add_argument('--timestamp-field', required=True, help='Top-level ISO-8601 field, e.g. first_seen_utc')
    ap.add_argument('--cutoff', required=True, help='Timezone-aware ISO-8601 cutoff')
    ap.add_argument('--group-field', default='duplicate_group', help='Optional duplicate/cluster group field; blank means no group')
    ap.add_argument('--out-dir', required=True)
    args=ap.parse_args(); src=Path(args.input_jsonl); out=Path(args.out_dir); cutoff=parse_dt(args.cutoff)
    rows=[]
    for i,line in enumerate(src.read_text(encoding='utf-8').splitlines(),1):
        if not line.strip(): continue
        row=json.loads(line)
        if args.timestamp_field not in row: raise SystemExit(f'Line {i} missing timestamp field {args.timestamp_field!r}; no defensible time split can be made.')
        try: dt=parse_dt(str(row[args.timestamp_field]))
        except Exception as e: raise SystemExit(f'Line {i} invalid timestamp: {e}')
        rows.append((row,dt))
    if not rows: raise SystemExit('No records found')
    dev=[]; test=[]; group_split={}
    for row,dt in rows:
        split='development' if dt < cutoff else 'test'
        group=str(row.get(args.group_field,'') or '').strip()
        if group:
            prev=group_split.setdefault(group,split)
            if prev!=split: raise SystemExit(f'Data leakage: duplicate group {group!r} spans development and test.')
        (dev if split=='development' else test).append(row)
    if not dev or not test: raise SystemExit(f'Both splits must be non-empty; got development={len(dev)}, test={len(test)}')
    out.mkdir(parents=True,exist_ok=True)
    paths={'development':out/'development.jsonl','test':out/'test.jsonl'}
    for name,items in [('development',dev),('test',test)]:
        paths[name].write_text(''.join(json.dumps(x,sort_keys=True)+'\n' for x in items),encoding='utf-8')
    manifest={'source_file':str(src),'source_sha256':sha(src),'timestamp_field':args.timestamp_field,'cutoff_utc':cutoff.isoformat(),'rule':'development < cutoff; test >= cutoff','group_field':args.group_field,'n_total':len(rows),'n_development':len(dev),'n_test':len(test),'development_sha256':sha(paths['development']),'test_sha256':sha(paths['test']),'created_utc':datetime.now(timezone.utc).isoformat(),'warning':'Freeze this manifest with the dataset and record approval. Timestamp chronology alone does not prove independence; check duplicates and prompt-tuning leakage.'}
    mp=out/'freeze_manifest.json'; mp.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(manifest,indent=2))
if __name__=='__main__': main()
