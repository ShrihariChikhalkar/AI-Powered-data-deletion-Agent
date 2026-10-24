import sys
import json
import pandas as pd
from parse_evidence import EvidenceParser

sys.stdout.reconfigure(encoding='utf-8')
p = EvidenceParser()
p.parse_all()

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')

for cid in ['case_03', 'case_10', 'case_12', 'case_16', 'case_18', 'case_20', 'case_22', 'case_32']:
    req = sample_reqs[sample_reqs['case_id'] == cid].iloc[0]
    out = sample_out[sample_out['case_id'] == cid].iloc[0]
    steps = json.loads(out['steps_json'])
    evs = set(s['evidence_id'] for s in steps if s['evidence_id'])
    print(f"\n=== {cid} | Expected: {out['deletion_status']} | Cited Evs: {evs} ===")
    for s in steps:
        print(f"  [{s['phase']}] {s['system_id']} / {s['resource_id']} : {s['operation']} -> {s['state']} (ev={s['evidence_id']})")
