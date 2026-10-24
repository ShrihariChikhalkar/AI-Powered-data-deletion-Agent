import sys
import json
import pandas as pd
from parse_evidence import EvidenceParser

sys.stdout.reconfigure(encoding='utf-8')
p = EvidenceParser()
p.parse_all()

sout = pd.read_csv('dataset/sample_output.csv')
for _, r in sout.iterrows():
    c = r['case_id']
    st = r['deletion_status']
    steps = json.loads(r['steps_json'])
    aud_steps = [s for s in steps if s['system_id'] == 'security_service']
    if aud_steps:
        s = aud_steps[0]
        f = [rec for rec in p.records if rec['resource_id'] == s['resource_id']]
        print(f"{c} ({st}): aud={s['resource_id']} ev_in_step='{s['evidence_id']}' -> parsed in {[x['evidence_id'] for x in f]}")
