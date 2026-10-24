import sys
import json
import pandas as pd

sys.stdout.reconfigure(encoding='utf-8')
sout = pd.read_csv('dataset/sample_output.csv')
for _, r in sout.iterrows():
    c = r['case_id']
    st = r['deletion_status']
    steps = json.loads(r['steps_json'])
    verifs = [s for s in steps if s['phase'] == 'VERIFICATION']
    findings = [s for s in steps if s['phase'] == 'FINDING']
    f_res = set(s['resource_id'] for s in findings)
    
    other_v = [s for s in verifs if s['system_id'] not in ('account_service', 'security_service') and s['resource_id'] not in f_res]
    if other_v:
        items = [(s['system_id'], s['resource_id'], s['operation'], s['evidence_id']) for s in other_v]
        print(f"{c} ({st}): Compliant resources verified: {items}")
