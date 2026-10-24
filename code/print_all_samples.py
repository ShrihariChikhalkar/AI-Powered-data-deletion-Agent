import sys
import json
import pandas as pd
sys.stdout.reconfigure(encoding='utf-8')

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
rules = pd.read_csv('dataset/deletion_rules.csv')

for idx, req in sample_reqs.iterrows():
    case_id = req['case_id']
    out_row = sample_out[sample_out['case_id'] == case_id].iloc[0]
    steps = json.loads(out_row['steps_json'])
    status = out_row['deletion_status']
    print(f"\n==================== {case_id} ({status}) ====================")
    print(f"Email: {req['email']} | Reported: {req['reported_status']} | AuditAt: {req['audit_at']}")
    print(f"Text: {req['request_text']}")
    print("Steps:")
    for s in steps:
        print(f"  [{s['step_no']}] {s['phase']} | {s['system_id']} | {s['resource_id']} | {s['operation']} | {s['state']} | ev={s['evidence_id']}")
