import sys
import json
import pandas as pd
sys.stdout.reconfigure(encoding='utf-8')

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
evidence_files = pd.read_csv('dataset/evidence_files.csv')
system_activity = pd.read_csv('dataset/system_activity.csv')

# Build map of case_id -> request info
req_dict = {r['case_id']: r for _, r in sample_reqs.iterrows()}

all_ev_ids = set()
for _, r in sample_out.iterrows():
    steps = json.loads(r['steps_json'])
    for s in steps:
        if s['evidence_id']:
            all_ev_ids.add(s['evidence_id'])

print("Evidence IDs cited in sample_output:", sorted(list(all_ev_ids)))
for ev_id in sorted(list(all_ev_ids)):
    row = evidence_files[evidence_files['file_id'] == ev_id]
    if len(row) > 0:
        print(f"  {ev_id}: {row.iloc[0]['file_path']} ({row.iloc[0]['captured_at']})")
    else:
        print(f"  {ev_id}: NOT IN EVIDENCE_FILES manifest!")
