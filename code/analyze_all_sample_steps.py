import sys
import json
import pandas as pd
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
evidence_manifest = pd.read_csv('dataset/evidence_files.csv')
activity = pd.read_csv('dataset/system_activity.csv')

print("=== Analyzing all 32 sample outputs ===")
for idx, req in sample_reqs.iterrows():
    cid = req['case_id']
    out_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    steps = json.loads(out_row['steps_json'])
    status = out_row['deletion_status']
    
    # print summary
    phases = [s['phase'] for s in steps]
    ops = [s['operation'] for s in steps]
    res_list = [f"{s['system_id']}:{s['resource_id']}" for s in steps]
    ev_list = [s['evidence_id'] for s in steps if s['evidence_id']]
    
    print(f"\n{cid} [{status}] ({len(steps)} steps) Cited Ev: {set(ev_list)}")
    for s in steps:
        print(f"  {s['step_no']}. [{s['phase']}] {s['system_id']} / {s['resource_id']} : {s['operation']} -> {s['state']} (ev={s['evidence_id']})")
