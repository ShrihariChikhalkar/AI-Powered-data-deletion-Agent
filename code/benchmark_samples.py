import sys
import json
import pandas as pd
from audit_engine import AuditEngine

sys.stdout.reconfigure(encoding='utf-8')

engine = AuditEngine()

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')

total_cases = 0
status_matches = 0
exact_step_matches = 0

for _, req in sample_reqs.iterrows():
    cid = req['case_id']
    actual = engine.process_case(req)
    expected_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    
    total_cases += 1
    
    act_status = actual['deletion_status']
    exp_status = expected_row['deletion_status']
    
    if act_status == exp_status:
        status_matches += 1
    else:
        print(f"[{cid}] Status mismatch: Expected {exp_status}, Got {act_status}")
        continue
        
    act_steps = json.loads(actual['steps_json'])
    exp_steps = json.loads(expected_row['steps_json'])
    
    # Compare steps
    diffs = []
    if len(act_steps) != len(exp_steps):
        diffs.append(f"Step count: expected {len(exp_steps)}, got {len(act_steps)}")
    else:
        for idx, (es, as_) in enumerate(zip(exp_steps, act_steps)):
            for k in ['step_no', 'phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id']:
                if es.get(k) != as_.get(k):
                    diffs.append(f"Step {idx+1} {k}: expected '{es.get(k)}', got '{as_.get(k)}'")
                    
    if not diffs:
        exact_step_matches += 1
    else:
        print(f"[{cid}] {exp_status} Step mismatch:")
        for d in diffs[:5]:
            print(f"    {d}")

print("\n================ BENCHMARK RESULTS ================")
print(f"Status Accuracy: {status_matches}/{total_cases} ({status_matches/total_cases*100:.1f}%)")
print(f"Exact Step Match: {exact_step_matches}/{total_cases} ({exact_step_matches/total_cases*100:.1f}%)")
print("====================================================")
