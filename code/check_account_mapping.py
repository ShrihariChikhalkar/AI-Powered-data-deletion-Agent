import sys
import json
import pandas as pd
sys.stdout.reconfigure(encoding='utf-8')

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
system_activity = pd.read_csv('dataset/system_activity.csv')

deletion_acts = system_activity[system_activity['source_system'] == 'deletion_worker']

print("Checking account resources in deletion_worker activities for sample cases:")
for idx, req in sample_reqs.iterrows():
    cid = req['case_id']
    req_t = req['requested_at']
    rep_t = req['reported_at']
    aud_t = req['audit_at']
    
    out = sample_out[sample_out['case_id'] == cid].iloc[0]
    steps = json.loads(out['steps_json'])
    acc_step = [s['resource_id'] for s in steps if s['system_id'] == 'account_service']
    
    # Find deletion_worker activities on account_service around rep_t
    # or between req_t and rep_t
    window_acts = deletion_acts[(deletion_acts['target_system'] == 'account_service') & 
                                (deletion_acts['event_time'] >= req_t) & 
                                (deletion_acts['event_time'] <= aud_t)]
    
    # Check if the acc_step is in window_acts
    matched_in_window = [r for r in acc_step if r in window_acts['resource_id'].values]
    print(f"{cid}: Expected {acc_step} | In window: {matched_in_window} | Total acts in window: {len(window_acts)}")
    if len(acc_step) > 0 and len(matched_in_window) == 0:
        print(f"  --> MISSING! All acts in window:")
        for _, a in window_acts.iterrows():
            print(f"      {a['event_time']} {a['resource_id']} {a['details']}")
