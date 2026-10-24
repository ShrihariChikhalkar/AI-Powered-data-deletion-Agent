import sys
import json
import pandas as pd
sys.stdout.reconfigure(encoding='utf-8')

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
identities = pd.read_csv('dataset/user_identities.csv')
audit_log = pd.read_csv('dataset/user_audit_log.csv')
system_activity = pd.read_csv('dataset/system_activity.csv')

identities['email_clean'] = identities['email'].str.strip().str.lower()
curr_email_to_user = dict(zip(identities['email_clean'], identities['user_id']))

hist_email_rows = audit_log[audit_log['field_name'] == 'email']
hist_email_to_user = {}
for _, row in hist_email_rows.iterrows():
    if pd.notna(row['old_value']):
        hist_email_to_user[str(row['old_value']).strip().lower()] = row['user_id']
    if pd.notna(row['new_value']):
        hist_email_to_user[str(row['new_value']).strip().lower()] = row['user_id']

for idx, req in sample_reqs.iterrows():
    case_id = req['case_id']
    req_email = str(req['email']).strip().lower()
    uid = curr_email_to_user.get(req_email) or hist_email_to_user.get(req_email)
    
    out_row = sample_out[sample_out['case_id'] == case_id].iloc[0]
    steps = json.loads(out_row['steps_json'])
    status = out_row['deletion_status']
    
    # Let's find all activities between requested_at and audit_at
    req_time = req['requested_at']
    rep_time = req['reported_at']
    audit_time = req['audit_at']
    
    # Check deletion_worker activities around rep_time (+/- 1 day or between req_time and audit_time)
    acts = system_activity[(system_activity['event_time'] >= req_time) & (system_activity['event_time'] <= audit_time)]
    
    # Filter acts that mention any of the resources in steps
    step_res = set(s['resource_id'] for s in steps)
    matched_acts = acts[acts['resource_id'].isin(step_res)]
    
    print(f"\n{case_id} ({status}) | User: {uid} | Req: {req_time} -> Rep: {rep_time} -> Audit: {audit_time}")
    print(f"Step resources ({len(step_res)}): {step_res}")
    print(f"Matched activities ({len(matched_acts)}):")
    for _, a in matched_acts.iterrows():
        print(f"  {a['event_time']} | {a['event_type']} | {a['source_system']} -> {a['target_system']} | {a['resource_id']} | {a['reported_result']}")
