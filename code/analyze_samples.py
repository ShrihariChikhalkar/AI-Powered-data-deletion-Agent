import sys
import json
import pandas as pd
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8')

requests = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
identities = pd.read_csv('dataset/user_identities.csv')
audit_log = pd.read_csv('dataset/user_audit_log.csv')
activity = pd.read_csv('dataset/system_activity.csv')

print("Mapping sample cases...")
for idx, req in requests.iterrows():
    case_id = req['case_id']
    req_email = req['email'].lower()
    
    # 1. Identity resolution
    # Find matching identity by current email or audit_log
    user_match = identities[identities['email'].str.lower() == req_email]
    hist_match = audit_log[(audit_log['field_name'] == 'email') & (audit_log['old_value'].str.lower() == req_email)]
    
    user_id = None
    all_emails = {req_email}
    all_phones = set()
    user_name = None
    
    if len(user_match) > 0:
        u_row = user_match.iloc[0]
        user_id = u_row['user_id']
        all_emails.add(u_row['email'].lower())
        all_phones.add(u_row['phone'])
        user_name = u_row['name']
    elif len(hist_match) > 0:
        user_id = hist_match.iloc[0]['user_id']
        u_row = identities[identities['user_id'] == user_id].iloc[0]
        all_emails.add(u_row['email'].lower())
        all_phones.add(u_row['phone'])
        user_name = u_row['name']
        
    if user_id:
        # also get all historical emails/phones
        u_audits = audit_log[audit_log['user_id'] == user_id]
        for _, a_row in u_audits.iterrows():
            if a_row['field_name'] == 'email':
                all_emails.add(str(a_row['old_value']).lower())
                all_emails.add(str(a_row['new_value']).lower())
            if a_row['field_name'] == 'phone':
                all_phones.add(str(a_row['old_value']))
                all_phones.add(str(a_row['new_value']))
                
    # Now look at sample_output for this case
    out_row = sample_out[sample_out['case_id'] == case_id].iloc[0]
    steps = json.loads(out_row['steps_json'])
    status = out_row['deletion_status']
    
    # Find activities around requested_at and reported_at or mentioning user_id or resources
    step_resources = [s['resource_id'] for s in steps]
    
    print(f"\n--- {case_id} | Status: {status} | User: {user_id} ({user_name}) | Req Email: {req_email} ---")
    print(f"Emails: {all_emails}")
    print(f"Req: {req['requested_at']} -> Reported: {req['reported_at']} ({req['reported_status']}) -> Audit: {req['audit_at']}")
    print(f"Steps in sample_output ({len(steps)}):")
    for s in steps:
        print(f"  {s['phase']} | {s['system_id']} | {s['resource_id']} | {s['operation']} | {s['state']} | ev={s['evidence_id']}")
        
    # Check what activity rows exist for these step resources:
    res_acts = activity[activity['resource_id'].isin(step_resources)]
    if len(res_acts) > 0:
        print("  Matching activities for step resources:")
        for _, a in res_acts.iterrows():
            print(f"    act={a['activity_id']} time={a['event_time']} type={a['event_type']} src={a['source_system']} tgt={a['target_system']} res={a['resource_id']} reslt={a['reported_result']}")
