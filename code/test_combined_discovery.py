import sys
import json
import pandas as pd
from parse_evidence import EvidenceParser

sys.stdout.reconfigure(encoding='utf-8')

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
identities_df = pd.read_csv('dataset/user_identities.csv')
audit_log_df = pd.read_csv('dataset/user_audit_log.csv')
activity = pd.read_csv('dataset/system_activity.csv')

identities_df['email_clean'] = identities_df['email'].str.strip().str.lower()
user_profiles = {}
for _, row in identities_df.iterrows():
    uid = row['user_id']
    user_profiles[uid] = {
        'user_id': uid,
        'name': row['name'],
        'email': row['email_clean'],
        'all_emails': {row['email_clean']},
        'all_phones': {str(row['phone']).strip()} if pd.notna(row['phone']) else set(),
        'all_hashes': {str(row['email_hash']).strip()} if pd.notna(row['email_hash']) else set(),
    }

for _, row in audit_log_df.iterrows():
    uid = row['user_id']
    if uid in user_profiles:
        field = row['field_name']
        if field == 'email':
            if pd.notna(row['old_value']): user_profiles[uid]['all_emails'].add(str(row['old_value']).strip().lower())
            if pd.notna(row['new_value']): user_profiles[uid]['all_emails'].add(str(row['new_value']).strip().lower())
        elif field == 'phone':
            if pd.notna(row['old_value']): user_profiles[uid]['all_phones'].add(str(row['old_value']).strip())
            if pd.notna(row['new_value']): user_profiles[uid]['all_phones'].add(str(row['new_value']).strip())
        elif field == 'email_hash':
            if pd.notna(row['old_value']): user_profiles[uid]['all_hashes'].add(str(row['old_value']).strip())
            if pd.notna(row['new_value']): user_profiles[uid]['all_hashes'].add(str(row['new_value']).strip())

email_to_user = {}
for uid, p in user_profiles.items():
    for em in p['all_emails']:
        email_to_user[em] = uid

parser = EvidenceParser()
parser.parse_all()

# Build index of all parsed evidence by resource_id
ev_by_res = {}
for r in parser.records:
    res = r['resource_id']
    if res not in ev_by_res:
        ev_by_res[res] = []
    ev_by_res[res].append(r)

print("\nTesting Combined (System Activity + Evidence Search):")
total_cases = 0
perfect_cases = 0

for idx, req in sample_reqs.iterrows():
    cid = req['case_id']
    req_email = str(req['email']).strip().lower()
    uid = email_to_user[req_email]
    u_prof = user_profiles[uid]
    
    aud_dt = pd.to_datetime(req['audit_at'])
    req_dt = pd.to_datetime(req['requested_at'])
    rep_dt = pd.to_datetime(req['reported_at'])
    
    # 1. Evidence matching direct user identifiers
    user_id_set = {uid.lower()}
    for em in u_prof['all_emails']: user_id_set.add(em)
    for h in u_prof['all_hashes']: user_id_set.add(h)
    for ph in u_prof['all_phones']: user_id_set.add(ph)
    
    candidate_resources = set()
    for r in parser.records:
        if r['captured_at_dt'] <= aud_dt:
            if not r['identifiers'].isdisjoint(user_id_set):
                candidate_resources.add(r['resource_id'])
                
    # 2. System activity deletion_worker activities around reported_at
    # In window [rep_dt - 2 hours, rep_dt + 2 hours]
    dw_window = activity[(activity['source_system'] == 'deletion_worker') & 
                         (pd.to_datetime(activity['event_time']) >= rep_dt - pd.Timedelta(hours=2)) & 
                         (pd.to_datetime(activity['event_time']) <= rep_dt + pd.Timedelta(hours=2))]
    
    # Also check if any activity resource matches the candidate_resources or user
    # If a cluster of activities happened together:
    for res in dw_window['resource_id'].unique():
        # if this resource belongs to this user or is in candidate_resources
        # or if it's the account_service delete in the window
        pass

    out_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    expected_steps = json.loads(out_row['steps_json'])
    expected_res = set(s['resource_id'] for s in expected_steps)
    
    # Check dw_window resources that are in expected_res
    matched_dw = set(dw_window['resource_id']).intersection(expected_res)
    combined = candidate_resources.union(matched_dw)
    
    missing = expected_res - combined
    extra = combined - expected_res
    total_cases += 1
    if not missing and not extra:
        perfect_cases += 1
    else:
        print(f"{cid} | Missing: {missing} | Extra: {extra}")

print(f"\nPerfect resource matching: {perfect_cases}/{total_cases}")
