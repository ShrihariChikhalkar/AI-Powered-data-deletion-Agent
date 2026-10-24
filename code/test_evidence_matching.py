import sys
import json
import pandas as pd
from parse_evidence import EvidenceParser

sys.stdout.reconfigure(encoding='utf-8')

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
identities_df = pd.read_csv('dataset/user_identities.csv')
audit_log_df = pd.read_csv('dataset/user_audit_log.csv')

identities_df['email_clean'] = identities_df['email'].str.strip().str.lower()
user_profiles = {}
for _, row in identities_df.iterrows():
    uid = row['user_id']
    user_profiles[uid] = {
        'user_id': uid,
        'name': row['name'],
        'email': row['email_clean'],
        'phone': str(row['phone']).strip() if pd.notna(row['phone']) else None,
        'email_hash': str(row['email_hash']).strip() if pd.notna(row['email_hash']) else None,
        'all_emails': {row['email_clean']},
        'all_phones': {str(row['phone']).strip()} if pd.notna(row['phone']) else set(),
        'all_hashes': {str(row['email_hash']).strip()} if pd.notna(row['email_hash']) else set(),
        'all_names': {str(row['name']).strip()} if pd.notna(row['name']) else set(),
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
        elif field == 'name':
            if pd.notna(row['old_value']): user_profiles[uid]['all_names'].add(str(row['old_value']).strip())
            if pd.notna(row['new_value']): user_profiles[uid]['all_names'].add(str(row['new_value']).strip())

email_to_user = {}
for uid, p in user_profiles.items():
    for em in p['all_emails']:
        email_to_user[em] = uid

parser = EvidenceParser()
parser.parse_all()

print("\nTesting matching on sample cases:")
for idx, req in sample_reqs.iterrows():
    cid = req['case_id']
    req_email = str(req['email']).strip().lower()
    uid = email_to_user[req_email]
    u_prof = user_profiles[uid]
    
    aud_dt = pd.to_datetime(req['audit_at'])
    
    # User's search identifiers
    user_id_set = {uid.lower()}
    for em in u_prof['all_emails']: user_id_set.add(em)
    for h in u_prof['all_hashes']: user_id_set.add(h)
    for ph in u_prof['all_phones']: user_id_set.add(ph)
    
    # Find evidence records matching user_id_set with captured_at_dt <= aud_dt
    matched_ev_recs = []
    for r in parser.records:
        if r['captured_at_dt'] <= aud_dt:
            if not r['identifiers'].isdisjoint(user_id_set):
                matched_ev_recs.append(r)
                
    # Compare with sample_output
    out_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    expected_steps = json.loads(out_row['steps_json'])
    expected_res = set(s['resource_id'] for s in expected_steps)
    
    found_res = set(r['resource_id'] for r in matched_ev_recs)
    
    print(f"{cid} ({out_row['deletion_status']}) | User: {uid}")
    print(f"  Expected resources ({len(expected_res)}): {expected_res}")
    print(f"  Found in evidence ({len(found_res)}): {found_res}")
    missing = expected_res - found_res
    if missing:
        print(f"  --> MISSING FROM EVIDENCE: {missing}")
