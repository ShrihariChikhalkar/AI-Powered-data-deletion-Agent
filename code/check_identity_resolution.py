import sys
import pandas as pd
sys.stdout.reconfigure(encoding='utf-8')

requests = pd.read_csv('dataset/deletion_requests.csv')
identities = pd.read_csv('dataset/user_identities.csv')
audit_log = pd.read_csv('dataset/user_audit_log.csv')

identities['email_clean'] = identities['email'].str.strip().str.lower()
curr_email_to_user = dict(zip(identities['email_clean'], identities['user_id']))

hist_email_rows = audit_log[audit_log['field_name'] == 'email']
hist_email_to_user = {}
for _, row in hist_email_rows.iterrows():
    if pd.notna(row['old_value']):
        hist_email_to_user[str(row['old_value']).strip().lower()] = row['user_id']
    if pd.notna(row['new_value']):
        hist_email_to_user[str(row['new_value']).strip().lower()] = row['user_id']

matched = 0
unmatched = []

for idx, req in requests.iterrows():
    req_email = str(req['email']).strip().lower()
    uid = curr_email_to_user.get(req_email) or hist_email_to_user.get(req_email)
    if uid:
        matched += 1
    else:
        unmatched.append((req['case_id'], req_email))

print(f"Matched {matched}/{len(requests)} cases to user_id.")
if unmatched:
    print(f"Unmatched {len(unmatched)} cases:")
    for c, e in unmatched[:10]:
        print(f"  {c}: {e}")
