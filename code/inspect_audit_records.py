import sys
import json
import pandas as pd
sys.stdout.reconfigure(encoding='utf-8')

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
identities_df = pd.read_csv('dataset/user_identities.csv')
audit_log_df = pd.read_csv('dataset/user_audit_log.csv')

identities_df['email_clean'] = identities_df['email'].str.strip().str.lower()
curr_map = dict(zip(identities_df['email_clean'], identities_df['user_id']))

for idx, req in sample_reqs.iterrows():
    cid = req['case_id']
    em = str(req['email']).strip().lower()
    u = curr_map.get(em)
    out_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    steps = json.loads(out_row['steps_json'])
    aud_step = [s['resource_id'] for s in steps if s['system_id'] == 'security_service']
    acc_step = [s['resource_id'] for s in steps if s['system_id'] == 'account_service']
    ev_step = [s['evidence_id'] for s in steps if s['system_id'] == 'security_service']
    print(f"{cid} | user: {u} | email: {em} | account: {acc_step} | audit_record: {aud_step} | ev: {ev_step}")
