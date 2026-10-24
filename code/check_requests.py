import sys
import pandas as pd

sys.stdout.reconfigure(encoding='utf-8')
reqs = pd.read_csv('dataset/deletion_requests.csv')

non_del_keywords = [
    'leave the account active', 'not asking for deletion', 'keep the account as it is',
    'do not close the account', 'without removing any of my records', 'marketing lists only',
    'not a request to erase', 'leave my profile', 'continue using the service',
    "don't delete or change anything", 'do not delete', 'not asking to erase'
]

non_del = []
for _, r in reqs.iterrows():
    txt = r['request_text'].lower()
    if any(k in txt for k in non_del_keywords):
        non_del.append((r['case_id'], r['request_text']))

print(f"Total non-deletion requests found: {len(non_del)}")
for cid, txt in non_del:
    print(f"  {cid}: {txt}")
