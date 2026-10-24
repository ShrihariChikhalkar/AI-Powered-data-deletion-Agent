import sys
import json
import pandas as pd
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

# Check case_01 in user_identities
identities = pd.read_csv('dataset/user_identities.csv')
print("Searching for amina.elmasri@gmail.com in user_identities:")
u1 = identities[identities['email'].str.lower() == 'amina.elmasri@gmail.com']
print(u1)

# Check audit log for user_01
audit_log = pd.read_csv('dataset/user_audit_log.csv')
print("\nAudit log for user_01:")
print(audit_log[audit_log['user_id'] == 'user_01'])

# Check system_activity for user_01 or account_001 or amina
activity = pd.read_csv('dataset/system_activity.csv')
print("\nSystem activity mentioning account_001 or amina or user_01:")
print(activity[activity['resource_id'] == 'account_001'])
print(activity[activity['details'].str.contains('account_001|user_01|amina', case=False, na=False)])

# Check evidence_54 file path
evidence_manifest = pd.read_csv('dataset/evidence_files.csv')
print("\nEvidence 54 manifest:")
ev54 = evidence_manifest[evidence_manifest['file_id'] == 'evidence_54']
print(ev54)

# Let's inspect the contents of evidence_54 file
ev54_path = Path('dataset') / ev54.iloc[0]['file_path']
print(f"\nPath: {ev54_path}")
if ev54_path.exists():
    with open(ev54_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    print(f"Content length: {len(content)}")
    print("Does content contain amina, user_01, account_001?")
    for term in ['amina', 'user_01', 'account_001', 'El-Masri']:
        print(f"  '{term}' in file: {term.lower() in content.lower()}")
    # print first 500 chars
    print("Preview:")
    print(content[:500])
