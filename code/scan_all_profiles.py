import sys
import json
import sqlite3
import pandas as pd
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')

# Let's inspect where customer_profiles / accounts are found across all files
user_to_accounts = {}

# 1. Check all JSON snapshot bundles and exports
for p in Path('dataset/evidence/records').glob('*.json'):
    try:
        with open(p, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # check if snapshot bundle
        if 'snapshots' in data:
            for s in data['snapshots']:
                for rec in s.get('records', []):
                    u = rec.get('customer_reference') or rec.get('subject_reference') or rec.get('user_id')
                    res = rec.get('resource_id')
                    em = rec.get('email') or rec.get('requester_email') or rec.get('owner_email')
                    if res and (u or em):
                        # record mapping
                        pass
        # check service_resource_export
        if 'service_exports' in data:
            for svc, sdata in data['service_exports'].items():
                for subk, items in sdata.items():
                    for it in items:
                        pass
    except Exception as e:
        pass

print("Done scanning records.")
