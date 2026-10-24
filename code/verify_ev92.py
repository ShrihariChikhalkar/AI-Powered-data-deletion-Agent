import sys
import json
import pandas as pd
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence/records/service_resource_export_20260915_114455.json', 'r', encoding='utf-8') as f:
    ev92 = json.load(f)

print("Checking evidence_92 entries for user_26:")
for svc, data in ev92['service_exports'].items():
    for subkey, items in data.items():
        for it in items:
            s_it = str(it)
            if 'user_26' in s_it:
                print(f"  {svc} -> {it.get('resource_id')}: {it}")

print("\nChecking evidence_92 entries for user_29 (noah.f438085@outlook.com):")
for svc, data in ev92['service_exports'].items():
    for subkey, items in data.items():
        for it in items:
            s_it = str(it)
            if 'user_29' in s_it or 'noah.f' in s_it:
                print(f"  {svc} -> {it.get('resource_id')}: {it}")
