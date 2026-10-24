import pandas as pd
import json

df_samples = pd.read_csv('dataset/sample_deletion_requests.csv')
df_out = pd.read_csv('dataset/sample_output.csv')

print(f"Sample requests count: {len(df_samples)}")
print(f"Sample output count: {len(df_out)}")

merged = pd.merge(df_samples, df_out, on='case_id')
for idx, row in merged.iterrows():
    steps = json.loads(row['steps_json'])
    print(f"\nCase: {row['case_id']} | Status: {row['deletion_status']} | Reported: {row['reported_status']} | Email: {row['email']}")
    print(f"Audit at: {row['audit_at']}")
    print(f"Request: {row['request_text']}")
    print(f"Steps count: {len(steps)}")
    for s in steps:
        print(f"  Step {s['step_no']} [{s['phase']}]: sys={s['system_id']} res={s['resource_id']} op={s['operation']} state={s['state']} ev={s.get('evidence_id')}")
