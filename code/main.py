import sys
import pandas as pd
from full_pipeline import FullAuditPipeline

sys.stdout.reconfigure(encoding='utf-8')

print("Initializing Data Deletion Audit Agent Pipeline...")
pipeline = FullAuditPipeline(dataset_dir="dataset")

print("Loading all deletion requests...")
reqs = pd.read_csv("dataset/deletion_requests.csv")
print(f"Total requests to process: {len(reqs)}")

results = []
for idx, (_, row) in enumerate(reqs.iterrows(), 1):
    res = pipeline.process_case(row)
    results.append(res)
    if idx % 50 == 0 or idx == len(reqs):
        print(f"Processed {idx}/{len(reqs)} cases...")

output_df = pd.DataFrame(results, columns=['case_id', 'deletion_status', 'steps_json'])

# Sort canonically by case_id
# Use integer sort on case_id suffix
output_df['case_num'] = output_df['case_id'].apply(lambda x: int(x.split('_')[1]))
output_df = output_df.sort_values('case_num').drop(columns=['case_num'])

# Write output.csv
output_df.to_csv("output.csv", index=False)
print(f"Successfully generated output.csv with {len(output_df)} rows.")

# Verify output.csv
print("\nValidating output.csv format...")
with open("output.csv", "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"Header: {lines[0].strip()}")
print(f"Total lines: {len(lines)} (Header + {len(lines)-1} data rows)")
print(f"First data row: {lines[1][:60]}...")
print(f"Last data row: {lines[-1][:60]}...")

counts = output_df['deletion_status'].value_counts().to_dict()
print(f"Status distribution: {counts}")
