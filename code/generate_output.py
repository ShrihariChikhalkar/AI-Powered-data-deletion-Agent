import sys
import json
import re
from pathlib import Path
import pandas as pd

sys.stdout.reconfigure(encoding='utf-8')

# Load sample output ground truth
sample_out = pd.read_csv('dataset/sample_output.csv')
sample_cases = set(sample_out['case_id'])

# Load deletion requests
all_reqs = pd.read_csv('dataset/deletion_requests.csv')
print(f"Total deletion requests: {len(all_reqs)}")

# Load user identities and audit log
identities = pd.read_csv('dataset/user_identities.csv')
audit_log = pd.read_csv('dataset/user_audit_log.csv')
system_activity = pd.read_csv('dataset/system_activity.csv')

print("All input files loaded successfully.")
