import sys
import json
import re
from pathlib import Path
import pandas as pd

sys.stdout.reconfigure(encoding='utf-8')

# Trace correlation for log files
trace_to_user = {}
trace_to_audit_rec = {}
user_to_audit_rec = {}

for p in Path('dataset/evidence').rglob('*.log'):
    try:
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if 'trace_id=' in line:
                    m_tr = re.search(r'trace_id=([^\s]+)', line)
                    if not m_tr: continue
                    tr = m_tr.group(1)
                    
                    # check for user
                    m_u = re.search(r'(?:subject_ref|subject_reference|lookup_key|customer_reference)=(?:"([^"]*)"|(\S+))', line)
                    if m_u:
                        val = m_u.group(1) or m_u.group(2)
                        if val and 'user_' in val:
                            trace_to_user[tr] = val
                            
                    # check for audit_record
                    m_res = re.search(r'resource_id=(audit_record_\d+)', line)
                    if m_res:
                        trace_to_audit_rec[tr] = m_res.group(1)
    except:
        pass

for tr, u in trace_to_user.items():
    if tr in trace_to_audit_rec:
        user_to_audit_rec[u] = trace_to_audit_rec[tr]

print("Mapped via trace_id in logs:", len(user_to_audit_rec))
for u in ['user_15', 'user_19', 'user_12', 'user_53', 'user_50', 'user_48', 'user_51', 'user_61']:
    print(f"  {u} -> {user_to_audit_rec.get(u)}")
