import sys
import pandas as pd

sys.stdout.reconfigure(encoding='utf-8')
act = pd.read_csv('dataset/system_activity.csv')
sreq = pd.read_csv('dataset/sample_deletion_requests.csv')

for cid in ['case_03', 'case_04', 'case_21', 'case_25', 'case_26', 'case_27', 'case_28', 'case_31']:
    r = sreq[sreq['case_id'] == cid].iloc[0]
    rep = pd.to_datetime(r['reported_at'])
    w = act[(act['source_system'] == 'deletion_worker') & 
            (pd.to_datetime(act['event_time']) >= rep - pd.Timedelta(hours=2)) & 
            (pd.to_datetime(act['event_time']) <= rep + pd.Timedelta(hours=2))]
    print(f"{cid} (rep={r['reported_at']}): dw activities = {list(w['resource_id'])}")
