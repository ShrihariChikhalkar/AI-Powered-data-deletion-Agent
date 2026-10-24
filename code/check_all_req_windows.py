import sys
import pandas as pd
sys.stdout.reconfigure(encoding='utf-8')

requests = pd.read_csv('dataset/deletion_requests.csv')
activity = pd.read_csv('dataset/system_activity.csv')
dw = activity[activity['source_system'] == 'deletion_worker']

print("Total requests:", len(requests))
print("Total deletion worker activities:", len(dw))

# Count activities per request window
counts = []
for _, req in requests.iterrows():
    rep_t = pd.to_datetime(req['reported_at'])
    acts = dw[(pd.to_datetime(dw['event_time']) >= rep_t - pd.Timedelta(hours=3)) & 
              (pd.to_datetime(dw['event_time']) <= rep_t + pd.Timedelta(hours=3))]
    counts.append(len(acts))

s_counts = pd.Series(counts)
print("Activity counts in +/-3h window of reported_at:")
print(s_counts.describe())
