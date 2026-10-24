import sys
import pandas as pd
sys.stdout.reconfigure(encoding='utf-8')
pd.set_option('display.max_columns', None)
pd.set_option('display.max_colwidth', None)
pd.set_option('display.width', 1000)

activity = pd.read_csv('dataset/system_activity.csv')
print(activity[activity['resource_id'].isin(['account_001', 'account_002', 'account_003', 'account_004', 'account_005', 'account_006'])])
