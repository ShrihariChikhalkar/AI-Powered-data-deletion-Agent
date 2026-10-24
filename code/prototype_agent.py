import sys
import json
import sqlite3
import re
import pandas as pd
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

# 1. Load basic datasets
rules_df = pd.read_csv('dataset/deletion_rules.csv')
identities_df = pd.read_csv('dataset/user_identities.csv')
audit_log_df = pd.read_csv('dataset/user_audit_log.csv')
evidence_files_df = pd.read_csv('dataset/evidence_files.csv')
system_activity_df = pd.read_csv('dataset/system_activity.csv')

# Build identity profiles
identities_df['email_clean'] = identities_df['email'].str.strip().str.lower()
user_profiles = {}
for _, row in identities_df.iterrows():
    uid = row['user_id']
    user_profiles[uid] = {
        'user_id': uid,
        'name': row['name'],
        'email': row['email_clean'],
        'phone': str(row['phone']).strip() if pd.notna(row['phone']) else None,
        'email_hash': str(row['email_hash']).strip() if pd.notna(row['email_hash']) else None,
        'all_emails': {row['email_clean']},
        'all_phones': {str(row['phone']).strip()} if pd.notna(row['phone']) else set(),
        'all_hashes': {str(row['email_hash']).strip()} if pd.notna(row['email_hash']) else set(),
        'all_names': {str(row['name']).strip()} if pd.notna(row['name']) else set(),
    }

for _, row in audit_log_df.iterrows():
    uid = row['user_id']
    if uid in user_profiles:
        field = row['field_name']
        if field == 'email':
            if pd.notna(row['old_value']): user_profiles[uid]['all_emails'].add(str(row['old_value']).strip().lower())
            if pd.notna(row['new_value']): user_profiles[uid]['all_emails'].add(str(row['new_value']).strip().lower())
        elif field == 'phone':
            if pd.notna(row['old_value']): user_profiles[uid]['all_phones'].add(str(row['old_value']).strip())
            if pd.notna(row['new_value']): user_profiles[uid]['all_phones'].add(str(row['new_value']).strip())
        elif field == 'email_hash':
            if pd.notna(row['old_value']): user_profiles[uid]['all_hashes'].add(str(row['old_value']).strip())
            if pd.notna(row['new_value']): user_profiles[uid]['all_hashes'].add(str(row['new_value']).strip())
        elif field == 'name':
            if pd.notna(row['old_value']): user_profiles[uid]['all_names'].add(str(row['old_value']).strip())
            if pd.notna(row['new_value']): user_profiles[uid]['all_names'].add(str(row['new_value']).strip())

email_to_user = {}
for uid, p in user_profiles.items():
    for em in p['all_emails']:
        email_to_user[em] = uid

print("Loaded and indexed user identities.")
