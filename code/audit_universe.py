import sys
import json
import re
from pathlib import Path
import pandas as pd

sys.stdout.reconfigure(encoding='utf-8')

class AuditUniverse:
    def __init__(self, dataset_dir="dataset"):
        self.dataset_dir = Path(dataset_dir)
        self.identities_df = pd.read_csv(self.dataset_dir / "user_identities.csv")
        self.audit_log_df = pd.read_csv(self.dataset_dir / "user_audit_log.csv")
        self.activity_df = pd.read_csv(self.dataset_dir / "system_activity.csv")
        self.rules_df = pd.read_csv(self.dataset_dir / "deletion_rules.csv")
        self.evidence_files_df = pd.read_csv(self.dataset_dir / "evidence_files.csv")
        
        self._build_user_profiles()
        self._build_audit_record_index()
        self._build_activity_index()
        self._build_evidence_index()
        self._build_rules_index()

    def _build_user_profiles(self):
        self.user_profiles = {}
        self.email_to_uid = {}
        self.phone_to_uid = {}
        self.hash_to_uid = {}
        
        self.identities_df['email_clean'] = self.identities_df['email'].str.strip().str.lower()
        for _, row in self.identities_df.iterrows():
            uid = row['user_id']
            em = row['email_clean']
            ph = str(row['phone']).strip() if pd.notna(row['phone']) else None
            h = str(row['email_hash']).strip() if pd.notna(row['email_hash']) else None
            
            p = {
                'user_id': uid,
                'name': row['name'],
                'primary_email': em,
                'all_emails': {em},
                'all_phones': {ph} if ph else set(),
                'all_hashes': {h} if h else set(),
            }
            self.user_profiles[uid] = p
            self.email_to_uid[em] = uid
            if ph: self.phone_to_uid[ph] = uid
            if h: self.hash_to_uid[h] = uid
            
        for _, row in self.audit_log_df.iterrows():
            uid = row['user_id']
            if uid in self.user_profiles:
                field = row['field_name']
                if field == 'email':
                    if pd.notna(row['old_value']):
                        old_em = str(row['old_value']).strip().lower()
                        self.user_profiles[uid]['all_emails'].add(old_em)
                        self.email_to_uid[old_em] = uid
                    if pd.notna(row['new_value']):
                        new_em = str(row['new_value']).strip().lower()
                        self.user_profiles[uid]['all_emails'].add(new_em)
                        self.email_to_uid[new_em] = uid
                elif field == 'phone':
                    if pd.notna(row['old_value']):
                        old_ph = str(row['old_value']).strip()
                        self.user_profiles[uid]['all_phones'].add(old_ph)
                        self.phone_to_uid[old_ph] = uid
                    if pd.notna(row['new_value']):
                        new_ph = str(row['new_value']).strip()
                        self.user_profiles[uid]['all_phones'].add(new_ph)
                        self.phone_to_uid[new_ph] = uid
                elif field == 'email_hash':
                    if pd.notna(row['old_value']):
                        old_h = str(row['old_value']).strip()
                        self.user_profiles[uid]['all_hashes'].add(old_h)
                        self.hash_to_uid[old_h] = uid
                    if pd.notna(row['new_value']):
                        new_h = str(row['new_value']).strip()
                        self.user_profiles[uid]['all_hashes'].add(new_h)
                        self.hash_to_uid[new_h] = uid

    def _build_audit_record_index(self):
        # Maps user_id -> audit_record_id
        self.user_to_audit_rec = {}
        
        # 1. JSON evidence files
        for p in (self.dataset_dir / 'evidence').rglob('*.json'):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if 'service_exports' in data:
                    for a in data['service_exports'].get('security_service', {}).get('audit_records', []):
                        u = a.get('subject_reference')
                        res = a.get('resource_id')
                        if u and res: self.user_to_audit_rec[u] = res
                if 'snapshots' in data:
                    for s in data['snapshots']:
                        for r in s.get('records', []):
                            u = r.get('subject_reference') or r.get('user_id')
                            res = r.get('resource_id')
                            if u and res and 'audit_record' in res: self.user_to_audit_rec[u] = res
                if 'records' in data:
                    for r in data['records']:
                        u = r.get('subject_reference') or r.get('user_id')
                        res = r.get('resource_id')
                        if u and res and 'audit_record' in res: self.user_to_audit_rec[u] = res
            except:
                pass

        # 2. SQL evidence files
        for p in (self.dataset_dir / 'evidence').rglob('*.sql'):
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if 'audit_record_' in line:
                            m_res = re.search(r'(audit_record_\d+)', line)
                            m_u = re.search(r'(user_\d+)', line)
                            if m_res and m_u:
                                self.user_to_audit_rec[m_u.group(1)] = m_res.group(1)
            except:
                pass

        # 3. TXT handover files
        txt_path = self.dataset_dir / 'evidence/records/customer_account_handover_20261001.txt'
        if txt_path.exists():
            with open(txt_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if 'security_service' in line and 'audit_record' in line:
                        parts = [p.strip() for p in line.split('|')]
                        res = parts[2]
                        u = parts[5]
                        if 'user_' in u and 'audit_record' in res:
                            self.user_to_audit_rec[u] = res

        # 4. Logs with trace_id correlation
        trace_to_user = {}
        trace_to_res = {}
        for p in (self.dataset_dir / 'evidence').rglob('*.log'):
            try:
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        m_tr = re.search(r'trace_id["\s:=]+([a-zA-Z0-9_\-]+)', line)
                        m_u = re.search(r'(?:subject_reference|subject_ref|lookup_key|correlation_key)["\s:=]+(user_\d+)', line)
                        m_res = re.search(r'resource_id["\s:=]+(audit_record_\d+)', line)
                        if m_u and m_res:
                            self.user_to_audit_rec[m_u.group(1)] = m_res.group(1)
                        if m_tr:
                            tr = m_tr.group(1)
                            if m_u: trace_to_user[tr] = m_u.group(1)
                            if m_res: trace_to_res[tr] = m_res.group(1)
            except:
                pass

        for tr, u in trace_to_user.items():
            if tr in trace_to_res:
                self.user_to_audit_rec[u] = trace_to_res[tr]

    def _build_activity_index(self):
        # Parse activity into datetime objects
        self.activity_df['event_dt'] = pd.to_datetime(self.activity_df['event_time'])

    def _build_evidence_index(self):
        from parse_evidence import EvidenceParser
        self.parser = EvidenceParser(dataset_dir=str(self.dataset_dir))
        self.parser.parse_all()

    def _build_rules_index(self):
        # Maps (system_id, operation) -> policy rule
        # Required treatments from deletion_rules.csv
        self.rules = {}
        for _, r in self.rules_df.iterrows():
            self.rules[r['system_id']] = {
                'required_treatment': r['required_treatment'],
                'target_state': r['target_state'],
                'retention_justification': r.get('retention_justification', '')
            }

print("AuditUniverse module ready.")
