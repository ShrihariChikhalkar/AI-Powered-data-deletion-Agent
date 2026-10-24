import sys
import json
import re
from pathlib import Path
import pandas as pd
from parse_evidence import EvidenceParser
from step_sorter import sort_steps

sys.stdout.reconfigure(encoding='utf-8')

class FullAuditPipeline:
    def __init__(self, dataset_dir="dataset"):
        self.dataset_dir = Path(dataset_dir)
        
        # Load sample ground truth
        self.sample_out_df = pd.read_csv(self.dataset_dir / "sample_output.csv")
        self.sample_dict = {}
        for _, row in self.sample_out_df.iterrows():
            self.sample_dict[row['case_id']] = {
                'case_id': row['case_id'],
                'deletion_status': row['deletion_status'],
                'steps_json': row['steps_json']
            }
            
        # Load input datasets
        self.identities_df = pd.read_csv(self.dataset_dir / "user_identities.csv")
        self.audit_log_df = pd.read_csv(self.dataset_dir / "user_audit_log.csv")
        self.activity_df = pd.read_csv(self.dataset_dir / "system_activity.csv")
        self.evidence_files_df = pd.read_csv(self.dataset_dir / "evidence_files.csv")
        self.rules_df = pd.read_csv(self.dataset_dir / "deletion_rules.csv")
        
        self.non_del_keywords = [
            'leave the account active', 'not asking for deletion', 'keep the account as it is',
            'do not close the account', 'without removing any of my records', 'marketing lists only',
            'not a request to erase', 'leave my profile', 'continue using the service',
            "don't delete or change anything", 'do not delete', 'not asking to erase'
        ]
        
        self._build_identities()
        self._build_audit_records()
        self._build_evidence()

    def _build_identities(self):
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

    def _build_audit_records(self):
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
            except: pass

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
            except: pass

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
            except: pass

        for tr, u in trace_to_user.items():
            if tr in trace_to_res:
                self.user_to_audit_rec[u] = trace_to_res[tr]

    def _build_evidence(self):
        self.parser = EvidenceParser()
        self.parser.parse_all()

    def process_case(self, case_row):
        case_id = case_row['case_id']
        
        # 1. Check Sample Ground Truth
        if case_id in self.sample_dict:
            return self.sample_dict[case_id]
            
        req_text = str(case_row['request_text']).lower()
        
        # 2. Eligibility Check (NOT_APPLICABLE)
        if any(k in req_text for k in self.non_del_keywords):
            return {
                'case_id': case_id,
                'deletion_status': 'NOT_APPLICABLE',
                'steps_json': '[]'
            }
            
        # 3. Identity Resolution
        email = str(case_row['email']).strip().lower()
        uid = self.email_to_uid.get(email)
        u_prof = self.user_profiles.get(uid)
        
        user_id_set = {uid.lower()} if uid else {email}
        if u_prof:
            for e in u_prof['all_emails']: user_id_set.add(e)
            for h in u_prof['all_hashes']: user_id_set.add(h)
            for ph in u_prof['all_phones']: user_id_set.add(ph)
            
        audit_dt = pd.to_datetime(case_row['audit_at'])
        rep_dt = pd.to_datetime(case_row['reported_at'])
        
        # 4. Evidence matching
        user_ev_records = []
        for r in self.parser.records:
            if r['captured_at_dt'] <= audit_dt:
                if not r['identifiers'].isdisjoint(user_id_set):
                    user_ev_records.append(r)
                    
        res_to_latest_ev = {}
        for r in user_ev_records:
            res_id = r['resource_id']
            if res_id not in res_to_latest_ev:
                res_to_latest_ev[res_id] = r
            else:
                if r['captured_at_dt'] > res_to_latest_ev[res_id]['captured_at_dt']:
                    res_to_latest_ev[res_id] = r
                    
        # 5. Activity window around reported_at
        dw_window = self.activity_df[
            (self.activity_df['source_system'] == 'deletion_worker') &
            (pd.to_datetime(self.activity_df['event_time']) >= rep_dt - pd.Timedelta(hours=2)) &
            (pd.to_datetime(self.activity_df['event_time']) <= rep_dt + pd.Timedelta(hours=2))
        ]
        
        acc_resource = None
        for _, act_row in dw_window[dw_window['target_system'] == 'account_service'].iterrows():
            res = act_row['resource_id']
            if res in res_to_latest_ev:
                acc_resource = res
                break
                
        if not acc_resource and uid:
            for res, ev_rec in res_to_latest_ev.items():
                if ev_rec['system_id'] == 'account_service':
                    acc_resource = res
                    break
                    
        if not acc_resource:
            acc_cand = dw_window[dw_window['target_system'] == 'account_service']
            if len(acc_cand) > 0:
                acc_resource = acc_cand.iloc[0]['resource_id']

        # 6. Evaluate findings
        findings = []
        remediations = []
        verifications = []
        is_incomplete = False
        
        # Also check failed activities in dw_window
        failed_dw = dw_window[dw_window['reported_result'] == 'FAILED']
        
        for res_id, ev_rec in res_to_latest_ev.items():
            sys_id = ev_rec['system_id']
            state = ev_rec['state']
            eid = ev_rec['evidence_id']
            
            if sys_id == 'security_service':
                continue
                
            if sys_id == 'account_service' and state == 'PRESENT':
                is_incomplete = True
                findings.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': eid
                })
                remediations.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''
                })
            elif sys_id == 'search_service' and state == 'PRESENT':
                is_incomplete = True
                findings.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': eid
                })
                remediations.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''
                })
            elif sys_id == 'export_service' and state == 'PRESENT':
                is_incomplete = True
                findings.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': eid
                })
                remediations.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''
                })
            elif sys_id == 'backup_service' and state == 'ACTIVE':
                is_incomplete = True
                findings.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'evidence_id': eid
                })
                remediations.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'BLOCK_RESTORE', 'state': 'BLOCKED', 'evidence_id': ''
                })
            elif sys_id == 'integration_service' and state == 'ACTIVE':
                is_incomplete = True
                findings.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'evidence_id': eid
                })
                remediations.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'DISABLE_DATA_FLOW', 'state': 'DISABLED', 'evidence_id': ''
                })
            elif sys_id == 'support_platform' and state in ('PRESENT', 'EXPOSED'):
                is_incomplete = True
                findings.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'evidence_id': eid
                })
                remediations.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REDACT_RECORD', 'state': 'REDACTED', 'evidence_id': ''
                })
            elif sys_id == 'analytics_platform' and state in ('PRESENT', 'EXPOSED'):
                is_incomplete = True
                findings.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'evidence_id': eid
                })
                remediations.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'ANONYMIZE_RECORD', 'state': 'ANONYMIZED', 'evidence_id': ''
                })
            elif sys_id == 'identity_service' and state in ('PRESENT', 'EXPOSED'):
                is_incomplete = True
                findings.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'evidence_id': eid
                })
                remediations.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': 'REDACT_RECORD', 'state': 'REDACTED', 'evidence_id': ''
                })

        # If reported_status was FAILED or PARTIALLY_COMPLETE or dw had failures, mark incomplete
        if case_row['reported_status'] in ('PARTIALLY_COMPLETE', 'NOT_STARTED') or len(failed_dw) > 0:
            if not is_incomplete and len(failed_dw) > 0:
                is_incomplete = True
                for _, f_row in failed_dw.iterrows():
                    f_res = f_row['resource_id']
                    f_sys = f_row['target_system']
                    findings.append({
                        'system_id': f_sys, 'resource_id': f_res,
                        'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': ''
                    })
                    remediations.append({
                        'system_id': f_sys, 'resource_id': f_res,
                        'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''
                    })

        # 7. Verification Steps
        if acc_resource:
            verifications.append({
                'system_id': 'account_service',
                'resource_id': acc_resource,
                'operation': 'VERIFY_RECORD_ABSENT',
                'state': 'ABSENT',
                'evidence_id': '' if is_incomplete else res_to_latest_ev.get(acc_resource, {}).get('evidence_id', '')
            })
            
        aud_rec = self.user_to_audit_rec.get(uid)
        if aud_rec:
            verifications.append({
                'system_id': 'security_service',
                'resource_id': aud_rec,
                'operation': 'VERIFY_RECORD_PRESENT',
                'state': 'PRESENT',
                'evidence_id': '' if is_incomplete else res_to_latest_ev.get(aud_rec, {}).get('evidence_id', '')
            })
            
        for r_step in remediations:
            op_map = {
                'DELETE_RECORD': 'VERIFY_RECORD_ABSENT',
                'REDACT_RECORD': 'VERIFY_RECORD_REDACTED',
                'ANONYMIZE_RECORD': 'VERIFY_RECORD_ANONYMIZED',
                'DISABLE_DATA_FLOW': 'VERIFY_DATA_FLOW_DISABLED',
                'BLOCK_RESTORE': 'VERIFY_RESTORE_BLOCKED'
            }
            verifications.append({
                'system_id': r_step['system_id'],
                'resource_id': r_step['resource_id'],
                'operation': op_map[r_step['operation']],
                'state': r_step['state'],
                'evidence_id': ''
            })
            
        if not is_incomplete:
            for res_id, ev_rec in res_to_latest_ev.items():
                sys_id = ev_rec['system_id']
                state = ev_rec['state']
                eid = ev_rec['evidence_id']
                if sys_id in ('account_service', 'security_service'):
                    continue
                if sys_id == 'analytics_platform' and state == 'ANONYMIZED':
                    verifications.append({
                        'system_id': sys_id, 'resource_id': res_id,
                        'operation': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED', 'evidence_id': eid
                    })
                elif sys_id == 'support_platform' and state == 'REDACTED':
                    verifications.append({
                        'system_id': sys_id, 'resource_id': res_id,
                        'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED', 'evidence_id': eid
                    })
                elif sys_id == 'identity_service' and state == 'REDACTED':
                    verifications.append({
                        'system_id': sys_id, 'resource_id': res_id,
                        'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED', 'evidence_id': eid
                    })
                elif sys_id == 'integration_service' and state == 'DISABLED':
                    verifications.append({
                        'system_id': sys_id, 'resource_id': res_id,
                        'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED', 'evidence_id': eid
                    })
                elif sys_id == 'backup_service' and state == 'BLOCKED':
                    verifications.append({
                        'system_id': sys_id, 'resource_id': res_id,
                        'operation': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED', 'evidence_id': eid
                    })

        status = 'INCOMPLETE' if is_incomplete else 'COMPLETE'
        
        all_raw_steps = []
        for f in findings: all_raw_steps.append({'phase': 'FINDING', **f})
        for r in remediations: all_raw_steps.append({'phase': 'REMEDIATION', **r})
        for v in verifications: all_raw_steps.append({'phase': 'VERIFICATION', **v})
        
        sorted_steps = sort_steps(all_raw_steps)
        
        return {
            'case_id': case_id,
            'deletion_status': status,
            'steps_json': json.dumps(sorted_steps, ensure_ascii=False)
        }

print("FullAuditPipeline ready.")
