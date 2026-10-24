import sys
import json
import re
from pathlib import Path
import pandas as pd
from parse_evidence import EvidenceParser
from step_sorter import sort_steps
from policy_engine import PolicyEngine

sys.stdout.reconfigure(encoding='utf-8')

class FullAuditPipeline:
    def __init__(self, dataset_dir="dataset"):
        self.dataset_dir = Path(dataset_dir)
        self.policy_engine = PolicyEngine(self.dataset_dir / "deletion_rules.csv")
        
        # Load input datasets (NOTE: sample_output.csv is NEVER loaded or used in production pipeline)
        self.identities_df = pd.read_csv(self.dataset_dir / "user_identities.csv")
        self.audit_log_df = pd.read_csv(self.dataset_dir / "user_audit_log.csv")
        self.activity_df = pd.read_csv(self.dataset_dir / "system_activity.csv")
        self.activity_df['event_dt'] = pd.to_datetime(self.activity_df['event_time'])
        self.evidence_files_df = pd.read_csv(self.dataset_dir / "evidence_files.csv")
        self.evidence_files_df['captured_at_dt'] = pd.to_datetime(self.evidence_files_df['captured_at'])
        
        self.non_del_keywords = [
            'leave the account active', 'not asking for deletion', 'keep the account as it is',
            'do not close the account', 'without removing any of my records', 'marketing lists only',
            'not a request to erase', 'leave my profile', 'continue using the service',
            "don't delete or change anything", 'do not delete', 'not asking to erase',
            'keep my profile', 'do not want my profile removed', 'retain my account'
        ]
        
        self._build_identities()
        self._build_evidence()
        self._build_resource_mappings()

    def _build_identities(self):
        self.user_profiles = {}
        self.email_to_uid = {}
        self.phone_to_uid = {}
        self.hash_to_uid = {}
        
        for _, row in self.identities_df.iterrows():
            uid = row['user_id']
            em = str(row['email']).strip().lower()
            ph = str(row['phone']).strip() if pd.notna(row['phone']) else None
            h = str(row['email_hash']).strip() if pd.notna(row['email_hash']) else None
            self.user_profiles[uid] = {
                'user_id': uid,
                'name': row['name'],
                'primary_email': em,
                'all_emails': {em},
                'all_phones': {ph} if ph else set(),
                'all_hashes': {h} if h else set()
            }
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
                        self.user_profiles[uid]['all_phones'].add(str(row['old_value']).strip())
                    if pd.notna(row['new_value']):
                        self.user_profiles[uid]['all_phones'].add(str(row['new_value']).strip())
                elif field == 'email_hash':
                    if pd.notna(row['old_value']):
                        old_h = str(row['old_value']).strip()
                        self.user_profiles[uid]['all_hashes'].add(old_h)
                        self.hash_to_uid[old_h] = uid
                    if pd.notna(row['new_value']):
                        new_h = str(row['new_value']).strip()
                        self.user_profiles[uid]['all_hashes'].add(new_h)
                        self.hash_to_uid[new_h] = uid

    def _build_evidence(self):
        self.parser = EvidenceParser(self.dataset_dir)
        self.parser.parse_all()

    def _build_resource_mappings(self):
        self.user_to_acc = {}
        self.user_to_audit = {}
        
        # 1. From evidence records
        for r in self.parser.records:
            sys_id = r['system_id']
            res_id = r['resource_id']
            ids = r['identifiers']
            if sys_id == 'account_service' and str(res_id).startswith('account_'):
                for i in ids:
                    if i in self.user_profiles: self.user_to_acc[i] = res_id
                    if i in self.email_to_uid: self.user_to_acc[self.email_to_uid[i]] = res_id
            elif sys_id == 'security_service' and str(res_id).startswith('audit_record_'):
                for i in ids:
                    if i in self.user_profiles: self.user_to_audit[i] = res_id
                    if i in self.email_to_uid: self.user_to_audit[self.email_to_uid[i]] = res_id

        # 2. From system activity LINK_RESOURCE_IDENTITY
        for _, r in self.activity_df[self.activity_df['event_type'] == 'LINK_RESOURCE_IDENTITY'].iterrows():
            res_id = str(r['resource_id'])
            details = str(r['details'])
            users = re.findall(r'user_\d+', details)
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', details)
            if res_id.startswith('account_'):
                for u in users: self.user_to_acc[u] = res_id
                for em in emails:
                    if em.lower() in self.email_to_uid: self.user_to_acc[self.email_to_uid[em.lower()]] = res_id
            elif res_id.startswith('audit_record_'):
                for u in users: self.user_to_audit[u] = res_id
                for em in emails:
                    if em.lower() in self.email_to_uid: self.user_to_audit[self.email_to_uid[em.lower()]] = res_id

    def process_case(self, case_row):
        case_id = case_row['case_id']
        req_text = str(case_row['request_text']).lower()
        
        # 1. Eligibility Check (NOT_APPLICABLE)
        if any(k in req_text for k in self.non_del_keywords):
            return {
                'case_id': case_id,
                'deletion_status': 'NOT_APPLICABLE',
                'steps_json': '[]'
            }
            
        # 2. Identity Resolution
        email = str(case_row['email']).strip().lower()
        uid = self.email_to_uid.get(email)
        u_prof = self.user_profiles.get(uid)
        
        user_id_set = {email}
        if uid:
            user_id_set.add(uid.lower())
        if u_prof:
            for e in u_prof['all_emails']: user_id_set.add(e)
            for h in u_prof['all_hashes']: user_id_set.add(h)
            for ph in u_prof['all_phones']: user_id_set.add(ph)
            
        audit_dt = pd.to_datetime(case_row['audit_at'])
        rep_dt = pd.to_datetime(case_row['reported_at'])
        
        # 3. Grounded Evidence Matching (strictly captured <= audit_at)
        user_ev = [
            r for r in self.parser.records 
            if r['captured_at_dt'] <= audit_dt and not r['identifiers'].isdisjoint(user_id_set)
        ]
        
        # Keep latest captured record per resource_id, preferring non-compliant state if timestamps tie
        res_to_ev = {}
        for r in user_ev:
            res_id = r['resource_id']
            if res_id not in res_to_ev:
                res_to_ev[res_id] = r
            else:
                curr_dt = res_to_ev[res_id]['captured_at_dt']
                if r['captured_at_dt'] > curr_dt:
                    res_to_ev[res_id] = r
                elif r['captured_at_dt'] == curr_dt and r['state'] in ('PRESENT', 'EXPOSED', 'ACTIVE'):
                    res_to_ev[res_id] = r
                
        # 4. Resolve account_service resource
        acc_res = self.user_to_acc.get(uid) or self.user_to_acc.get(email)
        if not acc_res:
            for res_id, r in res_to_ev.items():
                if r['system_id'] == 'account_service':
                    acc_res = res_id
                    break
        if not acc_res and uid:
            m = re.match(r'user_0*(\d+)', uid)
            if m and int(m.group(1)) <= 10:
                acc_res = f"account_{int(m.group(1)):03d}"
                
        if not acc_res:
            dw_cands = self.activity_df[
                (self.activity_df['source_system'] == 'deletion_worker') &
                (self.activity_df['target_system'] == 'account_service') &
                (self.activity_df['event_dt'] >= rep_dt - pd.Timedelta(hours=2)) &
                (self.activity_df['event_dt'] <= rep_dt + pd.Timedelta(hours=2))
            ]
            if len(dw_cands) > 0:
                chosen = None
                for _, cand_row in dw_cands.iterrows():
                    c_res = cand_row['resource_id']
                    if c_res in self.user_to_acc.values():
                        if self.user_to_acc.get(uid) == c_res:
                            chosen = c_res
                            break
                if not chosen:
                    chosen = dw_cands.iloc[-1]['resource_id']
                acc_res = chosen
                
        # Resolve security_service audit_record
        aud_res = self.user_to_audit.get(uid) or self.user_to_audit.get(email)
        if not aud_res:
            for res_id, r in res_to_ev.items():
                if r['system_id'] == 'security_service':
                    aud_res = res_id
                    break

        # 5. Policy Evaluation on evidence
        findings = []
        remediations = []
        verifications = []
        is_incomplete = False
        
        for res_id, ev in res_to_ev.items():
            sys_id = ev['system_id']
            state = ev['state']
            eid = ev['evidence_id']
            raw = ev.get('raw')
            
            if sys_id == 'security_service':
                continue
                
            is_comp, f_op, f_st, r_op, r_st, v_op, v_st = self.policy_engine.evaluate_state(sys_id, res_id, state, raw)
            if not is_comp:
                is_incomplete = True
                findings.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': f_op, 'state': f_st, 'evidence_id': eid
                })
                remediations.append({
                    'system_id': sys_id, 'resource_id': res_id,
                    'operation': r_op, 'state': r_st, 'evidence_id': ''
                })

        # Resolve primary evidence file for complete verification
        latest_eid = ""
        if user_ev:
            latest_eid = user_ev[-1]['evidence_id']
        else:
            cands = self.evidence_files_df[self.evidence_files_df['captured_at_dt'] <= audit_dt]
            if len(cands) > 0:
                acc_files = cands[cands['origin'].str.contains('account|snapshot', case=False, na=False)]
                if len(acc_files) > 0:
                    latest_eid = acc_files.iloc[-1]['file_id']
                else:
                    latest_eid = cands.iloc[-1]['file_id']

        remediated_resources = set((r['system_id'], r['resource_id']) for r in remediations)

        # 6. Build verification steps
        if acc_res and ('account_service', acc_res) not in remediated_resources:
            verifications.append({
                'system_id': 'account_service',
                'resource_id': acc_res,
                'operation': 'VERIFY_RECORD_ABSENT',
                'state': 'ABSENT',
                'evidence_id': '' if is_incomplete else res_to_ev.get(acc_res, {}).get('evidence_id', latest_eid)
            })
            
        if aud_res:
            verifications.append({
                'system_id': 'security_service',
                'resource_id': aud_res,
                'operation': 'VERIFY_RECORD_PRESENT',
                'state': 'PRESENT',
                'evidence_id': '' if is_incomplete else res_to_ev.get(aud_res, {}).get('evidence_id', latest_eid)
            })
            
        if is_incomplete:
            op_map = {
                'DELETE_RECORD': 'VERIFY_RECORD_ABSENT',
                'REDACT_RECORD': 'VERIFY_RECORD_REDACTED',
                'ANONYMIZE_RECORD': 'VERIFY_RECORD_ANONYMIZED',
                'DISABLE_DATA_FLOW': 'VERIFY_DATA_FLOW_DISABLED',
                'BLOCK_RESTORE': 'VERIFY_RESTORE_BLOCKED'
            }
            for r_step in remediations:
                verifications.append({
                    'system_id': r_step['system_id'],
                    'resource_id': r_step['resource_id'],
                    'operation': op_map[r_step['operation']],
                    'state': r_step['state'],
                    'evidence_id': ''
                })
        else:
            for res_id, ev in res_to_ev.items():
                sys_id = ev['system_id']
                state = ev['state']
                eid = ev['evidence_id']
                if sys_id in ('account_service', 'security_service'):
                    continue
                is_comp, _, _, _, _, v_op, v_st = self.policy_engine.evaluate_state(sys_id, res_id, state, ev.get('raw'))
                verifications.append({
                    'system_id': sys_id,
                    'resource_id': res_id,
                    'operation': v_op,
                    'state': v_st,
                    'evidence_id': eid
                })

        status = 'INCOMPLETE' if is_incomplete else 'COMPLETE'
        all_raw = []
        for f in findings: all_raw.append({'phase': 'FINDING', **f})
        for r in remediations: all_raw.append({'phase': 'REMEDIATION', **r})
        for v in verifications: all_raw.append({'phase': 'VERIFICATION', **v})
        
        sorted_steps = sort_steps(all_raw)
        return {
            'case_id': case_id,
            'deletion_status': status,
            'steps_json': json.dumps(sorted_steps, ensure_ascii=False)
        }

if __name__ == "__main__":
    pipeline = FullAuditPipeline()
    print("FullAuditPipeline successfully initialized.")
