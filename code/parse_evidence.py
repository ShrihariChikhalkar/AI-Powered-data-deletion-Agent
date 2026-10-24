import sys
import json
import sqlite3
import re
from pathlib import Path
import pandas as pd
import fitz

sys.stdout.reconfigure(encoding='utf-8')

evidence_manifest = pd.read_csv('dataset/evidence_files.csv')
evidence_manifest['captured_at_dt'] = pd.to_datetime(evidence_manifest['captured_at'])

# Load OCR data
ocr_cache = {}
ocr_path = Path('dataset/evidence/images_ocr.json')
if ocr_path.exists():
    with open(ocr_path, 'r', encoding='utf-8') as f:
        ocr_cache = json.load(f)

class EvidenceParser:
    def __init__(self):
        self.records = []

    def parse_all(self):
        for _, row in evidence_manifest.iterrows():
            fid = row['file_id']
            fpath = Path('dataset') / row['file_path']
            captured_at = row['captured_at']
            captured_at_dt = row['captured_at_dt']
            
            if not fpath.exists():
                continue
                
            suffix = fpath.suffix.lower()
            try:
                if suffix == '.json':
                    self.parse_json(fid, fpath, captured_at, captured_at_dt)
                elif suffix == '.sql':
                    self.parse_sql(fid, fpath, captured_at, captured_at_dt)
                elif suffix == '.log':
                    self.parse_log(fid, fpath, captured_at, captured_at_dt)
                elif suffix == '.txt':
                    self.parse_txt(fid, fpath, captured_at, captured_at_dt)
                elif suffix == '.pdf':
                    self.parse_pdf(fid, fpath, captured_at, captured_at_dt)
                elif suffix == '.png':
                    self.parse_png(fid, fpath, captured_at, captured_at_dt)
            except Exception as e:
                print(f"Error parsing {fid} ({fpath}): {e}")
                
        print(f"Parsed total {len(self.records)} records across all evidence files.")

    def add_rec(self, fid, captured_at, captured_at_dt, system_id, resource_id, identifiers, status_type, raw):
        clean_ids = set()
        for i in identifiers:
            if i and pd.notna(i):
                clean_ids.add(str(i).strip().lower())
        self.records.append({
            'evidence_id': fid,
            'captured_at': captured_at,
            'captured_at_dt': captured_at_dt,
            'system_id': system_id,
            'resource_id': resource_id,
            'identifiers': clean_ids,
            'status_type': status_type,
            'state': status_type,
            'raw': raw
        })

    def parse_json(self, fid, fpath, captured_at, captured_at_dt):
        with open(fpath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # 1. service_resource_export
        if 'service_exports' in data:
            se = data['service_exports']
            # account_service
            for p in se.get('account_service', {}).get('profile_lookups', []):
                res_id = p.get('resource_id')
                prof = p.get('profile') or {}
                ids = {prof.get('email'), prof.get('customer_reference'), prof.get('phone'), prof.get('email_hash')}
                status = 'ABSENT' if p.get('status_code') == 404 else ('PRESENT' if p.get('status_code') == 200 else 'UNKNOWN')
                self.add_rec(fid, captured_at, captured_at_dt, 'account_service', res_id, ids, status, p)
            # analytics_platform
            for p in se.get('analytics_platform', {}).get('profiles', []):
                res_id = p.get('resource_id')
                ids = {p.get('email'), p.get('customer_reference'), p.get('phone'), p.get('email_hash')}
                status = 'EXPOSED' if p.get('email') or p.get('customer_reference') else 'ANONYMIZED'
                self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, status, p)
            # backup_service
            for b in se.get('backup_service', {}).get('restore_entries', []):
                res_id = b.get('resource_id')
                ids = {b.get('customer_email'), b.get('customer_reference')}
                status = 'ACTIVE' if b.get('restore_allowed') else 'BLOCKED'
                self.add_rec(fid, captured_at, captured_at_dt, 'backup_service', res_id, ids, status, b)
            # export_service
            for e in se.get('export_service', {}).get('exports', []):
                res_id = e.get('resource_id')
                ids = {e.get('owner_email'), e.get('customer_reference'), e.get('owner_phone')}
                self.add_rec(fid, captured_at, captured_at_dt, 'export_service', res_id, ids, 'PRESENT', e)
            # integration_service
            for c in se.get('integration_service', {}).get('connectors', []):
                res_id = c.get('resource_id')
                ids = {c.get('customer_email'), c.get('customer_reference')}
                status = 'ACTIVE' if c.get('enabled') else 'DISABLED'
                self.add_rec(fid, captured_at, captured_at_dt, 'integration_service', res_id, ids, status, c)
            # search_service
            for s in se.get('search_service', {}).get('index_queries', []):
                res_id = s.get('resource_id')
                hits = s.get('hits', {})
                docs = hits.get('documents', [])
                total = hits.get('total', 0)
                ids = {s.get('query')}
                for d in docs:
                    ids.add(d.get('email'))
                    ids.add(d.get('customer_reference'))
                status = 'PRESENT' if total > 0 else 'ABSENT'
                self.add_rec(fid, captured_at, captured_at_dt, 'search_service', res_id, ids, status, s)
            # security_service
            for a in se.get('security_service', {}).get('audit_records', []):
                res_id = a.get('resource_id')
                ids = {a.get('subject_reference')}
                self.add_rec(fid, captured_at, captured_at_dt, 'security_service', res_id, ids, 'PRESENT', a)
            # support_platform
            for t in se.get('support_platform', {}).get('tickets', []):
                res_id = t.get('resource_id')
                ids = {t.get('requester_email'), t.get('customer_reference'), t.get('requester_phone')}
                status = 'EXPOSED' if t.get('requester_email') or t.get('requester_phone') else 'REDACTED'
                self.add_rec(fid, captured_at, captured_at_dt, 'support_platform', res_id, ids, status, t)
                
        # 2. records_assurance_snapshot_bundle
        elif 'snapshots' in data:
            for snap in data['snapshots']:
                ds = snap.get('data_store')
                col = snap.get('collection')
                for r in snap.get('records', []):
                    res_id = r.get('resource_id')
                    if col == 'customer_profiles':
                        ids = {r.get('email'), r.get('customer_reference'), r.get('phone')}
                        st = 'PRESENT' if r.get('account_status') == 'ACTIVE' else 'ABSENT'
                        self.add_rec(fid, captured_at, captured_at_dt, 'account_service', res_id, ids, st, r)
                    elif col == 'deleted_customer_references':
                        ids = {r.get('email'), r.get('subject_reference'), r.get('name'), r.get('phone')}
                        st = 'EXPOSED' if r.get('email') or r.get('phone') or r.get('name') else 'REDACTED'
                        self.add_rec(fid, captured_at, captured_at_dt, 'identity_service', res_id, ids, st, r)
                    elif col == 'security_audit_events':
                        ids = {r.get('subject_reference')}
                        self.add_rec(fid, captured_at, captured_at_dt, 'security_service', res_id, ids, 'PRESENT', r)
                    elif col in ['support_tickets', 'support_messages']:
                        ids = {r.get('subject_reference'), r.get('customer_reference')}
                        msg = r.get('message_text') or r.get('message_excerpt') or ''
                        emails = re.findall(r'[\w\.-]+@[\w\.-]+', msg)
                        for em in emails: ids.add(em)
                        st = 'EXPOSED' if len(emails) > 0 else 'REDACTED'
                        self.add_rec(fid, captured_at, captured_at_dt, 'support_platform', res_id, ids, st, r)

        # 3. single files
        elif 'records' in data:
            for r in data['records']:
                res_id = r.get('resource_id')
                if 'export' in str(fpath).lower():
                    ids = {r.get('owner_email')}
                    st = 'PRESENT' if r.get('download_available') else 'ABSENT'
                    self.add_rec(fid, captured_at, captured_at_dt, 'export_service', res_id, ids, st, r)
                elif 'analytics' in str(fpath).lower():
                    ids = {r.get('customer_reference'), r.get('email')}
                    st = 'ANONYMIZED' if not r.get('email') else 'EXPOSED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, st, r)
                elif 'security' in str(fpath).lower():
                    ids = {r.get('subject_reference'), r.get('user_id')}
                    self.add_rec(fid, captured_at, captured_at_dt, 'security_service', res_id, ids, 'PRESENT', r)

    def parse_sql(self, fid, fpath, captured_at, captured_at_dt):
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if not line.startswith('INSERT INTO'):
                    continue
                m_tbl = re.search(r'INSERT INTO ["\']?(\w+)["\']? VALUES\s*\((.*)\);', line)
                if not m_tbl:
                    continue
                tbl = m_tbl.group(1)
                vals_str = m_tbl.group(2)
                
                # Check if embedded JSON format: VALUES('res_id', 'origin_sys', 'collection', '{...}', 'timestamp')
                m_json_row = re.match(r"['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*,\s*['\"](\{.*\})['\"]\s*,\s*['\"]([^'\"]+)['\"]", vals_str)
                if m_json_row:
                    res_id = m_json_row.group(1)
                    origin_sys = m_json_row.group(2)
                    collection = m_json_row.group(3)
                    json_str = m_json_row.group(4)
                    try:
                        record_dict = json.loads(json_str)
                    except:
                        # unescape double quotes if any
                        try:
                            record_dict = json.loads(json_str.replace("''", "'"))
                        except:
                            record_dict = {}
                            
                    # Extract identifiers from JSON
                    ids = set()
                    for k in ['user_id', 'customer_reference', 'subject_reference', 'email', 'phone', 'email_hash']:
                        val = record_dict.get(k)
                        if val: ids.add(str(val))
                    if 'document' in record_dict and isinstance(record_dict['document'], dict):
                        doc = record_dict['document']
                        for k in ['customer_reference', 'email']:
                            if doc.get(k): ids.add(str(doc[k]))
                    if 'message_text' in record_dict:
                        for em in re.findall(r'[\w\.-]+@[\w\.-]+', str(record_dict['message_text'])):
                            ids.add(em)
                    if 'subject_selector' in record_dict:
                        ids.add(str(record_dict['subject_selector']))
                        
                    # State determination
                    st = 'PRESENT'
                    if origin_sys == 'account_service':
                        st = 'PRESENT'
                    elif origin_sys == 'search_service':
                        st = 'PRESENT'
                    elif origin_sys == 'analytics_platform':
                        st = 'PRESENT' if (record_dict.get('email') or record_dict.get('user_id')) else 'ANONYMIZED'
                    elif origin_sys == 'support_platform':
                        st = 'REDACTED' if '[REDACTED]' in str(record_dict.get('message_text')) else 'PRESENT'
                    elif origin_sys == 'integration_service':
                        st = 'ACTIVE' if record_dict.get('enabled') is True else 'DISABLED'
                    elif origin_sys == 'backup_service':
                        st = 'ACTIVE' if record_dict.get('restore_allowed') is True else 'BLOCKED'
                    elif origin_sys == 'identity_service':
                        st = 'PRESENT' if record_dict.get('email') else 'REDACTED'
                    elif origin_sys == 'security_service':
                        st = 'PRESENT'
                        
                    self.add_rec(fid, captured_at, captured_at_dt, origin_sys, res_id, ids, st, record_dict)
                    continue

                # Fallback for standard comma-separated columns
                vals = [v.strip().strip("'\"") if v.strip() != 'NULL' else None for v in vals_str.split(',')]
                if len(vals) < 2: continue
                res_id = vals[0]
                
                if 'customer_profiles' in tbl or 'profiles' in tbl:
                    ids = {vals[1], vals[2], vals[3], vals[4] if len(vals) > 4 else None}
                    st = 'PRESENT'
                    self.add_rec(fid, captured_at, captured_at_dt, 'account_service', res_id, ids, st, vals)
                elif 'search' in tbl:
                    ids = set(vals[1:])
                    self.add_rec(fid, captured_at, captured_at_dt, 'search_service', res_id, ids, 'PRESENT', vals)
                elif 'analytics' in tbl:
                    ids = set(vals[1:])
                    has_email = any('@' in str(v) for v in vals if v)
                    st = 'PRESENT' if has_email else 'ANONYMIZED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, st, vals)
                elif 'backup' in tbl:
                    ids = set(vals[1:])
                    rest_allowed = any(v in ['1', 1, 'true', True] for v in vals)
                    st = 'ACTIVE' if rest_allowed else 'BLOCKED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'backup_service', res_id, ids, st, vals)
                elif 'connector' in tbl:
                    ids = set(vals[1:])
                    enabled = any(v in ['1', 1, 'true', True] for v in vals)
                    st = 'ACTIVE' if enabled else 'DISABLED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'integration_service', res_id, ids, st, vals)
                elif 'export' in tbl:
                    ids = set(vals[1:])
                    self.add_rec(fid, captured_at, captured_at_dt, 'export_service', res_id, ids, 'PRESENT', vals)
                elif 'security' in tbl:
                    ids = set(vals[1:])
                    self.add_rec(fid, captured_at, captured_at_dt, 'security_service', res_id, ids, 'PRESENT', vals)
                elif 'support' in tbl:
                    ids = set(vals[1:])
                    has_email = any('@' in str(v) for v in vals if v)
                    st = 'PRESENT' if has_email else 'REDACTED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'support_platform', res_id, ids, st, vals)

    def parse_log(self, fid, fpath, captured_at, captured_at_dt):
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if 'resource_id=' not in line: continue
                kvs = {}
                for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', line):
                    kvs[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
                    
                res_id = kvs.get('resource_id')
                if not res_id: continue
                evt = kvs.get('event', '')
                if '_started' in evt or evt.endswith('_started'):
                    continue
                svc = kvs.get('service')
                
                ids = {kvs.get('lookup_key'), kvs.get('customer_reference'), kvs.get('customer_email'), 
                       kvs.get('email'), kvs.get('subject_reference'), kvs.get('requester_email'), 
                       kvs.get('correlation_key'), kvs.get('matched_value'), kvs.get('subject_key')}
                
                if svc == 'account_service' or 'account_' in res_id:
                    status = 'ABSENT' if kvs.get('http_status') == '404' or kvs.get('rows') == '0' else 'PRESENT'
                    self.add_rec(fid, captured_at, captured_at_dt, 'account_service', res_id, ids, status, kvs)
                elif svc == 'search_service' or 'search_' in res_id:
                    status = 'PRESENT' if kvs.get('result') == 'hit' or kvs.get('total_hits') == '1' else 'ABSENT'
                    self.add_rec(fid, captured_at, captured_at_dt, 'search_service', res_id, ids, status, kvs)
                elif svc == 'integration_service' or 'data_flow_' in res_id:
                    enabled = kvs.get('enabled') == 'true'
                    status = 'ACTIVE' if enabled else 'DISABLED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'integration_service', res_id, ids, status, kvs)
                elif svc == 'backup_service' or 'backup_' in res_id:
                    restore_allowed = kvs.get('restore_allowed') == 'true' or (kvs.get('eligible') == 'true' and kvs.get('deletion_block') == 'false')
                    status = 'ACTIVE' if restore_allowed else 'BLOCKED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'backup_service', res_id, ids, status, kvs)
                elif svc == 'support_platform' or 'support_' in res_id:
                    if kvs.get('marker_found') == 'false':
                        status = 'PRESENT'
                    elif kvs.get('requester_email') and kvs.get('requester_email') != 'null':
                        status = 'EXPOSED'
                    elif kvs.get('matched_value'):
                        status = 'EXPOSED'
                    else:
                        status = 'REDACTED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'support_platform', res_id, ids, status, kvs)
                elif svc == 'analytics_platform' or 'analytics_' in res_id:
                    if (kvs.get('email') and kvs.get('email') != 'null') or (kvs.get('email_opt_in') == 'true'):
                        status = 'EXPOSED'
                    else:
                        status = 'ANONYMIZED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, status, kvs)
                elif svc == 'security_service' or 'audit_record_' in res_id:
                    self.add_rec(fid, captured_at, captured_at_dt, 'security_service', res_id, ids, 'PRESENT', kvs)

    def parse_txt(self, fid, fpath, captured_at, captured_at_dt):
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 6:
                        ts, sys_id, res_id, cat, st, ident = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                        status_map = {
                            'NOT_FOUND': 'ABSENT',
                            'FOUND': 'PRESENT',
                            'IDENTIFIABLE': 'EXPOSED',
                            'ANONYMIZED': 'ANONYMIZED',
                            'REDACTED': 'REDACTED',
                            'ACTIVE': 'ACTIVE',
                            'DISABLED': 'DISABLED',
                            'BLOCKED': 'BLOCKED'
                        }
                        self.add_rec(fid, captured_at, captured_at_dt, sys_id, res_id, {ident}, status_map.get(st, st), parts)

    def parse_pdf(self, fid, fpath, captured_at, captured_at_dt):
        doc = fitz.open(fpath)
        txt = ""
        for page in doc: txt += page.get_text() + "\n"
        for match in re.finditer(r'(support_\d+|audit_record_\d+|account_\d+)', txt):
            res_id = match.group(1)
            start = max(0, match.start() - 200)
            end = min(len(txt), match.end() + 200)
            surr = txt[start:end]
            emails = set(re.findall(r'[\w\.-]+@[\w\.-]+', surr))
            users = set(re.findall(r'user_\d+', surr))
            sys_id = 'support_platform' if 'support' in res_id else ('security_service' if 'audit' in res_id else 'account_service')
            st = 'PRESENT'
            self.add_rec(fid, captured_at, captured_at_dt, sys_id, res_id, emails.union(users), st, {'text': surr})

    def parse_png(self, fid, fpath, captured_at, captured_at_dt):
        norm_path = 'dataset/' + str(fpath.relative_to('dataset')).replace('\\', '/')
        txt = ocr_cache.get(norm_path, '')
        for match in re.finditer(r'(search_\d+|support_\d+|analytics_\d+|backup_\d+|data_flow_\d+|export_\d+|tombstone_\d+|audit_record_\d+|account_\d+)', txt):
            res_id = match.group(1)
            start = max(0, match.start() - 200)
            end = min(len(txt), match.end() + 200)
            surr = txt[start:end]
            emails = set(re.findall(r'[\w\.-]+@[\w\.-]+', surr))
            users = set(re.findall(r'user_\d+', surr))
            sys_id = 'search_service' if 'search' in res_id else ('support_platform' if 'support' in res_id else 'account_service')
            self.add_rec(fid, captured_at, captured_at_dt, sys_id, res_id, emails.union(users), 'PRESENT', {'text': surr})

if __name__ == '__main__':
    parser = EvidenceParser()
    parser.parse_all()
