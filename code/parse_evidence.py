import sys
import json
import sqlite3
import re
from pathlib import Path
import pandas as pd
import fitz

class EvidenceParser:
    """
    Robust Evidence Parser supporting:
    - In-memory SQLite execution of .sql snapshot exports
    - JSON service exports and 14-collection snapshot bundles
    - Two-pass trace_id correlation across observability .log files
    - Formatted pipe-delimited .txt handover logs
    - PyMuPDF text & attachment extraction for .pdf documents
    - OCR-assisted extraction for .png screenshots
    """
    def __init__(self, dataset_dir="dataset"):
        self.dataset_dir = Path(dataset_dir)
        self.evidence_manifest = pd.read_csv(self.dataset_dir / 'evidence_files.csv')
        self.evidence_manifest['captured_at_dt'] = pd.to_datetime(self.evidence_manifest['captured_at'])
        
        ocr_path = self.dataset_dir / 'evidence/images_ocr.json'
        self.ocr_cache = {}
        if ocr_path.exists():
            with open(ocr_path, 'r', encoding='utf-8') as f:
                self.ocr_cache = json.load(f)
                
        self.records = []

    def add_rec(self, fid, captured_at, captured_at_dt, system_id, resource_id, identifiers, state, raw=None):
        clean_ids = set()
        for i in identifiers:
            if i and pd.notna(i) and str(i).strip() and str(i).lower() != 'none' and str(i).lower() != 'null':
                clean_ids.add(str(i).strip().lower())
        self.records.append({
            'evidence_id': fid,
            'captured_at': captured_at,
            'captured_at_dt': captured_at_dt,
            'system_id': system_id,
            'resource_id': resource_id,
            'identifiers': clean_ids,
            'state': state,
            'raw': raw
        })

    def parse_all(self):
        self.records.clear()
        for _, row in self.evidence_manifest.iterrows():
            fid = row['file_id']
            fpath = self.dataset_dir / row['file_path']
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
                
        print(f"Total evidence records extracted: {len(self.records)}")

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
            ap_data = se.get('analytics_platform', {})
            ap_profiles = ap_data.get('profiles', []) if isinstance(ap_data, dict) else ap_data
            for p in ap_profiles:
                res_id = p.get('resource_id')
                ids = {p.get('email'), p.get('customer_reference'), p.get('phone'), p.get('email_hash')}
                status = 'EXPOSED' if p.get('email') or p.get('phone') else 'ANONYMIZED'
                self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, status, p)
            # backup_service
            for b in se.get('backup_service', {}).get('restore_entries', []):
                res_id = b.get('resource_id')
                ids = {b.get('customer_email'), b.get('customer_reference'), b.get('subject_reference')}
                status = 'ACTIVE' if b.get('restore_allowed') else 'BLOCKED'
                self.add_rec(fid, captured_at, captured_at_dt, 'backup_service', res_id, ids, status, b)
            # export_service
            for e in se.get('export_service', {}).get('exports', []):
                res_id = e.get('resource_id')
                ids = {e.get('owner_email'), e.get('customer_reference'), e.get('owner_phone')}
                status = 'PRESENT' if e.get('download_available') else 'ABSENT'
                self.add_rec(fid, captured_at, captured_at_dt, 'export_service', res_id, ids, status, e)
            # integration_service
            for c in se.get('integration_service', {}).get('connectors', []):
                res_id = c.get('resource_id')
                ids = {c.get('customer_email'), c.get('customer_reference'), c.get('subject_selector')}
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
                ids = {a.get('subject_reference'), a.get('customer_reference')}
                self.add_rec(fid, captured_at, captured_at_dt, 'security_service', res_id, ids, 'PRESENT', a)
            # support_platform
            for t in se.get('support_platform', {}).get('tickets', []):
                res_id = t.get('resource_id')
                ids = {t.get('requester_email'), t.get('customer_reference'), t.get('requester_phone')}
                status = 'EXPOSED' if t.get('requester_email') or t.get('requester_phone') else 'REDACTED'
                self.add_rec(fid, captured_at, captured_at_dt, 'support_platform', res_id, ids, status, t)

        # 2. snapshot bundles
        elif 'snapshots' in data:
            for snap in data['snapshots']:
                ds = snap.get('data_store')
                col = snap.get('collection')
                for r in snap.get('records', []):
                    res_id = r.get('resource_id')
                    if not res_id: continue
                    
                    if col == 'customer_profiles':
                        ids = {r.get('email'), r.get('customer_reference'), r.get('phone'), r.get('user_id')}
                        st = 'PRESENT' if r.get('account_status') == 'ACTIVE' else 'ABSENT'
                        self.add_rec(fid, captured_at, captured_at_dt, 'account_service', res_id, ids, st, r)
                    elif col == 'customer_analytics_reports':
                        ids = {r.get('email'), r.get('user_id'), r.get('customer_reference'), r.get('phone'), r.get('email_hash')}
                        st = 'EXPOSED' if r.get('email') or r.get('phone') else 'ANONYMIZED'
                        self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, st, r)
                    elif col == 'backup_catalog':
                        ids = {r.get('subject_reference'), r.get('customer_email')}
                        st = 'ACTIVE' if r.get('restore_allowed') else 'BLOCKED'
                        self.add_rec(fid, captured_at, captured_at_dt, 'backup_service', res_id, ids, st, r)
                    elif col == 'connector_configurations':
                        ids = {r.get('subject_selector'), r.get('customer_reference')}
                        st = 'ACTIVE' if r.get('enabled') else 'DISABLED'
                        self.add_rec(fid, captured_at, captured_at_dt, 'integration_service', res_id, ids, st, r)
                    elif col == 'customer_search_documents':
                        doc = r.get('document') or {}
                        ids = {doc.get('email'), doc.get('customer_reference'), doc.get('display_name')}
                        self.add_rec(fid, captured_at, captured_at_dt, 'search_service', res_id, ids, 'PRESENT', r)
                    elif col == 'customer_export_jobs':
                        ids = {r.get('owner_email'), r.get('customer_reference')}
                        st = 'PRESENT' if r.get('download_available') else 'ABSENT'
                        self.add_rec(fid, captured_at, captured_at_dt, 'export_service', res_id, ids, st, r)
                    elif col == 'security_audit_events':
                        ids = {r.get('subject_reference'), r.get('user_id')}
                        self.add_rec(fid, captured_at, captured_at_dt, 'security_service', res_id, ids, 'PRESENT', r)
                    elif col == 'deleted_customer_references':
                        ids = {r.get('email'), r.get('subject_reference'), r.get('name'), r.get('phone')}
                        st = 'EXPOSED' if r.get('email') or r.get('phone') or r.get('name') else 'REDACTED'
                        self.add_rec(fid, captured_at, captured_at_dt, 'identity_service', res_id, ids, st, r)
                    elif col == 'support_conversations':
                        ids = {r.get('subject_reference'), r.get('customer_reference')}
                        msg = r.get('message_text') or ''
                        emails = re.findall(r'[\w\.-]+@[\w\.-]+', msg)
                        for em in emails: ids.add(em)
                        st = 'EXPOSED' if ('[REDACTED]' not in msg and len(emails) > 0) else 'REDACTED'
                        self.add_rec(fid, captured_at, captured_at_dt, 'support_platform', res_id, ids, st, r)
                    elif col == 'ticket_attachments':
                        ids = {r.get('uploaded_by'), r.get('customer_reference')}
                        self.add_rec(fid, captured_at, captured_at_dt, 'support_platform', res_id, ids, 'PRESENT', {'is_attachment': True, **r})
                    elif col in ('legal_service', 'retained_order_records'):
                        ids = {r.get('subject_reference')}
                        self.add_rec(fid, captured_at, captured_at_dt, 'legal_service', res_id, ids, 'PRESENT', r)

        # 3. single record manifests
        elif 'records' in data:
            for r in data['records']:
                res_id = r.get('resource_id')
                if not res_id: continue
                if 'export' in str(fpath).lower():
                    ids = {r.get('owner_email'), r.get('customer_reference')}
                    st = 'PRESENT' if r.get('download_available') else 'ABSENT'
                    self.add_rec(fid, captured_at, captured_at_dt, 'export_service', res_id, ids, st, r)
                elif 'analytics' in str(fpath).lower():
                    ids = {r.get('customer_reference'), r.get('email'), r.get('user_id')}
                    st = 'ANONYMIZED' if not r.get('email') else 'EXPOSED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, st, r)
                elif 'security' in str(fpath).lower():
                    ids = {r.get('subject_reference'), r.get('user_id')}
                    self.add_rec(fid, captured_at, captured_at_dt, 'security_service', res_id, ids, 'PRESENT', r)

    def parse_sql(self, fid, fpath, captured_at, captured_at_dt):
        conn = sqlite3.connect(':memory:')
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            sql_text = f.read()
        conn.executescript(sql_text)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [t[0] for t in cursor.fetchall() if t[0] != 'snapshot_scope']
        
        for tbl in tables:
            cursor.execute(f"PRAGMA table_info({tbl});")
            cols = [c[1] for c in cursor.fetchall()]
            
            cursor.execute(f"SELECT * FROM {tbl};")
            rows = cursor.fetchall()
            
            # Case A: Generic customer_data payload table (resource_id, origin_sys, collection, payload, updated_at)
            if 'origin_sys' in cols or (len(cols) == 5 and 'customer_data' in tbl):
                for row in rows:
                    res_id, origin_sys, collection, payload, updated_at = row[0], row[1], row[2], row[3], row[4]
                    try:
                        record_dict = json.loads(payload)
                    except:
                        try:
                            record_dict = json.loads(payload.replace("''", "'"))
                        except:
                            record_dict = {}
                            
                    ids = set()
                    for k in ['user_id', 'customer_reference', 'subject_reference', 'email', 'phone', 'email_hash', 'owner_email', 'customer_email', 'subject_selector', 'uploaded_by']:
                        if record_dict.get(k): ids.add(str(record_dict[k]))
                    if 'document' in record_dict and isinstance(record_dict['document'], dict):
                        for k in ['customer_reference', 'email', 'display_name']:
                            if record_dict['document'].get(k): ids.add(str(record_dict['document'][k]))
                    if 'message_text' in record_dict:
                        for em in re.findall(r'[\w\.-]+@[\w\.-]+', str(record_dict['message_text'])):
                            ids.add(em)
                            
                    st = 'PRESENT'
                    if origin_sys == 'account_service':
                        st = 'PRESENT' if record_dict.get('account_status') == 'ACTIVE' else 'ABSENT'
                    elif origin_sys == 'search_service':
                        st = 'PRESENT'
                    elif origin_sys == 'analytics_platform':
                        st = 'EXPOSED' if (record_dict.get('email') or record_dict.get('phone')) else 'ANONYMIZED'
                    elif origin_sys == 'support_platform':
                        msg = str(record_dict.get('message_text', ''))
                        st = 'REDACTED' if ('[REDACTED]' in msg or not re.search(r'[\w\.-]+@[\w\.-]+', msg)) else 'EXPOSED'
                    elif origin_sys == 'integration_service':
                        st = 'ACTIVE' if record_dict.get('enabled') is True else 'DISABLED'
                    elif origin_sys == 'backup_service':
                        st = 'ACTIVE' if record_dict.get('restore_allowed') is True else 'BLOCKED'
                    elif origin_sys == 'identity_service':
                        st = 'EXPOSED' if record_dict.get('email') else 'REDACTED'
                        
                    self.add_rec(fid, captured_at, captured_at_dt, origin_sys, res_id, ids, st, record_dict)
                continue

            # Case B: Specific domain tables
            for row in rows:
                r_dict = dict(zip(cols, row))
                res_id = r_dict.get('resource_id')
                if not res_id: continue
                
                if 'profiles' in tbl:
                    ids = {r_dict.get('customer_reference'), r_dict.get('user_id'), r_dict.get('email'), r_dict.get('phone'), r_dict.get('full_name')}
                    st = 'PRESENT' if r_dict.get('account_status') == 'ACTIVE' else 'ABSENT'
                    self.add_rec(fid, captured_at, captured_at_dt, 'account_service', res_id, ids, st, r_dict)
                elif 'search' in tbl:
                    ids = {r_dict.get('customer_reference'), r_dict.get('email'), r_dict.get('phone'), r_dict.get('display_name')}
                    self.add_rec(fid, captured_at, captured_at_dt, 'search_service', res_id, ids, 'PRESENT', r_dict)
                elif 'analytics' in tbl:
                    ids = {r_dict.get('customer_reference'), r_dict.get('email'), r_dict.get('phone'), r_dict.get('email_hash')}
                    st = 'EXPOSED' if (r_dict.get('email') or r_dict.get('phone')) else 'ANONYMIZED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, st, r_dict)
                elif 'support' in tbl:
                    ids = {r_dict.get('customer_reference'), r_dict.get('requester_email'), r_dict.get('requester_phone')}
                    st = 'EXPOSED' if (r_dict.get('requester_email') or r_dict.get('requester_phone')) else 'REDACTED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'support_platform', res_id, ids, st, r_dict)
                elif 'export' in tbl:
                    ids = {r_dict.get('customer_reference'), r_dict.get('owner_email'), r_dict.get('owner_phone')}
                    self.add_rec(fid, captured_at, captured_at_dt, 'export_service', res_id, ids, 'PRESENT', r_dict)
                elif 'connector' in tbl:
                    ids = {r_dict.get('customer_reference'), r_dict.get('customer_email')}
                    st = 'ACTIVE' if r_dict.get('enabled') in (1, '1', True) else 'DISABLED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'integration_service', res_id, ids, st, r_dict)
                elif 'backup' in tbl:
                    ids = {r_dict.get('customer_reference'), r_dict.get('customer_email')}
                    st = 'ACTIVE' if r_dict.get('restore_allowed') in (1, '1', True) else 'BLOCKED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'backup_service', res_id, ids, st, r_dict)
                elif 'security' in tbl:
                    ids = {r_dict.get('subject_reference')}
                    self.add_rec(fid, captured_at, captured_at_dt, 'security_service', res_id, ids, 'PRESENT', r_dict)

        conn.close()

    def parse_log(self, fid, fpath, captured_at, captured_at_dt):
        trace_to_ids = {}
        # Pass 1: Correlate trace_id to identifiers
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                kvs = {}
                for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', line):
                    kvs[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
                tr = kvs.get('trace_id') or kvs.get('requestId')
                if tr:
                    if tr not in trace_to_ids: trace_to_ids[tr] = set()
                    for k in ['subject_key', 'lookup_key', 'customer_email', 'email', 'owner_email', 'requester_email', 
                              'customer_reference', 'subject_reference', 'matched_value', 'correlation_key', 'subject_ref']:
                        if kvs.get(k): trace_to_ids[tr].add(str(kvs[k]).strip().lower())
                    for em in re.findall(r'[\w\.-]+@[\w\.-]+', line):
                        trace_to_ids[tr].add(em.strip().lower())
                    for u in re.findall(r'user_\d+', line):
                        trace_to_ids[tr].add(u.strip().lower())

        # Pass 2: Extract events
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if 'resource_id=' not in line and 'resource_id="' not in line:
                    continue
                kvs = {}
                for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', line):
                    kvs[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
                res_id = kvs.get('resource_id')
                if not res_id: continue
                evt = kvs.get('event', '')
                if '_started' in evt or evt.endswith('_started'):
                    continue
                svc = kvs.get('service') or kvs.get('function')
                tr = kvs.get('trace_id') or kvs.get('requestId')
                
                ids = set()
                if tr and tr in trace_to_ids:
                    ids.update(trace_to_ids[tr])
                for k in ['subject_key', 'lookup_key', 'customer_email', 'email', 'owner_email', 'requester_email', 
                          'customer_reference', 'subject_reference', 'matched_value', 'correlation_key', 'subject_ref']:
                    if kvs.get(k): ids.add(str(kvs[k]).strip().lower())
                for em in re.findall(r'[\w\.-]+@[\w\.-]+', line):
                    ids.add(em.strip().lower())
                for u in re.findall(r'user_\d+', line):
                    ids.add(u.strip().lower())
                    
                if svc == 'account_service' or 'account_' in res_id:
                    st = 'ABSENT' if kvs.get('http_status') == '404' or kvs.get('rows') == '0' else 'PRESENT'
                    self.add_rec(fid, captured_at, captured_at_dt, 'account_service', res_id, ids, st, kvs)
                elif svc == 'search_service' or 'search_' in res_id:
                    st = 'PRESENT' if kvs.get('result') == 'hit' or kvs.get('total_hits') == '1' else 'ABSENT'
                    self.add_rec(fid, captured_at, captured_at_dt, 'search_service', res_id, ids, st, kvs)
                elif svc == 'integration_service' or 'data_flow_' in res_id:
                    st = 'ACTIVE' if kvs.get('enabled') == 'true' else 'DISABLED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'integration_service', res_id, ids, st, kvs)
                elif svc == 'backup_service' or 'backup_' in res_id:
                    restore_allowed = kvs.get('restore_allowed') == 'true' or (kvs.get('eligible') == 'true' and kvs.get('deletion_block') == 'false')
                    st = 'ACTIVE' if restore_allowed else 'BLOCKED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'backup_service', res_id, ids, st, kvs)
                elif svc == 'support_platform' or 'support_' in res_id:
                    if kvs.get('marker_found') == 'false':
                        st = 'PRESENT'
                    elif kvs.get('rows') == '1':
                        st = 'PRESENT'
                    elif kvs.get('requester_email') and kvs.get('requester_email') != 'null':
                        st = 'EXPOSED'
                    elif '[REDACTED]' in str(kvs.get('message_text')):
                        st = 'REDACTED'
                    else:
                        st = 'REDACTED'
                    self.add_rec(fid, captured_at, captured_at_dt, 'support_platform', res_id, ids, st, kvs)
                elif svc == 'analytics_platform' or 'analytics_' in res_id:
                    if kvs.get('email_opt_in') == 'true':
                        st = 'PRESENT'
                        self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, st, {'is_marketing': True, **kvs})
                    elif kvs.get('email') and kvs.get('email') != 'null':
                        st = 'EXPOSED'
                        self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, st, kvs)
                    else:
                        st = 'ANONYMIZED'
                        self.add_rec(fid, captured_at, captured_at_dt, 'analytics_platform', res_id, ids, st, kvs)
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
                            'NOT_FOUND': 'ABSENT', 'FOUND': 'PRESENT', 'IDENTIFIABLE': 'EXPOSED',
                            'ANONYMIZED': 'ANONYMIZED', 'REDACTED': 'REDACTED',
                            'ACTIVE': 'ACTIVE', 'DISABLED': 'DISABLED', 'BLOCKED': 'BLOCKED'
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
            
            is_attachment = 'attachment' in str(fpath).lower() or 'delivery' in str(fpath).lower()
            sys_id = 'support_platform' if 'support' in res_id else ('security_service' if 'audit' in res_id else 'account_service')
            st = 'PRESENT'
            self.add_rec(fid, captured_at, captured_at_dt, sys_id, res_id, emails.union(users), st, {'is_attachment': is_attachment, 'text': surr})

    def parse_png(self, fid, fpath, captured_at, captured_at_dt):
        norm_path = 'dataset/' + str(fpath.relative_to('dataset')).replace('\\', '/')
        txt = self.ocr_cache.get(norm_path, '')
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
    p = EvidenceParser()
    p.parse_all()
