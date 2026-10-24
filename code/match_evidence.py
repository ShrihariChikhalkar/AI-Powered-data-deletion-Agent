import sys
import json
import pandas as pd
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
sample_out = pd.read_csv('dataset/sample_output.csv')
evidence_manifest = pd.read_csv('dataset/evidence_files.csv')
identities = pd.read_csv('dataset/user_identities.csv')
audit_log = pd.read_csv('dataset/user_audit_log.csv')

# Build user dictionary
identities['email_clean'] = identities['email'].str.strip().str.lower()
user_info = {}
for _, row in identities.iterrows():
    u = row['user_id']
    user_info[u] = {
        'user_id': u,
        'name': row['name'],
        'email': row['email_clean'],
        'phone': row['phone'],
        'email_hash': row['email_hash'],
        'all_emails': {row['email_clean']},
        'all_phones': {str(row['phone'])},
        'all_hashes': {str(row['email_hash'])},
        'all_names': {str(row['name'])},
    }

for _, row in audit_log.iterrows():
    u = row['user_id']
    if u in user_info:
        field = row['field_name']
        if field == 'email':
            if pd.notna(row['old_value']): user_info[u]['all_emails'].add(str(row['old_value']).strip().lower())
            if pd.notna(row['new_value']): user_info[u]['all_emails'].add(str(row['new_value']).strip().lower())
        elif field == 'phone':
            if pd.notna(row['old_value']): user_info[u]['all_phones'].add(str(row['old_value']).strip())
            if pd.notna(row['new_value']): user_info[u]['all_phones'].add(str(row['new_value']).strip())
        elif field == 'email_hash':
            if pd.notna(row['old_value']): user_info[u]['all_hashes'].add(str(row['old_value']).strip())
            if pd.notna(row['new_value']): user_info[u]['all_hashes'].add(str(row['new_value']).strip())
        elif field == 'name':
            if pd.notna(row['old_value']): user_info[u]['all_names'].add(str(row['old_value']).strip())
            if pd.notna(row['new_value']): user_info[u]['all_names'].add(str(row['new_value']).strip())

email_to_user = {}
for u, d in user_info.items():
    for em in d['all_emails']:
        email_to_user[em] = u

# Pre-load text content of all evidence files
ev_contents = {}
for _, ev in evidence_manifest.iterrows():
    fid = ev['file_id']
    fpath = Path('dataset') / ev['file_path']
    if fpath.exists():
        if fpath.suffix.lower() == '.pdf':
            import fitz
            doc = fitz.open(fpath)
            txt = ""
            for page in doc: txt += page.get_text() + "\n"
            ev_contents[fid] = txt
        elif fpath.suffix.lower() == '.png':
            pass
        else:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                ev_contents[fid] = f.read()

# Also load OCR text for PNGs
with open('dataset/evidence/images_ocr.json', 'r', encoding='utf-8') as f:
    ocr_data = json.load(f)
for _, ev in evidence_manifest.iterrows():
    fid = ev['file_id']
    fpath = 'dataset/' + ev['file_path'].replace('\\', '/')
    if fpath in ocr_data:
        ev_contents[fid] = ocr_data[fpath]

print(f"Loaded content for {len(ev_contents)} evidence files.")

evidence_manifest['captured_at_dt'] = pd.to_datetime(evidence_manifest['captured_at'])

# Now for each sample case, find which evidence files captured at or before audit_at mention ANY identifier of the user!
for idx, req in sample_reqs.iterrows():
    cid = req['case_id']
    req_email = str(req['email']).strip().lower()
    u = email_to_user[req_email]
    u_data = user_info[u]
    
    aud_dt = pd.to_datetime(req['audit_at'])
    
    # search terms:
    terms = set()
    terms.add(u)
    for em in u_data['all_emails']: terms.add(em)
    for h in u_data['all_hashes']: terms.add(h)
    
    # Also find expected cited evidence
    out_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    expected_steps = json.loads(out_row['steps_json'])
    expected_cited = sorted(list(set(s['evidence_id'] for s in expected_steps if s['evidence_id'])))
    
    # Find matching evidence files captured at or before aud_dt
    matching_evs = []
    for fid, content in ev_contents.items():
        ev_row = evidence_manifest[evidence_manifest['file_id'] == fid].iloc[0]
        if ev_row['captured_at_dt'] <= aud_dt:
            for term in terms:
                if term in content or term.lower() in content.lower():
                    matching_evs.append((fid, ev_row['captured_at'], term))
                    break
                    
    matched_fids = sorted(list(set(m[0] for m in matching_evs)))
    print(f"{cid} ({out_row['deletion_status']}) | User: {u} | Expected cited: {expected_cited} | Found in: {matched_fids}")
