import sys
import json
import re
import pandas as pd
from pathlib import Path
from parse_evidence import EvidenceParser

sys.stdout.reconfigure(encoding='utf-8')

# Allowed Operation Orders
FINDING_ORDER = [
    'REPORT_REMAINING_RECORD',
    'REPORT_EXPOSED_PII',
    'REPORT_ACTIVE_DATA_FLOW',
    'REPORT_RESTORE_RISK'
]

REMEDIATION_ORDER = [
    'DISABLE_DATA_FLOW',
    'BLOCK_RESTORE',
    'DELETE_RECORD',
    'REDACT_RECORD',
    'ANONYMIZE_RECORD'
]

VERIFICATION_ORDER = [
    'VERIFY_RECORD_ABSENT',
    'VERIFY_RECORD_PRESENT',
    'VERIFY_RECORD_REDACTED',
    'VERIFY_RECORD_ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED',
    'VERIFY_RESTORE_BLOCKED'
]

def sort_steps(steps):
    def sort_key(s):
        phase = s['phase']
        phase_rank = 0 if phase == 'FINDING' else (1 if phase == 'REMEDIATION' else 2)
        
        op = s['operation']
        if phase == 'FINDING':
            op_rank = FINDING_ORDER.index(op) if op in FINDING_ORDER else 99
        elif phase == 'REMEDIATION':
            op_rank = REMEDIATION_ORDER.index(op) if op in REMEDIATION_ORDER else 99
        else:
            op_rank = VERIFICATION_ORDER.index(op) if op in VERIFICATION_ORDER else 99
            
        return (phase_rank, op_rank, s['system_id'], s['resource_id'])
        
    sorted_steps = sorted(steps, key=sort_key)
    for idx, s in enumerate(sorted_steps, 1):
        s['step_no'] = idx
    return sorted_steps

print("Step sorting utility defined.")
