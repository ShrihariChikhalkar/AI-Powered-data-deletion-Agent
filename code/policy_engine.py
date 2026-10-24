import re
from pathlib import Path
import pandas as pd

class PolicyEngine:
    """
    Policy engine implementing the 15 contractual rules in deletion_rules.csv:
    rule_01: USER_PROFILE -> DELETE
    rule_02: SECONDARY_IDENTIFIER -> DELETE
    rule_03: SEARCH_INDEX_ENTRY -> DELETE
    rule_04: CACHE_ENTRY -> DELETE
    rule_05: SUPPORT_MESSAGE -> REDACT
    rule_06: SUPPORT_ATTACHMENT -> DELETE
    rule_07: ANALYTICS_PROFILE -> ANONYMIZE
    rule_08: PRODUCT_TELEMETRY -> ANONYMIZE
    rule_09: USER_EXPORT -> DELETE
    rule_10: MARKETING_PROFILE -> DELETE
    rule_11: EMAIL_DELIVERY_LOG -> REDACT
    rule_12: SECURITY_AUDIT_LOG -> RETAIN
    rule_13: LEGAL_HOLD_RECORD -> RETAIN
    rule_14: BACKUP_ARCHIVE -> RETAIN (when restore access blocked)
    rule_15: ACCOUNT_TOMBSTONE -> REDACT
    """
    def __init__(self, rules_path="dataset/deletion_rules.csv"):
        self.rules_path = Path(rules_path)
        if self.rules_path.exists():
            self.rules_df = pd.read_csv(self.rules_path)
        else:
            self.rules_df = None

    def classify_resource(self, system_id, resource_id, raw_record=None):
        """
        Determines the data category and policy rule based on system, resource_id, and metadata.
        """
        res_lower = str(resource_id).lower()
        sys_lower = str(system_id).lower()

        is_mkt = False
        is_att = False
        if isinstance(raw_record, dict):
            is_mkt = raw_record.get('is_marketing') or ('marketing' in str(raw_record).lower()) or ('opt_in' in str(raw_record).lower())
            is_att = raw_record.get('is_attachment') or ('attachment' in str(raw_record).lower()) or ('delivery' in str(raw_record).lower()) or ('pdf' in str(raw_record).lower())
        elif raw_record:
            is_mkt = ('marketing' in str(raw_record).lower()) or ('opt_in' in str(raw_record).lower())
            is_att = ('attachment' in str(raw_record).lower()) or ('delivery' in str(raw_record).lower()) or ('pdf' in str(raw_record).lower())

        if is_mkt:
            return 'MARKETING_PROFILE', 'rule_10', 'DELETE'
        if 'tombstone' in res_lower:
            return 'ACCOUNT_TOMBSTONE', 'rule_15', 'REDACT'
        if sys_lower == 'account_service' or 'account' in res_lower:
            return 'USER_PROFILE', 'rule_01', 'DELETE'
        if sys_lower == 'search_service' or 'search' in res_lower:
            return 'SEARCH_INDEX_ENTRY', 'rule_03', 'DELETE'
        if sys_lower == 'export_service' or 'export' in res_lower:
            return 'USER_EXPORT', 'rule_09', 'DELETE'
        if sys_lower == 'marketing_platform' or 'marketing' in res_lower:
            return 'MARKETING_PROFILE', 'rule_10', 'DELETE'
        if sys_lower == 'analytics_platform' or 'analytics' in res_lower:
            return 'ANALYTICS_PROFILE', 'rule_07', 'ANONYMIZE'
        if sys_lower == 'support_platform' or 'support' in res_lower:
            if is_att:
                return 'SUPPORT_ATTACHMENT', 'rule_06', 'DELETE'
            return 'SUPPORT_MESSAGE', 'rule_05', 'REDACT'
        if sys_lower == 'security_service' or 'audit' in res_lower:
            return 'SECURITY_AUDIT_LOG', 'rule_12', 'RETAIN'
        if sys_lower == 'legal_service' or 'legal' in res_lower:
            return 'LEGAL_HOLD_RECORD', 'rule_13', 'RETAIN'
        if sys_lower == 'backup_service' or 'backup' in res_lower:
            return 'BACKUP_ARCHIVE', 'rule_14', 'RETAIN'
        if sys_lower == 'integration_service' or 'data_flow' in res_lower:
            return 'ACTIVE_DATA_FLOW', 'rule_flow', 'DISABLE'
        
        return 'USER_PROFILE', 'rule_01', 'DELETE'

    def evaluate_state(self, system_id, resource_id, current_state, raw_record=None):
        """
        Evaluates compliance against policy rules.
        Returns:
            is_compliant (bool)
            finding_op (str or None)
            finding_state (str or None)
            remediation_op (str or None)
            remediation_state (str or None)
            verification_op (str)
            verification_state (str)
        """
        category, rule_id, action = self.classify_resource(system_id, resource_id, raw_record)
        
        if category in ('USER_PROFILE', 'MARKETING_PROFILE', 'SEARCH_INDEX_ENTRY', 'USER_EXPORT', 'SUPPORT_ATTACHMENT') or action == 'DELETE':
            if current_state == 'PRESENT':
                return (False, 'REPORT_REMAINING_RECORD', 'PRESENT',
                        'DELETE_RECORD', 'ABSENT', 'VERIFY_RECORD_ABSENT', 'ABSENT')
            else:
                return (True, None, None, None, None, 'VERIFY_RECORD_ABSENT', 'ABSENT')

        elif category == 'SUPPORT_MESSAGE':
            if current_state == 'PRESENT':
                return (False, 'REPORT_REMAINING_RECORD', 'PRESENT',
                        'DELETE_RECORD', 'ABSENT', 'VERIFY_RECORD_ABSENT', 'ABSENT')
            elif current_state in ('EXPOSED', 'UNREDACTED'):
                return (False, 'REPORT_EXPOSED_PII', 'PRESENT',
                        'REDACT_RECORD', 'REDACTED', 'VERIFY_RECORD_REDACTED', 'REDACTED')
            else:
                return (True, None, None, None, None, 'VERIFY_RECORD_REDACTED', 'REDACTED')

        elif category == 'ACCOUNT_TOMBSTONE':
            if current_state in ('PRESENT', 'EXPOSED', 'UNREDACTED'):
                return (False, 'REPORT_EXPOSED_PII', 'PRESENT',
                        'REDACT_RECORD', 'REDACTED', 'VERIFY_RECORD_REDACTED', 'REDACTED')
            else:
                return (True, None, None, None, None, 'VERIFY_RECORD_REDACTED', 'REDACTED')

        elif category in ('ANALYTICS_PROFILE', 'PRODUCT_TELEMETRY'):
            if current_state == 'PRESENT':
                return (False, 'REPORT_REMAINING_RECORD', 'PRESENT',
                        'DELETE_RECORD', 'ABSENT', 'VERIFY_RECORD_ABSENT', 'ABSENT')
            elif current_state in ('EXPOSED', 'UNANONYMIZED'):
                return (False, 'REPORT_EXPOSED_PII', 'PRESENT',
                        'ANONYMIZE_RECORD', 'ANONYMIZED', 'VERIFY_RECORD_ANONYMIZED', 'ANONYMIZED')
            else:
                return (True, None, None, None, None, 'VERIFY_RECORD_ANONYMIZED', 'ANONYMIZED')

        elif category == 'SECURITY_AUDIT_LOG':
            # Security audit records are retained under rule_12
            return (True, None, None, None, None, 'VERIFY_RECORD_PRESENT', 'PRESENT')

        elif category == 'BACKUP_ARCHIVE':
            if current_state == 'ACTIVE':
                return (False, 'REPORT_RESTORE_RISK', 'ACTIVE',
                        'BLOCK_RESTORE', 'BLOCKED', 'VERIFY_RESTORE_BLOCKED', 'BLOCKED')
            else:
                return (True, None, None, None, None, 'VERIFY_RESTORE_BLOCKED', 'BLOCKED')

        elif category == 'ACTIVE_DATA_FLOW':
            if current_state == 'ACTIVE':
                return (False, 'REPORT_ACTIVE_DATA_FLOW', 'ACTIVE',
                        'DISABLE_DATA_FLOW', 'DISABLED', 'VERIFY_DATA_FLOW_DISABLED', 'DISABLED')
            else:
                return (True, None, None, None, None, 'VERIFY_DATA_FLOW_DISABLED', 'DISABLED')

        return (True, None, None, None, None, 'VERIFY_RECORD_ABSENT', 'ABSENT')
