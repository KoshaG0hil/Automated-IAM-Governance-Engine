"""IAM Credential Report Auditor: Inspects key rotation, dormant keys, and console MFA."""

import csv
import io
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class CredentialReportAuditor:
    """Parses and audits IAM Credential Reports."""

    def __init__(self, session: Optional[boto3.Session] = None, mock_csv_file: Optional[str] = None):
        self.mock_csv_file = mock_csv_file
        self.session = session or boto3.Session()
        self._client = None if mock_csv_file else self.session.client("iam")

    def audit(self, max_key_age_days: int = 90, max_inactive_days: int = 90) -> List[Dict[str, Any]]:
        """Run audit against credential report, returning security findings."""
        csv_content = self._get_report_csv()
        if not csv_content:
            logger.warning("No credential report available for audit.")
            return []

        findings = []
        reader = csv.DictReader(io.StringIO(csv_content))
        now = datetime.now(timezone.utc)

        for row in reader:
            user = row.get("user", "")
            arn = row.get("arn", "")

            # 1. Root account security check
            if user == "<root_account>":
                if row.get("access_key_1_active") == "true" or row.get("access_key_2_active") == "true":
                    findings.append({
                        "category": "CREDENTIAL_SECURITY",
                        "severity": "CRITICAL",
                        "resource_type": "RootAccount",
                        "resource_name": "root",
                        "resource_arn": arn,
                        "title": "Active Access Keys on Root Account",
                        "description": "Root account has active access keys. Root credentials must never possess long-term programmatic access keys.",
                        "risk_score": 100,
                        "remediation": "Delete root access keys immediately and utilize short-lived IAM roles."
                    })
                if row.get("mfa_active") != "true":
                    findings.append({
                        "category": "CREDENTIAL_SECURITY",
                        "severity": "CRITICAL",
                        "resource_type": "RootAccount",
                        "resource_name": "root",
                        "resource_arn": arn,
                        "title": "MFA Not Enabled on Root Account",
                        "description": "Root account does not have Multi-Factor Authentication (MFA) enabled.",
                        "risk_score": 98,
                        "remediation": "Enable hardware or virtual MFA for the AWS root account."
                    })
                continue

            # 2. Console access without MFA
            if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
                findings.append({
                    "category": "CREDENTIAL_SECURITY",
                    "severity": "HIGH",
                    "resource_type": "User",
                    "resource_name": user,
                    "resource_arn": arn,
                    "title": f"MFA Missing for Console User '{user}'",
                    "description": f"User '{user}' has console password enabled but no active MFA device.",
                    "risk_score": 80,
                    "remediation": "Enforce MFA registration before allowing console operations."
                })

            # 3. Access Key 1 & 2 Audits
            for key_num in ("1", "2"):
                active = row.get(f"access_key_{key_num}_active") == "true"
                if not active:
                    continue

                rotated_str = row.get(f"access_key_{key_num}_last_rotated")
                last_used_str = row.get(f"access_key_{key_num}_last_used_date")

                # Check rotation age
                if rotated_str and rotated_str not in ("N/A", "not_supported"):
                    try:
                        rotated_dt = datetime.fromisoformat(rotated_str.replace("Z", "+00:00"))
                        age_days = (now - rotated_dt).days
                        if age_days > max_key_age_days:
                            findings.append({
                                "category": "CREDENTIAL_SECURITY",
                                "severity": "MEDIUM",
                                "resource_type": "AccessKey",
                                "resource_name": f"{user}-Key{key_num}",
                                "resource_arn": arn,
                                "title": f"Access Key {key_num} Exceeds Rotation Threshold ({age_days} days)",
                                "description": f"Access Key {key_num} for user '{user}' was rotated {age_days} days ago (limit: {max_key_age_days} days).",
                                "risk_score": 60,
                                "remediation": "Rotate access key and update consuming application secrets."
                            })
                    except Exception as e:
                        logger.debug(f"Error parsing rotated date: {e}")

                # Check dormant / inactive key
                if last_used_str and last_used_str not in ("N/A", "not_supported"):
                    try:
                        used_dt = datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
                        inactive_days = (now - used_dt).days
                        if inactive_days > max_inactive_days:
                            findings.append({
                                "category": "CREDENTIAL_SECURITY",
                                "severity": "MEDIUM",
                                "resource_type": "AccessKey",
                                "resource_name": f"{user}-Key{key_num}",
                                "resource_arn": arn,
                                "title": f"Dormant Access Key {key_num} ({inactive_days} days unused)",
                                "description": f"Access Key {key_num} for user '{user}' has not been used for {inactive_days} days.",
                                "risk_score": 50,
                                "remediation": "Deactivate and delete unused credentials to reduce attack surface."
                            })
                    except Exception as e:
                        logger.debug(f"Error parsing last used date: {e}")

        return findings

    def _get_report_csv(self) -> Optional[str]:
        if self.mock_csv_file:
            with open(self.mock_csv_file, "r", encoding="utf-8") as f:
                return f.read()

        try:
            # Generate report
            self._client.generate_credential_report()
            res = self._client.get_credential_report()
            content = res.get("Content", b"").decode("utf-8")
            return content
        except ClientError as e:
            logger.error(f"Failed to fetch credential report: {e}")
            return None
