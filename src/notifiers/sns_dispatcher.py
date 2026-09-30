"""SNS Alert Dispatcher: Formats and sends high-severity IAM governance alerts."""

import json
import logging
from typing import Any, Dict, List, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class SNSAlertDispatcher:
    """Dispatches IAM drift and anomaly alerts to Amazon SNS."""

    def __init__(self, topic_arn: Optional[str] = None, session: Optional[boto3.Session] = None):
        self.topic_arn = topic_arn
        self.session = session or boto3.Session()
        self._client = self.session.client("sns") if topic_arn else None

    def format_alert_message(self, finding: Dict[str, Any], trigger_source: str = "SCHEDULED_AUDIT") -> str:
        """Create a human-readable alert message suitable for email/Slack."""
        return (
            f"🚨 [IAM GOVERNANCE ALERT] {finding.get('severity')} - {finding.get('title')}\n"
            f"======================================================================\n"
            f"• Priority:           {finding.get('priority', 'P2')}\n"
            f"• Anomaly Risk Score: {finding.get('adjusted_risk_score', finding.get('risk_score', 0))}/100\n"
            f"• Category:           {finding.get('category')}\n"
            f"• Trigger Source:     {trigger_source}\n"
            f"• Resource Type:      {finding.get('resource_type')}\n"
            f"• Resource Name:      {finding.get('resource_name')}\n"
            f"• Resource ARN:       {finding.get('resource_arn', 'N/A')}\n"
            f"\n"
            f"Details:\n"
            f"{finding.get('description')}\n"
            f"\n"
            f"Recommended Remediation:\n"
            f"{finding.get('remediation')}\n"
            f"======================================================================\n"
        )

    def dispatch(self, findings: List[Dict[str, Any]], trigger_source: str = "SCHEDULED_AUDIT") -> int:
        """Send notifications for critical and high findings. Returns number of alerts sent."""
        # Alert on P1 and P2 findings
        high_severity_findings = [
            f for f in findings
            if f.get("priority") in ("P1 - IMMEDIATE", "P2 - HIGH")
            or f.get("severity") in ("CRITICAL", "HIGH")
        ]

        if not high_severity_findings:
            logger.info("No high-severity findings requiring SNS notification.")
            return 0

        dispatched_count = 0
        for finding in high_severity_findings:
            subject = f"IAM Alert [{finding.get('severity')}]: {finding.get('title')[:80]}"
            message = self.format_alert_message(finding, trigger_source)

            if not self.topic_arn or not self._client:
                # Log locally if no topic configured (mock / test mode)
                logger.info(f"[SIMULATED SNS ALERT]\nSubject: {subject}\n{message}")
                dispatched_count += 1
                continue

            try:
                self._client.publish(
                    TopicArn=self.topic_arn,
                    Subject=subject,
                    Message=message,
                    MessageAttributes={
                        "Severity": {
                            "DataType": "String",
                            "StringValue": finding.get("severity", "MEDIUM")
                        },
                        "Priority": {
                            "DataType": "String",
                            "StringValue": finding.get("priority", "P3")
                        }
                    }
                )
                dispatched_count += 1
            except ClientError as e:
                logger.error(f"Failed to publish SNS alert: {e}")

        return dispatched_count
