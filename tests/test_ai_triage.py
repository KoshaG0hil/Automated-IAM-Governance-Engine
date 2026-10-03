"""Unit tests for the AI Triage Layer."""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from scoring.ai_triage import AITriageLayer


def test_ai_triage_critical_finding():
    triage = AITriageLayer()
    finding = {
        "category": "PRIVILEGE_ESCALATION",
        "severity": "CRITICAL",
        "adjusted_risk_score": 100,
        "title": "Privilege Escalation Vector: IAM CreatePolicyVersion",
        "resource_name": "DevOpsShadowAdminRole",
        "resource_type": "Role",
        "resource_arn": "arn:aws:iam::123456789012:role/DevOpsShadowAdminRole"
    }

    enriched = triage.triage_finding(finding)
    assert enriched["investigation_queue"] == AITriageLayer.QUEUE_URGENT_SOC
    assert "CRITICAL" in enriched["blast_radius"]
    assert "ACTIONABLE_URGENT" in enriched["noise_filter_verdict"]
    assert len(enriched["remediation_cli_command"]) > 0


def test_ai_triage_medium_hygiene_finding():
    triage = AITriageLayer()
    finding = {
        "category": "CREDENTIAL_SECURITY",
        "severity": "MEDIUM",
        "adjusted_risk_score": 60,
        "title": "Access Key 1 Exceeds Rotation Threshold (120 days)",
        "resource_name": "developer-bob",
        "resource_type": "User",
        "resource_arn": "arn:aws:iam::123456789012:user/developer-bob"
    }

    enriched = triage.triage_finding(finding)
    assert enriched["investigation_queue"] == AITriageLayer.QUEUE_IDENTITY_HYGIENE
    assert "FILTERED_TO_HYGIENE" in enriched["noise_filter_verdict"]
    assert "aws iam update-access-key" in enriched["remediation_cli_command"]
