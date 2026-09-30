"""Unit tests for the AnomalyScoringEngine."""

import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from scoring.anomaly_engine import AnomalyScoringEngine


@pytest.fixture
def scoring_engine():
    return AnomalyScoringEngine()


def test_anomaly_scoring_priority_and_posture(scoring_engine):
    raw_findings = [
        {
            "category": "EXCESSIVE_PERMISSIONS",
            "severity": "CRITICAL",
            "resource_type": "Role",
            "resource_name": "TestRole",
            "resource_arn": "arn:aws:iam::123456789012:role/TestRole",
            "title": "Admin Wildcard",
            "risk_score": 100
        },
        {
            "category": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "resource_type": "Role",
            "resource_name": "TestRole",
            "resource_arn": "arn:aws:iam::123456789012:role/TestRole",
            "title": "PrivEsc PassRole",
            "risk_score": 85
        }
    ]

    summary = scoring_engine.process_findings(raw_findings)
    assert summary["total_findings"] == 2
    assert summary["severity_breakdown"]["CRITICAL"] == 1
    assert summary["severity_breakdown"]["HIGH"] == 1
    # Compound multiplier should apply because both belong to TestRole
    findings = summary["findings"]
    assert findings[0]["priority"] == "P1 - IMMEDIATE"
    assert summary["posture_score"] < 100
