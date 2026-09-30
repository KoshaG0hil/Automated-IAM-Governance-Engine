"""Unit tests for the DriftDetector."""

import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from evaluators.drift_detector import DriftDetector


@pytest.fixture
def detector():
    baseline_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "baseline", "sample_baseline.yaml"))
    return DriftDetector(baseline_path=baseline_path)


def test_detect_unapproved_role(detector):
    roles = [
        {
            "RoleName": "UnapprovedRandomRole",
            "Arn": "arn:aws:iam::123456789012:role/UnapprovedRandomRole",
            "AttachedPolicies": [],
            "InlinePolicies": {},
            "PermissionsBoundary": None
        }
    ]
    findings = detector.detect_role_drift(roles)
    assert len(findings) == 1
    assert findings[0]["category"] == "CONFIGURATION_DRIFT"
    assert "Unapproved" in findings[0]["title"]


def test_detect_attached_policy_drift(detector):
    roles = [
        {
            "RoleName": "AppBackendServiceRole",
            "Arn": "arn:aws:iam::123456789012:role/AppBackendServiceRole",
            "PermissionsBoundary": "arn:aws:iam::123456789012:policy/StandardPermissionsBoundary",
            "AttachedPolicies": [
                {"PolicyName": "AppBackendLeastPrivilegePolicy", "PolicyArn": "arn:aws:iam::123456789012:policy/AppBackendLeastPrivilegePolicy"},
                {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
            ],
            "InlinePolicies": {}
        }
    ]
    findings = detector.detect_role_drift(roles)
    assert any(f["category"] == "POLICY_DRIFT" and "AdministratorAccess" in f["description"] for f in findings)


def test_detect_missing_boundary(detector):
    roles = [
        {
            "RoleName": "AppBackendServiceRole",
            "Arn": "arn:aws:iam::123456789012:role/AppBackendServiceRole",
            "PermissionsBoundary": None,
            "AttachedPolicies": [
                {"PolicyName": "AppBackendLeastPrivilegePolicy", "PolicyArn": "arn:aws:iam::123456789012:policy/AppBackendLeastPrivilegePolicy"}
            ],
            "InlinePolicies": {}
        }
    ]
    findings = detector.detect_role_drift(roles)
    assert any(f["category"] == "MISSING_GUARDRAIL" for f in findings)
