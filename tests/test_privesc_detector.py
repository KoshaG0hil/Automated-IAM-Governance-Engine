"""Unit tests for the PrivEscDetector."""

import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from evaluators.privesc_detector import PrivEscDetector


@pytest.fixture
def detector():
    rules_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "baseline", "privesc_rules.json"))
    return PrivEscDetector(rules_file_path=rules_path)


def test_detect_create_policy_version(detector):
    actions = {"iam:CreatePolicyVersion", "s3:GetObject"}
    findings = detector.evaluate_permissions(actions, "Role", "TestRole", "arn:aws:iam::123456789012:role/TestRole")
    assert any(f["rule_id"] == "PRIVESC-01" for f in findings)


def test_detect_passrole_ec2(detector):
    actions = {"iam:PassRole", "ec2:RunInstances"}
    findings = detector.evaluate_permissions(actions, "Role", "TestRole", "arn:aws:iam::123456789012:role/TestRole")
    assert any(f["rule_id"] == "PRIVESC-09" for f in findings)


def test_wildcard_matching(detector):
    actions = {"iam:*"}
    findings = detector.evaluate_permissions(actions, "Role", "AdminRole", "arn:aws:iam::123456789012:role/AdminRole")
    assert len(findings) > 0
    rule_ids = {f["rule_id"] for f in findings}
    assert "PRIVESC-01" in rule_ids
    assert "PRIVESC-03" in rule_ids


def test_benign_permissions(detector):
    actions = {"s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances"}
    findings = detector.evaluate_permissions(actions, "Role", "SafeRole", "arn:aws:iam::123456789012:role/SafeRole")
    assert len(findings) == 0
