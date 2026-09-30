"""Drift Detector: Compares active IAM roles, users, and policies against least-privilege baseline specifications."""

import logging
from typing import Any, Dict, List, Optional
import yaml

logger = logging.getLogger(__name__)


class DriftDetector:
    """Detects configuration drift between live IAM configurations and approved baselines."""

    def __init__(self, baseline_path: str = "baseline/sample_baseline.yaml"):
        self.baseline_path = baseline_path
        self.baseline = self._load_baseline(baseline_path)

    def _load_baseline(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Failed to load baseline from {path}: {e}")
            return {}

    def detect_role_drift(self, roles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate IAM roles against approved baseline configurations."""
        findings = []
        approved_roles_map = {r["role_name"]: r for r in self.baseline.get("approved_roles", [])}

        for role in roles:
            role_name = role.get("RoleName", "")
            role_arn = role.get("Arn", "")

            # 1. Check if role is approved in baseline
            if role_name not in approved_roles_map:
                findings.append({
                    "category": "CONFIGURATION_DRIFT",
                    "severity": "HIGH",
                    "resource_type": "Role",
                    "resource_name": role_name,
                    "resource_arn": role_arn,
                    "title": f"Unapproved / Shadow IAM Role '{role_name}' Detected",
                    "description": f"Role '{role_name}' is not registered in the approved baseline. Possible out-of-band creation or shadow asset.",
                    "risk_score": 75,
                    "remediation": f"Verify legitimate business purpose, add to baseline configuration, or decommission role '{role_name}'."
                })
                continue

            # Role is approved, verify configuration guardrails
            approved_cfg = approved_roles_map[role_name]

            # 2. Check attached policies drift
            allowed_policies = set(approved_cfg.get("allowed_attached_policies", []))
            actual_attached = {p["PolicyArn"] for p in role.get("AttachedPolicies", [])}
            unapproved_attached = actual_attached - allowed_policies

            for unapproved in unapproved_attached:
                is_admin = "AdministratorAccess" in unapproved
                findings.append({
                    "category": "POLICY_DRIFT",
                    "severity": "CRITICAL" if is_admin else "HIGH",
                    "resource_type": "Role",
                    "resource_name": role_name,
                    "resource_arn": role_arn,
                    "title": f"Unapproved Policy Attached to Role '{role_name}'",
                    "description": f"Role '{role_name}' has unapproved policy attached: {unapproved}.",
                    "risk_score": 95 if is_admin else 80,
                    "remediation": f"Detach policy {unapproved} from role '{role_name}' or submit change control to update baseline."
                })

            # 3. Check inline policies
            allow_inline = approved_cfg.get("allow_inline_policies", False)
            inline_policies = role.get("InlinePolicies", {})
            if not allow_inline and inline_policies:
                for inline_name in inline_policies.keys():
                    findings.append({
                        "category": "CONFIGURATION_DRIFT",
                        "severity": "HIGH",
                        "resource_type": "Role",
                        "resource_name": role_name,
                        "resource_arn": role_arn,
                        "title": f"Unapproved Inline Policy on Role '{role_name}'",
                        "description": f"Role '{role_name}' possesses inline policy '{inline_name}' while baseline mandates managed policies only.",
                        "risk_score": 70,
                        "remediation": f"Migrate inline policy '{inline_name}' to versioned customer-managed policy or delete it."
                    })

            # 4. Check permissions boundary
            req_boundary = approved_cfg.get("permissions_boundary_required", False)
            expected_boundary_arn = approved_cfg.get("permissions_boundary")
            actual_boundary_arn = role.get("PermissionsBoundary")

            if req_boundary and not actual_boundary_arn:
                findings.append({
                    "category": "MISSING_GUARDRAIL",
                    "severity": "HIGH",
                    "resource_type": "Role",
                    "resource_name": role_name,
                    "resource_arn": role_arn,
                    "title": f"Missing Permissions Boundary on Role '{role_name}'",
                    "description": f"Role '{role_name}' requires permissions boundary '{expected_boundary_arn}' but has none configured.",
                    "risk_score": 80,
                    "remediation": f"Attach required permissions boundary '{expected_boundary_arn}' to role '{role_name}'."
                })
            elif req_boundary and expected_boundary_arn and actual_boundary_arn != expected_boundary_arn:
                findings.append({
                    "category": "BOUNDARY_DRIFT",
                    "severity": "HIGH",
                    "resource_type": "Role",
                    "resource_name": role_name,
                    "resource_arn": role_arn,
                    "title": f"Mismatched Permissions Boundary on Role '{role_name}'",
                    "description": f"Role '{role_name}' is attached to '{actual_boundary_arn}' instead of approved '{expected_boundary_arn}'.",
                    "risk_score": 75,
                    "remediation": f"Update permissions boundary on role '{role_name}' to match approved baseline."
                })

        return findings

    def detect_user_drift(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate IAM users against approved baseline configurations."""
        findings = []
        approved_users_map = {u["user_name"]: u for u in self.baseline.get("approved_users", [])}

        for user in users:
            user_name = user.get("UserName", "")
            user_arn = user.get("Arn", "")

            # 1. Check if user is approved
            if user_name not in approved_users_map:
                findings.append({
                    "category": "CONFIGURATION_DRIFT",
                    "severity": "HIGH",
                    "resource_type": "User",
                    "resource_name": user_name,
                    "resource_arn": user_arn,
                    "title": f"Unapproved / Shadow IAM User '{user_name}' Detected",
                    "description": f"User '{user_name}' is not defined in the baseline configuration.",
                    "risk_score": 75,
                    "remediation": f"Audit user '{user_name}' creation source or remove unmanaged user."
                })
                continue

            approved_cfg = approved_users_map[user_name]

            # 2. Check attached policies
            allowed_policies = set(approved_cfg.get("allowed_attached_policies", []))
            actual_attached = {p["PolicyArn"] for p in user.get("AttachedPolicies", [])}
            unapproved = actual_attached - allowed_policies
            for unapp in unapproved:
                is_admin = "AdministratorAccess" in unapp
                findings.append({
                    "category": "POLICY_DRIFT",
                    "severity": "CRITICAL" if is_admin else "HIGH",
                    "resource_type": "User",
                    "resource_name": user_name,
                    "resource_arn": user_arn,
                    "title": f"Unapproved Policy Attached to User '{user_name}'",
                    "description": f"User '{user_name}' has unapproved policy attached: {unapp}.",
                    "risk_score": 95 if is_admin else 80,
                    "remediation": f"Detach policy {unapp} from user '{user_name}'."
                })

            # 3. Check inline policies
            if not approved_cfg.get("allow_inline_policies", False) and user.get("InlinePolicies"):
                for inline_name in user.get("InlinePolicies", {}).keys():
                    findings.append({
                        "category": "CONFIGURATION_DRIFT",
                        "severity": "HIGH",
                        "resource_type": "User",
                        "resource_name": user_name,
                        "resource_arn": user_arn,
                        "title": f"Unapproved Inline Policy on User '{user_name}'",
                        "description": f"User '{user_name}' has inline policy '{inline_name}' violating baseline policy constraints.",
                        "risk_score": 70,
                        "remediation": f"Remove inline policy '{inline_name}' from user '{user_name}'."
                    })

        return findings
