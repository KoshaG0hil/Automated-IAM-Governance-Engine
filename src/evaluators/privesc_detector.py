"""Privilege Escalation Detector: Identifies IAM permissions that enable escalation to administrator rights."""

import fnmatch
import json
import logging
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


class PrivEscDetector:
    """Evaluates IAM action sets against known privilege escalation patterns."""

    def __init__(self, rules_file_path: str = "baseline/privesc_rules.json"):
        self.rules = self._load_rules(rules_file_path)

    def _load_rules(self, file_path: str) -> List[Dict[str, Any]]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("rules", [])
        except Exception as e:
            logger.error(f"Failed to load privilege escalation rules from {file_path}: {e}")
            return []

    @staticmethod
    def _action_matches(action_pattern: str, target_action: str) -> bool:
        """Check if an allowed action pattern grants target_action."""
        if action_pattern == "*" or action_pattern == "*:*":
            return True
        return fnmatch.fnmatchcase(target_action.lower(), action_pattern.lower())

    def has_permission(self, allowed_actions: Set[str], required_action: str) -> bool:
        """Verify if any granted action fulfills the required permission."""
        return any(self._action_matches(pattern, required_action) for pattern in allowed_actions)

    def evaluate_permissions(self, allowed_actions: Set[str], entity_type: str, entity_name: str, entity_arn: str) -> List[Dict[str, Any]]:
        """Evaluate a set of allowed actions against all privilege escalation rules."""
        findings = []

        for rule in self.rules:
            req_perms = rule.get("required_permissions", [])
            is_vulnerable = True

            for req in req_perms:
                # req can be a single action string or a list of alternatives
                if isinstance(req, list):
                    if not any(self.has_permission(allowed_actions, alt) for alt in req):
                        is_vulnerable = False
                        break
                else:
                    if not self.has_permission(allowed_actions, req):
                        is_vulnerable = False
                        break

            if is_vulnerable:
                findings.append({
                    "category": "PRIVILEGE_ESCALATION",
                    "severity": rule.get("severity", "HIGH"),
                    "rule_id": rule.get("id"),
                    "resource_type": entity_type,
                    "resource_name": entity_name,
                    "resource_arn": entity_arn,
                    "title": f"Privilege Escalation Vector: {rule.get('name')}",
                    "description": rule.get("description"),
                    "risk_score": rule.get("risk_score", 85),
                    "remediation": rule.get("mitigation", "Restrict required permissions or enforce permissions boundaries.")
                })

        return findings
