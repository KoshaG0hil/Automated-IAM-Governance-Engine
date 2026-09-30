"""Policy Analyzer: Evaluates IAM policy documents for wildcards, dangerous permissions, and least-privilege violations."""

import fnmatch
from typing import Any, Dict, List, Set, Union


class PolicyAnalyzer:
    """Analyzes IAM policy documents against security best practices."""

    SENSITIVE_SERVICES = ["iam", "kms", "secretsmanager", "s3", "sts", "ec2"]

    def __init__(self, banned_actions: List[str] = None):
        self.banned_actions = banned_actions or []

    @staticmethod
    def _normalize_list(value: Union[str, List[str], None]) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)

    def extract_allowed_actions(self, policy_doc: Dict[str, Any]) -> Set[str]:
        """Extract all explicitly allowed actions from a policy document."""
        allowed_actions = set()
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                actions = self._normalize_list(stmt.get("Action"))
                allowed_actions.update(actions)
        return allowed_actions

    def matches_action(self, pattern: str, action: str) -> bool:
        """Check if an action matches an IAM wildcard pattern (e.g. 'iam:*' matches 'iam:PassRole')."""
        return fnmatch.fnmatchcase(action.lower(), pattern.lower())

    def analyze_policy_document(self, policy_doc: Dict[str, Any], entity_name: str, policy_name: str) -> List[Dict[str, Any]]:
        """Inspect a policy document for security weaknesses."""
        findings = []
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue

            actions = self._normalize_list(stmt.get("Action"))
            resources = self._normalize_list(stmt.get("Resource"))

            # 1. Full Administrator Access check (* on *)
            if ("*" in actions or "*:*" in actions) and "*" in resources:
                findings.append({
                    "category": "EXCESSIVE_PERMISSIONS",
                    "severity": "CRITICAL",
                    "resource_type": "IAMPolicy",
                    "resource_name": f"{entity_name}:{policy_name}",
                    "title": "Unrestricted Full Administrator Access (* on *)",
                    "description": f"Statement {idx + 1} grants full wildcard '*' actions across all AWS resources ('*').",
                    "risk_score": 100,
                    "remediation": "Replace full administrator access with explicit, scoped least-privilege actions and resources."
                })

            # 2. Wildcard actions on sensitive services
            for action in actions:
                for svc in self.SENSITIVE_SERVICES:
                    if action.lower() in [f"{svc}:*", "*"]:
                        findings.append({
                            "category": "EXCESSIVE_PERMISSIONS",
                            "severity": "HIGH",
                            "resource_type": "IAMPolicy",
                            "resource_name": f"{entity_name}:{policy_name}",
                            "title": f"Broad Wildcard Service Action '{action}'",
                            "description": f"Statement {idx + 1} grants broad administrative actions on sensitive service '{svc}' using wildcard '{action}'.",
                            "risk_score": 85,
                            "remediation": f"Limit actions for service '{svc}' to specific APIs required for workloads."
                        })

                # 3. Check for explicitly banned actions
                for banned in self.banned_actions:
                    if self.matches_action(action, banned):
                        findings.append({
                            "category": "BANNED_ACTION",
                            "severity": "CRITICAL",
                            "resource_type": "IAMPolicy",
                            "resource_name": f"{entity_name}:{policy_name}",
                            "title": f"Use of Explicitly Banned Action '{banned}'",
                            "description": f"Statement {idx + 1} grants action '{action}', which violates the governance baseline banning '{banned}'.",
                            "risk_score": 95,
                            "remediation": f"Remove action '{action}' from policy {policy_name} to comply with organizational guardrails."
                        })

            # 4. Wildcard resource on write / destructive actions
            if "*" in resources:
                state_changing_actions = [
                    a for a in actions
                    if not (a.lower().startswith("describe") or a.lower().startswith("get") or a.lower().startswith("list"))
                ]
                if state_changing_actions and "*" not in actions and "*:*" not in actions:
                    findings.append({
                        "category": "UNSCOPED_RESOURCE",
                        "severity": "MEDIUM",
                        "resource_type": "IAMPolicy",
                        "resource_name": f"{entity_name}:{policy_name}",
                        "title": f"State-Modifying Actions Without Scoped Resource ({len(state_changing_actions)} actions)",
                        "description": f"Statement {idx + 1} grants write/modification actions ({', '.join(state_changing_actions[:3])}...) against all resources ('*').",
                        "risk_score": 65,
                        "remediation": "Scope Resource ARN to specific target instances, buckets, or roles rather than using '*'."
                    })

        return findings
