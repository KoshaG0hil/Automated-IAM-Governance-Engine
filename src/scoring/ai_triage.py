"""AI-Style Triage Layer: Enriches findings with natural-language rationale, blast radius, and queue routing."""

from typing import Any, Dict, List


class AITriageLayer:
    """Simulates an AI Security Copilot triage workflow to reduce alert noise and prioritize investigation queues."""

    QUEUE_URGENT_SOC = "QUEUE-1: SOC Urgent Incident Response"
    QUEUE_CLOUDSEC_DRIFT = "QUEUE-2: CloudSec Escalation & Drift Queue"
    QUEUE_IDENTITY_HYGIENE = "QUEUE-3: Identity Hygiene & Credential Backlog"
    QUEUE_AUDIT_LOG = "QUEUE-4: Informational / Audit Verification"

    BLAST_RADIUS_ACCOUNT = "CRITICAL (Account-Wide Takeover Potential)"
    BLAST_RADIUS_PRIVESC = "HIGH (Privilege Escalation & Lateral Movement)"
    BLAST_RADIUS_DATA = "MEDIUM (Data Exfiltration & Resource Access)"
    BLAST_RADIUS_HYGIENE = "LOW (Credential / Compliance Drift)"

    def triage_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single security finding with AI triage context."""
        category = finding.get("category", "")
        severity = finding.get("severity", "LOW")
        title = finding.get("title", "")
        res_name = finding.get("resource_name", "")
        res_type = finding.get("resource_type", "")
        score = finding.get("adjusted_risk_score", finding.get("risk_score", 50))

        # 1. Determine Investigation Queue & Blast Radius
        if severity == "CRITICAL" or score >= 90:
            queue = self.QUEUE_URGENT_SOC
            blast_radius = self.BLAST_RADIUS_ACCOUNT
            noise_decision = "ACTIONABLE_URGENT (Top 5% critical threat requiring immediate human intervention)"
        elif severity == "HIGH" or score >= 75:
            queue = self.QUEUE_CLOUDSEC_DRIFT
            blast_radius = self.BLAST_RADIUS_PRIVESC
            noise_decision = "ACTIONABLE_HIGH (Configuration drift with attack path potential; escalated to CloudSec queue)"
        elif severity == "MEDIUM" or score >= 50:
            queue = self.QUEUE_IDENTITY_HYGIENE
            blast_radius = self.BLAST_RADIUS_DATA
            noise_decision = "FILTERED_TO_HYGIENE (Routine security hygiene; batched into sprint backlog to prevent alert fatigue)"
        else:
            queue = self.QUEUE_AUDIT_LOG
            blast_radius = self.BLAST_RADIUS_HYGIENE
            noise_decision = "SUPPRESSED_FROM_PAGE (Informational audit finding; archived in compliance logs)"

        # 2. Generate Contextual AI Rationale
        ai_rationale = self._generate_rationale(category, title, res_name, res_type)

        # 3. Generate Copy-Pasteable AWS CLI Remediation Command
        cli_command = self._generate_cli_remediation(category, title, res_name, res_type, finding.get("resource_arn", ""))

        triage_info = {
            "investigation_queue": queue,
            "blast_radius": blast_radius,
            "noise_filter_verdict": noise_decision,
            "ai_triage_rationale": ai_rationale,
            "remediation_cli_command": cli_command
        }

        finding.update(triage_info)
        return finding

    def _generate_rationale(self, category: str, title: str, res_name: str, res_type: str) -> str:
        if "Root" in title or "root" in res_name:
            return "Root credentials bypass all permissions boundaries and SCPs. Compromise yields irreversible full-account takeover."
        elif category == "PRIVILEGE_ESCALATION":
            return f"Entity '{res_name}' has permission primitives capable of bypassing least privilege to achieve administrative rights."
        elif category == "POLICY_DRIFT":
            return f"Out-of-band policy modification detected on '{res_name}' bypassing GitOps/IaC review pipelines."
        elif category == "MISSING_GUARDRAIL":
            return f"Absence of a permissions boundary on '{res_name}' allows downstream privilege expansion without guardrails."
        elif category == "EXCESSIVE_PERMISSIONS":
            return f"Wildcard permissions on '{res_name}' violate least-privilege standards and increase the attack blast radius."
        elif category == "CREDENTIAL_SECURITY":
            return f"Unrotated or dormant credentials on '{res_name}' represent an exposed attack surface vulnerable to credential stuffing."
        return f"Governance violation detected on {res_type} '{res_name}', deviating from approved baseline."

    def _generate_cli_remediation(self, category: str, title: str, res_name: str, res_type: str, res_arn: str) -> str:
        if "Root" in title:
            return "aws iam delete-access-key --user-name <root> --access-key-id <KEY_ID>"
        elif "Unapproved Policy" in title:
            return f"aws iam detach-role-policy --role-name {res_name} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        elif "Missing Permissions Boundary" in title:
            return f"aws iam put-role-permissions-boundary --role-name {res_name} --permissions-boundary arn:aws:iam::123456789012:policy/StandardPermissionsBoundary"
        elif "Unapproved / Shadow" in title:
            return f"aws iam get-role --role-name {res_name} && aws iam delete-role --role-name {res_name}"
        elif "Access Key" in title:
            return f"aws iam update-access-key --user-name {res_name} --access-key-id <KEY_ID> --status Inactive"
        return f"# Audit and scope permissions for {res_type} '{res_name}'"

    def enrich_all(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and triage a list of findings."""
        return [self.triage_finding(f) for f in findings]
