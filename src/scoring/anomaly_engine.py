"""Anomaly Scoring Engine: Prioritizes IAM drift and security findings using a multi-factor risk model."""

from collections import defaultdict
from typing import Any, Dict, List


class AnomalyScoringEngine:
    """Computes anomaly scores, posture ratings, and priority tiers for IAM findings."""

    SEVERITY_WEIGHTS = {
        "CRITICAL": 30,
        "HIGH": 15,
        "MEDIUM": 5,
        "LOW": 1
    }

    def process_findings(self, raw_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enrich raw findings with anomaly scores, compound risk, and generate summary metrics."""
        # 1. Group findings by resource to detect compound risk
        resource_findings = defaultdict(list)
        for finding in raw_findings:
            res_key = finding.get("resource_arn") or finding.get("resource_name") or "unknown"
            resource_findings[res_key].append(finding)

        enriched_findings = []
        for res_key, findings_list in resource_findings.items():
            count = len(findings_list)
            # Compound risk boost: entities with multiple simultaneous violations receive higher urgency
            compound_multiplier = 1.0 + (0.15 * min(count - 1, 5))

            for finding in findings_list:
                base_score = finding.get("risk_score", 50)
                final_score = min(100, int(base_score * compound_multiplier))
                finding["adjusted_risk_score"] = final_score

                # Determine Priority Tier
                if final_score >= 90 or finding.get("severity") == "CRITICAL":
                    priority = "P1 - IMMEDIATE"
                elif final_score >= 75 or finding.get("severity") == "HIGH":
                    priority = "P2 - HIGH"
                elif final_score >= 50:
                    priority = "P3 - MEDIUM"
                else:
                    priority = "P4 - LOW"

                finding["priority"] = priority
                enriched_findings.append(finding)

        # 2. Sort findings by adjusted risk score descending
        enriched_findings.sort(key=lambda x: x.get("adjusted_risk_score", 0), reverse=True)

        # 3. Calculate Account Posture Score (0-100%)
        # Base 100, deductions weighted by severity
        total_deduction = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        category_counts = defaultdict(int)

        for finding in enriched_findings:
            sev = finding.get("severity", "LOW")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            total_deduction += self.SEVERITY_WEIGHTS.get(sev, 1)

            cat = finding.get("category", "MISC")
            category_counts[cat] += 1

        posture_score = max(0, 100 - total_deduction)

        if posture_score >= 85:
            posture_grade = "GOOD (Low Drift)"
        elif posture_score >= 65:
            posture_grade = "FAIR (Moderate Drift & Risk)"
        else:
            posture_grade = "POOR (High Risk / Multiple Critical Drifts)"

        return {
            "posture_score": posture_score,
            "posture_grade": posture_grade,
            "total_findings": len(enriched_findings),
            "severity_breakdown": severity_counts,
            "category_breakdown": dict(category_counts),
            "findings": enriched_findings
        }
