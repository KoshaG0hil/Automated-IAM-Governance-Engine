"""CLI Entrypoint for the Automated IAM Governance & Configuration Drift Detection Engine."""

import argparse
from datetime import datetime, timezone
import json
import logging
import os
import sys

# Ensure local src directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from collectors.iam_collector import IAMCollector
from collectors.credential_report import CredentialReportAuditor
from evaluators.drift_detector import DriftDetector
from evaluators.policy_analyzer import PolicyAnalyzer
from evaluators.privesc_detector import PrivEscDetector
from scoring.anomaly_engine import AnomalyScoringEngine
from notifiers.sns_dispatcher import SNSAlertDispatcher
from reporting.report_generator import ReportGenerator

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IAMGovernanceCLI")


def run_full_scan(
    baseline_path: str,
    privesc_path: str,
    mock_file: str = None,
    mock_csv: str = None,
    output_dir: str = "reports",
    generate_reports: bool = True
):
    """Executes full IAM drift and least-privilege analysis."""
    print("\n" + "=" * 80)
    print(" 🚀 AUTOMATED IAM GOVERNANCE & CONFIGURATION DRIFT DETECTION ENGINE")
    print("=" * 80 + "\n")

    # 1. State Collection
    if mock_file:
        logger.info(f"Using mock IAM state file: {mock_file}")
        collector = IAMCollector(mock_file=mock_file)
    else:
        logger.info("Connecting to AWS via boto3 for live collection...")
        collector = IAMCollector()

    state = collector.collect_all()
    account_id = state.get("account_id", "123456789012")
    roles = state.get("roles", [])
    users = state.get("users", [])

    print(f"[*] Target Account ID : {account_id}")
    print(f"[*] Roles Discovered  : {len(roles)}")
    print(f"[*] Users Discovered  : {len(users)}")
    print(f"[*] Loading Baseline  : {baseline_path}")

    # 2. Evaluation
    drift_detector = DriftDetector(baseline_path)
    policy_analyzer = PolicyAnalyzer()
    privesc_detector = PrivEscDetector(privesc_path)
    cred_auditor = CredentialReportAuditor(mock_csv_file=mock_csv)

    raw_findings = []

    # Detect Role Drift & Wildcard/PrivEsc permissions
    raw_findings.extend(drift_detector.detect_role_drift(roles))
    for role in roles:
        role_name = role.get("RoleName", "UnknownRole")
        role_arn = role.get("Arn", "")
        # Inspect inline policies
        for p_name, doc in role.get("InlinePolicies", {}).items():
            raw_findings.extend(policy_analyzer.analyze_policy_document(doc, role_name, p_name))
            actions = policy_analyzer.extract_allowed_actions(doc)
            raw_findings.extend(privesc_detector.evaluate_permissions(actions, "Role", role_name, role_arn))

    # Detect User Drift & Wildcard/PrivEsc permissions
    raw_findings.extend(drift_detector.detect_user_drift(users))
    for user in users:
        user_name = user.get("UserName", "UnknownUser")
        user_arn = user.get("Arn", "")
        for p_name, doc in user.get("InlinePolicies", {}).items():
            raw_findings.extend(policy_analyzer.analyze_policy_document(doc, user_name, p_name))
            actions = policy_analyzer.extract_allowed_actions(doc)
            raw_findings.extend(privesc_detector.evaluate_permissions(actions, "User", user_name, user_arn))

    # Credential Report Audit
    cred_findings = cred_auditor.audit()
    raw_findings.extend(cred_findings)

    # 3. Anomaly Scoring & Prioritization
    scoring_engine = AnomalyScoringEngine()
    summary = scoring_engine.process_findings(raw_findings)

    # 4. Terminal Output
    print("\n" + "-" * 80)
    print(" 📊 EXECUTIVE AUDIT SUMMARY & ANOMALY POSTURE")
    print("-" * 80)
    print(f"  • Security Posture Score : {summary['posture_score']}/100")
    print(f"  • Posture Rating         : {summary['posture_grade']}")
    print(f"  • Total Findings         : {summary['total_findings']}")
    print(f"  • Critical Severity      : {summary['severity_breakdown']['CRITICAL']}")
    print(f"  • High Severity          : {summary['severity_breakdown']['HIGH']}")
    print(f"  • Medium Severity        : {summary['severity_breakdown']['MEDIUM']}")
    print(f"  • Low Severity           : {summary['severity_breakdown']['LOW']}")
    print("-" * 80)

    # Table of Top Findings
    findings = summary["findings"]
    if findings:
        table_rows = []
        for f in findings[:10]:
            table_rows.append([
                f.get("priority"),
                f.get("severity"),
                f.get("adjusted_risk_score"),
                f.get("resource_name")[:24],
                f.get("title")[:42]
            ])

        print("\n🔎 TOP PRIORITIZED FINDINGS:")
        if HAS_TABULATE:
            print(tabulate(
                table_rows,
                headers=["Priority", "Severity", "Risk", "Resource", "Finding Title"],
                tablefmt="rounded_grid"
            ))
        else:
            for row in table_rows:
                print(f"  [{row[0]}] {row[1]} (Score: {row[2]}) - {row[3]}: {row[4]}")

        if len(findings) > 10:
            print(f"\n  ... and {len(findings) - 10} more findings detailed in the full report.")

    # 5. Report Generation
    if generate_reports:
        rep_gen = ReportGenerator()
        out_paths = rep_gen.generate_all(summary, account_id, output_dir=output_dir)
        print("\n" + "=" * 80)
        print(" 📁 AUDIT REPORTS GENERATED SUCCESSFULLY:")
        print(f"  • HTML Dashboard : file://{os.path.abspath(out_paths['latest_html']).replace('\\', '/')}")
        print(f"  • CSV Export     : {os.path.abspath(out_paths['csv'])}")
        print(f"  • JSON Dump      : {os.path.abspath(out_paths['json'])}")
        print("=" * 80 + "\n")

    return summary


def simulate_event(event_file: str, baseline_path: str, privesc_path: str):
    """Simulates ingestion of a CloudTrail EventBridge event."""
    from lambda_handler import handle_cloudtrail_event
    logger.info(f"Simulating CloudTrail event ingestion from {event_file}")
    with open(event_file, "r", encoding="utf-8") as f:
        event = json.load(f)

    # Set env vars for handler
    os.environ["BASELINE_PATH"] = baseline_path
    os.environ["PRIVESC_RULES_PATH"] = privesc_path
    os.environ["MOCK_IAM_STATE"] = "tests/mock_data/mock_iam_state.json"

    res = handle_cloudtrail_event(event)
    print("\n" + "=" * 80)
    print(" ⚡ CLOUDTRAIL EVENT PROCESSING RESULT")
    print("=" * 80)
    print(json.dumps(res, indent=2))
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Automated IAM Governance & Configuration Drift Detection Engine")
    parser.add_argument("--scan", action="store_true", help="Run full IAM governance & drift scan")
    parser.add_argument("--mock", type=str, default="tests/mock_data/mock_iam_state.json", help="Path to mock IAM state JSON")
    parser.add_argument("--mock-csv", type=str, default="tests/mock_data/mock_credential_report.csv", help="Path to mock credential report CSV")
    parser.add_argument("--live", action="store_true", help="Connect to live AWS account via boto3 instead of mock")
    parser.add_argument("--baseline", type=str, default="baseline/sample_baseline.yaml", help="Path to baseline YAML")
    parser.add_argument("--privesc-rules", type=str, default="baseline/privesc_rules.json", help="Path to privesc rules JSON")
    parser.add_argument("--output-dir", type=str, default="reports", help="Directory to save generated reports")
    parser.add_argument("--simulate-event", type=str, help="Simulate a CloudTrail IAM mutation event from JSON file")

    args = parser.parse_args()

    if args.simulate_event:
        simulate_event(args.simulate_event, args.baseline, args.privesc_rules)
    else:
        mock_file = None if args.live else args.mock
        mock_csv = None if args.live else args.mock_csv
        run_full_scan(
            baseline_path=args.baseline,
            privesc_path=args.privesc_rules,
            mock_file=mock_file,
            mock_csv=mock_csv,
            output_dir=args.output_dir
        )


if __name__ == "__main__":
    main()
