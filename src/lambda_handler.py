"""AWS Lambda Handler: Processes real-time CloudTrail IAM mutation events and scheduled audits."""

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict
import boto3

from collectors.iam_collector import IAMCollector
from collectors.credential_report import CredentialReportAuditor
from evaluators.drift_detector import DriftDetector
from evaluators.policy_analyzer import PolicyAnalyzer
from evaluators.privesc_detector import PrivEscDetector
from scoring.anomaly_engine import AnomalyScoringEngine
from notifiers.sns_dispatcher import SNSAlertDispatcher
from reporting.report_generator import ReportGenerator

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
BASELINE_PATH = os.environ.get("BASELINE_PATH", "baseline/sample_baseline.yaml")
PRIVESC_RULES_PATH = os.environ.get("PRIVESC_RULES_PATH", "baseline/privesc_rules.json")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point for EventBridge events and scheduled audits."""
    logger.info(f"Received invocation event: {json.dumps(event, default=str)}")

    source = event.get("source", "")
    detail_type = event.get("detail-type", "")

    # Check if this is a real-time CloudTrail IAM mutation event
    if source == "aws.iam" or "CloudTrail" in detail_type:
        return handle_cloudtrail_event(event)

    # Otherwise, execute a full periodic account governance audit
    return handle_scheduled_audit()


def handle_cloudtrail_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Inspects a single IAM mutation event from CloudTrail."""
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "UnknownEvent")
    user_identity = detail.get("userIdentity", {}).get("arn", "UnknownUser")
    req_params = detail.get("requestParameters", {})

    logger.info(f"Analyzing CloudTrail IAM mutation: {event_name} initiated by {user_identity}")

    drift_detector = DriftDetector(BASELINE_PATH)
    policy_analyzer = PolicyAnalyzer()
    privesc_detector = PrivEscDetector(PRIVESC_RULES_PATH)
    anomaly_engine = AnomalyScoringEngine()
    dispatcher = SNSAlertDispatcher(SNS_TOPIC_ARN)

    raw_findings = []

    # 1. Evaluate specific mutated resource
    role_name = req_params.get("roleName")
    user_name = req_params.get("userName")
    policy_arn = req_params.get("policyArn")

    mock_state_path = os.environ.get("MOCK_IAM_STATE")
    session = boto3.Session()
    iam = session.client("iam")

    if role_name:
        role_data = None
        try:
            role_res = iam.get_role(RoleName=role_name)
            collector = IAMCollector(session=session)
            role_data = {
                "RoleName": role_name,
                "Arn": role_res["Role"]["Arn"],
                "AttachedPolicies": collector._get_role_attached_policies(role_name),
                "InlinePolicies": collector._get_role_inline_policies(role_name),
                "PermissionsBoundary": role_res["Role"].get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            }
        except Exception as e:
            logger.info(f"Live AWS role lookup for '{role_name}' bypassed/failed ({e}). Falling back to event & mock inspection...")
            # Fallback to mock state or synthetic role data from event
            if mock_state_path and os.path.exists(mock_state_path):
                collector = IAMCollector(mock_file=mock_state_path)
                mock_roles = collector.get_roles()
                for r in mock_roles:
                    if r.get("RoleName") == role_name:
                        role_data = r
                        break

            if not role_data:
                role_data = {
                    "RoleName": role_name,
                    "Arn": f"arn:aws:iam::123456789012:role/{role_name}",
                    "AttachedPolicies": [{"PolicyName": "AttachedPolicy", "PolicyArn": policy_arn}] if policy_arn else [],
                    "InlinePolicies": {},
                    "PermissionsBoundary": None
                }

        # If event attached a policy, ensure it is represented in role_data
        if policy_arn and not any(p.get("PolicyArn") == policy_arn for p in role_data.get("AttachedPolicies", [])):
            role_data["AttachedPolicies"].append({"PolicyName": policy_arn.split("/")[-1], "PolicyArn": policy_arn})

        # Check drift
        raw_findings.extend(drift_detector.detect_role_drift([role_data]))

        # Check policies for privesc and wildcards
        for p_name, doc in role_data.get("InlinePolicies", {}).items():
            raw_findings.extend(policy_analyzer.analyze_policy_document(doc, role_name, p_name))
            actions = policy_analyzer.extract_allowed_actions(doc)
            raw_findings.extend(privesc_detector.evaluate_permissions(actions, "Role", role_name, role_data["Arn"]))

    elif user_name:
        try:
            collector = IAMCollector(session=session)
            u_res = iam.get_user(UserName=user_name)
            user_data = {
                "UserName": user_name,
                "Arn": u_res["User"]["Arn"],
                "AttachedPolicies": collector._get_user_attached_policies(user_name),
                "InlinePolicies": collector._get_user_inline_policies(user_name),
                "Groups": collector._get_user_groups(user_name),
                "PermissionsBoundary": u_res["User"].get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            }
            raw_findings.extend(drift_detector.detect_user_drift([user_data]))

            for p_name, doc in user_data["InlinePolicies"].items():
                raw_findings.extend(policy_analyzer.analyze_policy_document(doc, user_name, p_name))
                actions = policy_analyzer.extract_allowed_actions(doc)
                raw_findings.extend(privesc_detector.evaluate_permissions(actions, "User", user_name, user_data["Arn"]))
        except Exception as e:
            logger.error(f"Error inspecting modified user {user_name}: {e}")

    # Process and score
    scored_results = anomaly_engine.process_findings(raw_findings)
    sent_count = dispatcher.dispatch(scored_results["findings"], trigger_source=f"CloudTrail:{event_name}")

    return {
        "statusCode": 200,
        "trigger": "CloudTrailEvent",
        "eventName": event_name,
        "initiator": user_identity,
        "findings_count": len(scored_results["findings"]),
        "alerts_dispatched": sent_count
    }


def handle_scheduled_audit() -> Dict[str, Any]:
    """Performs full account audit sweep, scores findings, and uploads reports."""
    logger.info("Executing scheduled IAM governance audit sweep...")
    session = boto3.Session()
    collector = IAMCollector(session=session)
    state = collector.collect_all()

    drift_detector = DriftDetector(BASELINE_PATH)
    policy_analyzer = PolicyAnalyzer()
    privesc_detector = PrivEscDetector(PRIVESC_RULES_PATH)
    cred_auditor = CredentialReportAuditor(session=session)
    anomaly_engine = AnomalyScoringEngine()
    dispatcher = SNSAlertDispatcher(SNS_TOPIC_ARN)

    raw_findings = []

    # 1. Role drift & policy evaluation
    roles = state.get("roles", [])
    raw_findings.extend(drift_detector.detect_role_drift(roles))
    for role in roles:
        for p_name, doc in role.get("InlinePolicies", {}).items():
            raw_findings.extend(policy_analyzer.analyze_policy_document(doc, role["RoleName"], p_name))
            actions = policy_analyzer.extract_allowed_actions(doc)
            raw_findings.extend(privesc_detector.evaluate_permissions(actions, "Role", role["RoleName"], role["Arn"]))

    # 2. User drift & policy evaluation
    users = state.get("users", [])
    raw_findings.extend(drift_detector.detect_user_drift(users))
    for user in users:
        for p_name, doc in user.get("InlinePolicies", {}).items():
            raw_findings.extend(policy_analyzer.analyze_policy_document(doc, user["UserName"], p_name))
            actions = policy_analyzer.extract_allowed_actions(doc)
            raw_findings.extend(privesc_detector.evaluate_permissions(actions, "User", user["UserName"], user["Arn"]))

    # 3. Credential Report Audit
    raw_findings.extend(cred_auditor.audit())

    # 4. Score and prioritize
    scored_results = anomaly_engine.process_findings(raw_findings)

    # 5. Dispatch SNS alerts for high/critical findings
    alerts_sent = dispatcher.dispatch(scored_results["findings"], trigger_source="ScheduledAccountAudit")

    # 6. Upload audit report to S3 if configured
    if REPORTS_BUCKET:
        try:
            s3 = session.client("s3")
            rep_gen = ReportGenerator()
            date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            s3.put_object(
                Bucket=REPORTS_BUCKET,
                Key=f"audits/iam_audit_{date_str}.json",
                Body=json.dumps(scored_results, default=str),
                ContentType="application/json"
            )
            logger.info(f"Uploaded audit report to s3://{REPORTS_BUCKET}/audits/iam_audit_{date_str}.json")
        except Exception as e:
            logger.error(f"Failed to upload report to S3: {e}")

    return {
        "statusCode": 200,
        "trigger": "ScheduledAudit",
        "posture_score": scored_results["posture_score"],
        "posture_grade": scored_results["posture_grade"],
        "total_findings": scored_results["total_findings"],
        "alerts_dispatched": alerts_sent
    }
