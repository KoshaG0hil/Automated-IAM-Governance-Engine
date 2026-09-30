# Automated IAM Governance & Configuration Drift Detection Engine

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![Terraform](https://img.shields.io/badge/Terraform-v1.5%2B-purple.svg)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-IAM%20%7C%20EventBridge%20%7C%20Lambda%20%7C%20SNS-orange.svg)](https://aws.amazon.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade cloud security platform that continuously evaluates AWS Identity & Access Management (IAM) configurations against declarative least-privilege baselines, detects configuration drift, scans for privilege escalation attack paths, and scores anomalies for real-time alerting and audit reporting.

---

## 🎯 Executive Highlights & Resume Alignment

- **Automated IAM Governance**: Replaces error-prone manual IAM audits with declarative YAML baselines and continuous validation across IAM roles, users, and customer-managed policies.
- **Configuration Drift Detection**: Identifies out-of-band policy attachments, missing permissions boundaries, unapproved inline policies, and shadow IAM assets in seconds.
- **Privilege Escalation Vector Analysis**: Evaluates permissions against 21+ documented AWS IAM privilege escalation techniques (Rhino Security Labs & Bishop Fox research), including `iam:PassRole` + compute service combinations and `iam:CreatePolicyVersion`.
- **Lightweight Anomaly-Scoring Engine**: Implements a compound-risk prioritization model (0–100 score) factoring in administrative wildcards (`*`), privilege escalation vectors, and credential dormancy (>90 days unused) to calculate an overall Security Posture Score.
- **Event-Driven & Scheduled Remediation**: Integrates AWS CloudTrail and Amazon EventBridge for real-time mutation alerts via Amazon SNS, paired with automated scheduled audit sweeps that archive audit-ready HTML, CSV, and JSON evidence to Amazon S3.

---

## 🌐 Live Interactive Demo

You can interact with the generated security audit dashboard directly in your web browser:  
👉 **[Launch Live IAM Governance Audit Dashboard](https://koshag0hil.github.io/Automated-IAM-Governance-Engine/)**

*Features real-time client-side severity filtering, compound risk scores, affected resource drill-downs, and actionable remediation instructions.*

---

## 🏛️ System Architecture

```
                                  ┌───────────────────────────────┐
                                  │        AWS Environment        │
                                  └───────────────┬───────────────┘
                                                  │
                 CloudTrail IAM Events            │   Scheduled Audit (Cron)
           (CreatePolicy, AttachRolePolicy, etc.) │   (Daily / Hourly Sweep)
                               │                  │
                               ▼                  ▼
                    ┌───────────────────────────────────┐
                    │    Amazon EventBridge Rules       │
                    └─────────────────┬─────────────────┘
                                      │ Invokes
                                      ▼
                    ┌───────────────────────────────────┐
                    │  IAM Governance Engine (Lambda)   │
                    └─────────────────┬─────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│  Drift Detector  │        │ PrivEsc Detector │        │ Credential Audit │
│  - YAML Baseline │        │ - 21+ Attack     │        │ - Inactive Keys  │
│  - Shadow Roles  │        │   Signatures     │        │ - Root Activity  │
│  - Boundary Gaps │        │ - Wildcards (*)  │        │ - MFA Checks     │
└────────┬─────────┘        └────────┬─────────┘        └────────┬─────────┘
         │                           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     ▼
                    ┌───────────────────────────────────┐
                    │    Anomaly Scoring Engine         │
                    │  - Compound Risk Multiplier       │
                    │  - Priority Tiers (P1 to P4)      │
                    │  - Security Posture Score (0-100) │
                    └─────────────────┬─────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    ▼                                   ▼
        ┌───────────────────────┐           ┌───────────────────────┐
        │ Amazon SNS Dispatcher │           │   Report Generator    │
        │ - Immediate Alerts    │           │ - Executive HTML      │
        │ - Email / Slack Hooks │           │ - Auditor CSV / JSON  │
        │ - P1/P2 Escalations   │           │ - S3 Evidence Archive │
        └───────────────────────┘           └───────────────────────┘
```

---

## 📂 Project Structure

```
Automated-IAM-Governance-Engine/
├── baseline/
│   ├── sample_baseline.yaml       # Approved least-privilege baseline definitions
│   └── privesc_rules.json         # 21+ Privilege escalation signatures
├── src/
│   ├── __init__.py
│   ├── main.py                    # CLI tool for local audits & CloudTrail simulation
│   ├── lambda_handler.py          # AWS Lambda entrypoint for EventBridge & audits
│   ├── collectors/
│   │   ├── iam_collector.py       # Live AWS boto3 collector & offline mock loader
│   │   └── credential_report.py   # Credential report auditor (keys, MFA, root)
│   ├── evaluators/
│   │   ├── drift_detector.py      # Baseline vs live state comparator
│   │   ├── policy_analyzer.py     # Wildcard & sensitive service analyzer
│   │   └── privesc_detector.py    # Privilege escalation pattern matcher
│   ├── scoring/
│   │   └── anomaly_engine.py      # Risk scoring, compound multiplier & posture grade
│   ├── notifiers/
│   │   └── sns_dispatcher.py      # SNS alert formatter & email/Slack dispatcher
│   └── reporting/
│       ├── report_generator.py    # JSON, CSV, and HTML report exporter
│       └── templates/report.html  # Modern responsive audit dashboard
├── terraform/
│   ├── main.tf                    # Complete AWS infrastructure (Lambda, EventBridge, SNS, S3)
│   ├── variables.tf               # Terraform input parameters
│   ├── outputs.tf                 # Exported resource ARNs
│   └── terraform.tfvars.example   # Example variables file
├── tests/
│   ├── test_drift_detector.py     # Drift detection unit tests
│   ├── test_privesc_detector.py   # PrivEsc vector unit tests
│   ├── test_anomaly_engine.py     # Anomaly scoring unit tests
│   ├── mock_data/                 # Mock IAM states & credential reports
│   └── mock_events/               # Mock CloudTrail IAM mutation events
├── requirements.txt
└── README.md
```

---

## ⚡ Quickstart & Local Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run a Full Offline Audit Scan (Mock Mode)
Run a complete compliance scan using the included realistic mock IAM environment. Generates interactive HTML, CSV, and JSON audit evidence immediately:

```bash
python src/main.py
```

**Terminal Output Preview:**
```text
================================================================================
 🚀 AUTOMATED IAM GOVERNANCE & CONFIGURATION DRIFT DETECTION ENGINE
================================================================================
[*] Target Account ID : 123456789012
[*] Roles Discovered  : 3
[*] Users Discovered  : 2
[*] Loading Baseline  : baseline/sample_baseline.yaml

--------------------------------------------------------------------------------
 📊 EXECUTIVE AUDIT SUMMARY & ANOMALY POSTURE
--------------------------------------------------------------------------------
  • Security Posture Score : 0/100
  • Posture Rating         : POOR (High Risk / Multiple Critical Drifts)
  • Total Findings         : 16
  • Critical Severity      : 4
  • High Severity          : 7
  • Medium Severity        : 5
--------------------------------------------------------------------------------

🔎 TOP PRIORITIZED FINDINGS:
╭────────────────┬────────────┬────────┬──────────────────────────┬────────────────────────────────────────────╮
│ Priority       │ Severity   │   Risk │ Resource                 │ Finding Title                              │
├────────────────┼────────────┼────────┼──────────────────────────┼────────────────────────────────────────────┤
│ P1 - IMMEDIATE │ CRITICAL   │    100 │ AppBackendServiceRole    │ Unapproved Policy Attached to Role         │
│ P1 - IMMEDIATE │ HIGH       │    100 │ AppBackendServiceRole    │ Missing Permissions Boundary on Role       │
│ P1 - IMMEDIATE │ CRITICAL   │    100 │ DevOpsShadowAdminRole    │ Privilege Escalation: IAM CreatePolicyVer  │
│ P1 - IMMEDIATE │ HIGH       │    100 │ DevOpsShadowAdminRole    │ Privilege Escalation: EC2 RunInstances     │
│ P1 - IMMEDIATE │ CRITICAL   │    100 │ root                     │ Active Access Keys on Root Account         │
│ P1 - IMMEDIATE │ CRITICAL   │    100 │ root                     │ MFA Not Enabled on Root Account            │
╰────────────────┴────────────┴────────┴──────────────────────────┴────────────────────────────────────────────╯
```

### 3. Simulate a Real-Time CloudTrail IAM Mutation Event
Simulate the ingestion of an unauthorized `AttachRolePolicy` event attaching `AdministratorAccess`:

```bash
python src/main.py --simulate-event tests/mock_events/cloudtrail_attach_admin_policy.json
```

**Output:**
```text
🚨 [IAM GOVERNANCE ALERT] CRITICAL - Unapproved Policy Attached to Role 'AppBackendServiceRole'
======================================================================
• Priority:           P1 - IMMEDIATE
• Anomaly Risk Score: 100/100
• Category:           POLICY_DRIFT
• Trigger Source:     CloudTrail:AttachRolePolicy
• Resource Type:      Role
• Resource Name:      AppBackendServiceRole
• Resource ARN:       arn:aws:iam::123456789012:role/AppBackendServiceRole

Details:
Role 'AppBackendServiceRole' has unapproved policy attached: arn:aws:iam::aws:policy/AdministratorAccess.

Recommended Remediation:
Detach policy arn:aws:iam::aws:policy/AdministratorAccess from role 'AppBackendServiceRole' or submit change control to update baseline.
======================================================================
```

### 4. Run Automated Test Suite
Verify all detection logic, privesc signatures, and anomaly scoring algorithms:

```bash
pytest -v
# 8 passed in 0.22s
```

---

## ☁️ Live AWS Deployment via Terraform

Deploy the automated governance platform into your AWS account with a single command:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your alert email and region

terraform init
terraform plan
terraform apply
```

### Resources Provisioned:
1. **AWS Lambda**: Serverless execution engine (`iam-governance-engine`).
2. **EventBridge Rule (CloudTrail)**: Subscribed to IAM mutations (`CreatePolicy`, `AttachRolePolicy`, etc.).
3. **EventBridge Rule (Scheduled)**: Daily audit cron sweep.
4. **Amazon SNS Topic**: Dispatches alerts for Critical and High severity findings.
5. **Amazon S3 Bucket**: Encrypted bucket for storing historical compliance evidence.
6. **IAM Execution Role**: Strictly scoped least-privilege audit role.

---

## 📊 Anomaly-Scoring Methodology

The engine applies a multi-factor risk model to avoid alert fatigue:

$$\text{Final Score} = \min\left(100, \text{Base Risk} \times \left(1 + 0.15 \times \min(N - 1, 5)\right)\right)$$

Where:
- $\text{Base Risk}$ is determined by the severity of the specific violation (e.g. 100 for Root Access Keys, 95 for `iam:CreatePolicyVersion`, 85 for `iam:PassRole` + `ec2:RunInstances`).
- $N$ is the number of simultaneous violations found on the same resource (Compound Risk Multiplier).
- Findings are automatically mapped to actionable priority tiers:
  - **P1 - IMMEDIATE**: Score $\ge 90$ or Critical (e.g. Unrestricted Administrator Access, Active Root Keys).
  - **P2 - HIGH**: Score $\ge 75$ or High (e.g. PrivEsc vectors, Unapproved Shadow Roles).
  - **P3 - MEDIUM**: Score $\ge 50$ (e.g. Unscoped write resources, Keys $>90$ days old).
  - **P4 - LOW**: Score $< 50$ (Advisory findings and minor drift).

---

## 📜 License
Distributed under the MIT License.
