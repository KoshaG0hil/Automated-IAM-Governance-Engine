# Comprehensive Project Guide: Automated IAM Governance & Configuration Drift Detection Engine

---

## 📑 Table of Contents
1. [What is This Project?](#1-what-is-this-project)
2. [Why We Built It: The Production Pain It Solves](#2-why-we-built-it-the-production-pain-it-solves)
3. [Who It Helps & Practical Value](#3-who-it-helps--practical-value)
4. [Architecture & Core Engineering Modules](#4-architecture--core-engineering-modules)
5. [Step-by-Step Usage & Execution Methods](#5-step-by-step-usage--execution-methods)
   - [Method 1: Interactive 1-Click Runner (Windows PowerShell / CMD)](#method-1-interactive-1-click-runner-windows-powershell--cmd)
   - [Method 2: Command-Line Interface (Local Mock Mode)](#method-2-command-line-interface-local-mock-mode)
   - [Method 3: Real-Time CloudTrail Security Mutation Simulation](#method-3-real-time-cloudtrail-security-mutation-simulation)
   - [Method 4: Automated Unit & Rule Verification](#method-4-automated-unit--rule-verification)
   - [Method 5: Live AWS Account Audit Scan](#method-5-live-aws-account-audit-scan)
   - [Method 6: Continuous 24/7 Cloud Deployment via Terraform](#method-6-continuous-247-cloud-deployment-via-terraform)
6. [How to Customize Guardrails & Baselines](#6-how-to-customize-guardrails--baselines)
7. [Anomaly-Scoring & Risk Prioritization Methodology](#7-anomaly-scoring--risk-prioritization-methodology)
8. [Interview Talk Track & Portfolio Presentation](#8-interview-talk-track--portfolio-presentation)

---

## 1. What is This Project?

The **Automated IAM Governance & Configuration Drift Detection Engine** is an enterprise-grade cloud security platform engineered to continuously audit, detect, and remediate identity security risks in Amazon Web Services (AWS).

At its core, the engine performs four autonomous functions:
1. **Baseline Governance**: Compares active IAM roles, users, and policies against declarative, GitOps-managed least-privilege baselines (defined in YAML).
2. **Configuration Drift Detection**: Identifies out-of-band changes—such as console modifications, unexpected policy attachments, missing permissions boundaries, and untracked "shadow" IAM assets.
3. **Privilege Escalation Detection**: Analyzes policy statements against 14+ documented attack vectors (based on Rhino Security Labs and Bishop Fox research) where non-admin principals can escalate privileges to full administrative control.
4. **Anomaly Scoring & Prioritization**: Uses a multi-factor mathematical scoring model (0–100) to weigh wildcards, dormant credentials, and compound violations, dispatching real-time SNS alerts and generating audit-ready HTML/CSV/JSON compliance evidence.

---

## 2. Why We Built It: The Production Pain It Solves

In modern cloud environments, **AWS IAM is the perimeter**. However, enterprise security teams face critical operational and security bottlenecks:

### 🔴 Problem 1: Manual IAM Reviews Are Slow, Expensive, and Outdated
- **The Reality**: Organizations typically conduct manual IAM reviews once per quarter or once a year using massive spreadsheets exported from the AWS console.
- **The Failure**: By the time an audit is completed, the findings are weeks old. A developer granted temporary admin access on Monday remains unreviewed until the next quarter.

### 🔴 Problem 2: Out-of-Band Configuration Drift ("Console Cowboy" Hotfixes)
- **The Reality**: Even if teams manage IAM via Infrastructure as Code (Terraform, CloudFormation), engineers frequently bypass CI/CD during production outages or tight deadlines, making manual changes directly in the AWS Management Console.
- **The Failure**: Terraform state and Git repositories no longer reflect actual cloud reality. Unapproved policies like `AdministratorAccess` or inline policies with wildcard `*` permissions remain silently active.

### 🔴 Problem 3: Privilege Escalation Blindspots
- **The Reality**: Basic security tools only flag obvious violations like `Action: "*"` on `Resource: "*"`.
- **The Failure**: Attackers and rogue insiders exploit subtle multi-permission combinations. For example, a role with `iam:PassRole` and `ec2:RunInstances` can launch an EC2 instance with an attached admin instance profile and extract temporary credentials via IMDS. Traditional linters miss this; this engine explicitly catches it.

### 🔴 Problem 4: Alert Fatigue & Lack of Prioritization
- **The Reality**: Legacy scanners dump hundreds of low-severity notifications into Slack or email channels, burying critical security issues under noise.
- **The Failure**: Security engineers suffer from alert fatigue. Critical risks (such as active access keys on the root account) get ignored alongside low-priority informational warnings.

### 🔴 Problem 5: Audit & Compliance Scramble
- **The Reality**: Preparing for SOC 2 Type II, ISO 27001, or CIS AWS Foundations Benchmark audits requires weeks of manual evidence gathering.
- **The Failure**: Engineering time is diverted away from feature delivery to take console screenshots and format compliance tables.

---

## 3. Who It Helps & Practical Value

| Role | How This Engine Helps |
| :--- | :--- |
| **Security Operations (SecOps)** | Replaces reactive quarterly reviews with **real-time event-driven alerts** whenever an IAM mutation occurs, cutting Mean Time to Detect (MTTD) from months to seconds. |
| **Cloud & DevOps Engineers** | Provides immediate feedback when a manual change drifts from approved IaC baselines, maintaining GitOps integrity. |
| **Compliance & GRC Teams** | Generates instant, downloadable HTML dashboards, CSV exports for spreadsheet analysis, and JSON evidence for SIEM systems (Splunk, Datadog). |
| **CISOs & Engineering Leadership** | Offers an executive **Account Security Posture Score (0–100%)** that provides quantifiable security posture visibility over time. |

---

## 4. Architecture & Core Engineering Modules

```
                             ┌───────────────────────────────┐
                             │        AWS Environment        │
                             └───────────────┬───────────────┘
                                             │
            CloudTrail IAM Events            │   Scheduled Audit Sweep (Cron)
      (CreatePolicy, AttachRolePolicy, etc.) │   (Daily / Hourly Trigger)
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
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Drift Detector  │   │ PrivEsc Detector │   │ Credential Audit │
│  - YAML Baseline │   │ - 14+ Attack     │   │ - Inactive Keys  │
│  - Shadow Roles  │   │   Signatures     │   │ - Root Activity  │
│  - Boundary Gaps │   │ - Wildcards (*)  │   │ - MFA Checks     │
└────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘
         │                      │                      │
         └──────────────────────┼──────────────────────┘
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
   │ - Real-Time Alerts    │           │ - Executive HTML      │
   │ - Email / Slack Hooks │           │ - Auditor CSV / JSON  │
   │ - P1/P2 Escalations   │           │ - S3 Evidence Archive │
   └───────────────────────┘           └───────────────────────┘
```

### Module Breakdown
- **`src/collectors/iam_collector.py`**: Interacts with AWS IAM via `boto3` paginators to fetch roles, users, managed policies, inline policy documents, and permissions boundaries. Supports offline JSON ingestion for local testing.
- **`src/collectors/credential_report.py`**: Requests and parses the AWS IAM Credential Report, identifying unrotated access keys (>90 days), dormant keys, console access lacking MFA, and root account activity.
- **`src/evaluators/drift_detector.py`**: Compares active cloud configurations against `baseline/sample_baseline.yaml`. Flags shadow assets, unapproved policies, unapproved inline policies, and missing/mismatched permissions boundaries.
- **`src/evaluators/policy_analyzer.py`**: Parses policy statements for administrative wildcards (`Action: "*"` / `Resource: "*"`), broad sensitive service permissions (`iam:*`, `s3:*`, `kms:*`), and explicitly banned API calls.
- **`src/evaluators/privesc_detector.py`**: Matches effective permissions against `baseline/privesc_rules.json` to detect multi-step privilege escalation vectors.
- **`src/scoring/anomaly_engine.py`**: Calculates finding-level risk scores, applies compound multipliers for resources with multiple violations, assigns priority tiers (`P1` to `P4`), and computes the account-wide Posture Score.
- **`src/notifiers/sns_dispatcher.py`**: Dispatches structured, human-readable notifications to Amazon SNS for any `P1 - IMMEDIATE` or `P2 - HIGH` finding.
- **`src/reporting/report_generator.py`**: Uses Jinja2 templating to render an interactive HTML dashboard, auditor-ready CSV spreadsheet, and raw JSON dump.

---

## 5. Step-by-Step Usage & Execution Methods

### Method 1: Interactive 1-Click Runner (Windows PowerShell / CMD)
The fastest way to test and demonstrate the engine without remembering command-line flags.

1. Open PowerShell in the project directory:
   ```powershell
   .\run.ps1
   ```
   *(Or double-click `run.bat` in Windows File Explorer)*

2. Select an option from the menu:
   - **`[1]`**: Runs a full audit scan in offline mock mode, calculates posture score, and automatically opens the interactive HTML report in your default browser.
   - **`[2]`**: Simulates an unauthorized CloudTrail mutation event and displays the instant P1 security alert.
   - **`[3]`**: Executes the automated `pytest` suite.
   - **`[4]`**: Runs a live audit scan against an active AWS account (if credentials are configured).
   - **`[5]`**: Exit.

---

### Method 2: Command-Line Interface (Local Mock Mode)
Run a complete compliance scan locally using realistic mock enterprise IAM data without needing an AWS account or incurring any cloud costs.

```powershell
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

**Viewing the Generated Evidence:**
- **HTML Dashboard**: `Start-Process reports\latest_audit_report.html`
- **CSV Spreadsheet**: Open `reports\iam_audit_*.csv` in Excel
- **JSON Evidence**: Open `reports\iam_audit_*.json` in VS Code

---

### Method 3: Real-Time CloudTrail Security Mutation Simulation
Simulate how the engine reacts when an unauthorized administrator attaches `AdministratorAccess` out-of-band to a backend service role (`AppBackendServiceRole`):

```powershell
python src/main.py --simulate-event tests/mock_events/cloudtrail_attach_admin_policy.json
```

**What Happens Behind the Scenes:**
1. The event payload is ingested mimicking an Amazon EventBridge trigger.
2. The engine parses `eventName: AttachRolePolicy`, the acting user `contractor-temp-admin`, and target policy `AdministratorAccess`.
3. Drift analysis flags that `AdministratorAccess` is not in `sample_baseline.yaml`.
4. The anomaly engine compounds the score to **100/100 (P1 - IMMEDIATE)**.
5. The SNS dispatcher triggers an instant alert containing the exact violation and remediation advice:

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

---

### Method 4: Automated Unit & Rule Verification
Verify that detection rules, wildcard parsers, and scoring math operate correctly:

```powershell
pytest -v
```

All 8 tests validate:
- Unapproved shadow role detection
- Policy drift & missing permissions boundary detection
- Single-permission and multi-permission privilege escalation matching
- Compound risk boost calculations

---

### Method 5: Live AWS Account Audit Scan
If you have active AWS credentials (`~/.aws/credentials` or environment variables):

1. Confirm AWS connectivity:
   ```powershell
   aws sts get-caller-identity
   ```

2. Run the audit against your live AWS account:
   ```powershell
   python src/main.py --live
   ```

The collector connects to AWS IAM via `boto3`, pulls live roles, users, and customer-managed policies, and generates an audit report for your real cloud environment.

---

### Method 6: Continuous 24/7 Cloud Deployment via Terraform
Deploy the serverless architecture into AWS so it monitors IAM mutations continuously in real time.

1. Navigate to the Terraform directory:
   ```powershell
   cd terraform
   ```

2. Copy the example variables file:
   ```powershell
   cp terraform.tfvars.example terraform.tfvars
   ```

3. Edit `terraform.tfvars` with your email address for SNS alerts:
   ```hcl
   aws_region   = "us-east-1"
   project_name = "iam-governance-engine"
   alert_email  = "your-security-team@example.com"
   ```

4. Initialize and deploy:
   ```powershell
   terraform init
   terraform plan
   terraform apply
   ```

**What Gets Created in AWS:**
- **Lambda Function (`iam-governance-engine`)**: Houses the governance engine.
- **EventBridge Rule 1 (Real-Time)**: Intercepts IAM mutations (`CreatePolicy`, `AttachRolePolicy`, `PutRolePolicy`, `CreateAccessKey`, etc.) via CloudTrail and immediately triggers Lambda.
- **EventBridge Rule 2 (Scheduled)**: Daily cron trigger (`cron(0 6 * * ? *)`) running full-account posture audits.
- **Amazon SNS Topic & Email Subscription**: Delivers instant alerts for P1/P2 findings.
- **Amazon S3 Bucket**: Secure, encrypted bucket (`AES256`, public access blocked) for compliance report archiving.
- **IAM Execution Role**: Strictly scoped least-privilege audit role.

To tear down all resources later:
```powershell
terraform destroy
```

---

## 6. How to Customize Guardrails & Baselines

### Customizing the Security Baseline (`baseline/sample_baseline.yaml`)
To approve new roles, users, or guardrails, update `baseline/sample_baseline.yaml`:

```yaml
global_guardrails:
  max_access_key_age_days: 90
  max_inactive_key_days: 90
  enforce_mfa_for_console_access: true
  banned_actions:
    - "iam:DeactivateMFADevice"
    - "cloudtrail:StopLogging"
    - "kms:ScheduleKeyDeletion"

approved_roles:
  - role_name: "MyNewMicroserviceRole"
    description: "Production payment processing role"
    allowed_attached_policies:
      - "arn:aws:iam::123456789012:policy/PaymentMicroservicePolicy"
    allow_inline_policies: false
    permissions_boundary_required: true
    permissions_boundary: "arn:aws:iam::123456789012:policy/StandardPermissionsBoundary"
```

### Adding New Privilege Escalation Rules (`baseline/privesc_rules.json`)
The engine dynamically ingests signatures from `baseline/privesc_rules.json`. You can add new attack vectors without changing any Python code:

```json
{
  "id": "PRIVESC-15",
  "name": "Custom PrivEsc Vector",
  "severity": "HIGH",
  "risk_score": 85,
  "description": "User can pass role to a custom compute service.",
  "required_permissions": [
    "iam:PassRole",
    "customservice:ExecuteAction"
  ],
  "mitigation": "Constrain iam:PassRole with resource-level conditions."
}
```

---

## 7. Anomaly-Scoring & Risk Prioritization Methodology

To eliminate alert fatigue, the engine applies a **Compound Risk Multiplier**:

$$\text{Final Score} = \min\left(100, \text{Base Risk} \times \left(1 + 0.15 \times \min(N - 1, 5)\right)\right)$$

Where:
- $\text{Base Risk}$: Baseline severity of the violation (e.g. 100 for Root Access Keys, 95 for `iam:CreatePolicyVersion`, 85 for `iam:PassRole` + `ec2:RunInstances`).
- $N$: Number of simultaneous security violations discovered on the same IAM entity. An entity with multiple minor issues is elevated in urgency because compound weaknesses represent higher exploitability.

### Priority Tier Classification
- 🚨 **`P1 - IMMEDIATE`** (Score $\ge 90$ or Critical): Full admin wildcards (`*`), root access keys, or active privilege escalation vectors. Triggers immediate SNS alert.
- ⚠️ **`P2 - HIGH`** (Score $75 - 89$ or High): Unapproved shadow roles, policy drift, or missing permissions boundaries. Triggers immediate SNS alert.
- 🟡 **`P3 - MEDIUM`** (Score $50 - 74$): Access keys $>90$ days old, dormant keys, or unscoped write permissions. Included in daily reports.
- ℹ️ **`P4 - LOW`** (Score $< 50$): Advisory notes and minor documentation variances.

---

## 8. Interview Talk Track & Portfolio Presentation

When discussing this project in a Cloud Security, DevSecOps, or Systems Engineering interview:

> *"In my AWS projects, I observed that IAM policy drift and accidental privilege escalation are among the most common causes of cloud breaches. Standard tools like AWS IAM Access Advisor only report what has been used, but don't prevent drift or detect complex multi-action privilege escalation attack paths.*
> 
> *To solve this, I engineered an Automated IAM Governance & Configuration Drift Detection platform. I implemented a declarative GitOps baseline in YAML to define approved roles, allowed policies, and required permissions boundaries.*
> 
> *I built an evaluator in Python that checks for configuration drift, wildcard permissions, and 14+ known privilege escalation vectors—like `iam:PassRole` paired with compute deployment APIs. To address alert fatigue, I designed an anomaly-scoring workflow that calculates compound risk scores and maps them into actionable priority tiers.*
> 
> *Finally, I deployed the solution using Terraform as an event-driven architecture using Amazon EventBridge and AWS Lambda to intercept CloudTrail mutations in real time, alerting via Amazon SNS and archiving compliance reports in S3 for SOC 2 and ISO 27001 readiness."*

---

## 📄 License
This project is open-source and distributed under the **MIT License**.
