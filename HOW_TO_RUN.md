# How to Run the Automated IAM Governance Engine

This guide walks you step-by-step through running, testing, and deploying the **Automated IAM Governance & Configuration Drift Detection Engine**.

---

## 📋 Prerequisites

Before running, ensure you have:
- **Python 3.10+** (Tested on Python 3.12 & 3.13)
- **Git**
- *(Optional for live AWS)*: AWS CLI configured with `aws configure` and Terraform v1.5+

---

## ⚡ Option 1: Quick 1-Click Run (Windows PowerShell)

We provide a convenient helper script:

```powershell
.\run.ps1
```

Or on Windows Command Prompt:
```cmd
run.bat
```

This presents an interactive menu to run scans, view reports, simulate events, or run tests with a single keystroke.

---

## 🛠️ Option 2: Step-by-Step Manual Execution

### Step 1: Clone Repository & Enter Directory
```bash
git clone https://github.com/KoshaG0hil/Automated-IAM-Governance-Engine.git
cd Automated-IAM-Governance-Engine
```

### Step 2: (Recommended) Create a Virtual Environment
```bash
# On Windows
python -m venv venv
.\venv\Scripts\activate

# On macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Full Governance & Drift Audit Scan
Run a complete compliance scan using the realistic mock IAM environment (no AWS account or credentials needed):

```bash
python src/main.py
```

**What this does:**
1. Loads the declarative least-privilege security baseline (`baseline/sample_baseline.yaml`).
2. Evaluates roles, users, and policies against 14+ privilege escalation signatures (`baseline/privesc_rules.json`).
3. Audits credential rotation age, dormant access keys, and console MFA.
4. Computes composite risk scores and the overall Account Security Posture score.
5. Prints the executive summary in the terminal.
6. Generates interactive HTML, CSV, and JSON audit files in the `reports/` folder.

### Step 5: View the Generated Interactive HTML Dashboard
Open the audit dashboard in your web browser:

```powershell
# On Windows
Start-Process reports\latest_audit_report.html

# On macOS
open reports/latest_audit_report.html

# On Linux
xdg-open reports/latest_audit_report.html
```

---

## 🚨 Option 3: Simulate a Real-Time CloudTrail Security Mutation

Simulate what happens when an unauthorized user (`contractor-temp-admin`) attaches `AdministratorAccess` out-of-band to a production role:

```bash
python src/main.py --simulate-event tests/mock_events/cloudtrail_attach_admin_policy.json
```

**Output:**
- The engine intercepts the `AttachRolePolicy` event.
- Flags a **P1 - IMMEDIATE** Critical alert (Risk Score: 100/100).
- Triggers a simulated SNS alert with complete violation details and remediation instructions.

---

## 🧪 Option 4: Run the Automated Unit Test Suite

Run all automated unit tests covering drift detection, privesc signatures, and anomaly scoring:

```bash
pytest -v
```

All 8 tests should pass in under 0.5s.

---

## ☁️ Option 5: Audit Your Own Live AWS Account (User Quickstart)

To audit your company's or your personal AWS account:

> **🔒 Non-Destructive Guarantee**: The live scan is **100% read-only**. It requires only standard read-only IAM permissions (`SecurityAudit` or `ViewOnlyAccess`) to inspect configurations via `boto3`. It will **never** modify, detach, or delete any of your cloud resources.

### 1. Authenticate with AWS
```bash
aws configure
# Verify target account connection
aws sts get-caller-identity
```

### 2. (Optional) Customize Your Baseline
Update `baseline/sample_baseline.yaml` to specify which roles and permissions boundaries are approved in your company. If left as default, the engine will still audit your account against CIS benchmarks (wildcards, dormant keys, privilege escalation vectors, MFA).

### 3. Run the Live Audit
```bash
python src/main.py --live
```

### 4. Review Your Results
```powershell
# Open your custom audit dashboard
Start-Process reports\latest_audit_report.html
```
The report presents your real AWS Account ID, posture score, co-located findings (P1 to P4), and exact copy-pasteable remediation steps.

---

## 🚀 Option 6: Deploy 24/7 Serverless Engine via Terraform

To deploy the automated Lambda engine, EventBridge rules, SNS topic, and S3 evidence bucket into AWS:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your alert email
# alert_email = "your-email@example.com"

terraform init
terraform plan
terraform apply
```

To tear down all resources later:
```bash
terraform destroy
```
