# Automated IAM Governance & Drift Detection Engine - Runner Script
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host " 🚀 Automated IAM Governance & Configuration Drift Detection Engine" -ForegroundColor Yellow
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Select an option to execute:"
Write-Host " [1] Run Full Audit Scan (Offline Mock Mode) + Open HTML Dashboard" -ForegroundColor Green
Write-Host " [2] Simulate Real-Time CloudTrail Security Mutation Event" -ForegroundColor Magenta
Write-Host " [3] Run Automated Unit Tests (pytest)" -ForegroundColor Cyan
Write-Host " [4] Run Live Audit Scan against Real AWS Account (requires credentials)" -ForegroundColor Yellow
Write-Host " [5] Exit"
Write-Host "------------------------------------------------------------------------"

$choice = Read-Host "Enter option [1-5]"

switch ($choice) {
    "1" {
        Write-Host "`n[*] Executing full IAM drift and least-privilege audit..." -ForegroundColor Cyan
        python src/main.py
        if ($LASTEXITCODE -eq 0 -and (Test-Path "reports\latest_audit_report.html")) {
            Write-Host "`n[*] Opening interactive HTML dashboard in default browser..." -ForegroundColor Green
            Start-Process "reports\latest_audit_report.html"
        }
    }
    "2" {
        Write-Host "`n[*] Simulating unauthorized CloudTrail AttachRolePolicy mutation..." -ForegroundColor Magenta
        python src/main.py --simulate-event tests/mock_events/cloudtrail_attach_admin_policy.json
    }
    "3" {
        Write-Host "`n[*] Executing unit test suite..." -ForegroundColor Cyan
        pytest -v
    }
    "4" {
        Write-Host "`n[*] Connecting to live AWS account via boto3..." -ForegroundColor Yellow
        python src/main.py --live
    }
    "5" {
        Write-Host "Exiting."
        exit 0
    }
    Default {
        Write-Host "Invalid option. Exiting."
    }
}
