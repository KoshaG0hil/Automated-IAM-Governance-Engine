@echo off
chcp 65001 > nul
cls
echo ========================================================================
echo  Automated IAM Governance ^& Configuration Drift Detection Engine
echo ========================================================================
echo Select an option to execute:
echo  [1] Run Full Audit Scan (Offline Mock Mode) + Open HTML Dashboard
echo  [2] Simulate Real-Time CloudTrail Security Mutation Event
echo  [3] Run Automated Unit Tests (pytest)
echo  [4] Run Live Audit Scan against Real AWS Account (requires credentials)
echo  [5] Exit
echo ------------------------------------------------------------------------

set /p choice="Enter option [1-5]: "

if "%choice%"=="1" (
    echo.
    echo [*] Executing full IAM drift and least-privilege audit...
    python src\main.py
    if exist reports\latest_audit_report.html (
        echo [*] Opening HTML report...
        start reports\latest_audit_report.html
    )
    goto end
)
if "%choice%"=="2" (
    echo.
    echo [*] Simulating CloudTrail mutation event...
    python src\main.py --simulate-event tests\mock_events\cloudtrail_attach_admin_policy.json
    goto end
)
if "%choice%"=="3" (
    echo.
    echo [*] Running pytest...
    pytest -v
    goto end
)
if "%choice%"=="4" (
    echo.
    echo [*] Running live AWS scan...
    python src\main.py --live
    goto end
)
if "%choice%"=="5" (
    goto end
)

:end
pause
