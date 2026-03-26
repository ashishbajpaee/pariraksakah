param(
    [string]$ApiBase = $(if ($env:API_BASE) { $env:API_BASE } else { "http://localhost:8080" }),
    [string]$Username = $(if ($env:DEMO_USER) { $env:DEMO_USER } else { "admin" }),
    [string]$Password = $(if ($env:DEMO_PASS) { $env:DEMO_PASS } else { "admin123" })
)

. (Join-Path $PSScriptRoot "_demo_common.ps1")

Write-ScenarioStep "Logging in to gateway"
$token = Get-DemoAccessToken -ApiBase $ApiBase -Username $Username -Password $Password
$headers = New-DemoHeaders -Token $token

$phishingLink = "https://paypa1-secure-approval.invalid/auth/review?ticket=wire-8841"

Write-ScenarioStep "Analyzing phishing email"
$email = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/phishing/analyze/email" -Headers $headers -Body @{
    sender = "finance-ops@fastpay-secure.com"
    subject = "Urgent payment remediation"
    text = "Urgent: wire transfer needed before audit close. Review the secure document and confirm immediately using the anonymous approval link."
}

Write-ScenarioStep "Analyzing phishing URL"
$url = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/phishing/analyze/url" -Headers $headers -Body @{
    url = $phishingLink
}

Write-ScenarioStep "Scoring social-engineering exposure"
$psychographic = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/phishing/analyze/psychographic" -Headers $headers -Body @{
    user_id = "fin-ops-17"
    display_name = "Asha Raman"
    department = "Finance"
    role = "Payments Approver"
    seniority_level = 4
    financial_authority = $true
    public_exposure_score = 0.74
    email_open_rate = 0.81
    phishing_sim_fail_rate = 0.22
    past_incidents = 1
    access_level = 4
    travel_frequency = 0.35
    work_hours_variance = 0.41
    social_connections = 18
}

$incidentId = $null
if ($email.is_threat -or $url.is_malicious) {
    Write-ScenarioStep "Escalating phishing finding into incident response"
    $incident = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/soar/incidents" -Headers $headers -Body @{
        alert_type = "phishing_confirmed"
        severity = "high"
        source_ip = "198.51.100.24"
        host = "mail-gateway-01"
        description = "Synthetic anonymous phishing link delivered to finance approver"
    }
    $incidentId = $incident.id
}

Write-Host ""
Write-Host "Anonymous phishing link prepared." -ForegroundColor Green
Write-Host "Link: $phishingLink"
Write-Host "Email verdict: $($email.label) ($($email.confidence))"
Write-Host "URL malicious: $($url.is_malicious) (risk=$($url.risk_score))"
Write-Host "Psychographic tier: $($psychographic.risk_tier)"
if ($incidentId) {
    Write-Host "Escalated incident: $incidentId"
}
