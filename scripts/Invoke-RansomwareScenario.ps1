param(
    [string]$ApiBase = $(if ($env:API_BASE) { $env:API_BASE } else { "http://localhost:8080" }),
    [string]$Username = $(if ($env:DEMO_USER) { $env:DEMO_USER } else { "admin" }),
    [string]$Password = $(if ($env:DEMO_PASS) { $env:DEMO_PASS } else { "admin123" })
)

. (Join-Path $PSScriptRoot "_demo_common.ps1")

Write-ScenarioStep "Logging in to gateway"
$token = Get-DemoAccessToken -ApiBase $ApiBase -Username $Username -Password $Password
$headers = New-DemoHeaders -Token $token

Write-ScenarioStep "Injecting pre-ransomware lateral movement"
$lateral = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/threats/analyze/network" -Headers $headers -Body @{
    src_ip = "10.0.5.81"
    dst_ip = "10.0.5.18"
    dst_port = 445
    protocol = "TCP"
    bytes_sent = 860000
    bytes_recv = 18000
    duration_ms = 91000
    user_agent = "ransomware-loader"
    payload_entropy = 7.3
    timestamp = (Get-Date).ToString("o")
}

Write-ScenarioStep "Injecting large outbound exfiltration burst"
$exfil = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/threats/analyze/network" -Headers $headers -Body @{
    src_ip = "10.0.5.18"
    dst_ip = "104.244.76.13"
    dst_port = 443
    protocol = "TCP"
    bytes_sent = 16000000
    bytes_recv = 240000
    duration_ms = 120000
    user_agent = "backup-sync"
    payload_entropy = 6.9
    timestamp = (Get-Date).AddSeconds(2).ToString("o")
}

Write-ScenarioStep "Creating ransomware incident"
$incident = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/soar/incidents" -Headers $headers -Body @{
    alert_type = "ransomware_detected"
    severity = "critical"
    source_ip = "185.220.101.77"
    host = "fin-srv-03"
    description = "Synthetic ransomware scenario for the finance server cluster"
}

$resolved = Wait-ForIncidentState -ApiBase $ApiBase -Headers $headers -IncidentId $incident.id
$audit = Invoke-DemoJson -Method Get -Uri "$ApiBase/api/v1/soar/audit/incidents/$($incident.id)" -Headers $headers

Write-Host ""
Write-Host "Ransomware scenario created." -ForegroundColor Green
Write-Host "Lateral severity: $($lateral.severity)"
Write-Host "Exfil severity: $($exfil.severity)"
Write-Host "Incident ID: $($incident.id)"
Write-Host "Incident status: $($resolved.status)"
Write-Host "Playbook: $($resolved.playbook_run.playbook_name)"
Write-Host "Audit entries: $($audit.total)"
