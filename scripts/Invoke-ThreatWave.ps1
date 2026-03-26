param(
    [string]$ApiBase = $(if ($env:API_BASE) { $env:API_BASE } else { "http://localhost:8080" }),
    [string]$Username = $(if ($env:DEMO_USER) { $env:DEMO_USER } else { "admin" }),
    [string]$Password = $(if ($env:DEMO_PASS) { $env:DEMO_PASS } else { "admin123" })
)

. (Join-Path $PSScriptRoot "_demo_common.ps1")

Write-ScenarioStep "Logging in to gateway"
$token = Get-DemoAccessToken -ApiBase $ApiBase -Username $Username -Password $Password
$headers = New-DemoHeaders -Token $token

$attackerIp = "185.220.101.34"
$targetIp = "10.0.5.42"
$ports = 21..45
$events = @()

foreach ($port in $ports) {
    $events += @{
        src_ip = $attackerIp
        dst_ip = $targetIp
        dst_port = $port
        protocol = "TCP"
        bytes_sent = 260000
        bytes_recv = 1200
        duration_ms = 350
        user_agent = "threat-wave-probe"
        payload_entropy = 6.7
        timestamp = (Get-Date).ToString("o")
    }
}

Write-ScenarioStep "Injecting batch network telemetry"
$batch = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/threats/analyze/batch" -Headers $headers -Body @{
    events = $events
}

Write-ScenarioStep "Injecting UEBA lateral movement signal"
$ueba = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/threats/analyze/ueba" -Headers $headers -Body @{
    user_id = "svc-finance-sync"
    action = "lateral_move"
    resource = "\\finance-fs-02\shares"
    source_ip = "10.0.5.19"
    hour_of_day = 2
    day_of_week = 6
    failed_attempts = 6
}

$recent = Invoke-DemoJson -Method Get -Uri "$ApiBase/api/v1/threats/recent?limit=5" -Headers $headers

Write-Host ""
Write-Host "Threat wave injected." -ForegroundColor Green
Write-Host "Batch events: $($events.Count)"
Write-Host "Threats found in batch: $($batch.threats_found)"
Write-Host "UEBA anomalous: $($ueba.is_anomalous) (risk=$($ueba.risk_score))"
Write-Host "Recent threat count: $($recent.total)"
