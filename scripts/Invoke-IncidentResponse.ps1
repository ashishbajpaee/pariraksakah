param(
    [string]$ApiBase = $(if ($env:API_BASE) { $env:API_BASE } else { "http://localhost:8080" }),
    [string]$Username = $(if ($env:DEMO_USER) { $env:DEMO_USER } else { "admin" }),
    [string]$Password = $(if ($env:DEMO_PASS) { $env:DEMO_PASS } else { "admin123" })
)

. (Join-Path $PSScriptRoot "_demo_common.ps1")

Write-ScenarioStep "Logging in to gateway"
$token = Get-DemoAccessToken -ApiBase $ApiBase -Username $Username -Password $Password
$headers = New-DemoHeaders -Token $token

Write-ScenarioStep "Creating manual incident"
$incident = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/soar/incidents" -Headers $headers -Body @{
    alert_type = "lateral_movement_detected"
    severity = "medium"
    source_ip = "10.0.5.91"
    host = "eng-ws-22"
    description = "Synthetic incident used to demonstrate manual SOAR execution"
}

Write-ScenarioStep "Triggering playbook execution"
$job = Invoke-DemoJson -Method Post -Uri "$ApiBase/api/v1/soar/incidents/$($incident.id)/execute" -Headers $headers -Body @{}

$resolved = Wait-ForIncidentState -ApiBase $ApiBase -Headers $headers -IncidentId $incident.id
$audit = Invoke-DemoJson -Method Get -Uri "$ApiBase/api/v1/soar/audit/incidents/$($incident.id)" -Headers $headers
$chain = Invoke-DemoJson -Method Get -Uri "$ApiBase/api/v1/soar/audit/chain/verify" -Headers $headers

Write-Host ""
Write-Host "Incident response triggered." -ForegroundColor Green
Write-Host "Incident ID: $($incident.id)"
Write-Host "Job ID: $($job.job_id)"
Write-Host "Incident status: $($resolved.status)"
Write-Host "Playbook: $($resolved.playbook_run.playbook_name)"
Write-Host "Playbook steps: $($resolved.playbook_run.steps.Count)"
Write-Host "Audit entries: $($audit.total)"
Write-Host "Audit chain valid: $($chain.valid)"
