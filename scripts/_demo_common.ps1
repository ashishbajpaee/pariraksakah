Set-StrictMode -Version Latest

function Write-ScenarioStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[demo] $Message" -ForegroundColor Cyan
}

function Get-DemoAccessToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiBase,
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $payload = @{
        username = $Username
        password = $Password
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Method Post `
        -Uri "$ApiBase/api/v1/auth/login" `
        -ContentType "application/json" `
        -Body $payload `
        -ErrorAction Stop

    if (-not $response.access_token) {
        throw "Login succeeded but access_token was missing."
    }

    return [string]$response.access_token
}

function New-DemoHeaders {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    return @{
        Authorization = "Bearer $Token"
        "Content-Type" = "application/json"
    }
}

function Invoke-DemoJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter()]
        [object]$Body
    )

    $invokeParams = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = $Headers
        ErrorAction = "Stop"
    }

    if ($PSBoundParameters.ContainsKey("Body")) {
        $invokeParams["Body"] = $Body | ConvertTo-Json -Depth 12
    }

    return Invoke-RestMethod @invokeParams
}

function Wait-ForIncidentState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiBase,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $true)]
        [string]$IncidentId,
        [int]$TimeoutSec = 20
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        $incident = Invoke-DemoJson -Method Get -Uri "$ApiBase/api/v1/soar/incidents/$IncidentId" -Headers $Headers
        $playbookRun = $null
        if ($incident -and $incident.PSObject.Properties.Name -contains "playbook_run") {
            $playbookRun = $incident.playbook_run
        }
        if (
            $playbookRun -and
            $playbookRun.status -and
            $playbookRun.status -ne "running"
        ) {
            return $incident
        }
        Start-Sleep -Milliseconds 800
    } while ((Get-Date) -lt $deadline)

    return $incident
}
