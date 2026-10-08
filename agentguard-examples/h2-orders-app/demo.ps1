param([string]$BaseUrl = 'http://localhost:8080')
$ErrorActionPreference = 'Stop'

function Connect-DemoUser([string]$Username) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:demo-pass"))
    $headers = @{ Authorization = "Basic $encoded" }
    $sessionInfo = Invoke-RestMethod "$BaseUrl/api/session" -Headers $headers -SessionVariable cookies
    $headers[$sessionInfo.csrfHeader] = $sessionInfo.csrfToken
    return @{ Headers = $headers; WebSession = $cookies }
}

function Invoke-DemoApi($Client, [string]$Method, [string]$Path, [int]$ExpectedStatus, $Body) {
    $arguments = @{
        Uri = "$BaseUrl/api$Path"; Method = $Method; Headers = $Client.Headers
        WebSession = $Client.WebSession; UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $arguments.ContentType = 'application/json'
        $arguments.Body = ($Body | ConvertTo-Json -Depth 10)
    }
    try {
        $response = Invoke-WebRequest @arguments
        $status = [int]$response.StatusCode
        $content = $response.Content
    } catch {
        if (-not $_.Exception.Response) { throw }
        $status = [int]$_.Exception.Response.StatusCode
        $content = $_.ErrorDetails.Message
    }
    if ($status -ne $ExpectedStatus) { throw "$Method $Path expected $ExpectedStatus, got ${status}: $content" }
    Write-Host "PASS $Method $Path -> $status"
    if ($content) { return $content | ConvertFrom-Json }
}

$developer = Connect-DemoUser 'developer'
$operator = Connect-DemoUser 'operator'
$approver = Connect-DemoUser 'approver'

$null = Invoke-DemoApi $developer GET '/databases/orders-dev/orders' 200
$null = Invoke-DemoApi $developer GET '/databases/orders-prod/orders' 403
$payload = @{
    product = 'Script-created plan'; amount = 39.50; customerEmail = 'script@example.test'
    password = 'script-top-secret'; internalNote = 'script-private-note'
    integration = @{ api_key = 'script-nested-secret'; region = 'local' }
    attempts = @(@{ token = 'script-list-secret'; result = 'ok' })
}
$created = Invoke-DemoApi $developer POST '/databases/orders-dev/orders' 201 $payload
$null = Invoke-DemoApi $developer POST "/orders/$($created.id)/refund" 200
$production = Invoke-DemoApi $operator POST '/databases/orders-prod/orders' 201 @{
    product = 'Approval workflow plan'; amount = 149; customerEmail = 'approval@example.test'
}
$null = Invoke-DemoApi $operator DELETE "/orders/$($production.id)" 403
$pending = Invoke-DemoApi $operator POST "/orders/$($production.id)/refund" 202
$null = Invoke-DemoApi $operator POST "/approvals/$($pending.approvalId)/approve" 403
$null = Invoke-DemoApi $approver POST "/approvals/$($pending.approvalId)/approve" 200
$null = Invoke-DemoApi $approver POST "/approvals/$($pending.approvalId)/approve" 409
$null = Invoke-DemoApi $developer POST '/policy-preview' 200
$audit = Invoke-DemoApi $developer GET '/audit' 200
$auditJson = $audit | ConvertTo-Json -Depth 30
foreach ($secret in @('script-top-secret', 'script-private-note', 'script-nested-secret', 'script-list-secret', 'script@example.test')) {
    if ($auditJson.Contains($secret)) { throw "Unsanitized value found in audit response: $secret" }
}
if (-not $auditJson.Contains('[HIDDEN]')) { throw 'Expected sanitized fields in audit output' }
Write-Host "PASS recursive audit redaction; $($audit.sqlCount) events in H2. Open the dashboard to inspect them."
