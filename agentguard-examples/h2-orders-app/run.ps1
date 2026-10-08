param([string]$JavaHome)
$ErrorActionPreference = 'Stop'
if (-not $JavaHome -and (Test-Path 'C:/Program Files/Java/jdk-21/bin/java.exe')) {
    $JavaHome = 'C:/Program Files/Java/jdk-21'
}
if ($JavaHome) {
    $env:JAVA_HOME = $JavaHome
    $env:PATH = "$JavaHome/bin;$env:PATH"
}
Push-Location $PSScriptRoot
try {
    & mvn -B -ntp verify
    if ($LASTEXITCODE -ne 0) { throw 'Build failed. Check that Maven uses JDK 21 or newer (mvn -version).' }
    Write-Host 'Open http://localhost:8080 - developer / demo-pass. Ctrl+C stops the app.'
    & java -jar target/h2-orders-app-1.0.0-SNAPSHOT.jar --debug=false
} finally {
    Pop-Location
}
