[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidOverwritingBuiltInCmdlets',
    '',
    Justification = 'The isolated test process shadows system commands to provide deterministic preflight fixtures.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPositionalParameters',
    '',
    Justification = 'Positional arguments keep the small assertion DSL readable in this test-only script.'
)]
param()

$ErrorActionPreference = 'Stop'

function Assert-Equal {
    param($Expected, $Actual, [string]$Because)
    if ($Expected -ne $Actual) {
        throw "$Because Expected '$Expected', received '$Actual'."
    }
}

function Assert-Match {
    param([string]$Pattern, [string]$Actual, [string]$Because)
    if ($Actual -notmatch $Pattern) {
        throw "$Because '$Actual' does not match '$Pattern'."
    }
}

$installerPath = Join-Path $PSScriptRoot '..\install.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $installerPath),
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "install.ps1 has $($parseErrors.Count) parse error(s)."
}

$functionsToTest = @(
    'Get-ConfigFile',
    'Test-WebConnection',
    'Test-InternetConnectivity',
    'Test-HttpsUrl',
    'Test-ExecutionPolicy',
    'Test-WindowsVersion',
    'Test-TestedOS',
    'Test-VM',
    'Test-SpaceUserName'
)
foreach ($functionName in $functionsToTest) {
    $functionAst = $ast.Find(
        { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName },
        $true
    )
    if (-not $functionAst) {
        throw "Required installer function '$functionName' was not found."
    }
    Invoke-Expression $functionAst.Extent.Text
}

# Stubs are resolved dynamically by the extracted installer functions. This process is dedicated
# to tests, so replacing these commands cannot affect a real installation session.
function Get-ExecutionPolicy { return $script:executionPolicy }
function Get-CimInstance { return $script:cimResult }
function Invoke-WebRequest {
    if ($script:webFailure) { throw 'simulated HTTPS failure' }
    return [pscustomobject]@{ StatusCode = $script:webStatusCode }
}
function Test-Connection { return $script:pingResult }

$script:executionPolicy = 'Unrestricted'
Assert-Equal $null (Test-ExecutionPolicy) 'Unrestricted execution policy should pass.'
$script:executionPolicy = 'Bypass'
Assert-Equal $null (Test-ExecutionPolicy) 'Process-scoped Bypass execution policy should pass.'
$script:executionPolicy = 'Restricted'
Assert-Match 'enable script execution' (Test-ExecutionPolicy) 'Restricted execution policy should fail.'

$script:cimResult = [pscustomobject]@{ Version = '10.0.26100'; BuildNumber = '26100'; Model = 'VirtualBox' }
Assert-Equal $null (Test-WindowsVersion) 'Windows 11 should pass the minimum-version check.'
Assert-Equal $null (Test-TestedOS) 'A listed Windows build should pass the tested-build check.'
Assert-Equal $null (Test-VM) 'A recognized virtual machine model should pass.'

$script:cimResult = [pscustomobject]@{ Version = '6.1.7601'; BuildNumber = '7601'; Model = 'Physical workstation' }
Assert-Match 'Only Windows' (Test-WindowsVersion) 'Windows 7 should fail the minimum-version check.'
Assert-Match 'has not been tested' (Test-TestedOS) 'An unlisted Windows build should be reported.'
Assert-Match 'not on a VM' (Test-VM) 'A physical model should fail VM detection.'

$script:cimResult = [pscustomobject]@{ Version = 'unknown'; BuildNumber = 'unknown'; Model = 'VirtualBox' }
Assert-Match 'Unable to determine Windows Version' (Test-WindowsVersion) 'A malformed OS version should fail safely.'
Assert-Match 'may not have been tested' (Test-TestedOS) 'A malformed build number should fail safely.'

$originalUserName = $env:UserName
try {
    $env:UserName = 'flare analyst'
    Assert-Match 'contains a space' (Test-SpaceUserName) 'A username containing spaces should fail.'
    $env:UserName = 'flare'
    Assert-Equal $null (Test-SpaceUserName) 'A simple username should pass.'
} finally {
    $env:UserName = $originalUserName
}

$script:webFailure = $false
$script:webStatusCode = 200
$script:pingResult = $false
Assert-Equal $null (Test-WebConnection 'example.invalid') 'Successful HTTPS should be authoritative when ping fails.'

$script:webFailure = $true
$script:pingResult = $false
Assert-Match 'ping.*also failed' (Test-WebConnection 'example.invalid') 'A total network failure should include ping context.'

# Replace the single-host probe to verify the orchestration helper's order and fail-fast behavior.
$script:probedHosts = @()
$script:failedHost = $null
function Test-WebConnection {
    param([string]$url)
    $script:probedHosts += $url
    if ($url -eq $script:failedHost) { return "failed: $url" }
}
$script:failedHost = 'github.com'
Assert-Equal 'failed: github.com' (Test-InternetConnectivity) 'Connectivity should return the first endpoint failure.'
Assert-Equal 'google.com,github.com' ($script:probedHosts -join ',') 'Connectivity should stop after the first failure.'
$script:probedHosts = @()
$script:failedHost = $null
Assert-Equal $null (Test-InternetConnectivity) 'Connectivity should pass when every endpoint passes.'
Assert-Equal 'google.com,github.com,raw.githubusercontent.com' ($script:probedHosts -join ',') 'Connectivity should probe every required endpoint in order.'

Assert-Equal $true (Test-HttpsUrl 'https://example.com/project') 'HTTPS project URLs should be accepted.'
Assert-Equal $false (Test-HttpsUrl 'http://example.com/project') 'HTTP project URLs should be rejected.'
Assert-Equal $false (Test-HttpsUrl 'file:///C:/Windows/System32/calc.exe') 'Local file URLs should be rejected.'
Assert-Equal $false (Test-HttpsUrl 'not-a-url') 'Malformed project URLs should be rejected.'

$configTestDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "flare-vm-config-test-$([Guid]::NewGuid().ToString('N'))"
try {
    New-Item -Path $configTestDirectory -ItemType Directory | Out-Null
    $sourceConfig = Join-Path $configTestDirectory 'source.xml'
    $copiedConfig = Join-Path $configTestDirectory 'copied.xml'
    Set-Content -LiteralPath $sourceConfig -Value '<config />'
    Get-ConfigFile -fileDestination $copiedConfig -fileSource $sourceConfig
    Assert-Equal $true (Test-Path -LiteralPath $sourceConfig) 'Using a local config must preserve the source file.'
    Assert-Equal '<config />' (Get-Content -LiteralPath $copiedConfig -Raw).Trim() 'The local config should be copied intact.'
    Get-ConfigFile -fileDestination $sourceConfig -fileSource $sourceConfig
    Assert-Equal '<config />' (Get-Content -LiteralPath $sourceConfig -Raw).Trim() 'Using the destination itself should be a no-op.'
} finally {
    if (Test-Path -LiteralPath $configTestDirectory) {
        Remove-Item -LiteralPath $configTestDirectory -Recurse -Force
    }
}

[xml]$config = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\config.xml') -Raw
if (-not $config.config.apps -or -not $config.config.'path-items') {
    throw 'config.xml is missing required apps or path-items sections.'
}

$installerText = Get-Content -LiteralPath $installerPath -Raw
if ($installerText -notmatch '(?s)\$error_info = Test-VM\s+if \(\$error_info\)\{\s+\$RunningVMTooltip\.Text = \$error_info') {
    throw 'The GUI VM check is not mapped to the VM tooltip.'
}

Write-Host 'Installer preflight tests: PASS'
