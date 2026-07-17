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
    'Test-WebConnection',
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

[xml]$config = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\config.xml') -Raw
if (-not $config.config.apps -or -not $config.config.'path-items') {
    throw 'config.xml is missing required apps or path-items sections.'
}

Write-Host 'Installer preflight tests: PASS'
