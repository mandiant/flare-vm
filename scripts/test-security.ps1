$ErrorActionPreference = 'Stop'

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

$installerParameterNames = $ast.ParamBlock.Parameters.Name.VariablePath.UserPath
if ('allowEmptyChecksums' -notin $installerParameterNames) {
    throw 'The allowEmptyChecksums compatibility switch is missing.'
}
if ('localPackageSource' -notin $installerParameterNames) {
    throw 'The explicit localPackageSource parameter is missing.'
}
if ('allowWebBootstrap' -notin $installerParameterNames) {
    throw 'The explicit allowWebBootstrap compatibility switch is missing.'
}
if ('passwordFile' -notin $installerParameterNames -or 'removePasswordFile' -notin $installerParameterNames) {
    throw 'The secure password-file parameters are missing.'
}

$saveFunction = $ast.Find(
    { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Save-FileFromUrl' },
    $true
)
if (-not $saveFunction) {
    throw 'Save-FileFromUrl was not found.'
}

# Load only the download helper. Dot-sourcing install.ps1 would execute the installer.
Invoke-Expression $saveFunction.Extent.Text

$destination = Join-Path ([System.IO.Path]::GetTempPath()) "flare-vm-http-test-$([Guid]::NewGuid().ToString('N'))"
try {
    $rejectionMessage = $null
    try {
        Save-FileFromUrl -fileSource 'http://example.invalid/config.xml' -fileDestination $destination 6>&1 | Out-Null
        throw 'The insecure HTTP download was not rejected.'
    } catch {
        $rejectionMessage = $_.Exception.Message
    }
    if (Test-Path -LiteralPath $destination) {
        throw 'An insecure HTTP download created a destination file.'
    }
    if ($rejectionMessage -notmatch 'absolute HTTPS URL') {
        throw 'The HTTP rejection did not report the HTTPS requirement.'
    }
} finally {
    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Force
    }
}

$installerText = Get-Content -LiteralPath $installerPath -Raw
if ($installerText -notmatch '(?s)if \(\$allowEmptyChecksums\.IsPresent\).*?choco feature enable -n allowEmptyChecksums.*?else.*?choco feature disable -n allowEmptyChecksums') {
    throw 'Chocolatey empty-checksum support is not guarded by the compatibility switch.'
}
if ($installerText -notmatch '(?s)if \(\$\{Env:ChocolateyInstall\}.*?choco upgrade boxstarter.*?else.*?bootstrapper\.ps1') {
    throw 'Boxstarter does not prefer the Chocolatey installation path over the mutable web bootstrap.'
}
if ($installerText -notmatch '(?s)if \(-not \$allowWebBootstrap\.IsPresent\).*?throw.*?bootstrapper\.ps1') {
    throw 'The mutable Boxstarter web bootstrap is not guarded by explicit opt-in.'
}
if ($installerText -match 'Set-BoxstarterConfig[^\r\n]*\$desktopPath' -or $installerText -match 'choco source[s]? add[^\r\n]*\$desktopPath') {
    throw 'The Desktop is still trusted as an implicit package source.'
}

$repoRoot = Split-Path -Parent (Resolve-Path $installerPath)
$builderText = Get-Content -LiteralPath (Join-Path $repoRoot 'virtualbox/vbox-build-flare-vm.py') -Raw
if ($builderText -match 'raw\.githubusercontent\.com/.+?/main/install\.ps1') {
    throw 'The VirtualBox builder still downloads a mutable installer from the main branch.'
}
if ($builderText -match '--password=' -or $builderText -match '-password\s+\{?GUEST_PASSWORD') {
    throw 'The VirtualBox builder exposes a guest password in a process command line.'
}

Write-Host 'Supply-chain security checks: PASS'
