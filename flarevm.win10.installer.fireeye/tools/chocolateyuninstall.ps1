$ErrorActionPreference = 'Continue'

$packageName = 'commandovm.win10.installer.fireeye'
$toolsDir    = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Set desktop background to black
set-itemproperty -path 'HKCU:\Control Panel\Colors' -name Background -value "0 0 0"

# Various options
$cache =  "$env:userprofile\AppData\Local\ChocoCache"
$globalCinstArgs = "--cacheLocation $cache"
$pkgPath = Join-Path $toolsDir "packages.json"


function Test-Win64() {
    return [IntPtr]::size -eq 8
}


# https://stackoverflow.com/questions/28077854/powershell-2-0-convertfrom-json-and-convertto-json-implementation
function ConvertFrom-Json([object] $item)
{
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer

    #The comma operator is the array construction operator in PowerShell
    return ,$ps_js.DeserializeObject($item)
}


function LoadPackages
{
    try {
        $json = Get-Content $pkgPath -ErrorAction Stop
        $packages = ConvertFrom-Json $json
    } catch {
        return $null
    }
    return $packages
}


function UninstallOnePackage
{
    param([hashtable] $pkg)
    $name = $pkg.name
    $pkgargs = $pkg.args
    try {
        $is64Only = $pkg.x64Only
    } catch {
        $is64Only = $false
    }

    if ($is64Only) {
        if (Test-WIn64) {
            # pass
        } else {
            Write-Warning "[!] Not uninstalling $name on x86 systems"
            return $true
        }
    }

    if ($pkg.args -eq $null)
    {
        $args = $globalCinstArgs
    } else {
        $args = $pkgsargs,$globalCinstArgs -Join " "
    }

    if ($agrs -like "-source") {
        Write-Warning "[!] Uninstalling using host choco.exe! Errors are not caught. Please check to confirm $name is uninstalled properly"
        Write-Warning "[!] Uninstalling with choco uninstall $name -x -y $args"
        $rc = iex "choco uninstall $name -x -y $args"
    } else {
        $rc = choco uninstall $name $args
    }
    if ($([System.Environment]::ExitCode) -ne 0 -And $([System.Environment]::ExitCode) -ne 3010)
    {
        return $false
    }
    return $true
}


function PostUninstall
{

    # Chocolatey setup
    Write-Host "Initializing chocolatey"

    try {
        Remove-Item $cache -Recurse
    } catch {
        # Ignore exception, in case the directory does not exist.
    }

    Remove-Item ${Env:TOOL_LIST_SHORTCUT}
}


function PreUninstall
{
    try {
        Remove-Item $cache -Recurse
    } catch {
        # Ignore exception, in case the directory does not exist.
    }
}


function Main {
    PreUninstall

    $json = LoadPackages $pkgPath
    Write-Host $json
    if ($json -eq $null -Or $json.packages -eq $null)
    {
        Write-Host "Packages property not found! Exiting"
        return -1
    }

    $packages = $json.packages
    [array]::Reverse($packages)
    foreach ($pkg in $packages)
    {
        $name = $pkg.name
        Write-Host "Uninstalling $name"
        $rc = UninstallOnePackage $pkg
        if ($rc) {
        } else {
            Write-Error "Failed to install $name"
        }
    }

    PostUninstall
    return 0
}

Main
