$ErrorActionPreference = 'Stop'

Import-Module Boxstarter.Chocolatey
Import-Module "$($Boxstarter.BaseDir)\Boxstarter.Common\boxstarter.common.psd1"
Import-Module FireEyeVM.Common

# Boxstarter options
$cache           =  "${Env:UserProfile}\AppData\Local\ChocoCache"
$globalCinstArgs = "--cacheLocation $cache"

$toolsDir    = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$pkgPath          = Join-Path $toolsDir "packages.json"

# Set desktop background to black
Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name Background -Value "0 0 0" -Force | Out-Null


function LoadPackages {
    try {
        $json = Get-Content $pkgPath -ErrorAction Stop
        $packages = FE-ConvertFrom-Json $json
    } catch {
        return $null
    }
    return $packages
}


function UninstallOnePackage {
    param([hashtable] $pkg)
    $name = $pkg.name
    $pkgargs = $pkg.args
    try {
        $is64Only = $pkg.x64Only
    } catch {
        $is64Only = $false
    }

    if ($is64Only) {
        if (Get-OSArchitectureWidth -Compare 64) {
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

function PostUninstall {
    # Chocolatey setup
    Write-Host "Initializing chocolatey"

    try {
        Remove-Item $cache -Recurse
    } catch {
        # Ignore exception, in case the directory does not exist.
    }

    $desktopShortcut = Join-Path ${Env:UserProfile} "Desktop\FLARE.lnk"
    Remove-Item $desktopShortcut

    # Set common paths in environment variables
    [Environment]::SetEnvironmentVariable("TOOL_LIST_DIR", $null, "Machine")
    Uninstall-ChocolateyEnvironmentVariable -VariableName "TOOL_LIST_DIR" -VariableType 'Machine'
}


function PreUninstall {
    # Final flarevm installation
    cuninst -x -y $globalCinstArgs flarevm
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
