$ErrorActionPreference = 'Continue'

Import-Module Boxstarter.Chocolatey
Import-Module "$($Boxstarter.BaseDir)\Boxstarter.Common\boxstarter.common.psd1"
Import-Module FireEyeVM.common -Force -DisableNameChecking

$toolsDir         = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$flareFeed        = "https://www.myget.org/F/fireeye/api/v2"
$cache            =  "${Env:UserProfile}\AppData\Local\ChocoCache"
$globalCinstArgs  = "--cacheLocation $cache -y"
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

function InstallOnePackage {
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
            Write-Warning "[!] Not installing $name on x86 systems"
            return $true
        }
    }

    if ($pkgargs -eq $null) {
        $args = $globalCinstArgs
    } else {
        $args = $pkgargs,$globalCinstArgs -Join " "
    }

    if ($args -like "*-source*" -Or $args -like "*--package-parameters*") {
        Write-Warning "[!] Installing using host choco.exe! Errors are ignored. Please check to confirm $name is installed properly"
        Write-Warning "[!] Executing: iex choco upgrade $name $args"
        $rc = iex "choco upgrade $name $args"
        Write-Host $rc
    } else {
        choco upgrade $name $args
    }

    if ($([System.Environment]::ExitCode) -ne 0 -And $([System.Environment]::ExitCode) -ne 3010) {
        Write-Host "ExitCode: $([System.Environment]::ExitCode)"
        return $false
    }
    return $true
}

function InitialSetup {
    # Basic system setup
    Update-ExecutionPolicy Unrestricted
    Set-WindowsExplorerOptions -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowHiddenFilesFoldersDrives
    Disable-MicrosoftUpdate
    Disable-BingSearch
    Disable-GameBarTips
    Disable-ComputerRestore -Drive ${Env:SystemDrive}

    # Chocolatey setup
    Write-Host "Initializing chocolatey"
    iex "choco sources add -n=flare -s $flareFeed --priority 1"
    iex "choco feature enable -n allowGlobalConfirmation"
    iex "choco feature enable -n allowEmptyChecksums"

    # Create the cache directory
    New-Item -Path $cache -ItemType directory -Force


    # Set common paths in environment variables
    $toolListDir = [Environment]::GetEnvironmentVariable("TOOL_LIST_DIR", 2)
    if ($toolListDir -eq $null) {
        $toolListDir = Join-Path ${Env:ProgramData} "Microsoft\Windows\Start Menu\Programs\FLARE"
    }
    Install-ChocolateyEnvironmentVariable -VariableName "TOOL_LIST_DIR" -VariableValue $toolListDir -VariableType 'Machine'
    
    $toolListShortcut = [Environment]::GetEnvironmentVariable("TOOL_LIST_SHORTCUT", 2)
    if ($toolListShortcut -eq $null) {
        $toolListShortcut = Join-Path (Join-Path ${Env:UserProfile} "Desktop") "FLARE.lnk"
    }
    Install-ChocolateyShortcut -shortcutFilePath $toolListShortcut -targetPath $toolListDir
    Install-ChocolateyEnvironmentVariable -VariableName "TOOL_LIST_SHORTCUT" -VariableValue $toolListShortcut -VariableType 'Machine'

    refreshenv

    # BoxStarter setup
    Set-BoxstarterConfig -NugetSources "$flareFeed;https://chocolatey.org/api/v2"

    # Tweak power options to prevent installs from timing out
    & powercfg -change -monitor-timeout-ac 0 | Out-Null
    & powercfg -change -monitor-timeout-dc 0 | Out-Null
    & powercfg -change -disk-timeout-ac 0 | Out-Null
    & powercfg -change -disk-timeout-dc 0 | Out-Null
    & powercfg -change -standby-timeout-ac 0 | Out-Null
    & powercfg -change -standby-timeout-dc 0 | Out-Null
    & powercfg -change -hibernate-timeout-ac 0 | Out-Null
    & powercfg -change -hibernate-timeout-dc 0 | Out-Null


    if ((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") {
        # Update Tls settings
        if (Get-OSArchitectureWidth -Compare 64) {
            $cmdPath = Join-Path $toolsDir "tls_mod_x64.reg"
        } else {
            $cmdPath = Join-Path $toolsDir "tls_mod_x86.reg"
        }
        Start-Process -FilePath "reg.exe" -ArgumentList "import $cmdPath" -Wait -PassThru
    }
}


function CleanUp {
    # clean up the cache directory
    Remove-Item $cache -Recurse

    # Final flarevm installation
    iex "choco upgrade flarevm.config.flare $globalCinstArgs"
}


function Main {
    InitialSetup

    $json = LoadPackages $pkgPath
    if ($json -eq $null -Or $json.packages -eq $null) {
        Write-Host "Packages property not found! Exiting"
        return -1
    }

    $packages = $json.packages
    foreach ($pkg in $packages) {
        $name = $pkg.name
        $rc = InstallOnePackage $pkg
        if ($rc) {
            # Try not to get rate-limited
            if (-Not ($name.Contains(".flare"))) {
                Start-Sleep -Seconds 5
            }
        } else {
            Write-Host "Failed to install $name"
        }
    }

    CleanUp
    return 0
}


Main
