#$ErrorActionPreference = 'Stop'; # stop on all errors

$packageName		= 'flarevm.installer.flare' #
$toolsDir   		= "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$flareFeed 			= "https://www.myget.org/F/flare/api/v2"
$cache 				=  "$env:userprofile\AppData\Local\ChocoCache"
$globalCinstArgs 	= "--cacheLocation $cache -y"
$startPath 			= "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\FLARE"
$pkgPath 			= Join-Path $toolsDir "packages.json"

# Set desktop background to black
set-itemproperty -path 'HKCU:\Control Panel\Colors' -name Background -value "0 0 0"

function Test-Win64() {
    return [IntPtr]::size -eq 8
}

# https://stackoverflow.com/questions/28077854/powershell-2-0-convertfrom-json-and-convertto-json-implementation
function ConvertFrom-Json([object] $item) {
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer

    #The comma operator is the array construction operator in PowerShell
    return ,$ps_js.DeserializeObject($item)
}

function LoadPackages {
    try {
        $json = Get-Content $pkgPath -ErrorAction Stop
        $packages = ConvertFrom-Json $json
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
        if (Test-Win64) {
            # pass
        } else {
            Write-Warning "[!] Not installing $name on x86 systems"
            return $true
        }
    }


    if ($pkgargs -eq $null)
    {
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

    if ($([System.Environment]::ExitCode) -ne 0 -And $([System.Environment]::ExitCode) -ne 3010)
    {
        Write-Host "ExitCode: $([System.Environment]::ExitCode)"
        return $false
    }
    return $true
}

function InitialSetup
{

    # Basic system setup
    Update-ExecutionPolicy Unrestricted
    Disable-MicrosoftUpdate
    Set-WindowsExplorerOptions -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowHiddenFilesFoldersDrives
    Set-TaskbarOptions -Size Small
    Disable-BingSearch

    # Chocolatey setup
    Write-Host "Initializing chocolatey"
    iex "choco sources add -n=flare -s $flareFeed --priority 1"
    iex "choco feature enable -n allowGlobalConfirmation"
    iex "choco feature enable -n allowEmptyChecksums"

    # Create the cache directory
    New-Item -Path $cache -ItemType directory -Force

    # Create FLARE desktop shortcut
    if( -not (Test-Path -path $startPath) ) { New-Item -Path $startPath -ItemType directory }
    $desktopShortcut = Join-Path ${Env:USERPROFILE} "Desktop\FLARE.lnk"
    Install-ChocolateyShortcut -shortcutFilePath $desktopShortcut -targetPath $startPath

    # BoxStarter setup
    Set-BoxstarterConfig -NugetSources "$flareFeed;https://chocolatey.org/api/v2" -LocalRepo "."
}


function CleanUp
{
    # clean up the cache directory
    Remove-Item $cache -Recurse

    # Final flarevm installation
    choco upgrade flarevm.config.flare $globalCinstArgs
}


function Main {
    InitialSetup

    $json = LoadPackages $pkgPath
    Write-Host $json
    if ($json -eq $null -Or $json.packages -eq $null)
    {
        Write-Host "Packages property not found! Exiting"
        return -1
    }

    $packages = $json.packages
    foreach ($pkg in $packages)
    {
        $name = $pkg.name
        $rc = InstallOnePackage $pkg
        if ($rc) {
        } else {
            Write-Error "Failed to install $name"
        }
    }

    CleanUp
    return 0
}


Main
