<#
 Copyright 2017 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
#>

<#
    .SYNOPSIS
        Installation script for FLARE VM.
        ** Only install on a virtual machine! **

    .DESCRIPTION
        Installation script for FLARE VM that leverages Chocolatey and Boxstarter.
        Script verifies minimal settings necessary to install FLARE VM on a virtual machine.
        Script allows users to customize package selection and environment variables used in FLARE VM via a GUI before installation begins.
        A CLI-only mode is also available by providing specific command-line argument switches.

        To execute this script:
          1) Open PowerShell window as administrator
          2) Allow script execution for this session by running command "Set-ExecutionPolicy Bypass -Scope Process -Force"
          3) Unblock the install script by running "Unblock-File .\install.ps1"
          4) Execute the script by running ".\install.ps1"

    .PARAMETER password
        Current user password to allow reboot resiliency via Boxstarter. Prefer passwordFile because
        command-line arguments may be visible to other processes and retained in shell history.

    .PARAMETER passwordFile
        Path to a file containing the current user's password. Restrict access to this file.

    .PARAMETER removePasswordFile
        Delete passwordFile immediately after reading it. Recommended for automation-created files.

    .PARAMETER noPassword
        Switch parameter indicating a password is not needed for reboots.

    .PARAMETER customConfig
        Path to a configuration XML file. May be a file path or URL.

    .PARAMETER customLayout
        Path to a taskbar layout XML file. May be a file path or URL.

    .PARAMETER localPackageSource
        Optional path to a trusted local Chocolatey package directory. Local package sources are
        disabled by default to prevent package shadowing from the Desktop or current directory.

    .PARAMETER noWait
        Switch parameter to skip installation message before installation begins.

    .PARAMETER noGui
        Switch parameter to skip customization GUI.

    .PARAMETER noReboots
        Switch parameter to prevent reboots (not recommended).

    .PARAMETER noChecks
        Switch parameter to skip validation checks (not recommended).

    .PARAMETER allowEmptyChecksums
        Compatibility switch that permits Chocolatey packages without checksums. This weakens
        download integrity validation and should only be used for a package that cannot otherwise install.

    .PARAMETER allowWebBootstrap
        Compatibility switch that permits execution of Boxstarter's mutable web bootstrap when
        Chocolatey is unavailable. Prefer installing Chocolatey separately and leave this disabled.

    .EXAMPLE
        .\install.ps1

        Description
        ---------------------------------------
        Execute the installer to configure FLARE VM.

    .EXAMPLE
        .\install.ps1 -password Passw0rd! -noWait -noGui -noChecks

        Description
        ---------------------------------------
        CLI-only installation with minimal user interaction (some packages may require user interaction).
        To prevent reboots, also add the "-noReboots" switch.

    .EXAMPLE
        .\install.ps1 -customConfig "https://raw.githubusercontent.com/mandiant/flare-vm/main/config.xml"

        Description
        ---------------------------------------
        Use a custom configuration XML file hosted on the internet.

    .LINK
        https://github.com/mandiant/flare-vm
        https://github.com/mandiant/VM-Packages
#>

param (
  [string]$password = $null,
  [string]$passwordFile = $null,
  [switch]$removePasswordFile,
  [switch]$noPassword,
  [string]$customConfig = $null,
  [string]$customLayout = $null,
  [string]$localPackageSource = $null,
  [switch]$noWait,
  [switch]$noGui,
  [switch]$noReboots,
  [switch]$noChecks,
  [switch]$allowEmptyChecksums,
  [switch]$allowWebBootstrap
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not [string]::IsNullOrEmpty($password) -and -not [string]::IsNullOrWhiteSpace($passwordFile)) {
    throw 'Use either -password or -passwordFile, not both.'
}

# In an RE/malware-analysis lab, samples may already be executing on this VM by the time
# a reboot is needed. A password passed via -password is visible for the life of this
# process to anything that can enumerate process command lines (e.g. Get-CimInstance
# Win32_Process), and may also be retained in shell history. Warn loudly so -passwordFile
# (not visible via process enumeration) is used instead.
if (-not [string]::IsNullOrEmpty($password)) {
    Write-Host "[!] WARNING: -password exposes the plaintext password to any process on this VM (via process command-line enumeration) and to shell history. Prefer -passwordFile for malware analysis / RE lab use." -ForegroundColor Yellow
}

# Function to download files and handle errors consistently
function Save-FileFromUrl {
    param (
        [Parameter(Mandatory=$true)]
        [string]$fileSource,
        [Parameter(Mandatory=$true)]
        [string]$fileDestination,
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$sha256,
        [switch]$exitOnError
    )

    Write-Host "[+] Downloading file from '$fileSource'"
    $temporaryFile = "$fileDestination.download-$([Guid]::NewGuid().ToString('N'))"
    try {
        $sourceUri = New-Object System.Uri($fileSource)
        if (-not $sourceUri.IsAbsoluteUri -or $sourceUri.Scheme -ne 'https') {
            throw "Remote downloads must use an absolute HTTPS URL."
        }

        (New-Object net.webclient).DownloadFile($sourceUri, $temporaryFile)

        if ($sha256) {
            $actualSha256 = (Get-FileHash -Path $temporaryFile -Algorithm SHA256).Hash
            if ($actualSha256 -ne $sha256) {
                throw "SHA-256 mismatch. Expected $sha256, received $actualSha256."
            }
        }

        Move-Item -LiteralPath $temporaryFile -Destination $fileDestination -Force
    } catch {
        Write-Host "`t[!] Failed to download '$fileSource'"
        Write-Host "`t[!] $_"
        if ($exitOnError) {
            Start-Sleep 3
            exit 1
        }
        throw
    } finally {
        if (Test-Path -LiteralPath $temporaryFile) {
            Remove-Item -LiteralPath $temporaryFile -Force
        }
    }
}

# Function used for getting configuration files (such as config.xml and LayoutModification.xml)
function Get-ConfigFile {
    param (
        [string]$fileDestination,
        [string]$fileSource
    )
    # Check if the source is an existing file path.
    if (-not (Test-Path $fileSource)) {
        # If the source doesn't exist, assume it's a URL and download the file.
        Save-FileFromUrl -fileSource $fileSource -fileDestination $fileDestination
    } else {
        # Preserve user-provided configuration files. Copy only when source and destination differ.
        Write-Host "[+] Using existing file as configuration file."
        $sourcePath = [System.IO.Path]::GetFullPath($fileSource)
        $destinationPath = [System.IO.Path]::GetFullPath($fileDestination)
        if ($sourcePath -ne $destinationPath) {
            Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
        }
    }
}

# Set path to user's desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")
Set-Location -Path $desktopPath -PassThru | Out-Null

# Setting global variables
$script:checksPassed = $true
$mandatoryChecksPassed = $true
$exit_message = "Installation cannot continue."

################################# Functions that conduct Pre-Install Checks #################################
# Function to test the network stack. Ping/GET requests to the resource to ensure that network stack looks good for installation
function Test-WebConnection {
    param (
        [string]$url
    )

    Write-Host "[+] Checking for Internet connectivity ($url)... (mandatory)"

    # The HTTPS request is authoritative: ICMP (ping) is frequently blocked on networks that
    # still allow HTTPS, so a failed ping alone must not fail the check. Ping is only used as
    # extra context in the error message when the HTTPS request also fails.
    $response = $null
    try {
        $response = Invoke-WebRequest -Uri "https://$url" -UseBasicParsing -DisableKeepAlive
    }
    catch {
        $pingHint = ""
        if (-not (Test-Connection $url -Quiet)) {
            $pingHint = " (ping to $url also failed)"
        }
        return "Error accessing $url$pingHint. Exception: $($_.Exception.Message)`n`t[!] Check your network settings."
    }

    if ($response -and $response.StatusCode -ne 200) {
        return "Unable to access $url. Status code: $($response.StatusCode)`n`t[!] Check your network settings."
    }

}

function Test-InternetConnectivity {
    # Keep the required endpoints in one place so CLI and GUI preflight modes cannot drift.
    $requiredHosts = @('google.com', 'github.com', 'raw.githubusercontent.com')
    foreach ($requiredHost in $requiredHosts) {
        $errorInfo = Test-WebConnection $requiredHost
        if ($errorInfo) {
            return $errorInfo
        }
    }
}

function Test-HttpsUrl {
    param ([string]$url)

    $parsedUrl = $null
    return [System.Uri]::TryCreate($url, [System.UriKind]::Absolute, [ref]$parsedUrl) -and $parsedUrl.Scheme -eq 'https'
}


function Test-PSVersion{
    try {
		$psVersion = $PSVersionTable.PSVersion
		if ($psVersion -lt [System.Version]"5.0.0") {
		  return "Your PowerShell version ($psVersion) is not supported"
		}
	} catch {
		return "Unable to determine Powershell version"
	}
}

function Test-Admin {
    try {
		$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
		if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
			return "The script is not running as Administrator"
		}
	} catch {
		return "Unable to determine if the script is running as Administrator"
	}
}
function Test-ExecutionPolicy {
	try {
		$executionPolicy = (Get-ExecutionPolicy).ToString()
		if ($executionPolicy -notin @('Bypass', 'Unrestricted')){
			return "You need to enable script execution with 'Set-ExecutionPolicy Bypass -Scope Process -Force'"
		}
	} catch {
		return "Unable to determine Powershell execution policy"
	}
}
function Test-DefenderAndTamperProtection {
        try {
		$defender = Get-Service -Name WinDefend -ea 0
		if ($null -ne $defender) {
			if ($defender.Status -eq "Running") {
				 return "Disable Windows Defender through Group Policy, reboot, and rerun installer"
			}
		}
        $tpEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction Stop
        if ($tpEnabled.TamperProtection -eq 5) {
            return "Disable Tamper Protection, reboot, and rerun installer"
        }
    } catch {
		return "Unable to determine if TamperProtection and Defender are enabled"
    }
}

function Test-WindowsVersion {
	try {
		$os = Get-CimInstance -Class Win32_OperatingSystem
		$osMajorVersion = 0
		# CIM returns Version as text (examples: "6.1.7601", "10.0.19045"). Cast the
		# major component explicitly so PowerShell does not perform a lexical string comparison.
		if (-not [int]::TryParse($os.Version.Split('.')[0], [ref]$osMajorVersion)) {
			throw "Invalid Windows version '$($os.Version)'"
		}
		if ($osMajorVersion -lt 10) {
			return "Only Windows >= 10 is supported"
		}
	} catch {
		return "Unable to determine Windows Version"
	}
}

# 19045: https://www.microsoft.com/en-us/software-download/windows10ISO downloaded on April 25 2023.
# 20348: the version used by windows-2022 in GH actions
# 26100: https://www.microsoft.com/en-us/software-download/windows11 downloaded on May 6 2025.
function Test-TestedOS {
	$testedVersions = @(19045, 20348, 26100)
	try {
		$osVersion = 0
		$buildNumber = (Get-CimInstance -class Win32_OperatingSystem).BuildNumber
		if (-not [int]::TryParse($buildNumber, [ref]$osVersion)) {
			throw "Invalid Windows build number '$buildNumber'"
		}
		if (-not ($osVersion -in $testedVersions)){
			return "Windows version $osVersion has not been tested. Tested versions: $($testedVersions -join ', ')"
		}
	} catch {
		return "Windows version may not have been tested. Tested versions: $($testedVersions -join ', ')"
	}
}
function Test-VM {
    $virtualModels = @('VirtualBox', 'VMware', 'Virtual Machine', 'Hyper-V')
    try {
		$computerSystemModel = (Get-CimInstance win32_computersystem).model
		$isVirtualModel = $false

		foreach ($model in $virtualModels) {
			if ($computerSystemModel.Contains($model)) {
				$isVirtualModel = $true
				break
			}
		}

		if (-not ($isVirtualModel)) {
			return "You are not on a VM or have hardened your machine to not appear as such"
		}
	} catch {
		return "Unable to determine if you are on a VM"
	}
}

function Test-SpaceUserName {
	try {
		if (${Env:UserName} -match '\s') {
			return "Username '${Env:UserName}' contains a space and will break installation"
		}
	} catch {
		return "Unable to determine if the username contains a space"
	}
}
function Test-Storage {
	try {
		$disk = Get-PSDrive (Get-Location).Drive.Name
		Start-Sleep -Seconds 1
		if (-not (($disk.used + $disk.free)/1GB -gt 58.8)) {
			return "A minimum of 60 GB hard drive space is preferred, increase hard drive space"
		}
	} catch {
		return "Unable to determine hard drive space"
	}
}



if ($noGui.IsPresent) {
	if (-not $noChecks.IsPresent) {
		# Check PowerShell version
		Write-Host "[+] Checking if PowerShell version is compatible (mandatory)..."
		$error_info = Test-PSVersion
		if ($error_info){
			Write-Host "`t[!] $error_info" -ForegroundColor Red
			$mandatoryChecksPassed = $false
		}

		# Ensure script is ran as administrator
		Write-Host "[+] Checking if script is running as administrator (mandatory)..."
		$error_info = Test-Admin
		if ($error_info) {
			Write-Host "`t[!] $error_info"  -ForegroundColor Red
			$mandatoryChecksPassed = $false
		}

		# Ensure execution policy is unrestricted
		Write-Host "[+] Checking if execution policy is unrestricted.. (mandatory)."
		$error_info = Test-ExecutionPolicy
		if ($error_info) {
			Write-Host "`t[!] $error_info" -ForegroundColor Red
			$mandatoryChecksPassed = $false
		}

		# Check if Windows < 10
		Write-Host "[+] Checking Operating System version compatibility..."
		$error_info = Test-WindowsVersion
		if ($error_info) {
			Write-Host "`t[!] $error_info" -ForegroundColor Yellow
			$script:checksPassed = $false
		}

		# Check if host has been tested
		Write-Host "[+] Checking if the Operating System has been tested..."
		$error_info= Test-TestedOS
		if ($error_info) {
			Write-Host "`t[!] $error_info" -ForegroundColor Yellow
			$script:checksPassed = $false
		}

		# Check if system is a virtual machine
		Write-Host "[+] Checking if the system runs on a Virtual Machine..."
		$error_info = Test-VM
		if ($error_info) {
			Write-Host "`t[!] $error_info" -ForegroundColor Yellow
			$script:checksPassed = $false
		}

		# Check for spaces in the username, exit if identified
		Write-Host "[+] Checking for spaces in the username... (mandatory)"
		$error_info = Test-SpaceUserName
		if ($error_info) {
			Write-Host "`t[!] $error_info" -ForegroundColor Red
			$mandatoryChecksPassed = $false
		}

		# Check if host has enough disk space
		Write-Host "[+] Checking if host has enough disk space..."
		$error_info = Test-Storage
		if ($error_info) {
			Write-Host "`t[!] $error_info"   -ForegroundColor Yellow
			$script:checksPassed = $false
		}

		# Internet connectivity checks
		$error_info = Test-InternetConnectivity
		if ($error_info){
			Write-Host "`t[+] $error_info" -ForegroundColor Red
			$mandatoryChecksPassed = $false
		}

		# Check if Tamper Protection is disabled
		Write-Host "[+] Checking if Windows Defender Tamper Protection is disabled..."
		$error_info = Test-DefenderAndTamperProtection
		if ($error_info) {
			Write-Host "`t[!]$error_info"  -ForegroundColor Red
			$script:checksPassed = $false
		}

		if (-not $mandatoryChecksPassed){
			Write-Host "[!] $exit_message" -ForegroundColor Red
			Start-Sleep 3
            exit 1
		}

		if (-not $script:checksPassed){
			Write-Host "[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
			$response = Read-Host
			if ($response -notin @("y","Y")) {
				exit 1
			}
		}

		Write-Host "[+] Setting password to never expire to avoid that a password expiration blocks the installation..."
		$UserNoPasswd = Get-CimInstance Win32_UserAccount -Filter "Name='${Env:UserName}'"
		$UserNoPasswd | Set-CimInstance -Property @{ PasswordExpires = $false }

		# Prompt user to remind them to take a snapshot
		Write-Host "[-] Have you taken a VM snapshot to ensure you can revert to pre-installation state? (Y/N): " -ForegroundColor Yellow -NoNewline
		$response = Read-Host
		if ($response -notin @("y","Y")) {
			exit 1
		}
	}

}

function Open-CheckManager {
	if ($formChecksManager.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
		exit
	}
}
# Init Window Install checks
if (-not $noGui.IsPresent) {

    Write-Host "[+] Starting GUI to allow user to edit configuration file..."
    ################################################################################
    ## BEGIN GUI
    ################################################################################
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -Assembly System.Drawing

    $errorColor = [System.Drawing.ColorTranslator]::FromHtml("#c80505")
    $successColor = [System.Drawing.ColorTranslator]::FromHtml("#417505")
    $grayedColor = [System.Drawing.ColorTranslator]::FromHtml("#6e6964")
	$orangeColor = [System.Drawing.ColorTranslator]::FromHtml("#bf8334")

    if (-not $noChecks.IsPresent) {

		#################################################################################################
		################################ Installer Checks Form Controls #################################
		#################################################################################################

		$formChecksManager = New-Object system.Windows.Forms.Form -Property ([ordered]@{
		    ClientSize = New-Object System.Drawing.Point(700,640)
		    text = "FLAREVM Pre-Install Checks"
		    TopMost = $true
		    StartPosition = 'CenterScreen'
		})

		$ChecksPanel = New-Object system.Windows.Forms.Panel -Property ([ordered]@{
		    height = 460
		    width = 89
		    location = New-Object System.Drawing.Point(570,8)
		})

		$InstallChecksGroup = New-Object system.Windows.Forms.Groupbox -Property ([ordered]@{
		    height = 490
		    width = 665
		    text = "Installation Checks"
		    location = New-Object System.Drawing.Point(23,14)
		})

		################################# Check Labels #################################

		$PSVersionLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Valid Powershell version"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(15,18)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

        $RunningAsAdminLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
            text = "Running as Administrator"
            AutoSize = $true
            width = 25
            height = 10
            location = New-Object System.Drawing.Point(15,59)
            Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        })

		$ExecutionPolicyLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Script Execution Enabled"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(15,104)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		$validWindowsVersionLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Valid Windows Version"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,149)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		$WindowsReleaseLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Tested Windows Version"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(15,193)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		$RunningVMLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Running in a Virtual Machine"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(15,239)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		$usernameContainsSpacesLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Valid username"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,285)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		$EnoughHardStorageLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Enough Hard Drive Space"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(15,325)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		$internetConnectivityLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Internet connectivity"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,369)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		$WindowsDefenderLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Windows Defender Disabled"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(15,411)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		################################# Check Boolean Controls #################################

		$PSVersion = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,18)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $errorColor
		})

		$RunningAsAdmin = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,63)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $errorColor
		})

		$ExecutionPolicy = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,108)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $errorColor
		})

		$validWindowsVersion = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,150)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $errorColor
		})

		$WindowsRelease = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,195)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $orangeColor
		})

		$RunningVM = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,240)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $orangeColor
		})

		$usernameContainsSpaces = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,285)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $errorColor
		})

		$EnoughHardStorage = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,322)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $orangeColor
		})

		$internetConnectivity = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,368)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $errorColor
		})

		$WindowsDefender = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "False"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(24,409)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		    ForeColor = $orangeColor
		})

		################################# Check Tooltip Controls #################################
		$verticalPosition = 41

		# $PSVersionTooltip
		$PSVersionTooltip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Powershell version must be >= 5 (mandatory)"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})
		$verticalPosition += 44

		# $RunningAsAdminTooltip
		$RunningAsAdminTooltip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "You must run the script as Administrator (mandatory)"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})
		$verticalPosition += 44

		# $ExecutionPolicyTooltip
		$ExecutionPolicyTooltip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "You must enable script execution (mandatory)"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})
		$verticalPosition += 44

		# $validWindowsVersionToolTip
		$validWindowsVersionToolTip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Only Windows Version >= 10 is supported (mandatory)"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})
		$verticalPosition += 44

		# $WindowsReleaseTooltip
		$WindowsReleaseTooltip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "You might run into issues when using a non tested version"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})
		$verticalPosition += 44

		# $RunningVMTooltip
		$RunningVMTooltip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Only run this script inside a Virtual Machine (VM)"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})
		$verticalPosition += 44

		# $usernameContainsSpacesToolTip
		$usernameContainsSpacesToolTip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Username cannot contain spaces (mandatory)"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})
		$verticalPosition += 44

		# $EnoughHardStorageTooltip
		$EnoughHardStorageTooltip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "A minimum of 60 GB hard drive space is preferred"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})
		$verticalPosition += 44

		# $internetConnectivityTooltip
		$internetConnectivityTooltip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "You must have internet connection (mandatory)"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})
		$verticalPosition += 44

		# $WindowsDefenderTooltip
		$WindowsDefenderTooltip = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Disable Windows Defender and Tamper Protection"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(15,$verticalPosition)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    ForeColor = $grayedColor
		})


		################################# Check Completion Controls #################################

		$breakInstallationLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    Text = $exit_message
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(40,530)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
		    ForeColor = $errorColor
		    Visible = $false
		})

		$BreakMyInstallCheckbox = New-Object system.Windows.Forms.CheckBox -Property ([ordered]@{
		    Visible = $false
		    text = "I understand that continuing without satisfying all pre-install checks might cause install issues"
		    AutoSize = $true
		    width = 324
		    height = 21
		    location = New-Object System.Drawing.Point(30,510)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})

        $snapshotCheckBox = New-Object system.Windows.Forms.CheckBox -Property ([ordered]@{
            Text = "I have taken a VM snapshot to ensure I can revert to pre-installation state"
            AutoSize = $true
            location = New-Object System.Drawing.Point(30,532)
            Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
            Visible = $false
        })

		$ChecksCompleteButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    text = "Continue"
		    width = 97
		    height = 37
		    enabled = $false
		    DialogResult = [System.Windows.Forms.DialogResult]::OK
		    location = New-Object System.Drawing.Point(420,565)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
		})
		$ChecksCompleteButton.Add_Click({
			$script:checksPassed = $true
			[void]$formChecksManager.Close()
		})

		$checksCancelButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    Text = "Cancel"
		    width = 97
		    height = 37
		    location = New-Object System.Drawing.Point(519,565)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
		    DialogResult = [System.Windows.Forms.DialogResult]::Cancel
		})

		$InstallChecksGroup.controls.AddRange(@($ChecksPanel,$RunningAsAdminLabel,$ExecutionPolicyLabel,$WindowsDefenderLabel,$WindowsReleaseLabel,$RunningVMLabel,$PSVersionLabel,$internetConnectivityLabel,$validWindowsVersionLabel,$validWindowsVersionToolTip,$RunningAsAdminTooltip,$ExecutionPolicyTooltip,$WindowsDefenderTooltip,$WindowsReleaseTooltip,$RunningVMTooltip,$EnoughHardStorageLabel, $EnoughHardStorageTooltip,$PSVersionTooltip,$internetConnectivityTooltip,$usernameContainsSpacesLabel,$usernameContainsSpacesToolTip,$RunningAsAdmin,$EnoughHardStorage))
		$formChecksManager.controls.AddRange(@($InstallChecksGroup,$ChecksCompleteButton,$checksCancelButton,$BreakMyInstallCheckbox,$snapshotCheckBox,$breakInstallationLabel))
		$ChecksPanel.controls.AddRange(@($RunningAsAdmin, $ExecutionPolicy,$WindowsDefender,$WindowsRelease,$RunningVM, $EnoughHardStorage, $PSVersion, $internetConnectivity, $validWindowsVersion,$usernameContainsSpaces ))

	    # Make sure that the user completed all pre-install steps
		$error_info = Test-Admin
		if ($error_info){
			$RunningAsAdmin.Text = $error_info
			$RunningAsAdmin.Forecolor = $errorColor
            $mandatoryChecksPassed = $false
        } else {
			$RunningAsAdmin.Text = "True"
            $RunningAsAdmin.ForeColor = $successColor
        }
		$error_info = Test-ExecutionPolicy
		if ($error_info){
			$ExecutionPolicyTooltip.Text = $error_info
			$ExecutionPolicyTooltip.Forecolor = $errorColor
            $mandatoryChecksPassed = $false
        } else {
			$ExecutionPolicy.Text = "True"
            $ExecutionPolicy.ForeColor = $successColor
        }
		$error_info = Test-DefenderAndTamperProtection
		if ($error_info){
			$WindowsDefenderTooltip.Text = $error_info
			$WindowsDefenderTooltip.Forecolor = $orangeColor
            $script:checksPassed = $false
        } else {
			$WindowsDefender.Text = "True"
            $WindowsDefender.ForeColor = $successColor
        }

		$error_info = Test-TestedOS
		if ($error_info){
            $WindowsReleaseTooltip.Text = $error_info
			$WindowsReleaseTooltip.Forecolor = $orangeColor
            $script:checksPassed = $false
        } else {
			$WindowsRelease.Text = "True"
            $WindowsRelease.ForeColor = $successColor
        }
		$error_info = Test-VM
		if ($error_info){
            $RunningVMTooltip.Text = $error_info
			$RunningVMTooltip.Forecolor = $orangeColor
            $script:checksPassed = $false
        } else {
			$RunningVM.Text = "True"
            $RunningVM.ForeColor = $successColor
        }
		$error_info = Test-Storage
		if ($error_info){
            $EnoughHardStorageTooltip.Forecolor = $orangeColor
			$EnoughHardStorageTooltip.Text = $error_info
            $script:checksPassed = $false
        } else {
			$EnoughHardStorage.Text = "True"
            $EnoughHardStorage.ForeColor = $successColor
        }
		$error_info = Test-PSVersion
		if ($error_info){
			$PSVersionTooltip.Text = $error_info
			$PSVersionTooltip.Forecolor = $errorColor
            $MandatoryChecksPassed = $false
		} else {
			$PSVersion.Text = "True"
			$PSVersion.ForeColor = $successColor
        }

		$error_info = Test-InternetConnectivity
		if ($error_info){
			$internetConnectivityTooltip.Text = $error_info
			$internetConnectivityTooltip.Forecolor = $errorColor
			$mandatoryChecksPassed = $false
		}else {
	        $internetConnectivity.Text = "True"
			$internetConnectivity.ForeColor = $successColor
		}
		$error_info = Test-WindowsVersion
		if ($error_info){
			$validWindowsVersionToolTip.Text = $error_info
			$validWindowsVersionToolTip.Forecolor = $errorColor
			$mandatoryChecksPassed = $false
		} else {
			$validWindowsVersion.Text = "True"
			$validWindowsVersion.ForeColor = $successColor
		}
		$error_info = Test-SpaceUserName
		if ($error_info){
			$usernameContainsSpacesToolTip.Text = $error_info
			$usernameContainsSpacesToolTip.Forecolor = $errorColor
			$mandatoryChecksPassed = $false
		}else {
			$usernameContainsSpaces.Text = "True"
			$usernameContainsSpaces.ForeColor = $successColor
		}

		#only display the checkbox if some checks did not pass
		if ($mandatoryChecksPassed){
			if ($script:checksPassed){
			    $BreakMyInstallCheckbox.Visible = $false
			    $snapshotCheckBox.Visible = $true
			}else{
				$BreakMyInstallCheckbox.Visible = $true
				$snapshotCheckBox.Visible = $true
			}
		}else{
			$breakInstallationLabel.visible = $true
		}

		$snapshotCheckBox.Add_CheckStateChanged({
			if (($snapshotCheckBox.Checked) -and ($script:checksPassed)){
				$ChecksCompleteButton.enabled = $true
			} else {
				if (($snapshotCheckBox.Checked) -and (-not $script:checksPassed)){
				   $ChecksCompleteButton.enabled = $BreakMyInstallCheckbox.Checked
			    } else{
				    if (-not ($snapshotCheckBox.Checked)){
				        $ChecksCompleteButton.enabled = $false
					}
			    }
			}
		})

		$BreakMyInstallCheckbox.Add_CheckStateChanged({
			if ($BreakMyInstallCheckbox.Checked){
				  $ChecksCompleteButton.enabled = $snapshotCheckBox.Checked
			} else{
			   $ChecksCompleteButton.enabled = $false
			}
		})
        Open-CheckManager
	}
    # init GUI controls of the install customization Window
    $formEnv = New-Object system.Windows.Forms.Form -Property ([ordered]@{
        ClientSize = New-Object System.Drawing.Point(750,350)
        text = "FLARE VM Install Customization"
        TopMost = $true
        MaximizeBox = $false
        FormBorderStyle = 'FixedDialog'
        StartPosition = 'CenterScreen'
    })

    $envVarGroup = New-Object system.Windows.Forms.Groupbox -Property ([ordered]@{
        height = 201
        width = 690
        text = "Environment Variable Customization"
        location = New-Object System.Drawing.Point(15,59)
    })

    $welcomeLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
        text = "Welcome to FLARE VM's custom installer. Please select your options below.`nDefault values will be used if you make no modifications."
        AutoSize = $true
        width = 25
        height = 10
        location = New-Object System.Drawing.Point(15,14)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })

    $vmCommonDirText = New-Object system.Windows.Forms.TextBox -Property ([ordered]@{
        multiline = $false
        width = 385
        height = 20
        location = New-Object System.Drawing.Point(190,21)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })

    $vmCommonDirSelect = New-Object system.Windows.Forms.Button -Property ([ordered]@{
        text = "Select Folder"
        width = 95
        height = 30
        location = New-Object System.Drawing.Point(588,17)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })
    $selectFolderArgs1 = @{textBox=$vmCommonDirText; envVar="VM_COMMON_DIR"}
    $vmCommonDirSelect.Add_Click({Get-Folder @selectFolderArgs1})

    $vmCommonDirLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
        text = "%VM_COMMON_DIR%"
        AutoSize = $true
        width = 25
        height = 10
        location = New-Object System.Drawing.Point(2,24)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]::Bold)
    })

    $vmCommonDirNote = New-Object system.Windows.Forms.Label -Property ([ordered]@{
        text = "Shared module and metadata for VM (e.g., config, logs, etc...)"
        AutoSize = $true
        width = 25
        height = 10
        location = New-Object System.Drawing.Point(190,46)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })

    $toolListDirText = New-Object system.Windows.Forms.TextBox -Property ([ordered]@{
        multiline = $false
        width = 385
        height = 20
        location = New-Object System.Drawing.Point(190,68)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })

    $toolListDirSelect = New-Object system.Windows.Forms.Button -Property ([ordered]@{
        text = "Select Folder"
        width = 95
        height = 30
        location = New-Object System.Drawing.Point(588,64)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })
    $selectFolderArgs2 = @{textBox=$toolListDirText; envVar="TOOL_LIST_DIR"}
    $toolListDirSelect.Add_Click({Get-Folder @selectFolderArgs2})

    $toolListDirLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
        text = "%TOOL_LIST_DIR%"
        AutoSize = $true
        width = 25
        height = 10
        location = New-Object System.Drawing.Point(2,71)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]::Bold)
    })

    $toolListDirNote = New-Object system.Windows.Forms.Label -Property ([ordered]@{
        text = "Folder to store tool categories and shortcuts"
        AutoSize = $true
        width = 25
        height = 10
        location = New-Object System.Drawing.Point(190,94)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })

    $rawToolsDirText = New-Object system.Windows.Forms.TextBox -Property ([ordered]@{
        multiline = $false
        width = 385
        height = 20
        location = New-Object System.Drawing.Point(190,113)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })

    $rawToolsDirSelect = New-Object system.Windows.Forms.Button -Property ([ordered]@{
        text = "Select Folder"
        width = 95
        height = 30
        location = New-Object System.Drawing.Point(588,109)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })
    $selectFolderArgs4 = @{textBox=$rawToolsDirText; envVar="RAW_TOOLS_DIR"}
    $rawToolsDirSelect.Add_Click({Get-Folder @selectFolderArgs4})

    $rawToolsDirLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
        text = "%RAW_TOOLS_DIR%"
        AutoSize = $true
        width = 25
        height = 10
        location = New-Object System.Drawing.Point(2,116)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]::Bold)
    })

    $rawToolsDirNote = New-Object system.Windows.Forms.Label -Property ([ordered]@{
        text = "Folder to store downloaded tools"
        AutoSize = $true
        width = 25
        height = 10
        location = New-Object System.Drawing.Point(190,137)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    })

    $okButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
        text = "Continue"
        width = 97
        height = 37
        location = New-Object System.Drawing.Point(480,280)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',11)
        DialogResult = [System.Windows.Forms.DialogResult]::OK
    })

    $cancelButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
        text = "Cancel"
        width = 97
        height = 37
        location = New-Object System.Drawing.Point(580,280)
        Font = New-Object System.Drawing.Font('Microsoft Sans Serif',11)
        DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    })

    $formEnv.controls.AddRange(@($envVarGroup,$okButton,$cancelButton,$welcomeLabel))
    $formEnv.AcceptButton = $okButton
    $formEnv.CancelButton = $cancelButton

    $envVarGroup.controls.AddRange(@($vmCommonDirText,$vmCommonDirSelect,$vmCommonDirLabel,$toolListDirText,$toolListDirSelect,$toolListDirLabel,$vmCommonDirNote,$toolListDirNote,$rawToolsDirText,$rawToolsDirSelect,$rawToolsDirLabel,$rawToolsDirNote))

}
if (-not $noPassword.IsPresent) {
    # Get user credentials for autologin during reboots
    if (-not [string]::IsNullOrWhiteSpace($passwordFile)) {
        if (-not (Test-Path -LiteralPath $passwordFile -PathType Leaf)) {
            throw "Password file does not exist: '$passwordFile'"
        }
        try {
            $password = (Get-Content -LiteralPath $passwordFile -Raw).TrimEnd("`r", "`n")
        } finally {
            if ($removePasswordFile.IsPresent) {
                Remove-Item -LiteralPath $passwordFile -Force -ErrorAction SilentlyContinue
            }
        }
        if ([string]::IsNullOrEmpty($password)) {
            throw 'Password file is empty.'
        }
    }
    if ([string]::IsNullOrEmpty($password)) {
        Write-Host "[+] Getting user credentials ..."
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True
        Start-Sleep -Milliseconds 500
        $credentials = Get-Credential ${Env:UserName}
    } else {
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $credentials = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList ${Env:UserName}, $securePassword
        # Best-effort scrub: drop the plaintext/SecureString copies now that $credentials
        # holds what's needed, shrinking the window a later-running sample in this same
        # session could recover the password via Get-Variable or a memory scan.
        $securePassword = $null
        Remove-Variable -Name password, securePassword -ErrorAction SilentlyContinue
        [System.GC]::Collect()
    }
}

# Check Boxstarter version
$boxstarterVersionGood = $false
if (${Env:ChocolateyInstall} -and (Test-Path "${Env:ChocolateyInstall}\bin\choco.exe")) {
    # 'choco info -r' returns machine-readable 'name|version' lines. Match the exact 'boxstarter'
    # line only (other lines may be present) and guard the version parse so a missing/odd value
    # leaves $boxstarterVersionGood as $false instead of throwing under $ErrorActionPreference='Stop'.
    $boxstarterInfo = choco info -l -r "boxstarter" | Where-Object { $_ -match '^boxstarter\|' } | Select-Object -First 1
    if ($boxstarterInfo) {
        $null, $version = $boxstarterInfo -split '\|'
        $parsedVersion = $null
        if ([System.Version]::TryParse($version, [ref]$parsedVersion)) {
            $boxstarterVersionGood = $parsedVersion -ge [System.Version]"3.0.2"
        }
    }
}

# Install Boxstarter if needed
if (-not $boxstarterVersionGood) {
    Write-Host "[+] Installing Boxstarter..." -ForegroundColor Cyan
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

    if (${Env:ChocolateyInstall} -and (Test-Path "${Env:ChocolateyInstall}\bin\choco.exe")) {
        # Avoid executing the mutable web bootstrap when Chocolatey is already available.
        choco upgrade boxstarter -y --source="https://community.chocolatey.org/api/v2/"
        if ($LASTEXITCODE -ne 0) {
            throw "Chocolatey failed to install Boxstarter (exit code $LASTEXITCODE)."
        }
    } else {
        if (-not $allowWebBootstrap.IsPresent) {
            throw "Chocolatey is required for secure Boxstarter installation. Install Chocolatey first or explicitly use -allowWebBootstrap."
        }
        Write-Host "`t[!] Chocolatey is unavailable; using Boxstarter's official web bootstrap." -ForegroundColor Yellow
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1'))
        Get-Boxstarter -Force
    }

    Start-Sleep -Milliseconds 500
}
Import-Module "${Env:ProgramData}\boxstarter\boxstarter.chocolatey\boxstarter.chocolatey.psd1" -Force

# Check Chocolatey version
$version = choco --version
$chocolateyVersionGood = [System.Version]$version -ge [System.Version]"2.0.0"

# Update Chocolatey if needed
if (-not ($chocolateyVersionGood)) { choco upgrade chocolatey }

# Attempt to disable updates (i.e., windows updates and store updates)
Write-Host "[+] Attempting to disable updates..."
Disable-MicrosoftUpdate
try {
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -PropertyType DWord -Value 2 -ErrorAction Stop -Force | Out-Null
} catch {
  Write-Host "`t[!] Failed to disable Microsoft Store updates" -ForegroundColor Yellow
}

# Set Boxstarter options
$Boxstarter.RebootOk = (-not $noReboots.IsPresent)
$Boxstarter.NoPassword = $noPassword.IsPresent
$Boxstarter.AutoLogin = $true
$Boxstarter.SuppressLogging = $True
$VerbosePreference = "SilentlyContinue"
$vmPackagesSource = 'https://www.myget.org/F/vm-packages/api/v2'
$communitySource = 'https://community.chocolatey.org/api/v2/'
$packageSources = @($vmPackagesSource, $communitySource)
$resolvedLocalPackageSource = $null
if (-not [string]::IsNullOrWhiteSpace($localPackageSource)) {
    if (-not (Test-Path -LiteralPath $localPackageSource -PathType Container)) {
        throw "Local package source must be an existing directory: '$localPackageSource'"
    }
    $resolvedLocalPackageSource = (Resolve-Path -LiteralPath $localPackageSource).Path
    Write-Host "`t[!] Trusting local Chocolatey packages from '$resolvedLocalPackageSource'." -ForegroundColor Yellow
    $packageSources = @($resolvedLocalPackageSource) + $packageSources
}
Set-BoxstarterConfig -NugetSources ($packageSources -join ';')
Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowFullPathInTitleBar

# Set Chocolatey options
Write-Host "[+] Updating Chocolatey settings..."
choco source add --name="vm-packages" --source="$vmPackagesSource" --priority=1
if ($resolvedLocalPackageSource) {
    choco source add --name="flare-local" --source="$resolvedLocalPackageSource" --priority=1
} else {
    choco source remove --name="flare-local" 2>$null | Out-Null
}
choco feature enable -n allowGlobalConfirmation
if ($allowEmptyChecksums.IsPresent) {
    Write-Host "`t[!] Allowing Chocolatey packages without checksums. Download integrity cannot be verified." -ForegroundColor Yellow
    choco feature enable -n allowEmptyChecksums
} else {
    choco feature disable -n allowEmptyChecksums
}
$cache = "${Env:LocalAppData}\ChocoCache"
New-Item -Path $cache -ItemType directory -Force | Out-Null
choco config set cacheLocation $cache

# Set power options to prevent installs from timing out
powercfg -change -monitor-timeout-ac 0 | Out-Null
powercfg -change -monitor-timeout-dc 0 | Out-Null
powercfg -change -disk-timeout-ac 0 | Out-Null
powercfg -change -disk-timeout-dc 0 | Out-Null
powercfg -change -standby-timeout-ac 0 | Out-Null
powercfg -change -standby-timeout-dc 0 | Out-Null
powercfg -change -hibernate-timeout-ac 0 | Out-Null
powercfg -change -hibernate-timeout-dc 0 | Out-Null

Write-Host "[+] Checking for configuration file..."
$configPath = Join-Path $desktopPath "config.xml"
if ([string]::IsNullOrEmpty($customConfig)) {
    Write-Host "[+] Using github configuration file..."
    $configSource = 'https://raw.githubusercontent.com/mandiant/flare-vm/main/config.xml'
} else {
    Write-Host "[+] Using custom configuration file..."
    $configSource = $customConfig
}

Get-ConfigFile $configPath $configSource

Write-Host "Configuration file path: $configPath"

# Check the configuration file exists
if (-Not (Test-Path $configPath)) {
    Write-Host "`t[!] Configuration file missing: " $configPath -ForegroundColor Red
    Write-Host "`t[-] Please download config.xml from $configSource to your desktop" -ForegroundColor Yellow
    Write-Host "`t[-] Is the file on your desktop? (Y/N): " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -notin @("y","Y")) {
        exit 1
    }
    if (-Not (Test-Path $configPath)) {
        Write-Host "`t[!] Configuration file still missing: " $configPath -ForegroundColor Red
        Write-Host "`t[!] Exiting..." -ForegroundColor Red
        Start-Sleep 3
        exit 1
    }
}

# Get config contents
Start-Sleep 1
try {
    $configXml = [xml](Get-Content -LiteralPath $configPath -Raw)
    if (-not $configXml.config) {
        throw "Root element must be <config>."
    }
} catch {
    Write-Host "`t[!] Invalid configuration XML '$configPath': $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}



#########################################################################
# GUI Functions
#########################################################################

function Get-Folder($textBox, $envVar) {
	$folderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
	$folderBrowserDialog.RootFolder = 'MyComputer'
	if ($folderBrowserDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
		$textbox.text = (Join-Path $folderBrowserDialog.SelectedPath (Split-Path $envs[$envVar] -Leaf))
	}
}

# Function that accesses MyGet vm-packages API URL to process packages that are the latest version and have a category
# Saves vm-packages.xml into disk and follows the link after the </entry> tag to retrieve a new version of the XML file
# Returns $packagesByCategory, a hashtable of arrays, where each entry is a PSCustomObject
function Get-Packages-Categories {
   # MyGet API URL that contains a filter to display only the latest packages
   # This URL displays the last two versions of a package
   # Minimize the number of HTTP requests to display all the packages due to the number of versions a package might have
   $vmPackagesUrl = 'https://www.myget.org/F/vm-packages/api/v2/Packages?$filter=IsLatestVersion%20eq%20true'
   $vmPackagesFile = "${Env:VM_COMMON_DIR}\vm-packages.xml"
   $packagesByCategory=@{}
   do {
	  # Download the XML from MyGet API
	  Save-FileFromUrl -fileSource $vmPackagesUrl -fileDestination $vmPackagesFile -exitOnError

	  # Load the XML content
	  [xml]$vm_packages = Get-Content $vmPackagesFile

	  # Define the namespaces defined in vm-packages.xml to access nodes
  # Each package resides in the entry node that is defined in the dataservices namespace
	  # Each node has properties that are defined in the metadata namespace
	  $ns = New-Object System.Xml.XmlNamespaceManager($vm_packages.NameTable)
	  $ns.AddNamespace("atom", "http://www.w3.org/2005/Atom")
	  $ns.AddNamespace("d", "http://schemas.microsoft.com/ado/2007/08/dataservices")
	  $ns.AddNamespace("m", "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata")

	  # Extract package information from the XML
	  $vm_packages.feed.entry | ForEach-Object {
		 $isLatestVersion = $_.SelectSingleNode("m:properties/d:IsLatestVersion", $ns).InnerText
		 $category = $_.SelectSingleNode("m:properties/d:Tags", $ns).InnerText
		 # Select only packages that have the latest version, contain a category and the category is not excluded
		 if (($isLatestVersion -eq "true") -and ($category -ne "") -and ($excludedCategories -notcontains $category)) {
	            $packageName = $_.properties.Id
				$description = $_.properties.Description
				$projectUrl = $_.properties.projectUrl

				# Initialize category as an empty array
				if (-not ($packagesByCategory.ContainsKey($category))) {
					 $packagesByCategory[$category] = @()
				}
				$packageObject = [PSCustomObject]@{
				PackageName        = $packageName
				PackageDescription = $description
				}
				# Check if $projectUrl contains a valid URL
				if ($projectUrl -match "^http") {
					Add-Member -InputObject $packageObject -MemberType NoteProperty -Name "PackageUrl" -Value $projectURl
				}
				# Add the PackageName and PackageDescription (and PackageUrl if present) to each entry in the array
				$packagesByCategory[$category] += $packageObject
            }
		  }
	  # Check if there is a next link in the XML and set the API URL to that link if it exists
	  $nextLink = $vm_packages.SelectSingleNode("//atom:link[@rel='next']/@href", $ns)
	  $vmPackagesUrl = $nextLink."#text"

   } while ($vmPackagesUrl)

  return $packagesByCategory
}

# Function that returns an array of all the packages that are displayed sorted by category from $packagesByCategory
function Get-AllPackages{
	$listedPackages = $packagesByCategory.Values | ForEach-Object { $_ } | Select-Object -ExpandProperty PackageName
	return $listedPackages
}

# Function that returns additional packages from the config that are not displayed in the textboxes
# which includes both Choco packages and packages from excluded categories
function Get-AdditionalPackages{
   $additionalPackages=@()

   # Packages from the config that are not displayed
   $additionalPackages = $packagesToInstall | where-Object { $listedPackages -notcontains $_}
   return $additionalPackages
}

if (-not $noGui.IsPresent) {

	if ($script:checksPassed -or $noChecks.IsPresent) {
        Write-Host "[+] Beginning graphical install"

		# Gather lists of packages
		$envs = [ordered]@{}
		$configXml.config.envs.env.ForEach({ $envs[$_.name] = $_.value })
		$excludedCategories=@('Command and Control','Credential Access','Exploitation','Forensic','Lateral Movement', 'Payload Development','Privilege Escalation','Reconnaissance','Wordlists','Web Application')
		# Read packages to install from the config
		$packagesToInstall = $configXml.config.packages.package.name
		$packagesByCategory = Get-Packages-Categories
		$listedPackages = Get-AllPackages
		$additionalPackages = Get-AdditionalPackages

        $vmCommonDirText.text            = $envs['VM_COMMON_DIR']
		$rawToolsDirText.text            = $envs['RAW_TOOLS_DIR']
		$toolListDirText.text            = $envs['TOOL_LIST_DIR']

		$Result = $formEnv.ShowDialog()

		if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
			# Remove default environment variables
			$nodes = $configXml.SelectNodes('//config/envs/env')
			foreach($node in $nodes) {
				$node.ParentNode.RemoveChild($node) | Out-Null
			}

			# Add environment variables
			$envs = $configXml.SelectSingleNode('//envs')
			$newXmlNode = $envs.AppendChild($configXml.CreateElement("env"))
			$newXmlNode.SetAttribute("name", "VM_COMMON_DIR")
			$newXmlNode.SetAttribute("value", $vmCommonDirText.text);
			$newXmlNode = $envs.AppendChild($configXml.CreateElement("env"))
			$newXmlNode.SetAttribute("name", "TOOL_LIST_DIR")
			$newXmlNode.SetAttribute("value", $toolListDirText.text);
			$newXmlNode = $envs.AppendChild($configXml.CreateElement("env"))
			$newXmlNode.SetAttribute("name", "RAW_TOOLS_DIR")
			$newXmlNode.SetAttribute("value", $rawToolsDirText.text)

			[void]$formEnv.Close()

		} else {
			Write-Host "[+] Cancel pressed, stopping installation..."
			Start-Sleep 3
			exit 1
		}

		################################################################################
		## PACKAGE SELECTION BY CATEGORY
		################################################################################

		# Function that adds the selected packages to the config.xml for the installation
		function Install-Selected-Packages{
		  $selectedPackages  = @()
		  $packages = $configXml.SelectSingleNode('//packages')

		  # Remove all child nodes inside <packages>
		  while ($packages.HasChildNodes) {
			$packages.RemoveChild($packages.FirstChild)
		  }

		  foreach ($checkBox in $checkboxesPackages){
			if ($checkBox.Checked){
				$package = $checkbox.Text.split(":")[0]
				$selectedPackages += $package
			}
		  }

		  foreach ($package in $additionalPackagesBox.Items){
			 $selectedPackages += $package
		  }
		  # Add selected packages
		  foreach($package in $selectedPackages) {
			   $newXmlNode = $packages.AppendChild($configXml.CreateElement("package"))
			   $newXmlNode.SetAttribute("name", $package)
		  }
		}

		# Function that resets the checkboxes to match the config.xml
		function Set-InitialPackages {
			foreach ($checkBox in $checkboxesPackages){
				$package =$checkbox.Text.split(":")[0]
				if (($checkbox.Checked) -and ($package -notin $packagesToInstall)){
					$checkBox.Checked = $false
				}else{
				  if ((-not $checkbox.Checked ) -and ($package -in $packagesToInstall)){
					 $checkBox.Checked = $true
				  }
				}
			}
		}
		# Function that returns an array of packages that belong to a specific category
		function Get-PackagesByCategory{
			param (
			 [string]$category
			)
			return $packagesByCategory[$category]
		}

		# Function that checks all the checkboxes
		function Select-AllPackages {
			foreach ($checkBox in $checkboxesPackages){
				$checkBox.Checked = $true
			}
		}

		# Function that unchecks all the checkboxes
		function Clear-AllPackages {
			foreach ($checkBox in $checkboxesPackages){
				$checkBox.Checked = $false
			}
			$additionalPackagesBox.Items.clear()
		}

		# Function that adds a new package to the listBox of additional packages
		# If the package already exists it returns $false
		function Add-NewPackage {
			param (
			[Parameter(Mandatory=$true)]
			[string]$packageName
			)
			#$packageName = $packageName.Trim()
			$packageName = $packageName -replace '^\s+|\s+$', ''
			if ($packageName -notin $additionalPackagesBox.Items){
			   $additionalPackagesBox.Items.Add($packageName) | Out-Null
			   return $true
			}
			else{
			   return $false
			}

		}

		function Get-ChocoPackage {
			param (
			[Parameter(Mandatory=$true)]
			[string]$PackageName
			)

			choco search $PackageName -e -r | ForEach-Object {
				$Name, $Version = $_ -split '\|'
				New-Object -TypeName psobject -Property @{
					'Name' = $Name
					'Version' = $Version
				}
			}
		}

		 function Get-VMPackage {
			param (
			[Parameter(Mandatory=$true)]
			[string]$PackageName
			)
			if ($PackageName -notlike "*.vm") {
				$PackageName = $PackageName + ".vm"
			}
			choco search $PackageName --exact -r -s "https://www.myget.org/F/vm-packages/api/v2" | ForEach-Object {
				$Name, $Version = $_ -split '\|'
				New-Object -TypeName psobject -Property @{
					'Name' = $Name
					'Version' = $Version
				}
			}
		}

		function Set-AdditionalPackages {
			$additionalPackagesBox.Items.Clear()
			foreach($package in $additionalPackages)
			{
				$additionalPackagesBox.Items.Add($package) | Out-Null
			}
		}

		function Remove-SelectedPackages {
			$additionalPackagesBox.BeginUpdate()
			while ($additionalPackagesBox.SelectedItems.count -gt 0) {
				$additionalPackagesBox.Items.RemoveAt($additionalPackagesBox.SelectedIndex)
			}
			$additionalPackagesBox.EndUpdate()
		}

		Add-Type -AssemblyName System.Windows.Forms
		[System.Windows.Forms.Application]::EnableVisualStyles()

		$formCategories = New-Object system.Windows.Forms.Form -Property ([ordered]@{
		    ClientSize = New-Object System.Drawing.Point(1015,850)
		    text = "FLARE-VM Package selection"
		    StartPosition = 'CenterScreen'
		    TopMost = $true
		})

		if ([string]::IsNullOrEmpty($customConfig)) {
			$textLabel = "The default configuration (recommended) is pre-selected. Click on the reset button to restore the default configuration."
		} else {
			$textLabel = "The provided custom configuration is pre-selected. Click on the reset button to restore the custom configuration."
		}

		$labelCategories = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Select packages to install"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(30,20)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})


		$labelCategories2 = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = $textLabel
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(30,40)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})

		$panelCategories = New-Object system.Windows.Forms.Panel -Property ([ordered]@{
		    height = 530
		    width = 970
		    location = New-Object System.Drawing.Point(30,60)
		    AutoScroll = $true
		})

		$resetButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    text = "Reset"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(50,800)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})
		$resetButton.Add_Click({
						Set-InitialPackages
						Set-AdditionalPackages
					})

		$allPackagesButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    text = "Select All"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(130,800)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})
		$allPackagesButton.Add_Click({
		   [System.Windows.Forms.MessageBox]::Show('Selecting all packages considerable increases installation time and it is not desirable for most use cases','Warning')
		   Select-AllPackages
		})

		$clearPackagesButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    text = "Clear"
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(210,800)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})
		$clearPackagesButton.Add_Click({Clear-AllPackages})

		$installButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    text = "Install"
		    width = 97
		    height = 37
		    DialogResult = [System.Windows.Forms.DialogResult]::OK
		    location = New-Object System.Drawing.Point(750,800)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
		})

		$cancelButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    text = "Cancel"
		    width = 97
		    height = 37
		    location = New-Object System.Drawing.Point(850,800)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
		    DialogResult = [System.Windows.Forms.DialogResult]::Cancel
		})

		$formCategories.AcceptButton = $installButton
		$formCategories.CancelButton = $cancelButton

		# Create checkboxes for each package
		$checkboxesPackages = New-Object System.Collections.Generic.List[System.Object]
		# Initial vertical position for checkboxes
		$verticalPosition = 25
		$numCheckBoxPackages = 1
		$packages = @()
		foreach ($category in $packagesByCategory.Keys |Sort-Object) {
			# Create Labels for categories
			$labelCategory = New-Object System.Windows.Forms.Label -Property ([ordered]@{
			    Text = $category
			    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',11,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
			    AutoSize = $true
			    Location = New-Object System.Drawing.Point(10, $verticalPosition)
			})
			$panelCategories.Controls.Add($labelCategory)

			$NumPackages = 0
			$verticalPosition2 = $verticalPosition + 20
			$packages= Get-PackagesByCategory -category $category
			foreach ($package in $packages)
			{
				$NumPackages++
				$checkBox = New-Object System.Windows.Forms.CheckBox -Property ([ordered]@{
				    Text = $package.PackageName + ": " + $package.PackageDescription
				    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
				    AutoSize = $true
				    Location = New-Object System.Drawing.Point(10, $verticalPosition2)
				    Name = "checkBox$numCheckBoxPackages"
				})
				$checkboxesPackages.Add($checkBox)
				$panelCategories.Controls.Add($checkBox)
			    $url = $package.PackageUrl
				if ($url -and (Test-HttpsUrl $url)){
					$linkProjectUrl = New-Object System.Windows.Forms.linkLabel -Property ([ordered]@{
					    Top = $checkbox.Top + 2
					    Left = $checkbox.Right - 3
					    AutoSize = $true
					    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
					    LinkColor = "BLUE";
					    ActiveLinkColor = "RED"
					    Text = "Link"
					})
					$linkProjectUrl.Links.Add(0, 4, $url)| Out-Null
					$linkProjectUrl.add_Click({ Start-Process $this.Links.LinkData })
					$panelCategories.Controls.Add($linkProjectUrl)
				}
				$verticalPosition2 += 20
				$numCheckBoxPackages ++
			}
				# Increment to space checkboxes vertically
			$verticalPosition += 20 * ($NumPackages ) + 30
		}

		# Create empty label and add it to the form categories to add some space
		$posEnd = $verticalPosition2 +10
		$emptyLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    Width = 20
		    Height = 10
		    location = New-Object System.Drawing.Point(10,$posEnd)
		})
		$panelCategories.Controls.Add($emptyLabel)

		# Select packages that are in the config.xml
		Set-InitialPackages

		$additionalPackagesLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Additional packages to install"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(30,615)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		$additionalPackagesBox = New-Object system.Windows.Forms.ListBox -Property ([ordered]@{
		    text = "listBox"
		    SelectionMode = 'MultiSimple'
		    Sorted = $true
		    width = 130
		    height = 140
		    location = New-Object System.Drawing.Point(50,640)
		})

		$deletePackageButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    text = "-"
		    width = 24
		    height = 22
		    enabled = $true
		    location = New-Object System.Drawing.Point(190,670)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]::Bold)
		})
		$deletePackageButton.Add_Click({Remove-SelectedPackages})

		$packageLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "FLARE-VM uses Chocolatey packages. You can add additional packages from:"
		    width = 260
		    height = 35
		    AutoSize = $true
		    location = New-Object System.Drawing.Point(300,640)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})

		$labelChoco = New-Object System.Windows.Forms.Label -Property ([ordered]@{
		    Location = New-Object System.Drawing.Point(300,660)
		    Size = New-Object System.Drawing.Size(280,20)
		    AutoSize = $true
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    Text = "Community Packages"
		})

		$linkLabelChoco = New-Object System.Windows.Forms.linkLabel -Property ([ordered]@{
		    Location = New-Object System.Drawing.Point(440,660)
		    AutoSize = $true
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    LinkColor = "BLUE"
		    ActiveLinkColor = "RED"
		    Text = "https://community.chocolatey.org/packages"
		})
		$linkLabelChoco.add_Click({Start-Process "https://community.chocolatey.org/packages"})

		$labelFlarevm = New-Object System.Windows.Forms.Label -Property ([ordered]@{
		    Location = New-Object System.Drawing.Point(300,680)
		    Size = New-Object System.Drawing.Size(280,20)
		    AutoSize = $true
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    Text = "FLARE-VM Packages"
		})

		$linkLabelFlarevm = New-Object System.Windows.Forms.linkLabel -Property ([ordered]@{
		    Location = New-Object System.Drawing.Point(440,680)
		    AutoSize = $true
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    LinkColor = "BLUE"
		    ActiveLinkColor = "RED"
		    Text = "https://github.com/mandiant/VM-Packages/wiki/Packages"
		})
		$linkLabelFlarevm.add_Click({Start-Process "https://github.com/mandiant/VM-Packages/wiki/Packages"})

		Set-AdditionalPackages

		$chocoPackageLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = "Enter package name:"
		    AutoSize = $true
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(300,715)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})

		$packageTextBox = New-Object system.Windows.Forms.TextBox -Property ([ordered]@{
		    multiline = $false
		    width = 210
		    height = 20
		    location = New-Object System.Drawing.Point(300,735)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})
		$packageTextBox.Add_TextChanged({
				  if ($addPackageButton.Enabled -eq $true){
					  $addPackageButton.Enabled = $false
				  }
		})

		$chocoPackageErrorLabel = New-Object system.Windows.Forms.Label -Property ([ordered]@{
		    text = ""
		    AutoSize = $true
		    visible = $false
		    width = 25
		    height = 10
		    location = New-Object System.Drawing.Point(300,765)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
		})

		$findPackageButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    text = "Find Package"
		    width = 118
		    height = 30
		    enabled = $true
		    location = New-Object System.Drawing.Point(520,730)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})
		$findPackageButton.Add_Click({
			$chocoPackageErrorLabel.Visible = $true
			$chocoPackageErrorLabel.text = "Finding package ..."
			$vmPackage = Get-VMPackage -PackageName $packageTextBox.Text.Trim()
			if ($vmPackage){
				$packageName = $vmPackage | Select-Object -ExpandProperty Name
				$chocoPackageErrorLabel.text = "Found VM package"
				$chocoPackageErrorLabel.ForeColor = $successColor
				$packageTextBox.Text = $packageName
				$addPackageButton.enabled = $true
			} else {
				$chocoPackage = Get-ChocoPackage -PackageName $packageTextBox.Text
				if ($chocoPackage) {
				   $chocoPackageErrorLabel.text = "Found Choco package"
				   $chocoPackageErrorLabel.ForeColor = $successColor
				   $addPackageButton.enabled = $true
				} else {
				   $chocoPackageErrorLabel.text = "Package not found"
				   $chocoPackageErrorLabel.ForeColor = $errorColor
				   $addPackageButton.enabled = $false
				}
			}
		})

		$addPackageButton = New-Object system.Windows.Forms.Button -Property ([ordered]@{
		    text = "Add Package"
		    width = 118
		    height = 30
		    enabled = $false
		    location = New-Object System.Drawing.Point(650,730)
		    Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		})
		$addPackageButton.Add_Click({
					  if (Add-NewPackage -PackageName $packageTextBox.Text){
						  $chocoPackageErrorLabel.ForeColor = $successColor
						  $chocoPackageErrorLabel.text = "Package added"
					  }else {
						  $chocoPackageErrorLabel.ForeColor = $errorColor
						  $chocoPackageErrorLabel.text = "Error to add the package: duplicated"
					  }
					  $addPackageButton.enabled = $false
			  })

		$formCategories.controls.AddRange(@($additionalPackagesLabel,$packageLabel,$labelChoco,$labelFlarevm,$linkLabelChoco,$linkLabelFlarevm,$linkLabelFlarevm,$additionalPackagesBox,$deletePackageButton,$chocoPackageLabel,$packageTextBox,$chocoPackageErrorLabel,$findPackageButton,$addPackageButton))
		$formCategories.controls.AddRange(@($labelCategories,$labelCategories2,$panelCategories,$installButton,$resetButton,$allPackagesButton,$cancelButton,$clearPackagesButton))
		$formCategories.Add_Shown({$formCategories.Activate()})
		$resultCategories = $formCategories.ShowDialog()
		if ($resultCategories -eq [System.Windows.Forms.DialogResult]::OK){
			Install-Selected-Packages
		} else {
			Write-Host "[+] Cancel pressed, stopping installation..."
			Start-Sleep 3
			exit 1
		}
	}
		################################################################################
		## END GUI
		################################################################################
}

# Save the config file
Write-Host "[+] Saving configuration file..."
$configXml.save($configPath)

# Parse config and set initial environment variables
Write-Host "[+] Parsing configuration file..."
foreach ($env in $configXml.config.envs.env) {
    $path = [Environment]::ExpandEnvironmentVariables($($env.value))
    Write-Host "`t[+] Setting %$($env.name)% to: $path" -ForegroundColor Green
    [Environment]::SetEnvironmentVariable("$($env.name)", $path, "Machine")
}
[Environment]::SetEnvironmentVariable('VMname', 'FLARE-VM', [EnvironmentVariableTarget]::Machine)
refreshenv

# Install the common module
# This creates all necessary folders based on custom environment variables
Write-Host "[+] Installing shared module..."
choco install common.vm -y --force
refreshenv

# Use single config
$configXml.save((Join-Path ${Env:VM_COMMON_DIR} "config.xml"))
$configXml.save((Join-Path ${Env:VM_COMMON_DIR} "packages.xml"))

# Custom Start Layout setup
Write-Host "[+] Checking for custom Start Layout file..."
$layoutPath = Join-Path "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" "LayoutModification.xml"
if ([string]::IsNullOrEmpty($customLayout)) {
    $layoutSource = 'https://raw.githubusercontent.com/mandiant/flare-vm/main/LayoutModification.xml'
} else {
    $layoutSource = $customLayout
}

Get-ConfigFile $layoutPath $layoutSource
try {
    [xml](Get-Content -LiteralPath $layoutPath -Raw) | Out-Null
} catch {
    Write-Host "`t[!] Invalid layout XML '$layoutPath': $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Log basic system information to assist with troubleshooting
Write-Host "[+] Logging basic system information to assist with any future troubleshooting..."
Import-Module "${Env:VM_COMMON_DIR}\vm.common\vm.common.psm1" -Force -DisableNameChecking
VM-Get-Host-Info

Write-Host "[+] Installing the debloat.vm debloater and performance package"
choco install debloat.vm -y --force

# Download FLARE VM background image
$backgroundImage = "${Env:VM_COMMON_DIR}\background.png"
Save-FileFromUrl -fileSource 'https://raw.githubusercontent.com/mandiant/flare-vm/main/Images/flarevm-background.png' -fileDestination $backgroundImage
# Use background image for lock screen as well
$lockScreenImage = "${Env:VM_COMMON_DIR}\lockscreen.png"
Copy-Item $backgroundImage $lockScreenImage

if (-not $noWait.IsPresent) {
    # Show install notes and wait for timeout
    function Wait-ForInstall ($seconds) {
        $doneDT = (Get-Date).AddSeconds($seconds)
        while($doneDT -gt (Get-Date)) {
            $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
            $percent = ($seconds - $secondsLeft) / $seconds * 100
            Write-Progress -Activity "Please read install notes on console below" -Status "Beginning install in..." -SecondsRemaining $secondsLeft -PercentComplete $percent
            [System.Threading.Thread]::Sleep(500)
        }
        Write-Progress -Activity "Waiting" -Status "Beginning install..." -SecondsRemaining 0 -Completed
    }

    Write-Host @"
[!] INSTALL NOTES - PLEASE READ CAREFULLY [!]

- This install is not 100% unattended. Please monitor the install for possible failures. If install
fails, you may restart the install by re-running the install script with the following command:

    .\install.ps1 -password <password> -noWait -noGui -noChecks

- You can check which packages failed to install by listing the C:\ProgramData\chocolatey\lib-bad
directory. Failed packages are stored by folder name. You may attempt manual installation with the
following command:

    choco install -y <package_name>

- For any issues, please submit to GitHub:

    Installer related: https://github.com/mandiant/flare-vm
    Package related:   https://github.com/mandiant/VM-Packages

[!] Please copy this note for reference [!]
"@ -ForegroundColor Red -BackgroundColor White
    Wait-ForInstall -seconds 30
}

# Begin the package install
Write-Host "[+] Beginning install of configured packages..." -ForegroundColor Green
$PackageName = "installer.vm"
if ($noPassword.IsPresent) {
    Install-BoxstarterPackage -packageName $PackageName
} else {
    Install-BoxstarterPackage -packageName $PackageName -credential $credentials
}

