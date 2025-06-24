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
        Script allows users to customize package selection and envrionment variables used in FLARE VM via a GUI before installation begins.
        A CLI-only mode is also available by providing specific command-line arugment switches.

        To execute this script:
          1) Open PowerShell window as administrator
          2) Allow script execution by running command "Set-ExecutionPolicy Unrestricted"
          3) Unblock the install script by running "Unblock-File .\install.ps1"
          4) Execute the script by running ".\install.ps1"

    .PARAMETER password
        Current user password to allow reboot resiliency via Boxstarter. The script prompts for the password if not provided.

    .PARAMETER noPassword
        Switch parameter indicating a password is not needed for reboots.

    .PARAMETER customConfig
        Path to a configuration XML file. May be a file path or URL.

    .PARAMETER customLayout
        Path to a taskbar layout XML file. May be a file path or URL.

    .PARAMETER noWait
        Switch parameter to skip installation message before installation begins.

    .PARAMETER noGui
        Switch parameter to skip customization GUI.

    .PARAMETER noReboots
        Switch parameter to prevent reboots (not recommended).

    .PARAMETER noChecks
        Switch parameter to skip validation checks (not recommended).

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
  [switch]$noPassword,
  [string]$customConfig = $null,
  [string]$customLayout = $null,
  [switch]$noWait,
  [switch]$noGui,
  [switch]$noReboots,
  [switch]$noChecks
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Function to download files and handle errors consistently
function Save-FileFromUrl {
    param (
        [string]$fileSource,
        [string]$fileDestination,
        [switch]$exitOnError
    )
    Write-Host "[+] Downloading file from '$fileSource'"
    try {
        (New-Object net.webclient).DownloadFile($fileSource,$FileDestination)
    } catch {
        Write-Host "`t[!] Failed to download '$fileSource'"
        Write-Host "`t[!] $_"
        if ($exitOnError) {
            Start-Sleep 3
            exit 1
        }
    }
}

# Function to test the network stack. Ping/GET requests to the resource to ensure that network stack looks good for installation
function Test-WebConnection {
    param (
        [string]$url
    )

    Write-Host "[+] Checking for Internet connectivity ($url)..."

    if (-not (Test-Connection $url -Quiet)) {
        Write-Host "`t[!] It looks like you cannot ping $url. Check your network settings." -ForegroundColor Red
        Start-Sleep 3
        exit 1
    }

    $response = $null
    try {
        $response = Invoke-WebRequest -Uri "https://$url" -UseBasicParsing -DisableKeepAlive
    }
    catch {
        Write-Host "`t[!] Error accessing $url. Exception: $($_.Exception.Message)`n`t[!] Check your network settings." -ForegroundColor Red
        Start-Sleep 3
        exit 1
    }

    if ($response -and $response.StatusCode -ne 200) {
        Write-Host "`t[!] Unable to access $url. Status code: $($response.StatusCode)`n`t[!] Check your network settings." -ForegroundColor Red
        Start-Sleep 3
        exit 1
    }

    Write-Host "`t[+] Internet connectivity check for $url passed" -ForegroundColor Green
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
        # If the source exists as a file, move it to the destination.
        Write-Host "[+] Using existing file as configuration file."
        Move-Item -Path $fileSource -Destination $fileDestination -Force
    }
}

# Set path to user's desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")
Set-Location -Path $desktopPath -PassThru | Out-Null

if (-not $noChecks.IsPresent) {
    # Check PowerShell version
    Write-Host "[+] Checking if PowerShell version is compatible..."
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion -lt [System.Version]"5.0.0") {
        Write-Host "`t[!] You are using PowerShell version $psVersion. This is an old version and it is not supported" -ForegroundColor Red
        Read-Host "Press any key to exit..."
        exit 1
    } else {
        Write-Host "`t[+] Installing with PowerShell version $psVersion" -ForegroundColor Green
    }

    # Ensure script is ran as administrator
    Write-Host "[+] Checking if script is running as administrator..."
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "`t[!] Please run this script as administrator" -ForegroundColor Red
        Read-Host "Press any key to exit..."
        exit 1
    } else {
        Write-Host "`t[+] Running as administrator" -ForegroundColor Green
        Start-Sleep -Milliseconds 500
    }

    # Ensure execution policy is unrestricted
    Write-Host "[+] Checking if execution policy is unrestricted..."
    if ((Get-ExecutionPolicy).ToString() -ne "Unrestricted") {
        Write-Host "`t[!] Please run this script after updating your execution policy to unrestricted" -ForegroundColor Red
        Write-Host "`t[-] Hint: Set-ExecutionPolicy Unrestricted" -ForegroundColor Yellow
        Read-Host "Press any key to exit..."
        exit 1
    } else {
        Write-Host "`t[+] Execution policy is unrestricted" -ForegroundColor Green
        Start-Sleep -Milliseconds 500
    }

    # Check if Windows < 10
    $os = Get-CimInstance -Class Win32_OperatingSystem
    $osMajorVersion = $os.Version.Split('.')[0] # Version examples: "6.1.7601", "10.0.19045"
    Write-Host "[+] Checking Operating System version compatibility..."
    if ($osMajorVersion -lt 10) {
        Write-Host "`t[!] Only Windows >= 10 is supported" -ForegroundColor Yellow
        Write-Host "[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -notin @("y","Y")) {
            exit 1
        }
    }

    # Check if host has been tested
    # 17763: the version used by windows-2019 in GH actions
    # 19045: https://www.microsoft.com/en-us/software-download/windows10ISO downloaded on April 25 2023.
    # 20348: the version used by windows-2022 in GH actions
    $testedVersions = @(17763, 19045, 20348)
    if ($os.BuildNumber -notin $testedVersions) {
        Write-Host "`t[!] Windows version $osVersion has not been tested. Tested versions: $($testedVersions -join ', ')" -ForegroundColor Yellow
        Write-Host "`t[+] You are welcome to continue, but may experience errors downloading or installing packages" -ForegroundColor Yellow
        Write-Host "[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -notin @("y","Y")) {
            exit 1
        }
    } else {
        Write-Host "`t[+] Installing on Windows version $osVersion" -ForegroundColor Green
    }

    # Check if system is a virtual machine
    $virtualModels = @('VirtualBox', 'VMware', 'Virtual Machine', 'Hyper-V')
    $computerSystemModel = (Get-CimInstance -Class Win32_ComputerSystem).Model
    $isVirtualModel = $false

    foreach ($model in $virtualModels) {
        if ($computerSystemModel.Contains($model)) {
            $isVirtualModel = $true
            break
        }
    }

    if (!$isVirtualModel) {
        Write-Host "`t[!] You are not on a virual machine or have hardened your machine to not appear as a virtual machine" -ForegroundColor Red
        Write-Host "`t[!] Please do NOT install this on your host system as it can't be uninstalled completely" -ForegroundColor Red
        Write-Host "`t[!] ** Please only install on a virtual machine **" -ForegroundColor Red
        Write-Host "`t[!] ** Only continue if you know what you are doing! **" -ForegroundColor Red
        Write-Host "[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -notin @("y","Y")) {
            exit 1
        }
    }

    # Check for spaces in the username, exit if identified
    Write-Host "[+] Checking for spaces in the username..."
    if (${Env:UserName} -match '\s') {
        Write-Host "`t[!] Username '${Env:UserName}' contains a space and will break installation." -ForegroundColor Red
        Write-Host "`t[!] Exiting..." -ForegroundColor Red
        Start-Sleep 3
        exit 1
    } else {
        Write-Host "`t[+] Username '${Env:UserName}' does not contain any spaces." -ForegroundColor Green
    }

    # Check if host has enough disk space
    Write-Host "[+] Checking if host has enough disk space..."
    $disk = Get-PSDrive (Get-Location).Drive.Name
    Start-Sleep -Seconds 1
    if (-Not (($disk.used + $disk.free)/1GB -gt 58.8)) {
        Write-Host "`t[!] A minimum of 60 GB hard drive space is preferred. Please increase hard drive space of the VM, reboot, and retry install" -ForegroundColor Red
        Write-Host "`t[+] If you have multiple drives, you may change the tool installation location via the envrionment variable %RAW_TOOLS_DIR% in config.xml or GUI" -ForegroundColor Yellow
        Write-Host "`t[+] However, packages provided from the Chocolatey community repository will install to their default location" -ForegroundColor Yellow
        Write-Host "`t[+] See: https://stackoverflow.com/questions/19752533/how-do-i-set-chocolatey-to-install-applications-onto-another-drive" -ForegroundColor Yellow
        Write-Host "[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -notin @("y","Y")) {
            exit 1
        }
    } else {
        Write-Host "`t[+] Disk is larger than 60 GB" -ForegroundColor Green
    }

    # Internet connectivity checks
    Test-WebConnection 'google.com'
    Test-WebConnection 'github.com'
    Test-WebConnection 'raw.githubusercontent.com'

    Write-Host "`t[+] Network connectivity looks good" -ForegroundColor Green

    # Check if Tamper Protection is disabled
    Write-Host "[+] Checking if Windows Defender Tamper Protection is disabled..."
    try {
        $tpEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction Stop
        if ($tpEnabled.TamperProtection -eq 5) {
            Write-Host "`t[!] Please disable Tamper Protection, reboot, and rerun installer" -ForegroundColor Red
            Write-Host "`t[+] Hint: https://support.microsoft.com/en-us/windows/prevent-changes-to-security-settings-with-tamper-protection-31d51aaa-645d-408e-6ce7-8d7f8e593f87" -ForegroundColor Yellow
            Write-Host "`t[+] Hint: https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-windows-defender-antivirus.html" -ForegroundColor Yellow
            Write-Host "`t[+] Hint: https://github.com/jeremybeaume/tools/blob/master/disable-defender.ps1" -ForegroundColor Yellow
            Write-Host "`t[+] Hint: https://lazyadmin.nl/win-11/turn-off-windows-defender-windows-11-permanently/" -ForegroundColor Yellow
            Write-Host "`t[+] You are welcome to continue, but may experience errors downloading or installing packages" -ForegroundColor Yellow
            Write-Host "`t[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
            $response = Read-Host
            if ($response -notin @("y","Y")) {
                exit 1
            }
        } else {
            Write-Host "`t[+] Tamper Protection is disabled" -ForegroundColor Green
            Start-Sleep -Milliseconds 500
        }
    } catch {
        Write-Host "`t[+] Tamper Protection is either not enabled or not detected" -ForegroundColor Yellow
        Write-Host "`t[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -notin @("y","Y")) {
            exit 1
        }
        Start-Sleep -Milliseconds 500
    }

    # Check if Defender is disabled
    Write-Host "[+] Checking if Windows Defender service is disabled..."
    $defender = Get-Service -Name WinDefend -ea 0
    if ($null -ne $defender) {
        if ($defender.Status -eq "Running") {
            Write-Host "`t[!] Please disable Windows Defender through Group Policy, reboot, and rerun installer" -ForegroundColor Red
            Write-Host "`t[+] Hint: https://stackoverflow.com/questions/62174426/how-to-permanently-disable-windows-defender-real-time-protection-with-gpo" -ForegroundColor Yellow
            Write-Host "`t[+] Hint: https://www.windowscentral.com/how-permanently-disable-windows-defender-windows-10" -ForegroundColor Yellow
            Write-Host "`t[+] Hint: https://github.com/jeremybeaume/tools/blob/master/disable-defender.ps1" -ForegroundColor Yellow
            Write-Host "`t[+] You are welcome to continue, but may experience errors downloading or installing packages" -ForegroundColor Yellow
            Write-Host "`t[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
            $response = Read-Host
            if ($response -notin @("y","Y")) {
                exit 1
            }
        } else {
            Write-Host "`t[+] Defender is disabled" -ForegroundColor Green
            Start-Sleep -Milliseconds 500
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

if (-not $noPassword.IsPresent) {
    # Get user credentials for autologin during reboots
    if ([string]::IsNullOrEmpty($password)) {
        Write-Host "[+] Getting user credentials ..."
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True
        Start-Sleep -Milliseconds 500
        $credentials = Get-Credential ${Env:UserName}
    } else {
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $credentials = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList ${Env:UserName}, $securePassword
    }
}

# Check Boxstarter version
$boxstarterVersionGood = $false
if (${Env:ChocolateyInstall} -and (Test-Path "${Env:ChocolateyInstall}\bin\choco.exe")) {
    choco info -l -r "boxstarter" | ForEach-Object { $name, $version = $_ -split '\|' }
    $boxstarterVersionGood = [System.Version]$version -ge [System.Version]"3.0.2"
}

# Install Boxstarter if needed
if (-not $boxstarterVersionGood) {
    Write-Host "[+] Installing Boxstarter..." -ForegroundColor Cyan
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1'))
    Get-Boxstarter -Force

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
$global:VerbosePreference = "SilentlyContinue"
Set-BoxstarterConfig -NugetSources "$desktopPath;.;https://www.myget.org/F/vm-packages/api/v2;https://myget.org/F/vm-packages/api/v2;https://chocolatey.org/api/v2"
Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowFullPathInTitleBar

# Set Chocolatey options
Write-Host "[+] Updating Chocolatey settings..."
choco sources add -n="vm-packages" -s "$desktopPath;.;https://www.myget.org/F/vm-packages/api/v2;https://myget.org/F/vm-packages/api/v2" --priority 1
choco feature enable -n allowGlobalConfirmation
choco feature enable -n allowEmptyChecksums
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
    Write-Host "`t[-] Please download config.xml from $configPathUrl to your desktop" -ForegroundColor Yellow
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
$configXml = [xml](Get-Content $configPath)

if (-not $noGui.IsPresent) {
    $errorColor = [System.Drawing.ColorTranslator]::FromHtml("#c80505")
    $successColor = [System.Drawing.ColorTranslator]::FromHtml("#417505")

    Write-Host "[+] Starting GUI to allow user to edit configuration file..."
    ################################################################################
    ## BEGIN GUI
    ################################################################################
    Add-Type -AssemblyName System.Windows.Forms


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
       $vmPackagesUrl = "https://www.myget.org/F/vm-packages/api/v2/Packages?$filter=IsLatestVersion%20eq%20true"
       $vmPackagesFile = "${Env:VM_COMMON_DIR}\vm-packages.xml"
       $packagesByCategory=@{}
       do {
          # Download the XML from MyGet API
          Save-FileFromUrl -fileSource $vmPackagesUrl -fileDestination $vmPackagesFile --exitOnError

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

                  # Initialize category as an empty array
                  if (-not ($packagesByCategory.ContainsKey($category))) {
                     $packagesByCategory[$category] = @()
                  }
		  # Add the PackageName and PackageDesccription to each entry in the array
                  $packagesByCategory[$category] += [PSCustomObject]@{
                     PackageName = $packageName
                     PackageDescription = $description
                  }
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

    # Gather lists of packages
    $envs = [ordered]@{}
    $configXml.config.envs.env.ForEach({ $envs[$_.name] = $_.value })
    $excludedCategories=@('Command and Control','Credential Access','Exploitation','Forensic','Lateral Movement', 'Payload Development','Privilege Escalation','Reconnaissance','Wordlists','Web Application')
    # Read packages to install from the config
    $packagesToInstall = $configXml.config.packages.package.name
    $packagesByCategory = Get-Packages-Categories
    $listedPackages = Get-AllPackages
    $additionalPackages = Get-AdditionalPackages

    $formEnv                   = New-Object system.Windows.Forms.Form
    $formEnv.ClientSize        = New-Object System.Drawing.Point(750,350)
    $formEnv.text              = "FLARE VM Install Customization"
    $formEnv.TopMost           = $true
    $formEnv.MaximizeBox       = $false
    $formEnv.FormBorderStyle   = 'FixedDialog'
    $formEnv.StartPosition     = 'CenterScreen'

    $envVarGroup            = New-Object system.Windows.Forms.Groupbox
    $envVarGroup.height     = 201
    $envVarGroup.width      = 690
    $envVarGroup.text       = "Environment Variable Customization"
    $envVarGroup.location   = New-Object System.Drawing.Point(15,59)

    $welcomeLabel           = New-Object system.Windows.Forms.Label
    $welcomeLabel.text      = "Welcome to FLARE VM's custom installer. Please select your options below.`nDefault values will be used if you make no modifications."
    $welcomeLabel.AutoSize  = $true
    $welcomeLabel.width     = 25
    $welcomeLabel.height    = 10
    $welcomeLabel.location  = New-Object System.Drawing.Point(15,14)
    $welcomeLabel.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $vmCommonDirText                 = New-Object system.Windows.Forms.TextBox
    $vmCommonDirText.multiline       = $false
    $vmCommonDirText.width           = 385
    $vmCommonDirText.height          = 20
    $vmCommonDirText.location        = New-Object System.Drawing.Point(190,21)
    $vmCommonDirText.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $vmCommonDirText.text            = $envs['VM_COMMON_DIR']

    $vmCommonDirSelect               = New-Object system.Windows.Forms.Button
    $vmCommonDirSelect.text          = "Select Folder"
    $vmCommonDirSelect.width         = 95
    $vmCommonDirSelect.height        = 30
    $vmCommonDirSelect.location      = New-Object System.Drawing.Point(588,17)
    $vmCommonDirSelect.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $selectFolderArgs1 = @{textBox=$vmCommonDirText; envVar="VM_COMMON_DIR"}
    $vmCommonDirSelect.Add_Click({Get-Folder @selectFolderArgs1})

    $vmCommonDirLabel                = New-Object system.Windows.Forms.Label
    $vmCommonDirLabel.text           = "%VM_COMMON_DIR%"
    $vmCommonDirLabel.AutoSize       = $true
    $vmCommonDirLabel.width          = 25
    $vmCommonDirLabel.height         = 10
    $vmCommonDirLabel.location       = New-Object System.Drawing.Point(2,24)
    $vmCommonDirLabel.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]::Bold)

    $vmCommonDirNote                 = New-Object system.Windows.Forms.Label
    $vmCommonDirNote.text            = "Shared module and metadata for VM (e.g., config, logs, etc...)"
    $vmCommonDirNote.AutoSize        = $true
    $vmCommonDirNote.width           = 25
    $vmCommonDirNote.height          = 10
    $vmCommonDirNote.location        = New-Object System.Drawing.Point(190,46)
    $vmCommonDirNote.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $toolListDirText                 = New-Object system.Windows.Forms.TextBox
    $toolListDirText.multiline       = $false
    $toolListDirText.width           = 385
    $toolListDirText.height          = 20
    $toolListDirText.location        = New-Object System.Drawing.Point(190,68)
    $toolListDirText.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $toolListDirText.text            = $envs['TOOL_LIST_DIR']

    $toolListDirSelect               = New-Object system.Windows.Forms.Button
    $toolListDirSelect.text          = "Select Folder"
    $toolListDirSelect.width         = 95
    $toolListDirSelect.height        = 30
    $toolListDirSelect.location      = New-Object System.Drawing.Point(588,64)
    $toolListDirSelect.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $selectFolderArgs2 = @{textBox=$toolListDirText; envVar="TOOL_LIST_DIR"}
    $toolListDirSelect.Add_Click({Get-Folder @selectFolderArgs2})

    $toolListDirLabel                = New-Object system.Windows.Forms.Label
    $toolListDirLabel.text           = "%TOOL_LIST_DIR%"
    $toolListDirLabel.AutoSize       = $true
    $toolListDirLabel.width          = 25
    $toolListDirLabel.height         = 10
    $toolListDirLabel.location       = New-Object System.Drawing.Point(2,71)
    $toolListDirLabel.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]::Bold)

    $toolListDirNote                 = New-Object system.Windows.Forms.Label
    $toolListDirNote.text            = "Folder to store tool categories and shortcuts"
    $toolListDirNote.AutoSize        = $true
    $toolListDirNote.width           = 25
    $toolListDirNote.height          = 10
    $toolListDirNote.location        = New-Object System.Drawing.Point(190,94)
    $toolListDirNote.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $rawToolsDirText                 = New-Object system.Windows.Forms.TextBox
    $rawToolsDirText.multiline       = $false
    $rawToolsDirText.width           = 385
    $rawToolsDirText.height          = 20
    $rawToolsDirText.location        = New-Object System.Drawing.Point(190,113)
    $rawToolsDirText.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $rawToolsDirText.text            = $envs['RAW_TOOLS_DIR']

    $rawToolsDirSelect               = New-Object system.Windows.Forms.Button
    $rawToolsDirSelect.text          = "Select Folder"
    $rawToolsDirSelect.width         = 95
    $rawToolsDirSelect.height        = 30
    $rawToolsDirSelect.location      = New-Object System.Drawing.Point(588,109)
    $rawToolsDirSelect.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $selectFolderArgs4 = @{textBox=$rawToolsDirText; envVar="RAW_TOOLS_DIR"}
    $rawToolsDirSelect.Add_Click({Get-Folder @selectFolderArgs4})

    $rawToolsDirLabel                = New-Object system.Windows.Forms.Label
    $rawToolsDirLabel.text           = "%RAW_TOOLS_DIR%"
    $rawToolsDirLabel.AutoSize       = $true
    $rawToolsDirLabel.width          = 25
    $rawToolsDirLabel.height         = 10
    $rawToolsDirLabel.location       = New-Object System.Drawing.Point(2,116)
    $rawToolsDirLabel.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]::Bold)

    $rawToolsDirNote                 = New-Object system.Windows.Forms.Label
    $rawToolsDirNote.text            = "Folder to store downloaded tools"
    $rawToolsDirNote.AutoSize        = $true
    $rawToolsDirNote.width           = 25
    $rawToolsDirNote.height          = 10
    $rawToolsDirNote.location        = New-Object System.Drawing.Point(190,137)
    $rawToolsDirNote.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $okButton                        = New-Object system.Windows.Forms.Button
    $okButton.text                   = "Continue"
    $okButton.width                  = 97
    $okButton.height                 = 37
    $okButton.location               = New-Object System.Drawing.Point(480,280)
    $okButton.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',11)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $cancelButton                    = New-Object system.Windows.Forms.Button
    $cancelButton.text               = "Cancel"
    $cancelButton.width              = 97
    $cancelButton.height             = 37
    $cancelButton.location           = New-Object System.Drawing.Point(580,280)
    $cancelButton.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',11)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $formEnv.controls.AddRange(@($envVarGroup,$okButton,$cancelButton,$welcomeLabel))
    $formEnv.AcceptButton = $okButton
    $formEnv.CancelButton = $cancelButton

    $envVarGroup.controls.AddRange(@($vmCommonDirText,$vmCommonDirSelect,$vmCommonDirLabel,$toolListDirText,$toolListDirSelect,$toolListDirLabel,$toolListShortCutText,$toolListShortcutSelect,$toolListShortcutLabel,$vmCommonDirNote,$toolListDirNote,$toolListShortcutNote,$rawToolsDirText,$rawToolsDirSelect,$rawToolsDirLabel,$rawToolsDirNote))

    $formEnv.Topmost = $true
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

    $formCategories                            = New-Object system.Windows.Forms.Form
    $formCategories.ClientSize                 = New-Object System.Drawing.Point(1015,850)
    $formCategories.text                       = "FLARE-VM Package selection"
    $formCategories.StartPosition              = 'CenterScreen'
    $formCategories.TopMost                    = $true

    if ([string]::IsNullOrEmpty($customConfig)) {
        $textLabel = "The default configuration (recommended) is pre-selected. Click on the reset button to restore the default configuration."
    } else {
	    $textLabel = "The provided custom configuration is pre-selected. Click on the reset button to restore the custom configuration."
    }

    $labelCategories                = New-Object system.Windows.Forms.Label
    $labelCategories.text           = "Select packages to install"
    $labelCategories.AutoSize       = $true
    $labelCategories.width          = 25
    $labelCategories.height         = 10
    $labelCategories.location       = New-Object System.Drawing.Point(30,20)
    $labelCategories.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))


    $labelCategories2                = New-Object system.Windows.Forms.Label
    $labelCategories2.text           = $textLabel
    $labelCategories2.AutoSize       = $true
    $labelCategories2.location       = New-Object System.Drawing.Point(30,40)
    $labelCategories2.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $panelCategories                = New-Object system.Windows.Forms.Panel
    $panelCategories.height         = 530
    $panelCategories.width          = 970
    $panelCategories.location       = New-Object System.Drawing.Point(30,60)
    $panelCategories.AutoScroll     = $true

    $resetButton                 = New-Object system.Windows.Forms.Button
    $resetButton.text            = "Reset"
    $resetButton.AutoSize        = $true
    $resetButton.location        = New-Object System.Drawing.Point(50,800)
    $resetButton.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $resetButton.Add_Click({
                    Set-InitialPackages
                    Set-AdditionalPackages
                })

    $allPackagesButton                 = New-Object system.Windows.Forms.Button
    $allPackagesButton.text            = "Select All"
    $allPackagesButton.AutoSize        = $true
    $allPackagesButton.location        = New-Object System.Drawing.Point(130,800)
    $allPackagesButton.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $allPackagesButton.Add_Click({
       [System.Windows.Forms.MessageBox]::Show('Selecting all packages considerable increases installation time and it is not desirable for most use cases','Warning')
       Select-AllPackages
    })

    $clearPackagesButton	         = New-Object system.Windows.Forms.Button
    $clearPackagesButton.text            = "Clear"
    $clearPackagesButton.AutoSize        = $true
    $clearPackagesButton.location        = New-Object System.Drawing.Point(210,800)
    $clearPackagesButton.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $clearPackagesButton.Add_Click({Clear-AllPackages})

    $installButton            = New-Object system.Windows.Forms.Button
    $installButton.text       = "Install"
    $installButton.width      = 97
    $installButton.height     = 37
    $installButton.DialogResult   = [System.Windows.Forms.DialogResult]::OK
    $installButton.location   = New-Object System.Drawing.Point(750,800)
    $installButton.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

    $cancelButton            = New-Object system.Windows.Forms.Button
    $cancelButton.text       = "Cancel"
    $cancelButton.width      = 97
    $cancelButton.height     = 37
    $cancelButton.location   = New-Object System.Drawing.Point(850,800)
    $cancelButton.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

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
        $labelCategory = New-Object System.Windows.Forms.Label
        $labelCategory.Text = $category
        $labelCategory.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',11,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
        $labelCategory.AutoSize = $true
        $labelCategory.Location = New-Object System.Drawing.Point(10, $verticalPosition)
        $panelCategories.Controls.Add($labelCategory)

        $NumPackages = 0
        $verticalPosition2 = $verticalPosition + 20
		$packages= Get-PackagesByCategory -category $category
		foreach ($package in $packages)
		{
		    $NumPackages++
		    $checkBox = New-Object System.Windows.Forms.CheckBox
		    $checkBox.Text = $package.PackageName + ": " + $package.PackageDescription
		    $checkBox.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
		    $checkBox.AutoSize = $true
		    $checkBox.Location = New-Object System.Drawing.Point(10, $verticalPosition2)
		    $checkBox.Name = "checkBox$numCheckBoxPackages"
		    $checkboxesPackages.Add($checkBox)
		    $panelCategories.Controls.Add($checkBox)
		    $verticalPosition2 += 20
		    $numCheckBoxPackages ++
		}
        	# Increment to space checkboxes vertically
		$verticalPosition += 20 * ($NumPackages ) + 30
		$numCategories ++
	}

    # Create empty label and add it to the form categories to add some space
    $posEnd = $verticalPosition2 +10
    $emptyLabel                = New-Object system.Windows.Forms.Label
    $emptyLabel.Width = 20
    $emptyLabel.Height = 10
    $emptyLabel.location       = New-Object System.Drawing.Point(10,$posEnd)
    $panelCategories.Controls.Add($emptyLabel)

    # Select packages that are in the config.xml
    Set-InitialPackages

    $additionalPackagesLabel                          = New-Object system.Windows.Forms.Label
    $additionalPackagesLabel.text                     = "Additional packages to install"
    $additionalPackagesLabel.AutoSize                 = $true
    $additionalPackagesLabel.width                    = 25
    $additionalPackagesLabel.height                   = 10
    $additionalPackagesLabel.location                 = New-Object System.Drawing.Point(30,615)
    $additionalPackagesLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $additionalPackagesBox                 = New-Object system.Windows.Forms.ListBox
    $additionalPackagesBox.text            = "listBox"
    $additionalPackagesBox.SelectionMode   = 'MultiSimple'
    $additionalPackagesBox.Sorted          = $true
    $additionalPackagesBox.width           = 130
    $additionalPackagesBox.height          = 140
    $additionalPackagesBox.location        = New-Object System.Drawing.Point(50,640)

    $deletePackageButton          = New-Object system.Windows.Forms.Button
    $deletePackageButton.text     = "-"
    $deletePackageButton.width    = 24
    $deletePackageButton.height   = 22
    $deletePackageButton.enabled   = $true
    $deletePackageButton.location  = New-Object System.Drawing.Point(190,670)
    $deletePackageButton.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]::Bold)
    $deletePackageButton.Add_Click({Remove-SelectedPackages})

    $packageLabel                          = New-Object system.Windows.Forms.Label
    $packageLabel.text                     = "FLARE-VM uses Chocolatey packages. You can add additional packages from:"
    $packageLabel.width                    = 260
    $packageLabel.height                   = 35
    $packageLabel.AutoSize                 = $true
    $packageLabel.location                 = New-Object System.Drawing.Point(300,640)
    $packageLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $labelChoco                             = New-Object System.Windows.Forms.Label
    $labelChoco.Location                    = New-Object System.Drawing.Point(300,660)
    $labelChoco.Size                        = New-Object System.Drawing.Size(280,20)
    $labelChoco.AutoSize                    = $true
    $labelChoco.Font                        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $labelChoco.Text                        = "Community Packages"

    $linkLabelChoco                             = New-Object System.Windows.Forms.linkLabel
    $linkLabelChoco.Location                    = New-Object System.Drawing.Point(440,660)
    $linkLabelChoco.AutoSize                    = $true
    $linkLabelChoco.Font                        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $linkLabelChoco.LinkColor                   = "BLUE"
    $linkLabelChoco.ActiveLinkColor             = "RED"
    $linkLabelChoco.Text                        = "https://community.chocolatey.org/packages"
    $linkLabelChoco.add_Click({[system.Diagnostics.Process]::start("https://community.chocolatey.org/packages")})

    $labelFlarevm                             = New-Object System.Windows.Forms.Label
    $labelFlarevm.Location                    = New-Object System.Drawing.Point(300,680)
    $labelFlarevm.Size                        = New-Object System.Drawing.Size(280,20)
    $labelFlarevm.AutoSize                     = $true
    $labelFlarevm.Font                        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $labelFlarevm.Text                        = "FLARE-VM Packages"

    $linkLabelFlarevm                             = New-Object System.Windows.Forms.linkLabel
    $linkLabelFlarevm.Location                    = New-Object System.Drawing.Point(440,680)
    $linkLabelFlarevm.AutoSize                    = $true
    $linkLabelFlarevm.Font                        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $linkLabelFlarevm.LinkColor                   = "BLUE"
    $linkLabelFlarevm.ActiveLinkColor             = "RED"
    $linkLabelFlarevm.Text                        = "https://github.com/mandiant/VM-Packages/wiki/Packages"
    $linkLabelFlarevm.add_Click({[system.Diagnostics.Process]::start("https://github.com/mandiant/VM-Packages/wiki/Packages")})

    Set-AdditionalPackages

    $chocoPackageLabel                          = New-Object system.Windows.Forms.Label
    $chocoPackageLabel.text                     = "Enter package name:"
    $chocoPackageLabel.AutoSize                 = $true
    $chocoPackageLabel.width                    = 25
    $chocoPackageLabel.height                   = 10
    $chocoPackageLabel.location                 = New-Object System.Drawing.Point(300,715)
    $chocoPackageLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $packageTextBox                        = New-Object system.Windows.Forms.TextBox
    $packageTextBox.multiline              = $false
    $packageTextBox.width                  = 210
    $packageTextBox.height                 = 20
    $packageTextBox.location               = New-Object System.Drawing.Point(300,735)
    $packageTextBox.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $packageTextBox.Add_TextChanged({
              if ($addPackageButton.Enabled -eq $true){
                  $addPackageButton.Enabled = $false
              }
    })

    $chocoPackageErrorLabel                          = New-Object system.Windows.Forms.Label
    $chocoPackageErrorLabel.text                     = ""
    $chocoPackageErrorLabel.AutoSize                 = $true
    $chocoPackageErrorLabel.visible                  = $false
    $chocoPackageErrorLabel.width                    = 25
    $chocoPackageErrorLabel.height                   = 10
    $chocoPackageErrorLabel.location                 = New-Object System.Drawing.Point(300,765)
    $chocoPackageErrorLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $findPackageButton          = New-Object system.Windows.Forms.Button
    $findPackageButton.text     = "Find Package"
    $findPackageButton.width    = 118
    $findPackageButton.height   = 30
    $findPackageButton.enabled   = $true
    $findPackageButton.location  = New-Object System.Drawing.Point(520,730)
    $findPackageButton.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
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

    $addPackageButton          = New-Object system.Windows.Forms.Button
    $addPackageButton.text     = "Add Package"
    $addPackageButton.width    = 118
    $addPackageButton.height   = 30
    $addPackageButton.enabled   = $false
    $addPackageButton.location  = New-Object System.Drawing.Point(650,730)
    $addPackageButton.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
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

    $formCategories.controls.AddRange(@($additionalPackagesLabel,$packageLabel,$labelChoco,$labelFlarevm,$linkLabelChoco,$linkLabelFlarevm,$linkLabelFlarevm,$additionalPackagesBox,$deletePackageButton,$chocoPackageButton,$chocoPackageLabel,$packageTextBox,$chocoPackageErrorLabel,$findPackageButton,$addPackageButton))
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
    [Environment]::SetEnvironmentVariable('VMname', 'FLARE-VM', [EnvironmentVariableTarget]::Machine)
}
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

