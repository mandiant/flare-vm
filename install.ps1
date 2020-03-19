###########################################
#
# FLARE VM Installation Script
#
# To execute this script:
#   1) Open powershell window as administrator
#   2) Allow script execution by running command "Set-ExecutionPolicy Unrestricted"
#   3) Execute the script by running ".\install.ps1"
#
###########################################

param (
  [string]$password = "",
  [string]$profile_file = $null,
  [switch]$norestart
)

function Set-EnvironmentVariableWrap([string] $key, [string] $value)
{
<#
.SYNOPSIS
  Set the environment variable for all process, user and system wide scopes
.OUTPUTS
  True on success | False on error
#>
  try {
    [Environment]::SetEnvironmentVariable($key, $value)
    [Environment]::SetEnvironmentVariable($key, $value, 1)
    [Environment]::SetEnvironmentVariable($key, $value, 2)
  
    $rc = $true
  } catch {
    $rc = $false
  }
  $rc
}


function ConvertFrom-Json([object] $item) {
<#
.SYNOPSIS
  Convert a JSON string into a hash table

.DESCRIPTION
  Convert a JSON string into a hash table, without any validation

.OUTPUTS
  [hashtable] or $null
#>
  Add-Type -Assembly system.web.extensions
  $ps_js = New-Object system.web.script.serialization.javascriptSerializer

  try {
    $result = $ps_js.DeserializeObject($item)
  } catch {
    $result = $null
  }
  
  # Cast dictionary to hashtable
  [hashtable] $result
}


function ConvertTo-Json([object] $data) {
<#
.SYNOPSIS
  Convert a hashtable to a JSON string

.DESCRIPTION
  Convert a hashtable to a JSON string, without any validation

.OUTPUTS
  [string] or $null
#>
  Add-Type -Assembly system.web.extensions
  $ps_js = New-Object system.web.script.serialization.javascriptSerializer

  #The comma operator is the array construction operator in PowerShell
  try {
    $result = $ps_js.Serialize($data)
  } catch {
    $result = $null
  }
  
  $result
}


function Import-JsonFile {
<#
.DESCRIPTION
  Load a hashtable from a JSON file
  
.OUTPUTS
  [hashtable] or $null
#>
  param([string] $path)
  try {
    $json = Get-Content $path
    $result = ConvertFrom-Json $json
  } catch {
    $result = $null
  }
  
  $result
}


function Make-InstallerPackage($PackageName, $TemplateDir, $packages) {
  <#
  .SYNOPSIS
  Make a new installer package

  .DESCRIPTION
  Make a new installer package named installer. This package uses the custom packages.json file specified by the user.
  User can then call "Install-BoxStarterPackage installer" using the local repo.
  #>

  function Get-Tree($Path,$Include='*') { 
    @(Get-Item $Path -Include $Include -Force) + (Get-ChildItem $Path -Recurse -Include $Include -Force) | sort pspath -Descending -unique
  } 

  function Remove-Tree($Path,$Include='*') { 
      Get-Tree $Path $Include | Remove-Item -force -recurse
  } 

  $PackageDir = Join-Path $BoxStarter.LocalRepo $PackageName
  if (Test-Path $PackageDir) {
    Remove-Tree $PackageDir
  }

  $files = Get-ChildItem -Path $BoxStarter.LocalRepo -Filter $PackageName | Foreach-Object {($_.BaseName)} | Sort -Descending
  if ($files.count -gt 0) {
    foreach ($f in $files) {
      Remove-Item $f -force
    }
  }

  $Tmp = [System.IO.Path]::GetTempFileName()
  Write-Host -ForegroundColor Green "packages file is" + $tmp
  ConvertTo-Json @{"packages" = $packages} | Out-File -FilePath $Tmp
  
  if ([System.IO.Path]::IsPathRooted($TemplateDir)) {
    $ToolsDir = Join-Path $TemplateDir "tools"
  } else {
    $Here = Get-Location
    $ToolsDir = Join-Path (Join-Path $Here $TemplateDir) "tools"
  }
  $Dest = Join-Path $ToolsDir "packages.json"

  Move-Item -Force -Path $Tmp -Destination $Dest
  New-BoxstarterPackage -Name $PackageName -Description "My Own Installer" -Path $ToolsDir
}

function installBoxStarter()
{
  <#
  .SYNOPSIS
  Install BoxStarter on the current system
  .DESCRIPTION
  Install BoxStarter on the current system. Returns $true or $false to indicate success or failure. On
  fresh windows 7 systems, some root certificates are not installed and updated properly. Therefore,
  this funciton also temporarily trust all certificates before installing BoxStarter.
  #>

  # See: https://chocolatey.org/docs/installation#completely-offline-install
  # Attempt to set highest encryption available for SecurityProtocol.
  # PowerShell will not set this by default (until maybe .NET 4.6.x). This
  # will typically produce a message for PowerShell v2 (just an info message though)
  try {
    # Set TLS 1.2 (3072), then TLS 1.1 (768), then TLS 1.0 (192), finally SSL 3.0 (48)
    # Use integers because the enumeration values for TLS 1.2 and TLS 1.1 won't
    # exist in .NET 4.0, even though they are addressable if .NET 4.5+ is
    # installed (.NET 4.5 is an in-place upgrade).
    [System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192 -bor 48
  } catch {
    Write-Output 'Unable to set PowerShell to use TLS 1.2 and TLS 1.1 due to old .NET Framework installed. If you see underlying connection closed or trust errors, you may need to upgrade to .NET Framework 4.5+ and PowerShell v3+.'
  }

  # Try to install BoxStarter as is first, then fall back to be over trusing only if this step fails.
  try {
    if ($PSVersionTable -And $PSVersionTable.PSVersion.Major -ge 5) {
      . { iwr -useb https://boxstarter.org/bootstrapper.ps1 } | iex; Get-Boxstarter -Force
    } else {
      iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); Get-Boxstarter -Force
    }
    return $true
  } catch {
    Write-Host "Failed to install boxstarter. Trying again."
  }

  # https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
  # Allows current PowerShell session to trust all certificates
  # Also a good find: https://www.briantist.com/errors/could-not-establish-trust-relationship-for-the-ssltls-secure-channel/
  try {
  Add-Type @"
  using System.Net;
  using System.Security.Cryptography.X509Certificates;
  public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
      ServicePoint srvPoint, X509Certificate certificate,
      WebRequest request, int certificateProblem) {
      return true;
    }
  }
"@
  } catch {
      Write-Host "Failed to add new type"
  }

  try {
    # Become overly trusting
    $prevCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # Download and install boxstarter
    if ($PSVersionTable -And $PSVersionTable.PSVersion.Major -ge 5) {
      . { iwr -useb https://boxstarter.org/bootstrapper.ps1 } | iex; Get-Boxstarter -Force
    } else {
      iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); Get-Boxstarter -Force
    }
    # Restore previous trust settings for this PowerShell session
    # Note: SSL certs trusted from installing BoxStarter above will be trusted for the remaining PS session
    [System.Net.ServicePointManager]::CertificatePolicy = $prevCertPolicy

    return $true
  } catch {
    Write-Host "Failed to install boxstarter a second time."
    return $false
  }
}

if ([string]::IsNullOrEmpty($profile_file)) {
  Write-Host "[+] No custom profile is provided..."
  $profile = $null
} else {
  Write-Host "[+] Using the following profile $profile_file"
  $profile = Import-JsonFile $profile_file
  if ($profile -eq $null) {
    Write-Error "Invaild configuration! Exiting..."
    exit 1
  }
  # Confirmation message
  Write-Warning "[+] You are using a custom profile and list of packages. You will NOT receive updates"
  Write-Warning "[+] on new packages from FLAREVM automatically when running choco update."
}  


# Check to make sure script is run as administrator
Write-Host "[+] Checking if script is running as administrator.."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[ERR] Please run this script as administrator`n" -ForegroundColor Red
  Read-Host  "Press any key to continue"
  exit
}

# Check to make sure host is supported
Write-Host "[+] Checking to make sure Operating System is compatible"
if (-Not (((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") -or ([System.Environment]::OSVersion.Version.Major -eq 10))){
  Write-Host "`t[ERR] $((Get-WmiObject -class Win32_OperatingSystem).Caption) is not supported, please use Windows 7 Service Pack 1 or Windows 10" -ForegroundColor Red
  exit 
} else {
  Write-Host "`t$((Get-WmiObject -class Win32_OperatingSystem).Caption) supported" -ForegroundColor Green
}

# Get user credentials for autologin during reboots
Write-Host "[+] Getting user credentials ..."
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True
if ([string]::IsNullOrEmpty($password)) {
  $cred=Get-Credential $env:username
} else {
  $spasswd=ConvertTo-SecureString -String $password -AsPlainText -Force
  $cred=New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $env:username, $spasswd
}



Write-Host "[+] Installing Boxstarter"
$rc = installBoxStarter
if ( -Not $rc ) {
  Write-Host "[ERR] Failed to install BoxStarter`n" -ForegroundColor Red
  Read-Host  "`tPress ANY key to continue..."
  exit
}

# Boxstarter options
if ($norestart) {
  $BoxStarter.RebootOk = $false
} else {
  $Boxstarter.RebootOk = $true # Allow reboots?
}
$Boxstarter.NoPassword = $false # Is this a machine with no login password?
$Boxstarter.AutoLogin = $true # Save my password securely and auto-login after a reboot
Set-BoxstarterConfig -NugetSources "https://www.myget.org/F/fireeye/api/v2;https://chocolatey.org/api/v2"

# Go ahead and disable the Windows Updates
Disable-MicrosoftUpdate

# Disable Windows Defender
try {
  Get-Service WinDefend | Stop-Service -Force
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\WinDefend" -Name "Start" -Value 4 -Type DWORD -Force
} catch {
  Write-Warning "Failed to disable WinDefend service"
}

try {
  New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name "Windows Defender" -Force -ea 0 | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -PropertyType DWORD -Force -ea 0 | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0 -PropertyType DWORD -Force -ea 0 | Out-Null
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null
  if (-Not ((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601")) {
    Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
  }
} catch {
  Write-Warning "Failed to disable Windows Defender"
}

if ([System.Environment]::OSVersion.Version.Major -eq 10) {
  choco config set cacheLocation ${Env:TEMP}
}

# Needed for many applications
# Set up the correct feed
$fireeyeFeed = "https://www.myget.org/F/fireeye/api/v2"
iex "choco sources add -n=fireeye -s $fireeyeFeed --priority 1"
iex "choco upgrade -y vcredist-all.flare"
iex "refreshenv"

if ($profile -eq $null) {
  # Default install
  Write-Host "[+] Performing normal installation..."
  $startPath = Join-Path ${Env:ProgramData} "Microsoft\Windows\Start Menu\Programs\FLARE"
  if (-Not (Set-EnvironmentVariableWrap "TOOL_LIST_DIR" $startPath)) {
    Write-Warning "Failed to set environment variable TOOL_LIST_DIR"
  }

  $desktopShortcut = Join-Path ${Env:UserProfile} "Desktop\FLARE.lnk"
  if (-Not (Set-EnvironmentVariableWrap "TOOL_LIST_SHORTCUT" $desktopShortcut)) {
    Write-Warning "Failed to set environment variable TOOL_LIST_SHORTCUT"
  }

  choco upgrade -y -f common.fireeye
  if ($norestart) {
    Install-BoxStarterPackage -PackageName flarevm.installer.flare -DisableReboots
  } else {
    Install-BoxStarterPackage -PackageName flarevm.installer.flare -Credential $cred
  }
  exit 0
} 

# The necessary basic environment variables
$EnvVars = @(
  "VM_COMMON_DIR",
  "TOOL_LIST_DIR",
  "TOOL_LIST_SHORTCUT",
  "RAW_TOOLS_DIR"
  )

foreach ($envVar in $EnvVars) {
  try {
    $value = [Environment]::ExpandEnvironmentVariables($profile.env.($envVar))
    if (-Not (Set-EnvironmentVariableWrap $envVar $value)) {
      Write-Warning "[-] Failed to set environment variable $envVar"
    }
  } catch {}
}

choco install -y common.fireeye
refreshenv

$PackageName = "MyInstaller"
$TemplateDir = $profile.env.TEMPLATE_DIR
$Packages = $profile.packages
Make-InstallerPackage $PackageName $TemplateDir $Packages
Invoke-BoxStarterBuild $PackageName
if ($norestart) {
  Install-BoxStarterPackage -PackageName $PackageName -DisableReboots
} else {
  Install-BoxStarterPackage -PackageName $PackageName -Credential $cred
}
exit 0
