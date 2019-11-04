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
  [string]$profile_file = $null
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

  $PackageDir = Join-Path $BoxStarter.LocalRepo $PackageName
  if (Test-Path $PackageDir) {
    Remove-Item -Recurse -Force $PackageDir
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
  New-BoxstarterPackage -Name $PackageName -Description "My Own Instalelr" -Path $ToolsDir
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

  # Try to install BoxStarter as is first, then fall back to be over trusing only if this step fails.
  try {
    iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
    return $true
  } catch {
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
      Write-Debug "Failed to add new type"
  }
  try {
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
  } catch {
    Write-Debug "Failed to find SSL type...1"
  }
  try {
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls'
  } catch {
    Write-Debug "Failed to find SSL type...2"
  }
  $prevSecProtocol = [System.Net.ServicePointManager]::SecurityProtocol
  $prevCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy

  Write-Host "[+] Installing Boxstarter"
  # Become overly trusting
  [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
  # download and instal boxstarter
  iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
  # Restore previous trust settings for this PowerShell session
  # Note: SSL certs trusted from installing BoxStarter above will be trusted for the remaining PS session
  [System.Net.ServicePointManager]::SecurityProtocol = $prevSecProtocol
  [System.Net.ServicePointManager]::CertificatePolicy = $prevCertPolicy
  return $true
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
  Write-Host "[ERR] Failed to install BoxStarter"
  Read-Host  "      Press ANY key to continue..."
  exit
}

# Boxstarter options
$Boxstarter.RebootOk = $true # Allow reboots?
$Boxstarter.NoPassword = $false # Is this a machine with no login password?
$Boxstarter.AutoLogin = $true # Save my password securely and auto-login after a reboot
Set-BoxstarterConfig -NugetSources "https://www.myget.org/F/fireeye/api/v2;https://chocolatey.org/api/v2"

# Go ahead and disable the Windows Updates
Disable-MicrosoftUpdate
try {
  Set-MpPreference -DisableRealtimeMonitoring $true
  iex "cinst -y disabledefender-winconfig "
} catch {
}
if ([System.Environment]::OSVersion.Version.Major -eq 10) {
  choco config set cacheLocation ${Env:TEMP}
}

# Needed for many applications
# Set up the correct feed
$fireeyeFeed = "https://www.myget.org/F/fireeye/api/v2"
iex "choco sources add -n=fireeye -s $fireeyeFeed --priority 1"
iex "choco upgrade -y vcredist-all.flare"
iex "choco install -y powershell"
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
  Install-BoxStarterPackage -PackageName flarevm.installer.flare -Credential $cred
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
Install-BoxStarterPackage -PackageName $PackageName -Credential $cred
exit 0
