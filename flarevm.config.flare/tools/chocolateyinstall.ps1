#$ErrorActionPreference = 'Stop'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Set desktop background to black
Set-Itemproperty -Path 'HKCU:\Control Panel\Colors' -Name Background -Value "0 0 0" | Out-Null

# Update CMD default settings
$cmdPath = Join-Path $toolsDir "cmd.reg"
Start-Process -FilePath "reg.exe" -ArgumentList "import $cmdPath" -Wait -PassThru

# Add "Open Command Window Here as Admin"
$cmdPath = Join-Path $toolsDir "Add_Open_Command_Window_Here_as_Admin.reg"
Start-Process -FilePath "reg.exe" -ArgumentList "import $cmdPath" -Wait -PassThru

# Set desktop wallpaper using WallpaperChanger utility
$wallpaperName = 'flarevm.png'
$fileBackground = Join-Path $toolsDir $wallpaperName
$publicWallpaper = Join-Path ${env:public} $wallpaperName
$WallpaperChanger = Join-Path $toolsDir 'WallpaperChanger.exe'

foreach ($item in "0", "1", "2") {
  # Try to set it multiple times! Windows 10 is not consistent
  Copy-Item -Path $fileBackground -Destination $publicWallpaper -Force -ea 0 | Out-Null
  Set-ItemProperty -path 'HKCU:\Control Panel\Desktop' -name Wallpaper -type String -value $publicWallpaper -Force
  Set-ItemProperty -path 'HKCU:\Control Panel\Desktop' -name TileWallpaper -type String -value "0" -Force
  Set-ItemProperty -path 'HKCU:\Control Panel\Desktop' -name WallpaperStyle -type String -value "0" -Force
  Sleep -seconds 3
  rundll32.exe user32.dll, UpdatePerUserSystemParameters, 1, True
}

if ( -Not ([System.Environment]::OSVersion.Version.Major -eq 10)) {
  Invoke-Expression "$WallpaperChanger $fileBackground 1"
}

# Set desktop FLARE folder shortcut
Write-Host "[ * ] Setting up shortcuts"
$startPath = ${Env:TOOL_LIST_DIR}

# Add it and utilities to Explorer's favorites left-hand menu
$favoriteShortcut = Join-Path ${Env:UserProfile} "Links\FLARE.lnk"
Install-ChocolateyShortcut -shortcutFilePath $favoriteShortcut -targetPath $startPath

$utilities_path = Join-Path $startPath "Utilities"
if (Test-Path $utilities_path) {
  $favoriteShortcut = Join-Path ${Env:UserProfile} "Links\Utilities.lnk"
  Install-ChocolateyShortcut -shortcutFilePath $favoriteShortcut -targetPath $utilities_path
}

Write-Host "[ * ] Cleaning up desktop"
# Copy readme.txt on the Desktop
$fileReadme = Join-Path $toolsDir 'readme.txt'
$desktopReadme = Join-Path ${Env:UserProfile} "Desktop\README.txt"
Copy-Item $fileReadme $desktopReadme -Force

# Move Boxstarter Shell to FLARE directory
if (Test-Path -Path (Join-Path ${Env:Public} "Desktop\Boxstarter Shell.lnk")) {
  Move-Item -Path (Join-Path ${Env:Public} "Desktop\Boxstarter Shell.lnk") -Destination (Join-Path ${Env:TOOL_LIST_DIR} "Boxstarter Shell.lnk") -Force
}

# Remove desktop.ini files
try {
  Get-ChildItem -Path (Join-Path ${Env:UserProfile} "Desktop") -Hidden -Filter "desktop.ini" -Force | foreach {$_.Delete()}
  Get-ChildItem -Path (Join-Path ${Env:Public} "Desktop") -Hidden -Filter "desktop.ini" -Force | foreach {$_.Delete()}
} catch {
  Write-Warning "Warning: Failed to delete desktop.ini on user's and public profile's Desktop"
}


Write-Host "[ * ] Applying system configs"
# Should be PS >5.1 now, enable transcription and script block logging
# More info: https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html
if ($PSVersionTable -And $PSVersionTable.PSVersion.Major -ge 5) {
  $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell'
  if (-Not (Test-Path $psLoggingPath)) {
    New-Item -Path $psLoggingPath -Force | Out-Null
  }
  $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription'
  if (-Not (Test-Path $psLoggingPath)) {
    New-Item -Path $psLoggingPath -Force | Out-Null
  }
  New-ItemProperty -Path $psLoggingPath -Name "EnableInvocationHeader" -Value 1 -PropertyType DWORD -Force | Out-Null
  New-ItemProperty -Path $psLoggingPath -Name "EnableTranscripting" -Value 1 -PropertyType DWORD -Force | Out-Null
  New-ItemProperty -Path $psLoggingPath -Name "OutputDirectory" -Value (Join-Path ${Env:UserProfile} "Desktop\PS_Transcripts") -PropertyType String -Force | Out-Null
  
  $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
  if (-Not (Test-Path $psLoggingPath)) {
    New-Item -Path $psLoggingPath -Force | Out-Null
  }
  New-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force | Out-Null
}

if ((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") {
  # Disable Action Center messages
  $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
  if (-Not (Test-Path "$regPath")) {
    New-Item -Path "$($regPath.TrimEnd($regPath.Split('\')[-1]))" -Name "$($regPath.Split('\')[-1])" -Force | Out-Null
  }
  New-ItemProperty -Path $regPath -Name "HideSCAHealth" -Type DWORD -Value 1 -Force | Out-Null

  # Disable IE's nag screen
  $regPath = "HKCU:\Software\Microsoft\Internet Explorer\Main"
  if (-Not (Test-Path "$regPath")) {
    New-Item -Path "$($regPath.TrimEnd($regPath.Split('\')[-1]))" -Name "$($regPath.Split('\')[-1])" -Force | Out-Null
  }
  New-ItemProperty -Path $regPath -Name "Check_Associations" -Type String -Value "no" -Force | Out-Null

  # Disable LLMNR
  $registryPath = "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient"
  if (-Not (Test-Path "$registryPath")) {
    New-Item -path "$registryPath" -Force | Out-Null
  }
  New-ItemProperty -Path "$registryPath" -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force | Out-Null

  # Try to reduce the noise in PCAP data by disabling the below
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "CertificateRevocation" -Type DWORD -Value 0 -Force
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Type DWORD -Value 0 -Force
  netsh advfirewall firewall set rule group="Network Discovery" new enable=No
  netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No
  $services = @('upnphost', 'SSDPSRV', 'HomeGroupProvider', 'HomeGroupListener', 'fdPHost', 'FDResPub')
  foreach ($service in $services) {
    try {
      Write-Host "Stopping $service"
      Get-Service $service | Stop-Service -Force
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\$service" -Name "Start" -Value 4 -Type DWORD -Force
    } catch {
      Write-Warning "Failed to disable the service: $service"
    }
  }

  # Disable SMBv1 to be a little safer
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Type DWORD -Value 0 -Force
  sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
  sc.exe config mrxsmb10 start= disabled
}

#### Set file associations ####
Write-Host "[-] Setting file associations..." -ForegroundColor Green
# Zip
$7zip = "${Env:ProgramFiles}\7-Zip\7zFM.exe"
if (Test-Path $7zip) {
  $7zipfiletype = "7zFM.exe"
  cmd /c assoc .zip=$7zipfiletype | Out-Null
  cmd /c assoc .7z=$7zipfiletype | Out-Null
  cmd /c assoc .tar=$7zipfiletype | Out-Null
  cmd /c assoc .bz=$7zipfiletype | Out-Null
  cmd /c assoc .gz=$7zipfiletype | Out-Null
  cmd /c assoc .gzip=$7zipfiletype | Out-Null
  cmd /c assoc .bzip=$7zipfiletype | Out-Null
  cmd /c @"
    ftype $7zipfiletype="$7zip" "%1" "%*" > NUL
"@
  New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
  Set-ItemProperty -Path "HKCR:\$7zipfiletype" -Name "(DEFAULT)" -Value "$7zipfiletype file" -Force | Out-Null
  Write-Host "`t[+] 7zip -> .zip" -ForegroundColor Green
}

if ([System.Environment]::OSVersion.Version.Major -eq 10) {
  Write-Host -foregroundcolor Magenta "You are on Windows 10. Please reboot to make sure all changes are applied correctly!"
}