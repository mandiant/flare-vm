$ErrorActionPreference = 'Continue'

$packageName = 'flarevm.win10.config.fireeye'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

#### Check if a reboot is needed ####
FE-Check-Reboot $packageName

#### Start config ####
Write-Host "[+] Beginning host configuration..." -ForegroundColor Green


#### Update CMD default settings ####
Write-Host "[+] Updating CMD configuration..." -ForegroundColor Green
$cmdPath = Join-Path $toolsDir "cmd.reg"
Start-Process -FilePath "reg.exe" -ArgumentList "import $cmdPath" -Wait -PassThru
# Add "Open Command Window Here as Admin"
$cmdPath = Join-Path $toolsDir "Add_Open_Command_Window_Here_as_Admin.reg"
Start-Process -FilePath "reg.exe" -ArgumentList "import $cmdPath" -Wait -PassThru


#### Add timestamp to PowerShell prompt ####
Write-Host "[+] Updating PowerShell prompt..." -ForegroundColor Green
$psprompt = @"
function prompt
{
    Write-Host "FLARE " -ForegroundColor Green -NoNewLine
    Write-Host `$(get-date) -ForegroundColor Green
    Write-Host  "PS" `$PWD ">" -nonewline -foregroundcolor White
    return " "
}
"@
New-Item -ItemType File -Path $profile -Force | Out-Null
Set-Content -Path $profile -Value $psprompt
# Add timestamp to cmd prompt
# Note: The string below is base64-encoded due to issues properly escaping the '$' character in PowersShell
#   Offending string: "Y21kIC9jICdzZXR4IFBST01QVCBGTEFSRSRTJGQkcyR0JF8kcCQrJGcn"
#   Resolves to: "cmd /c 'setx PROMPT FLARE$S$d$s$t$_$p$+$g'"
iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y21kIC9jICdzZXR4IFBST01QVCBGTEFSRSRTJGQkcyR0JF8kcCQrJGcn"))) | Out-Null
Write-Host "[+] Timestamps added to cmd prompt and PowerShell" -ForegroundColor Green


#### Fix shift+space in powershell
# https://superuser.com/questions/1365875/shiftspace-not-working-in-powershell
Set-PSReadLineKeyHandler -Chord Shift+Spacebar -Function SelfInsert
Write-Host "[+] Fixed shift+space keybinding in PowerShell" -ForegroundColor Green


#### Update background ####
Write-Host "[+] Changing desktop background..." -ForegroundColor Green
# Set desktop background to black
Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name Background -Value "0 0 0" -Force | Out-Null
# Set desktop wallpaper using WallpaperChanger utility
$wallpaperName = 'flarevm.png'
$fileBackground = Join-Path $toolsDir $wallpaperName
$publicWallpaper = Join-Path ${env:public} $wallpaperName
$WallpaperChanger = Join-Path $toolsDir 'WallpaperChanger.exe'
Invoke-Expression "$WallpaperChanger $fileBackground 3"
# Attempt to set the background multiple times
foreach ($item in "0", "1", "2") {
  # Try to set it multiple times! Windows 10 is not consistent
  if ((Test-Path $publicWallpaper) -eq $false)
  {
    Copy-Item -Path $fileBackground -Destination $publicWallpaper -Force
  }
  Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name Wallpaper -value $publicWallpaper
  Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name TileWallpaper -value "0" -Force
  Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name WallpaperStyle -value "6" -Force
  Sleep -seconds 3
  rundll32.exe user32.dll, UpdatePerUserSystemParameters, 1, True
}


#### Configure desktop ####
Write-Host "[+] Configuring desktop..." -ForegroundColor Green
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


#### Enable script block logging ####
Write-Host "[+] Enabling PS script block logging..." -ForegroundColor Green
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
  Write-Host "`t[i] PowerShell transcripts will be saved to the desktop in PS_Transcripts." -ForegroundColor Green
}


#### Set file associations ####
Write-Host "[+] Setting file associations..." -ForegroundColor Green
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
  Write-Host "`t[i] 7zip -> .zip" -ForegroundColor Green
}


#### Done ####
Write-Host @"
[!]   Done with configuration, PLEASE ENSURE YOUR DESKTOP BACKGROUND HAS CHANGED.  [!]
[!]   If your background has not changed, please open an administrative terminal   [!]
[!]   and enter the following command: cinst -y flarevm.win10.config.fireeye -f    [!]
"@ -ForegroundColor Red -BackgroundColor White