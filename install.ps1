###########################################
#
# FLARE VM Installation Script
#
# To execute this script:
#   1) Open PowerShell window as administrator
#   2) Allow script execution by running command "Set-ExecutionPolicy Unrestricted"
#   3) Unblock the install script by running "Unblock-File .\install.ps1"
#   4) Execute the script by running ".\install.ps1"
#
###########################################
param (
  [string]$password = $null,
  [string]$customConfig = $null,
  [bool]$noChecks = $false,
  [bool]$noEdit = $false,
  [bool]$noWait = $false
)

# Set path to user's desktop
$desktopPath = [Environment]::GetFolderPath("Desktop")
Set-Location -Path $desktopPath -PassThru | Out-Null

if (-not $noChecks) {
    # Ensure script is ran as administrator
    Write-Host "[+] Checking if script is running as administrator..."
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "`t[!] Please run this script as administrator" -ForegroundColor Red
        Read-Host "Press any key to continue..."
        exit 1
    } else {
        Write-Host "`t[+] Running as administrator" -ForegroundColor Green
        Start-Sleep -Milliseconds 500
    }

    # Ensure Tamper Protection is disabled
    Write-Host "[+] Checking if Windows Defender Tamper Protection is disabled..."
    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection") {
        if ($(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection").TamperProtection -ne 0) {
            Write-Host "`t[!] Please disable Windows Defender Tamper Protection and retry install" -ForegroundColor Red
            Write-Host "`t[+] Hint: https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-windows-defender-antivirus.html" -ForegroundColor Yellow
            Read-Host "Press any key to continue..."
            exit 1
        } else {
            Write-Host "`t[+] Tamper Protection is disabled" -ForegroundColor Green
            Start-Sleep -Milliseconds 500
        }
    }

    # Ensure Defender is disabled
    Write-Host "[+] Checking if Windows Defender service is disabled..."
    $defender = Get-Service -Name WinDefend
    if ($defender.Status -eq "Running"){
        Write-Host "`t[!] Please disable Windows Defender through Group Policy and retry install" -ForegroundColor Red
        Write-Host "`t[+] Hint: https://stackoverflow.com/questions/62174426/how-to-permanently-disable-windows-defender-real-time-protection-with-gpo" -ForegroundColor Yellow
        Read-Host "Press any key to continue..."
        exit 1
    } else {
        Write-Host "`t[+] Defender is disabled" -ForegroundColor Green
        Start-Sleep -Milliseconds 500
    }

    # Check if Windows 7
    Write-Host "[+] Checking to make sure Operating System is compatible..."
    if ((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") {
        Write-Host "`t[!] Windows 7 is no longer supported / tested" -ForegroundColor Yellow
        Write-Host "[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -ne "Y"){
            exit 1
        }
    }

    # Ensure host has been tested
    # TODO: Add more build numbers
    $osVersion = (Get-WmiObject -class Win32_OperatingSystem).BuildNumber
    $validVersions = @(17763)
    if ($osVersion -notin $validVersions) {
        Write-Host "`t[!] Windows version $osVersion has not been tested, please use Windows 10 version 1809" -ForegroundColor Yellow
        Write-Host "[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -ne "Y"){
            exit 1
        }
    } else {
        Write-Host "`t[+] Installing on Windows version $osVersion" -ForegroundColor Green
    }

    # Ensure host has enough disk space
    # TODO: Decided the actual minimum size recommendation
    # TODO: Refactor to allow user to choose which drive Chocolatey will install packages by default and check that drive
    Write-Host "[+] Checking if host has enough disk space..."
    $disk = Get-PSDrive C
    Start-Sleep -Seconds 1
    if (-Not (($disk.used + $disk.free)/1GB -gt 58.8)) {
        Write-Host "`t[!] Install requires a minimum 60 GB hard drive space, please increase hard drive space to continue" -ForegroundColor Red
        Write-Host "[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -ne "Y"){
            exit 1
        }
    } else {
        Write-Host "`t[+] Disk is larger than 60 GB" -ForegroundColor Green
    }

    # Ensure system is a virtual machine
    $virtualModels = @('VirtualBox', 'VMware Virtual Platform', 'Virtual Machine')
    if ((Get-WmiObject win32_computersystem).model -notin $virtualModels) {
        Write-Host "`t[!] You are not on a virual machine or have hardened your machine to not appear as a virtual machine" -ForegroundColor Red
        Write-Host "`t[!] Please do NOT install this on your host system as it can't be uninstalled completely" -ForegroundColor Red
        Write-Host "`t[!] Please install on a virtual machine" -ForegroundColor Red
        Write-Host "`t[!] Only continue if know what you are doing!" -ForegroundColor Red
        Write-Host "[-] Do you still wish to proceed? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -ne "Y"){
            exit 1
        }
    }

    # Prompt user to remind them to take a snapshot
    Write-Host "[-] Do you need to take a VM snapshot before continuing? (Y/N): " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -ne "N") {
        Write-Host "[+] Exiting..." -ForegroundColor Red
        exit 1
    }
}

# Get user credentials for autologin during reboots
Write-Host "[+] Getting user credentials ..."
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True
if ([string]::IsNullOrEmpty($password)) {
    $credentials = Get-Credential ${Env:username}
} else {
    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    $credentials = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList ${Env:username}, $securePassword
}

Write-Host "`n[+] Beginning Install...`n" -ForegroundColor Green

# Install Boxstarter
Write-Host "[+] Installing Boxstarter" -ForegroundColor Green
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1'))
Get-Boxstarter -Force

# Fix verbosity issues with Boxstarter v3
# See: https://github.com/chocolatey/boxstarter/issues/501
$fileToFix = "${Env:ProgramData}\boxstarter\boxstarter.chocolatey\Chocolatey.ps1"
$offendingString = 'if ($val -is [string] -or $val -is [boolean]) {'
if ((Get-Content $fileToFix -raw) -contains $offendingString) {
    $fixString = 'if ($val -is [string] -or $val -is [boolean] -or $val -is [system.management.automation.actionpreference]) {'
    ((Get-Content $fileToFix -raw) -replace [regex]::escape($offendingString),$fixString) | Set-Content $fileToFix
}
$fileToFix = "${Env:ProgramData}\boxstarter\boxstarter.chocolatey\invoke-chocolatey.ps1"
$offendingString = 'Verbose           = $VerbosePreference'
if ((Get-Content $fileToFix -raw) -contains $offendingString) {
    $fixString = 'Verbose           = ($global:VerbosePreference -eq "Continue")'
    ((Get-Content $fileToFix -raw) -replace [regex]::escape($offendingString),$fixString) | Set-Content $fileToFix
}
Start-Sleep -Milliseconds 500
Import-Module "${Env:ProgramData}\boxstarter\boxstarter.chocolatey\boxstarter.chocolatey.psd1" -Force

# Set Boxstarter options
$Boxstarter.RebootOk = $true
$Boxstarter.NoPassword = $false
$Boxstarter.AutoLogin = $true
$global:VerbosePreference = "SilentlyContinue"
Set-BoxstarterConfig -NugetSources "$desktopPath;.;https://www.myget.org/F/vm-packages/api/v2;https://myget.org/F/vm-packages/api/v2;https://chocolatey.org/api/v2"

# Set Chocolatey options
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
if ([string]::IsNullOrEmpty($customConfig)) {
    # Download configuration file from GitHub
    $configPath = Join-Path $desktopPath "config.xml"
    $configPathUrl = 'https://raw.githubusercontent.com/mandiant/flare-vm/update_installer/config.xml'
    if (-Not (Test-Path $configPath)) {
        Write-Host "[+] Downloading configuration file..."
        (New-Object System.Net.WebClient).DownloadFile($configPathUrl, $configPath)
    }
    if (-Not (Test-Path $configPath)) {
        Write-Host "`t[!] Configuration file missing: " $configPath -ForegroundColor Red
        Write-Host "`t[-] Please download config.xml from $configPathUrl to your desktop" -ForegroundColor Yellow
        Write-Host "`t[-] Is the file on your desktop? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -ne "Y"){
            exit 1
        }
        if (-Not (Test-Path $configPath)) {
            Write-Host "`t[!] Configuration file still missing: " $configPath -ForegroundColor Red
            Write-Host "`t[!] Exiting..." -ForegroundColor Red
            Start-Sleep 3
            exit 1
        }
    }
} else {
    # User user-provided configuration file
    if (-not (Test-Path $customConfig)) {
        Write-Host "`t[!] Configuration file path is invalid: " $customConfig -ForegroundColor Red
        Write-Host "`t[!] Exiting..." -ForegroundColor Red
        Start-Sleep 3
        exit 1
    }
    $configPath = $customConfig
}

# Get config contents
Start-Sleep 1
$configXml = [xml](Get-Content $configPath)

if (-not $noEdit) {
    Write-Host "[+] Allowing user to edit configuration file..."
    ################################################################################
    ## BEGIN GUI
    ################################################################################
    Add-Type -AssemblyName System.Windows.Forms

    function Get-Folder1($textbox) {
        $folderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowserDialog.RootFolder = 'MyComputer'
        $folderBrowserDialog.ShowDialog()
        $textbox.text = (Join-Path $folderBrowserDialog.SelectedPath (Split-Path $envs['VM_COMMON_DIR'] -Leaf))
    }

    function Get-Folder2($textbox) {
        $folderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowserDialog.RootFolder = 'MyComputer'
        $folderBrowserDialog.ShowDialog()
        $textbox.text = (Join-Path $folderBrowserDialog.SelectedPath (Split-Path $envs['TOOL_LIST_DIR'] -Leaf))
    }

    function Get-Folder3($textbox) {
        $folderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowserDialog.RootFolder = 'MyComputer'
        $folderBrowserDialog.ShowDialog()
        $textbox.text = (Join-Path $folderBrowserDialog.SelectedPath (Split-Path $envs['TOOL_LIST_SHORTCUT'] -Leaf))
    }

    function Get-Folder4($textbox) {
        $folderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowserDialog.RootFolder = 'MyComputer'
        $folderBrowserDialog.ShowDialog()
        $textbox.text = (Join-Path $folderBrowserDialog.SelectedPath (Split-Path $envs['RAW_TOOLS_DIR'] -Leaf))
    }

    function Get-InstallablePackages {
        if (Get-Command clist -ErrorAction:SilentlyContinue) {
            choco list -s "https://www.myget.org/F/vm-packages/api/v2" -r | ForEach-Object {
                $Name, $Version = $_ -split '\|'
                New-Object -TypeName psobject -Property @{
                    'Name' = $Name
                    'Version' = $Version
                }
            }
        }
    }

    function Get-InstalledPackages {
        if (Get-Command clist -ErrorAction:SilentlyContinue) {
            choco list -lo -r | ForEach-Object {
                $Name, $Version = $_ -split '\|'
                New-Object -TypeName psobject -Property @{
                    'Name' = $Name
                    'Version' = $Version
                }
            }
        }
    }

    function Set-InitialPackages {
        $selectedPackagesBox.Items.Clear()
        foreach($package in $packagesToInstall)
        {
            $selectedPackagesBox.Items.Add($package) | Out-Null
        }

        $unselectedPackagesBox.Items.Clear()
        foreach($package in $allPackages)
        {
            $unselectedPackagesBox.Items.Add($package) | Out-Null
        }
    }

    function Add-SelectedPackages {
        $unselectedPackages = $unselectedPackagesBox.SelectedItems
        foreach($package in $unselectedPackages)
        {
            $selectedPackagesBox.BeginUpdate()
            $selectedPackagesBox.Items.Add($package) | Out-Null
            $selectedPackagesBox.EndUpdate()
        }

        $unselectedPackagesBox.BeginUpdate()
        while ($unselectedPackagesBox.SelectedItems.count -gt 0) {
            $unselectedPackagesBox.Items.RemoveAt($unselectedPackagesBox.SelectedIndex)
        }
        $unselectedPackagesBox.EndUpdate()
    }

    function Remove-SelectedPackages {
        $selectedPackages = $selectedPackagesBox.SelectedItems
        foreach($package in $selectedPackages)
        {
            $unselectedPackagesBox.BeginUpdate()
            $unselectedPackagesBox.Items.Add($package) | Out-Null
            $unselectedPackagesBox.EndUpdate()
        }

        $selectedPackagesBox.BeginUpdate()
        while ($selectedPackagesBox.SelectedItems.count -gt 0) {
            $selectedPackagesBox.Items.RemoveAt($selectedPackagesBox.SelectedIndex)
        }
        $selectedPackagesBox.EndUpdate()
    }

    # Gather lists of packages (i.e., available, already installed, to install)
    $installedPackages = (Get-InstalledPackages).Name
    $packagesToInstall = $configXml.config.packages.package.name | Where-Object { $installedPackages -notcontains $_ }
    $allPackages = (Get-InstallablePackages).Name | Where-Object { $packagesToInstall -notcontains $_ -and $installedPackages -notcontains $_}
    $envs = [ordered]@{}
    $configXml.config.envs.env.ForEach({ $envs[$_.name] = $_.value })

    $form                            = New-Object system.Windows.Forms.Form
    $form.ClientSize                 = New-Object System.Drawing.Point(717,740)
    $form.text                       = "FLARE VM Install Customization"
    $form.TopMost                    = $true
    $form.MaximizeBox                = $false
    $form.FormBorderStyle            = 'FixedDialog'
    $form.StartPosition              = 'CenterScreen'

    $envVarGroup                     = New-Object system.Windows.Forms.Groupbox
    $envVarGroup.height              = 245
    $envVarGroup.width               = 690
    $envVarGroup.text                = "Environment Variable Customization"
    $envVarGroup.location            = New-Object System.Drawing.Point(15,59)

    $packageGroup                    = New-Object system.Windows.Forms.Groupbox
    $packageGroup.height             = 380
    $packageGroup.width              = 540
    $packageGroup.text               = "Package Installation Customization"
    $packageGroup.location           = New-Object System.Drawing.Point(81,313)

    $removePackageButton             = New-Object system.Windows.Forms.Button
    $removePackageButton.text        = "<"
    $removePackageButton.width       = 22
    $removePackageButton.height      = 26
    $removePackageButton.location    = New-Object System.Drawing.Point(258,170)
    $removePackageButton.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $removePackageButton.Add_Click({Remove-SelectedPackages})

    $okButton                        = New-Object system.Windows.Forms.Button
    $okButton.text                   = "OK"
    $okButton.width                  = 90
    $okButton.height                 = 30
    $okButton.location               = New-Object System.Drawing.Point(481,700)
    $okButton.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $cancelButton                    = New-Object system.Windows.Forms.Button
    $cancelButton.text               = "Cancel"
    $cancelButton.width              = 90
    $cancelButton.height             = 30
    $cancelButton.location           = New-Object System.Drawing.Point(587,700)
    $cancelButton.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $selectedPackagesBox                    = New-Object system.Windows.Forms.ListBox
    $selectedPackagesBox.text               = "listBox"
    $selectedPackagesBox.SelectionMode      = 'MultiSimple'
    $selectedPackagesBox.Sorted             = $true
    $selectedPackagesBox.width              = 246
    $selectedPackagesBox.height             = 330
    $selectedPackagesBox.location           = New-Object System.Drawing.Point(288,40)

    $unselectedPackagesBox                  = New-Object system.Windows.Forms.ListBox
    $unselectedPackagesBox.text             = "listBox"
    $unselectedPackagesBox.SelectionMode    = 'MultiSimple'
    $unselectedPackagesBox.Sorted           = $true
    $unselectedPackagesBox.width            = 246
    $unselectedPackagesBox.height           = 308
    $unselectedPackagesBox.location         = New-Object System.Drawing.Point(6,65)

    $addPackageButton                = New-Object system.Windows.Forms.Button
    $addPackageButton.text           = ">"
    $addPackageButton.width          = 22
    $addPackageButton.height         = 26
    $addPackageButton.location       = New-Object System.Drawing.Point(258,206)
    $addPackageButton.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $addPackageButton.Add_Click({Add-SelectedPackages})

    $dontInstallLabel                = New-Object system.Windows.Forms.Label
    $dontInstallLabel.text           = "Available to Install"
    $dontInstallLabel.AutoSize       = $true
    $dontInstallLabel.width          = 25
    $dontInstallLabel.height         = 10
    $dontInstallLabel.location       = New-Object System.Drawing.Point(7,20)
    $dontInstallLabel.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $doInstallLabel                  = New-Object system.Windows.Forms.Label
    $doInstallLabel.text             = "To Install"
    $doInstallLabel.AutoSize         = $true
    $doInstallLabel.width            = 25
    $doInstallLabel.height           = 10
    $doInstallLabel.location         = New-Object System.Drawing.Point(289,20)
    $doInstallLabel.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

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
    $vmCommonDirSelect.Add_Click({Get-Folder1($vmCommonDirText)})

    $vmCommonDirLabel                = New-Object system.Windows.Forms.Label
    $vmCommonDirLabel.text           = "%VM_COMMON_DIR%"
    $vmCommonDirLabel.AutoSize       = $true
    $vmCommonDirLabel.width          = 25
    $vmCommonDirLabel.height         = 10
    $vmCommonDirLabel.location       = New-Object System.Drawing.Point(2,24)
    $vmCommonDirLabel.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

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
    $toolListDirSelect.Add_Click({Get-Folder2($toolListDirText)})

    $toolListDirLabel                = New-Object system.Windows.Forms.Label
    $toolListDirLabel.text           = "%TOOL_LIST_DIR%"
    $toolListDirLabel.AutoSize       = $true
    $toolListDirLabel.width          = 25
    $toolListDirLabel.height         = 10
    $toolListDirLabel.location       = New-Object System.Drawing.Point(2,71)
    $toolListDirLabel.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $toolListShortCutText            = New-Object system.Windows.Forms.TextBox
    $toolListShortCutText.multiline  = $false
    $toolListShortCutText.width      = 385
    $toolListShortCutText.height     = 20
    $toolListShortCutText.location   = New-Object System.Drawing.Point(190,113)
    $toolListShortCutText.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $toolListShortCutText.text       = $envs['TOOL_LIST_SHORTCUT']

    $toolListShortcutSelect          = New-Object system.Windows.Forms.Button
    $toolListShortcutSelect.text     = "Select Folder"
    $toolListShortcutSelect.width    = 95
    $toolListShortcutSelect.height   = 30
    $toolListShortcutSelect.location  = New-Object System.Drawing.Point(588,109)
    $toolListShortcutSelect.Font     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $toolListShortcutSelect.Add_Click({Get-Folder3($toolListShortCutText)})

    $toolListShortcutLabel           = New-Object system.Windows.Forms.Label
    $toolListShortcutLabel.text      = "%TOOL_LIST_SHORTCUT%"
    $toolListShortcutLabel.AutoSize  = $true
    $toolListShortcutLabel.width     = 25
    $toolListShortcutLabel.height    = 10
    $toolListShortcutLabel.location  = New-Object System.Drawing.Point(2,116)
    $toolListShortcutLabel.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $vmCommonDirNote                 = New-Object system.Windows.Forms.Label
    $vmCommonDirNote.text            = "Shared module and metadata for VM (e.g., config, logs, etc...)"
    $vmCommonDirNote.AutoSize        = $true
    $vmCommonDirNote.width           = 25
    $vmCommonDirNote.height          = 10
    $vmCommonDirNote.location        = New-Object System.Drawing.Point(190,46)
    $vmCommonDirNote.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $toolListDirNote                 = New-Object system.Windows.Forms.Label
    $toolListDirNote.text            = "Folder to store tool categories and shortcuts"
    $toolListDirNote.AutoSize        = $true
    $toolListDirNote.width           = 25
    $toolListDirNote.height          = 10
    $toolListDirNote.location        = New-Object System.Drawing.Point(190,94)
    $toolListDirNote.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $toolListShortcutNote            = New-Object system.Windows.Forms.Label
    $toolListShortcutNote.text       = "Shortcut to %TOOL_LIST_DIR%"
    $toolListShortcutNote.AutoSize   = $true
    $toolListShortcutNote.width      = 25
    $toolListShortcutNote.height     = 10
    $toolListShortcutNote.location   = New-Object System.Drawing.Point(190,137)
    $toolListShortcutNote.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $rawToolsDirText                 = New-Object system.Windows.Forms.TextBox
    $rawToolsDirText.multiline       = $false
    $rawToolsDirText.width           = 385
    $rawToolsDirText.height          = 20
    $rawToolsDirText.location        = New-Object System.Drawing.Point(190,157)
    $rawToolsDirText.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $rawToolsDirText.text            = $envs['RAW_TOOLS_DIR']

    $rawToolsDirSelect               = New-Object system.Windows.Forms.Button
    $rawToolsDirSelect.text          = "Select Folder"
    $rawToolsDirSelect.width         = 95
    $rawToolsDirSelect.height        = 30
    $rawToolsDirSelect.location      = New-Object System.Drawing.Point(588,153)
    $rawToolsDirSelect.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $rawToolsDirSelect.Add_Click({Get-Folder4($rawToolsDirText)})

    $rawToolsDirLabel                = New-Object system.Windows.Forms.Label
    $rawToolsDirLabel.text           = "%RAW_TOOLS_DIR%"
    $rawToolsDirLabel.AutoSize       = $true
    $rawToolsDirLabel.width          = 25
    $rawToolsDirLabel.height         = 10
    $rawToolsDirLabel.location       = New-Object System.Drawing.Point(2,160)
    $rawToolsDirLabel.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',9.5,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $rawToolsDirNote                 = New-Object system.Windows.Forms.Label
    $rawToolsDirNote.text            = "Folder to store downloaded tools"
    $rawToolsDirNote.AutoSize        = $true
    $rawToolsDirNote.width           = 25
    $rawToolsDirNote.height          = 10
    $rawToolsDirNote.location        = New-Object System.Drawing.Point(190,181)
    $rawToolsDirNote.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $metapackageNote1                = New-Object system.Windows.Forms.Label
    $metapackageNote1.text           = "Metapackages may install in a different location (package author`'s decision)"
    $metapackageNote1.AutoSize       = $true
    $metapackageNote1.width          = 25
    $metapackageNote1.height         = 10
    $metapackageNote1.location       = New-Object System.Drawing.Point(219,201)
    $metapackageNote1.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $metapackageNote2                = New-Object system.Windows.Forms.Label
    $metapackageNote2.text           = "Metapackages are wrappers around tools that install via dependencies"
    $metapackageNote2.AutoSize       = $true
    $metapackageNote2.width          = 25
    $metapackageNote2.height         = 10
    $metapackageNote2.location       = New-Object System.Drawing.Point(219,220)
    $metapackageNote2.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $metapackageNote3                = New-Object system.Windows.Forms.Label
    $metapackageNote3.text           = "Note:"
    $metapackageNote3.AutoSize       = $true
    $metapackageNote3.width          = 25
    $metapackageNote3.height         = 10
    $metapackageNote3.location       = New-Object System.Drawing.Point(182,210)
    $metapackageNote3.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $welcomeLabel                    = New-Object system.Windows.Forms.Label
    $welcomeLabel.text               = "Welcome to FLARE VM's custom installer. Please select your options below.`nDefault values will be used if you make no modifications."
    $welcomeLabel.AutoSize           = $true
    $welcomeLabel.width              = 25
    $welcomeLabel.height             = 10
    $welcomeLabel.location           = New-Object System.Drawing.Point(15,14)
    $welcomeLabel.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $packageTypeCombo                = New-Object system.Windows.Forms.ComboBox
    $packageTypeCombo.width          = 246
    $packageTypeCombo.height         = 20
    $packageTypeCombo.location       = New-Object System.Drawing.Point(6,40)
    $packageTypeCombo.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $packageTypeCombo.Items.Add('All') | Out-Null
    $packageTypeCombo.SelectedIndex = 0

    $form.controls.AddRange(@($envVarGroup,$packageGroup,$okButton,$cancelButton,$welcomeLabel))
    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton
    $packageGroup.controls.AddRange(@($unselectedPackagesBox,$selectedPackagesBox,$removePackageButton,$addPackageButton,$dontInstallLabel,$doInstallLabel,$packageTypeCombo))
    $envVarGroup.controls.AddRange(@($vmCommonDirText,$vmCommonDirSelect,$vmCommonDirLabel,$toolListDirText,$toolListDirSelect,$toolListDirLabel,$toolListShortCutText,$toolListShortcutSelect,$toolListShortcutLabel,$vmCommonDirNote,$toolListDirNote,$toolListShortcutNote,$rawToolsDirText,$rawToolsDirSelect,$rawToolsDirLabel,$rawToolsDirNote,$metapackageNote1,$metapackageNote2,$metapackageNote3))

    Set-InitialPackages

    $form.Topmost = $true
    $Result = $form.ShowDialog()

    if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
        Write-Host "[+] Installing selected packages..."

        # Remove default environment variables
        $nodes = $configXml.SelectNodes('//config/envs/env')
        foreach($node in $nodes) {
            $node.ParentNode.RemoveChild($node) | Out-Null
        }

        # Remove default packages
        $nodes = $configXml.SelectNodes('//config/packages/package')
        foreach($node in $nodes) {
            $node.ParentNode.RemoveChild($node) | Out-Null
        }

        # Add environment variables
        $envs = $configXml.SelectSingleNode('//envs')
        $newXmlNode = $envs.AppendChild($configXml.CreateElement("env"));
        $newXmlNode.SetAttribute("name", "VM_COMMON_DIR");
        $newXmlNode.SetAttribute("value", $vmCommonDirText.text);
        $newXmlNode = $envs.AppendChild($configXml.CreateElement("env"));
        $newXmlNode.SetAttribute("name", "TOOL_LIST_DIR");
        $newXmlNode.SetAttribute("value", $toolListDirText.text);
        $newXmlNode = $envs.AppendChild($configXml.CreateElement("env"));
        $newXmlNode.SetAttribute("name", "TOOL_LIST_SHORTCUT");
        $newXmlNode.SetAttribute("value", $toolListShortCutText.text);
        $newXmlNode = $envs.AppendChild($configXml.CreateElement("env"));
        $newXmlNode.SetAttribute("name", "RAW_TOOLS_DIR");
        $newXmlNode.SetAttribute("value", $rawToolsDirText.text);

        # Add selected packages
        $packages = $configXml.SelectSingleNode('//packages')
        foreach($package in $selectedPackagesBox.Items) {
            $newXmlNode = $packages.AppendChild($configXml.CreateElement("package"));
            $newXmlNode.SetAttribute("name", $package);
        }
    } else {
        Write-Host "[+] Cancel pressed, using default settings and installing default packages..."
    }

    ################################################################################
    ## END GUI
    ################################################################################
}


# Parse config and set initial environment variables
Write-Host "[+] Parsing configuration file..."
foreach ($env in $configXml.config.envs.env) {
    $path = [Environment]::ExpandEnvironmentVariables($($env.value))
    Write-Host "`t[+] Setting ENV var: $($env.name) to: $path" -ForegroundColor Green
    [Environment]::SetEnvironmentVariable("$($env.name)", $path, "Machine")
}
refreshenv

# Install the common module
# This creates all necessary folders based on custom environment variables
Write-Host "[+] Installing shared module..."
choco install common.vm -y --force
refreshenv

# Save the modified config to where the installer will look for it
Write-Host "[+] Saving modified configuration file..."
$configXml.save((Join-Path ${Env:VM_COMMON_DIR} "config.xml"))

if (-not $noWait) {
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

    .\install.ps1 -nochecks 1 [<password>]

- You can check which packages failed to install by listing the C:\ProgramData\chocolatey\lib-bad 
directory. Failed packages are stored by folder name. You may attempt manual installation with the 
following command:

    cinst -y <package_name>

- For any issues, please submit to GitHub:

    Installer related: https://github.com/mandiant/flare-vm
    Package related:   https://github.com/mandiant/VM-Packages

[!] Please copy this note for reference [!]
"@ -ForegroundColor Red -BackgroundColor White
    Wait-ForInstall -seconds 30
}

# Invoke installer package
Install-BoxstarterPackage -packageName "flarevm.installer.vm" -credential $credentials