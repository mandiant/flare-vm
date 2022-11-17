$ErrorActionPreference = 'Continue'
$global:VerbosePreference = "SilentlyContinue"
Import-Module vm.common -Force -DisableNameChecking

function Get-InstalledPackages {
    if (Get-Command clist -ErrorAction:SilentlyContinue) {
        clist -lo -r -all | ForEach-Object {
            $Name, $Version = $_ -split '\|'
            New-Object -TypeName psobject -Property @{
                'Name' = $Name
                'Version' = $Version
            }
        }
    }
}

try {
    # Gather packages to install
    $installedPackages = (Get-InstalledPackages).Name
    $configPath = Join-Path ${Env:VM_COMMON_DIR} "config.xml" -Resolve
    $configXml = [xml](Get-Content $configPath)
    $packagesToInstall = $configXml.config.packages.package.name | Where-Object { $installedPackages -notcontains $_ }

    # List packages to install
    Write-Host "[+] Packages to install:"
    foreach ($package in $packagesToInstall) {
        Write-Host "`t[+] $package"
    }
    Start-Sleep 1

    # Install the packages
    foreach ($package in $packagesToInstall) {
        Write-Host "[+] Installing: $package" -ForegroundColor Cyan
        choco install "$package" -y
    }
    Write-Host "[+] Installation complete" -ForegroundColor Green

    # Remove Chocolatey cache
    $cache = "${Env:LocalAppData}\ChocoCache"
    Remove-Item $cache -Recurse -Force

    # Ready failed packages file
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $failedPackages = Join-Path $desktopPath "failed_packages.txt"

    # Check and list failed packages from "lib-bad"
    $chocoLibBad = Join-Path ${Env:ProgramData} "chocolatey\lib-bad"
    if ((Test-Path $chocoLibBad)) {
        VM-Write-Log "ERROR" "Based on $chocoLibBad, the packages below failed to install:"
        Get-ChildItem -Path $chocoLibBad | Foreach-Object {
            VM-Write-Log "ERROR" "$($_.Name)"
            Add-Content $failedPackages $_.Name
        }
    }

    # Cross-compare packages to install versus installed packages to find failed packages
    $installedPackages = (Get-InstalledPackages).Name
    foreach ($package in $packagesToInstall) {
        if ($installedPackages -notcontains $package) {
            VM-Write-Log "ERROR" "Failed to install: $package"
            Add-Content $failedPackages $package
        }
    }

    # Log additional info if we found failed packages
    if ((Test-Path $failedPackages)) {
        VM-Write-Log "ERROR" "For each failed package, you may attempt a manual install via: cinst -y <package_name>"
        VM-Write-Log "ERROR" "Failed package list saved to: $failedPackages"
    }

    # Display installer log if available
    $logPath = Join-Path ${Env:VM_COMMON_DIR} "log.txt"
    if ((Test-Path $logPath)) {
        Write-Host "[-] Please see installer log for any errors: $logPath" -ForegroundColor Yellow
        Start-Sleep 5
        & notepad.exe $logPath
    }
} catch {
    VM-Write-Log-Exception $_
}