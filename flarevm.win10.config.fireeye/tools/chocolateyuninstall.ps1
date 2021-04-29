$ErrorActionPreference = 'Stop'
$packageName = 'flarevm.win10.config.flare'

try {
	$desktopReadme = Join-Path ${Env:UserProfile} "Desktop\README.txt"
	Remove-Item $desktopReadme
} catch {
	# pass
}