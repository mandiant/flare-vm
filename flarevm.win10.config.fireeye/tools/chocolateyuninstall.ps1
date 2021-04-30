$ErrorActionPreference = 'Stop'
$packageName = 'flarevm.win10.config.fireeye'

try {
	$desktopReadme = Join-Path ${Env:UserProfile} "Desktop\README.txt"
	Remove-Item $desktopReadme
} catch {
	# pass
}