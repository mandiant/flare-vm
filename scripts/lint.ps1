# Exclude rules that make the code less readable or involve changing the functionality
$excludedRules = "PSAvoidUsingPlainTextForPassword", "PSAvoidUsingConvertToSecureStringWithPlainText", "PSAvoidUsingWriteHost", "PSUseShouldProcessForStateChangingFunctions", "PSUseSingularNouns", "PSAvoidUsingInvokeExpression"

choco install psscriptanalyzer --version 1.23.0 --no-progress

# Manually iterate over all files instead of using -Recurse because
# PSScriptAnalyzer only outputs the script name (and most have the name
# chocolateyinstall.ps1)
$scripts = Get-ChildItem . -Filter *.ps*1 -Recurse -File -Name
$errorsCount = 0
foreach ($script in $scripts) {
  Write-Host -ForegroundColor Yellow $script
  ($errors = Invoke-ScriptAnalyzer $script -Recurse -ReportSummary -ExcludeRule $excludedRules)
  $errorsCount += $errors.Count
}

Exit($errorsCount)
