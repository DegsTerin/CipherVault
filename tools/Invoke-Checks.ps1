#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host '== CipherVault checks ==' -ForegroundColor Cyan
Write-Host

$pester = Get-Module -ListAvailable -Name Pester |
    Where-Object { $_.Version -eq [version]'6.2.0' } |
    Sort-Object Version -Descending |
    Select-Object -First 1

$analyzer = Get-Module -ListAvailable -Name PSScriptAnalyzer |
    Where-Object { $_.Version -eq [version]'1.25.0' } |
    Sort-Object Version -Descending |
    Select-Object -First 1

if ($null -eq $pester) {
    throw 'Pester 6.2.0 nao esta instalado. Execute .\tools\Install-DevDependencies.ps1'
}

if ($null -eq $analyzer) {
    throw 'PSScriptAnalyzer 1.25.0 nao esta instalado. Execute .\tools\Install-DevDependencies.ps1'
}

Import-Module Pester -RequiredVersion $pester.Version -Force
Import-Module PSScriptAnalyzer -RequiredVersion $analyzer.Version -Force

Write-Host "Pester: $($pester.Version)"
Write-Host "PSScriptAnalyzer: $($analyzer.Version)"
Write-Host

Write-Host '[1/2] PSScriptAnalyzer' -ForegroundColor Yellow
$scriptFiles = @(Get-ChildItem -Path . -Recurse -File -Filter *.ps1 | Where-Object { $_.FullName -notmatch '\\.git\\' })
$analysis = @()
foreach ($scriptFile in $scriptFiles) {
    $analysis += @(Invoke-ScriptAnalyzer -Path $scriptFile.FullName -Severity Error)
}
if ($analysis.Count -gt 0) {
    $analysis | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host
    Write-Host 'CIPHERVAULT | CHECKS FALHARAM' -ForegroundColor Red
    throw "PSScriptAnalyzer encontrou $($analysis.Count) erro(s)."
}
Write-Host 'OK' -ForegroundColor Green
Write-Host

Write-Host '[2/2] Pester' -ForegroundColor Yellow
$resultsPath = Join-Path $root 'test-results.xml'
if (Test-Path -LiteralPath $resultsPath) {
    Remove-Item -LiteralPath $resultsPath -Force
}

$config = New-PesterConfiguration
$config.Run.Path = '.\tests'
$config.Output.Verbosity = 'Minimal'
$config.TestResult.Enabled = $true
$config.TestResult.OutputPath = '.\test-results.xml'

$null = Invoke-Pester -Configuration $config

if (-not (Test-Path -LiteralPath $resultsPath)) {
    Write-Host
    Write-Host 'CIPHERVAULT | TESTES FALHARAM' -ForegroundColor Red
    throw 'O Pester terminou sem gerar o arquivo test-results.xml.'
}

[xml]$testXml = Get-Content -LiteralPath $resultsPath -Raw
$summary = $testXml.'test-results'

$total = [int]$summary.total
$errors = [int]$summary.errors
$failures = [int]$summary.failures
$notRun = [int]$summary.'not-run'
$inconclusive = [int]$summary.inconclusive
$ignored = [int]$summary.ignored
$skipped = [int]$summary.skipped

$passed = $total - $errors - $failures - $notRun - $inconclusive - $ignored - $skipped
if ($passed -lt 0) {
    $passed = 0
}

if (($errors + $failures + $notRun + $inconclusive + $ignored + $skipped) -gt 0) {
    Write-Host
    Write-Host 'CIPHERVAULT | TESTES FALHARAM' -ForegroundColor Red
    Write-Host "Testes passados: $passed | Falhas: $failures | Erros: $errors | Nao executados: $notRun"
    exit 1
}

Write-Host 'OK' -ForegroundColor Green
Write-Host
Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Green
Write-Host (('║{0}║' -f ('CIPHERVAULT | CHECKS OK'.PadLeft(31).PadRight(62)))) -ForegroundColor Green
Write-Host (('║{0}║' -f ('ANALISE E TESTES CONCLUIDOS'.PadLeft(32).PadRight(62)))) -ForegroundColor Green
Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Green
Write-Host
Write-Host 'PSScriptAnalyzer : OK' -ForegroundColor Green
Write-Host 'Pester           : OK' -ForegroundColor Green
Write-Host
Write-Host "Testes passados  : $passed" -ForegroundColor Green
Write-Host "Falhas           : $failures" -ForegroundColor Green
Write-Host "Erros             : $errors" -ForegroundColor Green
Write-Host "Nao executados   : $notRun" -ForegroundColor Green
Write-Host
