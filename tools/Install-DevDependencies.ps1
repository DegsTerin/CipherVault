#requires -Version 7.0
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host '== CipherVault development dependencies ==' -ForegroundColor Cyan
Write-Host

if (-not (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -eq [version]'6.2.0' })) {
    Install-Module Pester -RequiredVersion 6.2.0 -Repository PSGallery -Scope CurrentUser -Force -Confirm:$false -AllowClobber
}

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { $_.Version -eq [version]'1.25.0' })) {
    Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Repository PSGallery -Scope CurrentUser -Force -Confirm:$false -AllowClobber
}

Write-Host
Write-Host 'Dependencies installed.' -ForegroundColor Green
