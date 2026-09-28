#requires -Version 7.4
<#
.SYNOPSIS
    Creates a Windows desktop shortcut for CipherVault.

.DESCRIPTION
    Creates or updates a CipherVault.lnk shortcut on the current user's desktop.
    The shortcut launches PowerShell 7 directly with CipherVault.ps1.

    The shortcut does not use CMD, Windows Forms, WPF or an intermediate launcher.

.NOTES
    Requires PowerShell 7.4+ and a valid CipherVault.ps1 file in the repository root.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$productName = 'CipherVault'
$scriptPath = Join-Path $PSScriptRoot '..' 'CipherVault.ps1'
$scriptPath = [System.IO.Path]::GetFullPath($scriptPath)

if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw "CipherVault.ps1 was not found at '$scriptPath'."
}

$pwshCommand = Get-Command 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $pwshCommand) {
    $fallbackPwsh = Join-Path $PSHOME 'pwsh.exe'
    if (Test-Path -LiteralPath $fallbackPwsh -PathType Leaf) {
        $pwshPath = $fallbackPwsh
    }
    else {
        throw 'PowerShell 7 (pwsh.exe) was not found. Install PowerShell 7 and run this script again.'
    }
}
else {
    $pwshPath = $pwshCommand.Source
}

$desktopPath = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($desktopPath) -or -not (Test-Path -LiteralPath $desktopPath -PathType Container)) {
    throw 'The current user desktop folder could not be located.'
}

$shortcutPath = Join-Path $desktopPath "$productName.lnk"

$wshShell = $null
$shortcut = $null

try {
    $wshShell = New-Object -ComObject 'WScript.Shell'
    $shortcut = $wshShell.CreateShortcut($shortcutPath)

    $shortcut.TargetPath = $pwshPath
    $shortcut.Arguments = '-NoProfile -File "' + $scriptPath + '"'
    $shortcut.WorkingDirectory = Split-Path -Parent $scriptPath
    $shortcut.WindowStyle = 1
    $shortcut.Description = 'Launch CipherVault in PowerShell 7'
    $shortcut.IconLocation = "$pwshPath,0"
    $shortcut.Save()
}
finally {
    if ($null -ne $shortcut) {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
    }

    if ($null -ne $wshShell) {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($wshShell) | Out-Null
    }
}

Write-Host
Write-Host 'CipherVault desktop shortcut created.' -ForegroundColor Green
Write-Host "Shortcut: $shortcutPath" -ForegroundColor Gray
Write-Host
Write-Host 'You can now double-click the CipherVault shortcut on the desktop.' -ForegroundColor Gray
