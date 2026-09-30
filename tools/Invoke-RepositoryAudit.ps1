#requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
Set-Location $root

Write-Host '== CipherVault repository audit ==' -ForegroundColor Cyan
Write-Host

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git is not installed or is not in PATH.'
}

$isGitRepository = $false
$tracked = @()

try {
    $inside = (& git rev-parse --is-inside-work-tree 2>$null)
    if ($LASTEXITCODE -eq 0 -and $inside -eq 'true') {
        $isGitRepository = $true
        $tracked = @(git ls-files)
    }
}
catch {
    $isGitRepository = $false
}

if ($isGitRepository) {
    if ($tracked.Count -eq 0) {
        throw 'Git repository has no versioned files. Add the safe files to the index before running the audit.'
    }
    Write-Host 'Mode: files versioned by Git' -ForegroundColor DarkGray
}
else {
    $tracked = @(
        Get-ChildItem -LiteralPath $root -Recurse -File -Force |
            Where-Object {
                $_.FullName -notmatch [regex]::Escape([IO.Path]::DirectorySeparatorChar + '.git' + [IO.Path]::DirectorySeparatorChar) -and
                $_.FullName -notmatch '[\\/]test-results\\.(xml)$'
            } |
            ForEach-Object { [IO.Path]::GetRelativePath($root, $_.FullName).Replace([IO.Path]::DirectorySeparatorChar, '/') }
    )
    if ($tracked.Count -eq 0) {
        throw 'No files found to audit.'
    }
    Write-Host 'Mode: working tree (directory has not yet been initialised as a Git repository)' -ForegroundColor Yellow
    Write-Host 'Warning: the audit covers all local files, but does not verify the Git index state.' -ForegroundColor Yellow
}

$forbiddenPaths = @(
    '(?i)\.env(?:\.|$)',
    '(?i)(^|/)(credentials?|secrets?|tokens?)(?:/|$)',
    '(?i)\.(pem|pfx|p12|key)$'
)

$pathFindings = foreach ($path in $tracked) {
    foreach ($pattern in $forbiddenPaths) {
        if ($path -match $pattern) {
            [pscustomobject]@{ Type='Path'; Path=$path; Finding='Sensitive versioned file' }
            break
        }
    }
}

# High-confidence secret patterns only. Test fixtures with ordinary passwords are intentionally not matched.
$secretPatterns = [ordered]@{
    'Private key' = '-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
    'AWS access key' = '\bAKIA[0-9A-Z]{16}\b'
    'GitHub token' = '\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]+\b'
    'Slack token' = '\bxox[baprs]-[A-Za-z0-9-]+\b'
    'Google API key' = '\bAIza[0-9A-Za-z_-]{35}\b'
}

$findings = @($pathFindings)

foreach ($path in $tracked) {
    $full = Join-Path $root ($path -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        continue
    }

    try {
        $text = Get-Content -LiteralPath $full -Raw -ErrorAction Stop
    }
    catch {
        continue
    }

    foreach ($item in $secretPatterns.GetEnumerator()) {
        if ($text -match $item.Value) {
            $findings += [pscustomobject]@{
                Type='Content'
                Path=$path
                Finding="Possible $($item.Key)"
            }
        }
    }

    if ($path -match '(?i)\.(ps1|pyw)$' -and $text -match '(?i)\bSC3\b') {
        $findings += [pscustomobject]@{ Type='Content'; Path=$path; Finding='Reference to legacy SC3 format' }
    }
}

if ($tracked -contains 'test-results.xml') {
    $findings += [pscustomobject]@{ Type='Path'; Path='test-results.xml'; Finding='Tracked test artefact' }
}

foreach ($legacyPath in @('CipherVault.py', 'CipherVault.vbs')) {
    if ($tracked -contains $legacyPath) {
        $findings += [pscustomobject]@{ Type='Path'; Path=$legacyPath; Finding='Legacy launcher should not be versioned' }
    }
}

if (-not ($tracked -contains 'CipherVault.pyw')) {
    $findings += [pscustomobject]@{ Type='Path'; Path='CipherVault.pyw'; Finding='Required Windows double-click launcher is missing' }
}

if ($findings.Count -gt 0) {
    Write-Host 'REPOSITORY AUDIT: FAILED' -ForegroundColor Red
    $findings | Sort-Object Path, Finding | Format-Table -AutoSize | Out-String | Write-Host
    exit 1
}

Write-Host 'REPOSITORY AUDIT: OK' -ForegroundColor Green
Write-Host "Versioned files analysed: $($tracked.Count)" -ForegroundColor Green
