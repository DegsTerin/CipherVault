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
    throw 'Git nao esta instalado ou nao esta no PATH.'
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
        throw 'Repositorio Git sem arquivos versionados. Adicione os arquivos seguros ao indice antes da auditoria.'
    }
    Write-Host 'Modo: arquivos versionados pelo Git' -ForegroundColor DarkGray
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
        throw 'Nenhum arquivo encontrado para auditar.'
    }
    Write-Host 'Modo: working tree (diretorio ainda nao inicializado como repositorio Git)' -ForegroundColor Yellow
    Write-Host 'Aviso: a auditoria sera completa sobre os arquivos locais, mas nao verifica o estado do indice Git.' -ForegroundColor Yellow
}

$forbiddenPaths = @(
    '\.env(?:\.|$)',
    '(?i)(^|/)(credentials?|secrets?|tokens?)(?:/|$)',
    '(?i)\.(pem|pfx|p12|key)$'
)

$pathFindings = foreach ($path in $tracked) {
    foreach ($pattern in $forbiddenPaths) {
        if ($path -match $pattern) {
            [pscustomobject]@{ Type='Path'; Path=$path; Finding='Arquivo sensivel versionado' }
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
                Finding="Possivel $($item.Key)"
            }
        }
    }

    if ($text -match '(?m)^\s*(?:SC3)\b') {
        $findings += [pscustomobject]@{ Type='Content'; Path=$path; Finding='Referencia a formato legado SC3' }
    }
}

$forbiddenExtensions = @('.pem','.pfx','.p12','.key')
$forbiddenTracked = @($tracked | Where-Object { $forbiddenExtensions -contains ([IO.Path]::GetExtension($_).ToLowerInvariant()) })

if ($forbiddenTracked.Count -gt 0) {
    $findings += $forbiddenTracked | ForEach-Object { [pscustomobject]@{ Type='Path'; Path=$_; Finding='Extensao sensivel versionada' } }
}

if ($findings.Count -gt 0) {
    Write-Host 'AUDITORIA DE REPOSITORIO: FALHOU' -ForegroundColor Red
    $findings | Sort-Object Path, Finding | Format-Table -AutoSize | Out-String | Write-Host
    exit 1
}

Write-Host 'AUDITORIA DE REPOSITORIO: OK' -ForegroundColor Green
Write-Host "Arquivos versionados analisados: $($tracked.Count)" -ForegroundColor Green
