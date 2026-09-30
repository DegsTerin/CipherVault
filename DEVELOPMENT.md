# Development

## Environment

- PowerShell 7.4+
- Python 3.10+ for the double-click `.pyw` launcher
- Pester 6.2.0
- PSScriptAnalyzer 1.25.0

## Checks

```powershell
Get-ChildItem -Recurse -File -Filter *.ps1 | Unblock-File
.\tools\Invoke-Checks.ps1
```

The additional offensive security suite is in `tests/CipherVault.Security.Tests.ps1`.

## CI supply chain

The CI and release workflows pin GitHub Actions to full SHAs and pin the test-module versions. Dependabot monitors GitHub Actions updates.

## Pinned versions

Local checks and CI use Pester 6.2.0 and PSScriptAnalyzer 1.25.0 to make results reproducible.

Round 4 adds Known Answer Tests for PBKDF2-HMAC-SHA256 and AES-256-GCM, together with random Unicode tests.

## 3.4.1

Version 3.4.1 fixes two defects in its own test suite found during real execution: the RFC 7914 KAT with a short salt and the generation of supplementary Unicode characters.

## Repository audit

Before publishing, run:

```powershell
.\tools\Invoke-RepositoryAudit.ps1
```

The audit looks for sensitive files, selected high-confidence credential patterns, tracked `test-results.xml`, legacy launchers, and references to the legacy SC3 format. In a Git repository, it uses versioned files; outside Git, it analyses the working tree and reports that limitation.
