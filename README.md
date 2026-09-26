# CipherVault 3.6.2

Local message encryption system written in PowerShell 7.4+, designed to run exclusively in the terminal.

## Cryptography

- AES-256-GCM
- PBKDF2-HMAC-SHA256
- 600,000 iterations
- 16-byte random salt
- 12-byte random nonce
- 16-byte GCM tag
- 32-byte derived key
- AAD binding the format, algorithm and cryptographic parameters

The custom alphabet only remaps Base64. It does not increase cryptographic security.

## Format

The only supported format is:

```text
SC4.salt.nonce.tag.ciphertext
```

Messages using other format identifiers are rejected.

## Limits

- Password: 12 to 256 characters
- Message: up to 8 MiB in UTF-8
- Ciphertext: up to 8 MiB
- Received encoded text: up to 16 MiB

A minimum of 12 characters does not guarantee good entropy. Prefer long, random passwords.

## Features

```text
[1] Encrypt message
[2] Encrypt clipboard text
[3] Decrypt message
[4] About / parameters
[0] Exit
```

There are no Windows Forms, WPF or animations.

## Running

```powershell
pwsh -NoProfile -File .\CipherVault.ps1
```

If Windows blocks downloaded scripts, remove the mark of the web only from project files:

```powershell
Get-ChildItem -Recurse -File -Filter *.ps1 | Unblock-File
```

## Testing and analysis

Install the development tools:

```powershell
.\tools\Install-DevDependencies.ps1
```

Run the complete verification:

```powershell
.\tools\Invoke-Checks.ps1
```

Or run the test suite directly:

```powershell
Invoke-Pester .\tests
```

After the test suite runs, the project displays an explicit test completion message.

`Invoke-Checks.ps1` reports the actual counters read from the XML report, for example `Tests passed : 6` and `Failures : 0`.

For static analysis:

```powershell
Invoke-ScriptAnalyzer -Path .\CipherVault.ps1 -Severity Error
```

## Security

Do not present the project as "unbreakable", "military-grade", or as having been audited by third parties without independent evidence.

Security depends on the password and a local endpoint that has not been compromised. The terminal, clipboard, keyloggers, local malware and screen capture are outside the cryptographic scope.

See `SECURITY.md` and `SECURITY-AUDIT.md`.

## CI

GitHub Actions runs PSScriptAnalyzer and Pester on `windows-latest` for every push and pull request.

## Offensive security testing

Version 3.3.0 introduced a second round of security testing focused on malformed inputs, resource limits, terminal controls, invisible/bidi Unicode and basic parser fuzzing. See `SECURITY-AUDIT.md`.

The results should be reproduced in the supported Windows/PowerShell environment before any definitive release.

## Security status

The 3.1.1 baseline was run on Windows 11 with Pester 6.2.0 and PSScriptAnalyzer 1.25.0: 6 tests passed, with no failures or errors. Version 3.3.0 added a second layer of offensive security tests and fixed a control-character reflection issue in the terminal error path. See `SECURITY-AUDIT.md` for scope and limitations.

## Offensive security testing, round 3

Version 3.4.1 expanded testing for Base64 canonicalisation, internal whitespace, AAD, input limits, observable salt/nonce randomness, additional Unicode sanitisation and hardening of the development-tool installation process.

Version 3.4.1 continued to use the SC4 format exclusively and retained AES-256-GCM with PBKDF2-HMAC-SHA256.

## Offensive security testing, round 4

Version 3.4.1 added independent known-answer tests (KATs) for PBKDF2-HMAC-SHA256 and AES-256-GCM, as well as random Unicode round-trips. Version 3.4.1 also fixed two defects in the test suite identified during execution: the RFC 7914 vector uses a 4-byte salt, while the internal routine required 16 bytes, and the Unicode test attempted to convert code points above U+FFFF directly to `char`.

### Technical references

- RFC 7914, PBKDF2-HMAC-SHA256 test vector.
- NIST SP 800-38D, GCM and IV/nonce requirements.
- OWASP Password Storage Cheat Sheet, PBKDF2 parameters.

## Offensive security testing, round 5

Version 3.5.0 added case-sensitive validation of the SC4 identifier, structural size checks after decoding, key separation testing by salt, Unicode passwords outside the BMP and truncation testing for ciphertext that remains syntactically valid.

Version 3.5.0 also declared PowerShell 7.4+ as the minimum requirement. This corresponds to use of the `AesGcm` constructor that accepts the tag size explicitly, available in .NET 8+, which underpins PowerShell 7.4.

## Threat model

See `THREAT-MODEL.md`. CipherVault protects confidentiality and integrity, but does not provide identity authentication or anti-replay protection. The password remains the primary factor determining resistance to offline attacks.

## Offensive security testing, round 6

Version 3.6.0 consolidated the threat-model review and hardened GitHub publication. A repository audit was added to detect sensitive files, high-confidence credential patterns and references to the legacy SC3 format. The release workflow avoids including local test artefacts.

## Repository audit, 3.6.2

`Invoke-RepositoryAudit.ps1` works both inside a Git repository and in a working tree that has not yet been initialised as a Git repository. In a Git repository, it analyses versioned files. Outside Git, it analyses local files and explicitly reports that limitation.
