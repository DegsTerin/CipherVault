# CipherVault 3.6.2

Local message encryption system written in PowerShell 7.4+, designed to run exclusively in the terminal.

## Demo

![CipherVault terminal demo](assets/ciphervault-demo.gif)

The animated demo shows clipboard encryption, clipboard decryption and secure password generation.

## Cryptography

- AES-256-GCM
- PBKDF2-HMAC-SHA256
- 600,000 iterations
- 16-byte random salt
- 12-byte random nonce
- 16-byte GCM tag
- 32-byte derived key
- AAD binding the format version, algorithm and PBKDF2 iteration count

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

### Secure password generator

- Length: 12 to 256 characters.
- Allowed lengths are multiples of 4 so lowercase, uppercase, digits and symbols appear in equal quantities.
- Characters are selected with .NET `RandomNumberGenerator`.
- The four character classes are cryptographically shuffled.
- Generated passwords are copied to the clipboard when available.
- Generated passwords are not stored, logged or retained by CipherVault.

A minimum of 12 characters does not guarantee good entropy. Prefer long, random passwords.

## Features

```text
[1] Encrypt message
[2] Encrypt clipboard text
[3] Decrypt message
[4] Decrypt clipboard text
[5] Generate secure password
[6] About / parameters
[0] Exit
```

There are no Windows Forms, WPF, CMD launchers, WSH launchers or animations.

## Running

CipherVault requires PowerShell 7.4+. The optional double-click launcher also requires Python 3.10+.

### Double-click launcher

CipherVault includes a Windows `.pyw` launcher for direct startup.

Double-click:

```text
CipherVault.pyw
```

The launcher uses `pythonw.exe` so no intermediate Python console window is opened. It requests administrator approval through the Windows UAC and then launches PowerShell 7.4+ directly with `CipherVault.ps1`.

Requirements for the double-click launcher:

- Windows
- Python 3.10+ with `.pyw` file association
- PowerShell 7.4+

### Command line

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

`Invoke-Checks.ps1` reports the actual test counters read from the XML report.

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

## Threat model

See `THREAT-MODEL.md`. CipherVault protects confidentiality and integrity, but does not provide identity authentication or anti-replay protection. The password remains the main factor affecting resistance to offline attacks.

## Launcher and repository audit

The repository is published as source code. The `.pyw` launcher is only a startup helper; the cryptographic implementation remains entirely in `CipherVault.ps1`.

## Repository audit, 3.6.2

`Invoke-RepositoryAudit.ps1` works both in a Git repository and in a working tree that has not yet been initialised. In a Git repository, it analyses versioned files. Outside Git, it analyses local files and explicitly reports that limitation.
