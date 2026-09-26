# CipherVault, cryptographic and offensive security audit

**Current reviewed version:** 3.6.2
**Review date:** 2026-09-25

## Scope

The review covers the current code and test package. The focus was:

- key derivation;
- AES-GCM;
- salt and nonce;
- authentication through GCM and AAD;
- custom Base64 serialisation;
- input validation;
- tampering;
- terminal and clipboard exposure;
- resource abuse;
- testing and static analysis for public distribution.

This review is an assisted source-code audit, not a formal certification or an independent third-party audit. Dynamic execution must take place in the Windows/PowerShell environment supported by the project.

## Cryptographic construction

The project uses AES-256-GCM with a 128-bit tag, 96-bit nonce, 128-bit random salt and PBKDF2-HMAC-SHA256 with 600,000 iterations. The derived key is 256 bits.

The current format is exclusively:

```text
SC4.salt.nonce.tag.ciphertext
```

AAD binds the version, algorithm and KDF parameters.

## Included tests

The suite covers:

- reversibility of custom Base64;
- Unicode round-trip;
- observable randomness of messages generated from the same plaintext and password;
- incorrect password;
- modification of salt, tag and ciphertext;
- rejection of unsupported format identifiers.

## Current result

Tests run in the project's development environment should be recorded in CI and in the GitHub history. The absence of PSScriptAnalyzer findings at `Error` severity does not replace an independent cryptographic audit.

## Known limitations

- Passwords are received by PowerShell as `string`, so deterministic memory clearing is not guaranteed.
- The terminal and clipboard may expose text to operating-system mechanisms.
- The custom alphabet does not add entropy or replace encryption.
- Practical security remains dependent on password quality and endpoint integrity.

## Publication recommendation

Before the first public release, run on a supported Windows system:

```powershell
Invoke-ScriptAnalyzer -Path .\CipherVault.ps1 -Severity Error
Invoke-Pester .\tests
```

Preserve the CI result for each release.

## Second offensive security round, 2026-09-25

The second round was driven by the real 6/6 test result and by review of the input/output path, including cases not covered by the original suite.

### Finding R2-01, terminal control injection in error messages, fixed in 3.3.0

In version 3.1.1, some parsing errors reflected user-supplied characters directly in the exception message. The interactive flow printed the exception with `Write-Host`. A malformed ciphertext containing ESC/CSI could therefore inject terminal control sequences while the error was being handled. This did not break AES-GCM, but could alter the screen, overwrite information or produce visual spoofing in ANSI terminals.

Version 3.3.0 sanitises every error message before displaying it and reports invalid characters by code point without reflecting the raw character. C0/C1 controls, bidi controls and invisible characters are also escaped for display. PowerShell 7 and Windows Terminal support ANSI/VT sequences, so this layer must be treated as an input surface when untrusted text is displayed.

### Finding R2-02, offline password brute force, architectural risk

Anyone who obtains a ciphertext can test passwords offline. There is no rate limit because there is no server. PBKDF2-HMAC-SHA256 with 600,000 iterations follows the current OWASP reference for PBKDF2 when FIPS-140 is a requirement, but Argon2id is preferred when available because it is memory-hard. Practical protection depends heavily on password entropy.

### Finding R2-03, mutable CI dependencies, supply-chain risk, fixed in 3.3.0

The previous workflow used `actions/checkout@v4` by tag and installed modules by `MinimumVersion`. Tags and resolution to newer versions made CI execution less immutable and less reproducible. GitHub recommends pinning actions to a full SHA; version 3.3.0 pins `actions/checkout` to a specific commit and uses exact versions for Pester and PSScriptAnalyzer.

### Added coverage

The second round adds tests for malformed inputs, password length, plaintext limits, Base64 padding, salt/nonce/tag lengths, characters outside the alphabet, extra fields, terminal controls, bidi Unicode and basic parser fuzzing.

### Status

The 3.3.0 changes were prepared, but the new-round tests still needed to be run in the maintainer's Windows/PowerShell environment. The earlier 6/6 result remained valid for 3.1.1 and was used as the baseline.

## Result of the second round

The baseline supplied by the maintainer confirmed 6/6 tests, zero failures and zero errors on Windows 11. The second round should not replace that result; it extends it.

### Reproducible exploit identified in 3.1.1

An attacker able to supply malformed code could insert terminal control characters into a field reflected by error messages. A conceptual example is a version field containing `ESC` followed by a CSI sequence. The previous decoding function included the received value in the exception and the interactive flow printed it directly. Windows Terminal and other hosts support ANSI/VT, so untrusted text output must be sanitised.

### Fix applied in 3.3.0

- error messages displayed in the console pass through `ConvertTo-SafeConsoleText`;
- invalid-character diagnostics use `U+XXXX` instead of reflecting the raw character;
- the rejected version is no longer reflected literally;
- relevant C0/C1, bidirectional and invisible controls are escaped.

### Baseline cryptographic result

The maintainer's report on 2026-09-25 confirms 6 tests, all with result `Success`, including Unicode round-trip, different ciphertext on successive executions, incorrect password, salt/tag/ciphertext tampering and rejection of formats other than SC4.

### Residual risk: password

The main residual cryptographic risk is an offline attack against the password. PBKDF2-HMAC-SHA256 with 600,000 iterations is a configuration recognised by OWASP for PBKDF2 in FIPS scenarios, but Argon2id is preferred when available because it is memory-hard.

### Residual risk: CI and supply chain

Version 3.3.0 pins `actions/checkout` to a full SHA and pins the versions of modules used by the tests. GitHub recommends full SHAs for actions because tags can be moved.

### Audit limits

There was no attempt to break AES-GCM or PBKDF2 mathematically. The assessment covers implementation, format, parser, terminal surface, memory/resources and supply chain. It is not an independent security certification.

## Third offensive security round, 2026-09-25

### R3-01, non-canonical Base64, low

Some decoders accept non-zero padding bits, meaning more than one textual representation can produce the same bytes. Version 3.3.0 re-encodes each block and requires a case-sensitive match with the received representation.

### R3-02, accepted internal whitespace, low

The previous version removed internal whitespace before parsing, allowing different textual representations of the same code. Version 3.3.0 accepts only external whitespace through `Trim()` and rejects internal whitespace.

### R3-03, password buffer, low

`Read-PasswordHidden` used a character list without explicit cleanup of the internal storage. Version 3.3.0 uses a `char[]` buffer, clears it in `finally` and returns only the required string. This reduces the persistence of a mutable copy, although PowerShell strings remain managed by the runtime.

### R3-04, dependency installer, medium

The local installer accepted any minimum version and, for Pester, used `SkipPublisherCheck`. Version 3.3.0 pins Pester 6.2.0 and PSScriptAnalyzer 1.25.0, removes `SkipPublisherCheck` and does not alter the PSGallery trust policy.

### R3-05, fatal-path sanitisation, low

The final exception path still printed the raw message. Version 3.3.0 applies the same console sanitisation used by the other flows. PowerShell 7 supports ANSI/VT sequences in terminals, so untrusted text must not be reflected without treatment.

### R3-06, AAD, test added

The offensive suite now creates a ciphertext with valid fields but authenticates it with different AAD, then confirms that CipherVault rejects the message. This verifies that AAD is not merely documented but actually participates in GCM authentication.

### R3-07, residual password risk

The offline dictionary attack remains the main residual cryptographic risk. PBKDF2-HMAC-SHA256 with 600,000 iterations is a configuration recognised by OWASP when PBKDF2 is used, but Argon2id is preferred when an appropriate dependency is acceptable.

### R3-08, nonce per key

The project uses a random 96-bit nonce and a new random salt per message, which normally produces a new derived key for each ciphertext. The GCM IV uniqueness requirement remains relevant, as specified by NIST SP 800-38D. The suite adds a test covering eight distinct salt/nonce pairs per execution.

### Residual supply-chain considerations

GitHub recommends pinning Actions by full SHA. The workflow already uses a full SHA for checkout. For releases, signed tags and artifact attestations are also recommended to help verify artefact provenance.

## Fourth offensive security round, 2026-09-25

### R4-01, Known Answer Test gap, fixed

Earlier suites mainly validated round-trip behaviour. This demonstrates internal consistency, but does not by itself prove that PBKDF2 and AES-GCM are producing values compatible with independent references.

Version 3.4.1 adds known-answer vectors for PBKDF2-HMAC-SHA256 according to RFC 7914 and AES-256-GCM according to NIST vectors, allowing detection of an implementation that is internally consistent but algorithmically incorrect.

### R4-02, allocation before plaintext limit, hardening

Version 3.3.0 converted the string to UTF-8 before validating the byte limit. Version 3.4.1 adds a conservative preflight based on character length before conversion and keeps the exact byte-level check after conversion.

### R4-03, Unicode metamorphic testing

Twenty-five deterministic round-trips were added using characters from different Unicode blocks to exercise UTF-8 serialisation and reversibility beyond the fixed test set.

### Result

The new tests must be run in the supported Windows/PowerShell environment. Approval of round 4 requires PSScriptAnalyzer with no errors and all Pester tests passing.

## Assessment of round 4

The main gap identified was methodological: previous round-trip tests could pass even if both internal ends shared the same error. Known Answer Tests address this gap by comparing the implementation with external reference vectors.

Round 4 does not introduce a new cryptographic construction. It increases verification independence and reduces an important class of false negatives in testing.

## Post-execution correction for round 4, 2026-09-25

Local execution of 3.4.1 on Windows 11 produced 35 cases, with 33 passes and 2 failures. Both failures occurred in the test code, not in an attempt to break CipherVault:

1. The PBKDF2-HMAC-SHA256 Known Answer Test used the RFC 7914 vector with `P="passwd"`, `S="salt"`, `c=1` and `dkLen=64`. The `Get-DerivedKey` helper had imposed a 16-byte minimum salt, artificially blocking the 4-byte vector. RFC 7914 defines the vector salt as a sequence of octets and provides that value specifically for verification. The SC4 format layer continues to require a 16-byte salt before application key derivation.

2. The Unicode test attempted to convert a code point in the U+1F300..U+1F64F range directly to `System.Char`. Code points above U+FFFF require a surrogate pair and must be converted as a code point with `Char.ConvertFromUtf32`. The test error was corrected.

Neither failure demonstrates a vulnerability in AES-256-GCM or the SC4 format. They demonstrate that the verification infrastructure itself needed correction before the round 4 result could be used as evidence.

Version 3.4.1 preserves the cryptographic parameters of 3.4.1 and requires a new full execution in the maintainer's Windows/PowerShell environment.

## Fifth offensive security round, 2026-09-25

### R5-01, case-insensitive format identifier, low, fixed in 3.5.0

The PowerShell `-eq` operator is case-insensitive by default. The previous version could therefore accept `sc4` as the textual equivalent of `SC4`. This did not alter the cryptographic construction because the internal profile remained fixed to SC4, but it allowed more than one textual representation of the identifier. Version 3.5.0 uses case-sensitive comparison and adds a specific test.

### R5-02, incorrect declared compatibility, fixed in 3.5.0

The code uses `AesGcm` with a constructor that explicitly receives the tag size. The .NET 8 documentation presents this constructor and recommends specifying the required tag size to avoid truncation ambiguities. Because PowerShell 7.4 is based on .NET 8, the documentation now requires PowerShell 7.4+.

### R5-03, release chain, fixed in 3.5.0

The release workflow now rejects tags that do not follow `vMAJOR.MINOR.PATCH`, preventing a tag name from being used directly as a file path without validation.

### Added tests

- reject `sc4` instead of `SC4`;
- verify 16/12/16-byte sizes;
- key separation between different salts;
- password containing a code point outside U+FFFF;
- truncation of ciphertext that remains valid Base64.

Round 5 still depends on execution in the supported Windows/PowerShell environment before it can be considered approved.
