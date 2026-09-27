# Security Policy

## Password generator

CipherVault can generate cryptographically random passwords from 12 to 256 characters. To keep the four character classes balanced, the selected length must be a multiple of 4, with equal counts of lowercase letters, uppercase letters, digits and symbols.

Generated passwords are copied to the clipboard when available. CipherVault does not persist a password history or store generated passwords on disk.

## Scope

CipherVault is a local message-encryption application. Its purpose is to protect confidentiality and integrity against people who do not possess the password.

## Supported format

The only cryptographic format accepted by the application is SC4. Version 3.5.0 does not introduce a new format.

## Vulnerability reporting

Do not publish details of an exploitable vulnerability in a public issue before allowing time for a fix.

For a public GitHub project, configure Private Vulnerability Reporting and use that channel for sensitive reports.

Where possible, include:

- CipherVault version;
- operating system;
- PowerShell version;
- reproduction steps;
- test input or ciphertext;
- observed impact.

## Security model

CipherVault assumes:

- the password is secret and sufficiently strong;
- the local endpoint is not compromised;
- the user verifies the origin of scripts/releases;
- the clipboard and terminal may expose information according to system configuration.

CipherVault does not protect against:

- keyloggers;
- malware with access to the process or memory;
- screen capture;
- operating-system compromise;
- weak or reused passwords;
- deliberate password disclosure.

## Audit status

The review available in the repository is an assisted source-code audit, not an independent certification. Do not use the term "security audited" or an equivalent to represent a third-party audit that did not take place.

## Security testing

The project contains cryptographic integrity tests and an additional offensive suite covering parsing, limits, terminal controls and Unicode. Local execution results must be distinguished from an independent audit.

## Publication and provenance

For public releases, prefer signed tags and publish artefact hashes. GitHub provides signed-tag/commit verification and artifact attestations to link an artefact to the workflow and commit that produced it.

## Threat model

See `THREAT-MODEL.md` for the provided properties and known limitations, including identity authentication, replay, clipboard, local memory and offline attacks against the password.

For public releases, it is recommended to enable secret scanning and push protection in the repository. GitHub documents push protection as a preventive measure that blocks detected secrets before they reach the repository.
