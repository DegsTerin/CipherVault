# Release checklist

1. Run `Get-ChildItem -Recurse -File -Filter *.ps1 | Unblock-File` when required.
2. Run `./tools/Invoke-RepositoryAudit.ps1`.
3. Run `./tools/Invoke-Checks.ps1`.
4. Confirm `PSScriptAnalyzer : OK` and `Pester : OK`.
5. If the project does not yet have a `.git` directory, the audit works in `working tree` mode and reports that limitation.
6. After initialising Git, run the audit again to verify exactly which files are versioned.
7. Create a signed release tag, for example `git tag -s v3.6.2 -m "CipherVault v3.6.2"`.
8. Verify the tag with `git tag -v v3.6.2`.
