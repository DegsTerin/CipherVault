# Release checklist

1. Ensure `CipherVault.pyw` is present and `CipherVault.py`/`CipherVault.vbs` are absent.
2. Run `./tools/Invoke-RepositoryAudit.ps1`.
3. Run `./tools/Invoke-Checks.ps1`.
4. Confirm `PSScriptAnalyzer : OK` and `Pester : OK`.
5. The release workflow also validates the Python launcher and runs the repository audit and full test suite.
6. If the project does not yet have a `.git` directory, the audit works in `working tree` mode and reports that limitation.
7. After initialising Git, run the audit again to verify exactly which files are versioned.
8. Create a signed release tag, for example `git tag -s v3.6.2 -m "CipherVault v3.6.2"`.
9. Verify the tag with `git tag -v v3.6.2`.
