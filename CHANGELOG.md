# Changelog

## 3.6.2
- Replaced the console-based Python launcher with `CipherVault.pyw` so Windows can start it without an intermediate Python console window.
- The launcher requests administrator approval through UAC and starts PowerShell 7.4+ directly.
- Removed the legacy `CipherVault.py` and WSH launcher approach.
- Hardened CI and release verification for the Python launcher.
- Fixed repository metadata files and removed stale checksum/source-launcher artefacts.
- Fixed `Invoke-RepositoryAudit.ps1` so that it works correctly when the project does not yet have a `.git` directory.
- Removed invalid access to `$root.Path`; the root is now normalised as a string path.
- Relative paths are calculated with `[System.IO.Path]::GetRelativePath()`.
- Kept the explicit distinction between `Git repository` and `working tree` modes.
