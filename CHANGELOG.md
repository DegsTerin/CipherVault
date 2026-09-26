# Changelog

## 3.6.2
- Fixed `Invoke-RepositoryAudit.ps1` so that it works correctly when the project does not yet have a `.git` directory.
- Removed invalid access to `$root.Path`; the root is now normalised as a string path.
- Relative paths are calculated with `[System.IO.Path]::GetRelativePath()`.
- Kept the explicit distinction between `Git repository` and `working tree` modes.
