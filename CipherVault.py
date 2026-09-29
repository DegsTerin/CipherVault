from pathlib import Path
import os
import shutil
import subprocess
import sys


def main() -> int:
    project_directory = Path(__file__).resolve().parent
    cipher_vault_script = project_directory / "CipherVault.ps1"

    if not cipher_vault_script.is_file():
        print(
            f"CipherVault.ps1 was not found at '{cipher_vault_script}'.",
            file=sys.stderr,
        )
        return 1

    pwsh = shutil.which("pwsh")
    if pwsh is None:
        print(
            "PowerShell 7 (pwsh.exe) was not found. "
            "Install PowerShell 7 and try again.",
            file=sys.stderr,
        )
        return 1

    try:
        subprocess.Popen(
            [
                pwsh,
                "-NoProfile",
                "-File",
                str(cipher_vault_script),
            ],
            cwd=str(project_directory),
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
        )
    except OSError as error:
        print(
            f"PowerShell 7 could not be started: {error}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
