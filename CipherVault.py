from pathlib import Path
import ctypes
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

    arguments = subprocess.list2cmdline(
        [
            "-NoProfile",
            "-File",
            str(cipher_vault_script),
        ]
    )

    try:
        shell_execute = ctypes.windll.shell32.ShellExecuteW
        shell_execute.restype = ctypes.c_void_p

        result = shell_execute(
            None,
            "runas",
            pwsh,
            arguments,
            str(project_directory),
            1,
        )

        if result is None or result <= 32:
            print(
                "CipherVault could not be started with administrator privileges.",
                file=sys.stderr,
            )
            return 1
    except OSError as error:
        print(
            f"Administrator launch failed: {error}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
