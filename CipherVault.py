from pathlib import Path
import ctypes
import shutil
import subprocess
import sys


def show_error(message: str) -> None:
    ctypes.windll.user32.MessageBoxW(
        0,
        message,
        "CipherVault",
        0x10,
    )


def get_pythonw() -> str | None:
    executable = Path(sys.executable)
    sibling = executable.with_name("pythonw.exe")

    if sibling.is_file():
        return str(sibling)

    return shutil.which("pythonw")


def is_administrator() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_administrator(script_path: Path) -> int:
    pythonw = get_pythonw()

    if pythonw is None:
        show_error(
            "pythonw.exe was not found. "
            "A windowless Python interpreter is required for the double-click launcher."
        )
        return 1

    arguments = subprocess.list2cmdline(
        [
            str(script_path),
            "--elevated",
        ]
    )

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        pythonw,
        arguments,
        str(script_path.parent),
        1,
    )

    if result <= 32:
        show_error(
            "CipherVault could not be started with administrator privileges."
        )
        return 1

    return 0


def main() -> int:
    project_directory = Path(__file__).resolve().parent
    cipher_vault_script = project_directory / "CipherVault.ps1"

    if not cipher_vault_script.is_file():
        show_error(
            f"CipherVault.ps1 was not found at '{cipher_vault_script}'."
        )
        return 1

    if not is_administrator():
        return relaunch_as_administrator(Path(__file__).resolve())

    pwsh = shutil.which("pwsh")
    if pwsh is None:
        show_error(
            "PowerShell 7 (pwsh.exe) was not found. "
            "Install PowerShell 7 and try again."
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
        show_error(f"PowerShell 7 could not be started: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
