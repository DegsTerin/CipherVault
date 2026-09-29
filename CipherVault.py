#! /usr/bin/env pythonw
from pathlib import Path
import ctypes
import shutil
import subprocess
import sys


SW_HIDE = 0
SW_SHOW = 1


def hide_launcher_console() -> None:
    if sys.platform != "win32":
        return

    try:
        console_window = ctypes.windll.kernel32.GetConsoleWindow()
        if console_window:
            ctypes.windll.user32.ShowWindow(console_window, SW_HIDE)
    except OSError:
        pass


def show_error(message: str) -> None:
    ctypes.windll.user32.MessageBoxW(
        0,
        message,
        "CipherVault",
        0x10,
    )


def find_pwsh() -> str | None:
    pwsh = shutil.which("pwsh.exe")
    if pwsh:
        return pwsh

    candidates = [
        Path(sys.executable).resolve().anchor
        / "Program Files"
        / "PowerShell"
        / "7"
        / "pwsh.exe",
        Path(sys.executable).resolve().anchor
        / "Program Files"
        / "PowerShell"
        / "7-preview"
        / "pwsh.exe",
        Path.home()
        / "AppData"
        / "Local"
        / "Microsoft"
        / "PowerShell"
        / "7"
        / "pwsh.exe",
    ]

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return None


def is_administrator() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def launch_as_administrator(
    pwsh: str,
    cipher_vault_script: Path,
    project_directory: Path,
) -> int:
    arguments = subprocess.list2cmdline(
        [
            "-NoProfile",
            "-File",
            str(cipher_vault_script),
        ]
    )

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        pwsh,
        arguments,
        str(project_directory),
        SW_SHOW,
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

    pwsh = find_pwsh()
    if pwsh is None:
        show_error(
            "PowerShell 7 (pwsh.exe) was not found. "
            "Install PowerShell 7.4 or later and try again."
        )
        return 1

    if not is_administrator():
        hide_launcher_console()
        return launch_as_administrator(
            pwsh,
            cipher_vault_script,
            project_directory,
        )

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
