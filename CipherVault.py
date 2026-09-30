from pathlib import Path
import ctypes
import shutil
import sys
from ctypes import wintypes


SW_HIDE = 0
SW_SHOW = 1


def show_error(message: str) -> None:
    ctypes.windll.user32.MessageBoxW(
        0,
        message,
        "CipherVault",
        0x10,
    )


def hide_launcher_console() -> None:
    if sys.platform != "win32":
        return

    try:
        console_window = ctypes.windll.kernel32.GetConsoleWindow()
        if console_window:
            ctypes.windll.user32.ShowWindow(console_window, SW_HIDE)
    except OSError:
        pass


def find_pwsh() -> str | None:
    pwsh = shutil.which("pwsh.exe")
    if pwsh:
        return pwsh

    system_root = Path(
        __import__("os").environ.get("SystemRoot", r"C:\Windows")
    )

    candidates = [
        Path(sys.executable).resolve().anchor
        / "Program Files"
        / "PowerShell"
        / "7"
        / "pwsh.exe",
        system_root
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe",
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


def launch_elevated(
    executable: str,
    arguments: str,
    working_directory: Path,
) -> bool:
    shell_execute = ctypes.windll.shell32.ShellExecuteW
    shell_execute.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]
    shell_execute.restype = wintypes.HINSTANCE

    result = shell_execute(
        None,
        "runas",
        executable,
        arguments,
        str(working_directory),
        SW_SHOW,
    )

    return result > 32


def launch_cipher_vault(
    pwsh: str,
    cipher_vault_script: Path,
    project_directory: Path,
) -> bool:
    arguments = (
        "-NoProfile -ExecutionPolicy Bypass -File "
        + '"' + str(cipher_vault_script) + '"'
    )

    shell_execute = ctypes.windll.shell32.ShellExecuteW
    shell_execute.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]
    shell_execute.restype = wintypes.HINSTANCE

    result = shell_execute(
        None,
        None,
        pwsh,
        arguments,
        str(project_directory),
        SW_SHOW,
    )

    return result > 32


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

        arguments = (
            "-NoProfile -ExecutionPolicy Bypass -File "
            + '"' + str(cipher_vault_script) + '"'
        )

        if not launch_elevated(pwsh, arguments, project_directory):
            show_error(
                "CipherVault could not be started with administrator privileges."
            )
            return 1

        return 0

    if not launch_cipher_vault(
        pwsh,
        cipher_vault_script,
        project_directory,
    ):
        show_error("PowerShell 7 could not be started.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
