from pathlib import Path
import ctypes
import os
import subprocess
import sys
from ctypes import wintypes


SW_SHOW = 1


def show_error(message: str) -> None:
    ctypes.windll.user32.MessageBoxW(
        0,
        message,
        "CipherVault",
        0x10,
    )


def find_pwsh() -> Path | None:
    candidates: list[Path] = []

    for environment_name in ("ProgramW6432", "ProgramFiles"):
        base = os.environ.get(environment_name)
        if base:
            candidates.append(
                Path(base) / "PowerShell" / "7" / "pwsh.exe"
            )

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.extend(
            [
                Path(local_app_data)
                / "Microsoft"
                / "PowerShell"
                / "7"
                / "pwsh.exe",
                Path(local_app_data)
                / "Programs"
                / "PowerShell"
                / "7"
                / "pwsh.exe",
            ]
        )

    path_value = os.environ.get("PATH", "")
    for directory in path_value.split(os.pathsep):
        if not directory:
            continue

        candidate = Path(directory) / "pwsh.exe"
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue

        normalised = str(resolved).lower()
        trusted_fragments = (
            "\\program files\\powershell\\",
            "\\appdata\\local\\microsoft\\powershell\\",
            "\\appdata\\local\\programs\\powershell\\",
        )

        if any(fragment in normalised for fragment in trusted_fragments):
            candidates.append(resolved)

    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue

        key = os.path.normcase(str(resolved))
        if key in seen:
            continue

        seen.add(key)

        if resolved.is_file() and resolved.name.lower() == "pwsh.exe":
            return resolved

    return None


def launch_as_administrator(
    pwsh: Path,
    cipher_vault_script: Path,
    project_directory: Path,
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

    arguments = subprocess.list2cmdline(
        [
            "-NoProfile",
            "-File",
            str(cipher_vault_script),
        ]
    )

    result = shell_execute(
        None,
        "runas",
        str(pwsh),
        arguments,
        str(project_directory),
        SW_SHOW,
    )

    return result > 32


def main() -> int:
    if sys.platform != "win32":
        show_error("CipherVault can only be launched on Windows.")
        return 1

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
            "PowerShell 7.4+ (pwsh.exe) was not found in a standard "
            "installation location."
        )
        return 1

    if not launch_as_administrator(
        pwsh,
        cipher_vault_script,
        project_directory,
    ):
        show_error(
            "CipherVault could not be started with administrator privileges."
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
