from __future__ import annotations

import getpass
import os
import platform
import shutil
import socket
import subprocess
import sys


def current_os() -> str:
    name = platform.system().lower()
    if name.startswith("win"):
        return "windows"
    if name.startswith("linux"):
        return "linux"
    return name or "unknown"


def host_name() -> str:
    return socket.gethostname()


def current_user() -> str:
    return getpass.getuser()


def is_admin() -> bool:
    if current_os() == "windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return 1, "", str(exc)


def app_runtime() -> str:
    return getattr(sys, "frozen", False) and "frozen" or "python"
