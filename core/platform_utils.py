from __future__ import annotations

import getpass
import os
import platform
import shutil
import socket
import subprocess
import sys
import locale


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
        proc = subprocess.run(args, capture_output=True, timeout=timeout)
        encodings = ["utf-8-sig"]
        if current_os() == "windows":
            encodings.extend(["gbk", locale.getpreferredencoding(False)])
        else:
            encodings.append(locale.getpreferredencoding(False))
        return proc.returncode, decode_output(proc.stdout, encodings), decode_output(proc.stderr, encodings)
    except Exception as exc:
        return 1, "", str(exc)


def decode_output(data: bytes, encodings: list[str]) -> str:
    for encoding in encodings:
        if not encoding:
            continue
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def app_runtime() -> str:
    return getattr(sys, "frozen", False) and "frozen" or "python"
