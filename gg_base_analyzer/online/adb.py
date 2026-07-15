from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def find_adb() -> str | None:
    exe = shutil.which("adb")
    return exe


def adb_devices(adb: str | None = None) -> list[str]:
    adb = adb or find_adb()
    if not adb:
        return []
    try:
        out = subprocess.check_output([adb, "devices"], text=True, timeout=15, errors="replace")
    except (OSError, subprocess.SubprocessError):
        return []
    devices: list[str] = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def adb_shell(args: list[str], *, adb: str | None = None, serial: str | None = None) -> str:
    adb = adb or find_adb()
    if not adb:
        raise RuntimeError("未找到 adb，请安装 Android platform-tools 并加入 PATH")
    cmd = [adb]
    if serial:
        cmd.extend(["-s", serial])
    cmd.append("shell")
    cmd.extend(args)
    return subprocess.check_output(cmd, text=True, timeout=30, errors="replace")


def default_user_dir() -> Path:
    return Path.home() / "Documents" / "gg-base-analyzer"
