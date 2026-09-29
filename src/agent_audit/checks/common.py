"""检查项公共工具：命令执行、主机分类、文件遍历。"""

from __future__ import annotations

import ipaddress
import os
import subprocess  # nosec B404 —— 安全审计工具本体需调用系统命令（netstat/icacls/git）
from pathlib import Path


def run_cmd(args: list[str], timeout: int = 30, cwd: str | None = None) -> tuple[int, str, str]:
    """执行命令，返回 (rc, stdout, stderr)；命令不存在时 rc=127。"""
    try:
        p = subprocess.run(  # noqa: PLW1510 —— 返回码由调用方语义化处理；nosec B603 参数全为工具自构造
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(args)}"
    except OSError as e:
        return 126, "", str(e)


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower().rstrip(".") == "localhost"


def is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _skip_dir(name: str) -> bool:
    """目录名含这些子串时整体跳过：缓存/备份/运行时/浏览器配置目录是扫描噪音重灾区。"""
    n = name.lower()
    return any(
        t in n
        for t in (
            "cache",
            "backup",
            "node_modules",
            ".venv",
            "venv",
            "__pycache__",
            ".git",
            "profile",  # chrome-profile 等
            "site-packages",
            "dist",
            "build",
        )
    )


def iter_files(root: Path):
    """遍历目录产出文件路径，剪掉噪音目录。"""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        for fn in filenames:
            yield Path(dirpath) / fn
