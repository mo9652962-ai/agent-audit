"""检查 1：端口暴露——网关/服务必须只监听 127.0.0.1，严禁 0.0.0.0。

背景（2026 实战）：OpenClaw 默认监听 0.0.0.0:18789，国家应急中心通报 85% 实例
暴露公网；ComfyUI 1000+ 暴露实例被组僵尸网络。看到 0.0.0.0 → 立即改
--listen 127.0.0.1 或防火墙封禁。
"""

from __future__ import annotations

import ipaddress
import re
import sys
from ..models import CheckResult, Finding
from .common import run_cmd

CHECK_NAME = "ports"
CHECK_TITLE = "端口暴露检查"

# 已知 agent 服务端口（OpenClaw 网关 / ComfyUI / Hermes）
WATCH_PORTS = {18789: "OpenClaw 网关", 8188: "ComfyUI", 1042: "Hermes"}
# Windows 系统服务常见端口，绑 0.0.0.0 属正常行为，降级为 low
SYSTEM_NOISE_PORTS = {135, 137, 138, 139, 445, 5040, 5355, 5357, 5985, 7680, 3389, 912}
# Windows 系统进程：RPC 动态端口（49152-65535）绑 0.0.0.0 是默认行为，降级为 low
SYSTEM_PROCESSES = {
    "lsass.exe", "wininit.exe", "services.exe", "svchost.exe", "spoolsv.exe",
    "smss.exe", "csrss.exe", "winlogon.exe", "dwm.exe", "fontdrvhost.exe", "system",
}

LOCAL_RE = re.compile(r"^\[?([0-9a-fA-F:.]+|\*)\]?:(\d+)$")


def _parse_listeners() -> tuple[list[dict], str]:
    """跨平台解析 TCP 监听 socket，返回 (listeners, source)。"""
    listeners: list[dict] = []
    if sys.platform == "win32":
        rc, out, err = run_cmd(["netstat", "-ano", "-p", "tcp"])
        if rc != 0:
            return [], f"netstat failed: {err.strip()}"
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
                m = LOCAL_RE.match(parts[1])
                if m:
                    listeners.append({"addr": m.group(1), "port": int(m.group(2)), "pid": parts[4]})
        return listeners, "netstat -ano -p tcp"

    # unix: 先 ss，回退 netstat
    rc, out, err = run_cmd(["ss", "-tlnp"])
    if rc == 0:
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) >= 4 and parts[0] == "LISTEN":
                m = LOCAL_RE.match(parts[3])
                if m:
                    pm = re.search(r"pid=(\d+)", ln)
                    listeners.append({"addr": m.group(1), "port": int(m.group(2)), "pid": pm.group(1) if pm else ""})
        if listeners or not err.strip():
            return listeners, "ss -tlnp"
    rc, out, err = run_cmd(["netstat", "-tlnp"])
    if rc == 0:
        for ln in out.splitlines():
            parts = ln.split()
            if len(parts) >= 6 and "LISTEN" in parts:
                m = LOCAL_RE.match(parts[3])
                if m:
                    listeners.append(
                        {"addr": m.group(1), "port": int(m.group(2)), "pid": parts[6].split("/")[0] if len(parts) > 6 else ""}
                    )
        return listeners, "netstat -tlnp"
    return [], f"no listener source available: {err.strip()}"


def _is_loopback_addr(addr: str) -> bool:
    if addr == "::1":
        return True
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _proc_name(pid: str, cache: dict) -> str:
    if not pid:
        return ""
    if pid in cache:
        return cache[pid]
    name = ""
    if sys.platform == "win32":
        rc, out, _ = run_cmd(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"])
        if rc == 0 and out.strip():
            first = out.strip().splitlines()[0]
            if first.startswith('"'):
                name = first.split('","')[0].strip('"')
    else:
        rc, out, _ = run_cmd(["ps", "-p", pid, "-o", "comm="])
        if rc == 0:
            name = out.strip()
    cache[pid] = name
    return name


def check(ctx: dict) -> CheckResult:
    result = CheckResult(name=CHECK_NAME, title=CHECK_TITLE, summary="")
    watch = ctx.get("watch_ports") or WATCH_PORTS
    if isinstance(watch, (list, tuple, set)):
        watch = {int(p): "" for p in watch}
    noise = set(ctx.get("system_noise_ports") or SYSTEM_NOISE_PORTS)

    listeners, source = _parse_listeners()
    if not listeners and not source.startswith("netstat -ano -p tcp") and source != "ss -tlnp" and source != "netstat -tlnp":
        result.summary = f"无法获取监听列表：{source}"
        result.status = "error"
        return result

    findings: list[Finding] = []
    proc_cache: dict = {}
    loopback_n = 0
    wildcard_n = 0
    for l in listeners:
        l["process"] = _proc_name(l["pid"], proc_cache)
        addr, port = l["addr"], l["port"]
        is_any = addr in ("0.0.0.0", "::", "*")
        ev = f"{addr}:{port} PID {l['pid']} {l['process']}".strip()
        if is_any:
            wildcard_n += 1
            if port in watch:
                svc = f"（{watch[port]}）" if watch[port] else ""
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"端口 {port}{svc} 监听 {addr}",
                    severity="critical",
                    evidence=ev,
                    remediation="立即改只监听 127.0.0.1（如 --listen 127.0.0.1）或防火墙封禁公网入口；85% OpenClaw 实例暴露公网（国家应急中心通报）。",
                ))
            elif l.get("process", "").lower() in SYSTEM_PROCESSES and port >= 49152:
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"Windows 系统进程 RPC 动态端口 {port} 监听 {addr}",
                    severity="low",
                    evidence=ev,
                    remediation="Windows RPC 动态端口默认行为；确认防火墙未对公网放行即可。",
                ))
            elif port in noise:
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"系统服务端口 {port} 监听 {addr}",
                    severity="low",
                    evidence=ev,
                    remediation="Windows 系统服务常见行为；确认防火墙未对公网放行即可。",
                ))
            else:
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"未知服务端口 {port} 监听 {addr}",
                    severity="high",
                    evidence=ev,
                    remediation="确认进程归属；非本机必须暴露的服务一律改 127.0.0.1 或防火墙封禁。",
                ))
        elif not _is_loopback_addr(addr):
            findings.append(Finding(
                check=CHECK_NAME,
                title=f"端口 {port} 绑定具体网卡地址 {addr}",
                severity="medium",
                evidence=ev,
                remediation="绑定具体网卡意味着同网段可达；无局域网访问需求时改 127.0.0.1。",
            ))
        else:
            loopback_n += 1

    result.findings = findings
    result.details = {
        "source": source,
        "total_listeners": len(listeners),
        "loopback_listeners": loopback_n,
        "wildcard_listeners": wildcard_n,
        "listeners": [
            {"addr": l["addr"], "port": l["port"], "pid": l["pid"], "process": l.get("process", "")}
            for l in listeners
        ],
    }
    bad = [f for f in findings if f.severity in ("critical", "high")]
    if bad:
        result.summary = f"发现 {len(bad)} 个 0.0.0.0 通配监听需处理（共 {len(listeners)} 个监听）"
    else:
        result.summary = f"全部 {len(listeners)} 个监听均绑定 loopback 或具体地址，无 0.0.0.0 通配 ✅"
    result.derive_status()
    return result
