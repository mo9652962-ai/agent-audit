"""检查 7：MCP server 审计（对照 OWASP MCP Security Guide）。

审计判定清单（来自实战沉淀）：
| 检查项       | 通过标准                                 | 反例                     |
| 来源可信     | 本地 venv exe / 官方 @modelcontextprotocol/* | 未知名 npm 包、公网 URL |
| 无远程 MCP   | 全部 loopback（127.0.0.1）或本地进程      | http(s):// 非 loopback  |
| 鉴权         | loopback MCP 带 Bearer token             | 无鉴权端点               |
| 未使用即禁用 | enabled: false                           | 闲置 MCP 保持启用        |
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from ..models import CheckResult, Finding
from .common import is_loopback, is_private_ip

CHECK_NAME = "mcp"
CHECK_TITLE = "MCP Server 审计"


def _default_configs() -> list[Path]:
    home = Path.home()
    cands: list[Path] = []
    if sys.platform == "win32":
        cands.append(home / "AppData/Local/hermes/config.yaml")
        appdata = Path(os.environ.get("APPDATA", str(home / "AppData/Roaming")))
        cands.append(appdata / "Claude/claude_desktop_config.json")
    else:
        cands.append(home / ".hermes/config.yaml")
        cands.append(home / ".config/Claude/claude_desktop_config.json")
    return [c for c in cands if c.is_file()]


def _scalar(v: str):
    v = v.strip()
    if v.startswith("[") and v.endswith("]"):
        return [s.strip().strip("'\"") for s in v[1:-1].split(",") if s.strip()]
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    return v.strip("'\"")


def _mini_yaml(text: str) -> dict:
    """无 PyYAML 时的降级解析：仅提取 mcp_servers: 段的二级/三级键值。

    局限：多行列表、深层嵌套不解析；需要完整解析请 pip install PyYAML。
    """
    lines = text.splitlines()
    n = len(lines)
    i = 0
    while i < n and re.match(r"^mcp_servers:\s*(#.*)?$", lines[i]) is None:
        i += 1
    if i == n:
        return {}
    i += 1
    servers: dict = {}
    cur: str | None = None
    base_indent: int | None = None
    while i < n:
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        if not raw[0].isspace():
            break  # 下一个顶层键，mcp_servers 段结束
        indent = len(raw) - len(raw.lstrip(" "))
        if base_indent is None:
            base_indent = indent
        m = re.match(r"\s*([\w.\-]+):\s*(.*)$", raw)
        if not m:
            i += 1
            continue
        key, val = m.group(1), m.group(2).strip()
        if indent <= base_indent:
            cur = key
            servers[cur] = {}
            if val:
                servers[cur]["__inline__"] = val
        elif cur is not None:
            servers[cur][key] = _scalar(val)
        i += 1
    return {"mcp_servers": servers}


def _parse_config(path: Path) -> tuple[dict, dict, str]:
    """返回 (servers, toolsets, parser 标识)。"""
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix.lower() == ".json":
        data = json.loads(text) if text.strip() else {}
        parser = "json"
    else:
        try:
            import yaml
            data = yaml.safe_load(text) or {}
            parser = "pyyaml"
        except ImportError:
            data = _mini_yaml(text)
            parser = "regex-fallback"
    if not isinstance(data, dict):
        data = {}
    servers = data.get("mcp_servers") or data.get("mcpServers") or {}
    toolsets = data.get("platform_toolsets") or {}
    return (servers if isinstance(servers, dict) else {}), (toolsets if isinstance(toolsets, dict) else {}), parser


def _judge(name: str, conf: dict) -> tuple[str, str]:
    """判定单个 MCP server，返回 (verdict, reason)。

    verdict ∈ pass / info / medium / high / critical
    """
    if not conf.get("enabled", True):
        return "info", "已禁用（闲置 MCP 保持禁用是正确姿势）"
    url = conf.get("url")
    command = conf.get("command")
    if url:
        try:
            host = urlparse(str(url)).hostname or ""
        except ValueError:
            host = ""
        if is_loopback(host):
            auth = any(conf.get(k) for k in ("headers", "auth", "token", "bearer"))
            if auth:
                return "pass", "本地 loopback + 带鉴权"
            return "medium", "本地 loopback 但无鉴权字段（headers/token）"
        if is_private_ip(host):
            return "medium", "内网远程 MCP（非 loopback）"
        return "critical", "公网远程 MCP server（数据经第三方中转）"
    if command:
        args = [str(a) for a in (conf.get("args") or [])]
        if command in ("npx", "bunx") or command.endswith(("npx", "npx.cmd", "bunx")):
            pkg = next((a for a in args if not a.startswith("-")), "")
            if pkg.startswith("@modelcontextprotocol/"):
                return "pass", "官方 @modelcontextprotocol 包"
            return "high", f"未知名 npm 包：{pkg}（npx 临时执行不可审计）"
        if any(ch in command for ch in ("/", "\\")) or command.endswith(".exe"):
            return "pass", "本地可执行 / venv 程序"
        if command in ("python", "python3", "node", "uv", "uvx", "pythonw"):
            script = next((a for a in args if a.endswith((".py", ".js", ".mjs"))), "")
            if script:
                return "info", f"本地脚本：{script}（确认脚本来源可信）"
            return "info", "本地运行时启动（人工确认脚本来源）"
        return "info", f"来源需人工复核：{command}"
    return "info", "无 command/url 配置，人工复核"


def _remediation(verdict: str, reason: str) -> str:
    if verdict == "critical":
        return "删除该远程 MCP 配置；确需远程能力时自建网关 + 强鉴权。"
    if "npm 包" in reason:
        return "改用 @modelcontextprotocol/ 官方包或本地源码；安装前审查 npm 包。"
    if "无鉴权" in reason:
        return "加 headers Bearer token（参考 obsidian 27123 配置），并保持端口只监听 127.0.0.1。"
    if "内网远程" in reason:
        return "改用本地进程，或 SSH 隧道转到 loopback。"
    return ""


def check(ctx: dict) -> CheckResult:
    result = CheckResult(name=CHECK_NAME, title=CHECK_TITLE, summary="")
    paths = [Path(x).expanduser() for x in (ctx.get("mcp_configs") or [])]
    if not paths:
        paths = _default_configs()

    findings: list[Finding] = []
    details: dict = {}
    servers_seen = 0

    for path in paths:
        if not path.is_file():
            continue
        try:
            servers, toolsets, parser = _parse_config(path)
        except Exception as e:
            details[str(path)] = {"error": f"解析失败：{e}"}
            continue
        entry: dict = {"parser": parser, "servers": {}}
        if parser == "regex-fallback":
            findings.append(Finding(
                check=CHECK_NAME,
                title="无 PyYAML，MCP 配置使用降级解析",
                severity="info",
                evidence=str(path),
                remediation="pip install PyYAML 可获得更准确的解析。",
            ))
        for name, conf in servers.items():
            if not isinstance(conf, dict):
                conf = {"__inline__": str(conf)}
            src = str(conf.get("url") or conf.get("command") or "?")[:120]
            servers_seen += 1
            if not conf.get("enabled", True):
                entry["servers"][name] = {"enabled": False, "src": src, "verdict": "info", "reason": "已禁用"}
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"MCP [{name}] 已禁用（闲置未启用，符合最小攻击面）",
                    severity="info",
                    evidence=src,
                    remediation="",
                ))
                continue
            verdict, reason = _judge(name, conf)
            entry["servers"][name] = {"enabled": True, "src": src, "verdict": verdict, "reason": reason}
            if verdict in ("critical", "high", "medium"):
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"MCP [{name}] {reason}",
                    severity=verdict,
                    evidence=f"{path} → {src}",
                    remediation=_remediation(verdict, reason),
                ))
        if toolsets:
            entry["platform_toolsets"] = {str(k): v for k, v in toolsets.items()}
        details[str(path)] = entry

    result.findings = findings
    result.details = details
    if servers_seen == 0:
        result.summary = "未发现 MCP server 配置（可用 --mcp-config 指定）"
        result.status = "skipped"
    else:
        n_bad = sum(1 for f in findings if f.severity in ("critical", "high", "medium"))
        if n_bad:
            result.summary = f"共 {servers_seen} 个 MCP server，{n_bad} 个需关注"
        else:
            result.summary = f"共 {servers_seen} 个 MCP server，全部本地/官方 ✅"
        result.derive_status()
    return result
