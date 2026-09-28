"""检查 6：依赖审计——uv audit / pip-audit 扫描已知漏洞（P1）。

背景：2026-03 阿里云报告 LiteLLM/Axios/Apifox/Trivy 投毒波及 OpenClaw 等多个
应用 → 锁定依赖版本（uv.lock），避免自动升级到恶意版本。

工具链：优先 uv audit；不可用回退 uvx pip-audit / pip-audit；都没有则提示安装。
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from ..models import CheckResult, Finding
from .common import run_cmd

CHECK_NAME = "deps"
CHECK_TITLE = "依赖漏洞审计"

MARKERS = ("pyproject.toml", "uv.lock", "requirements.txt")
VULN_ID_RE = re.compile(r"\b((?:GHSA|PYSEC|CVE|OSV)-[A-Za-z0-9\-\.]+)")


def _parse_text_vulns(text: str) -> list[str]:
    lines = []
    for ln in text.splitlines():
        s = ln.strip()
        if s and VULN_ID_RE.search(s):
            lines.append(s[:200])
    return lines


def _parse_json_vulns(out: str) -> list[str]:
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return _parse_text_vulns(out)
    items = data if isinstance(data, list) else data.get("dependencies", [])
    vulns = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "?")
        ver = item.get("version", "?")
        for v in item.get("vulns", []):
            vid = v.get("id") or ((v.get("aliases") or ["?"])[0])
            fixes = v.get("fixes") or []
            fix = ", ".join(f.get("version", "?") for f in fixes if isinstance(f, dict)) or "无修复版本"
            vulns.append(f"{name}=={ver} {vid} fix: {fix}")
    return vulns


def check(ctx: dict) -> CheckResult:
    result = CheckResult(name=CHECK_NAME, title=CHECK_TITLE, summary="")
    roots = ctx.get("dep_dirs") or ctx.get("workspaces") or []

    targets: list[Path] = []
    seen: set = set()
    for root in roots:
        p = Path(root).expanduser()
        if not p.is_dir():
            continue
        candidates = [p] + [c for c in sorted(p.iterdir()) if c.is_dir()]
        for c in candidates:
            if any((c / m).exists() for m in MARKERS) and c not in seen:
                seen.add(c)
                targets.append(c)
    if not targets:
        result.summary = "未发现 Python 项目（pyproject.toml / uv.lock / requirements.txt）"
        result.status = "skipped"
        return result

    has_uv = shutil.which("uv") is not None
    has_pip_audit = shutil.which("pip-audit") is not None
    has_uvx = shutil.which("uvx") is not None

    findings: list[Finding] = []
    details: dict = {}
    total_vulns = 0
    audited = 0

    for t in targets:
        entry: dict = {"tool": None, "vuln_count": 0, "vulns": [], "note": ""}
        vuln_lines: list[str] = []
        tool_used = None

        if has_uv:
            rc, out, err = run_cmd(["uv", "audit"], cwd=str(t), timeout=300)
            if rc in (0, 1):
                tool_used = "uv audit"
                vuln_lines = _parse_text_vulns(out + "\n" + err)
            else:
                entry["note"] = f"uv audit 不可用（rc={rc}），回退 pip-audit"

        if tool_used is None and (has_pip_audit or has_uvx):
            if has_pip_audit:
                cmd = ["pip-audit", "--format", "json", "-l"]
                tool_name = "pip-audit"
            else:
                cmd = ["uvx", "pip-audit", "--format", "json"]
                tool_name = "uvx pip-audit"
            rc, out, err = run_cmd(cmd, cwd=str(t), timeout=300)
            if rc in (0, 1):
                tool_used = tool_name
                if rc == 1:
                    vuln_lines = _parse_json_vulns(out)
            else:
                note = f"pip-audit 执行失败 rc={rc}: {err.strip()[:120]}"
                entry["note"] = (entry["note"] + "；" + note) if entry["note"] else note

        entry["tool"] = tool_used
        if tool_used is None:
            findings.append(Finding(
                check=CHECK_NAME,
                title="无可用依赖审计工具",
                severity="info",
                evidence=str(t),
                remediation="安装 pip-audit（pip install pip-audit）或升级 uv 后重跑本检查。",
            ))
        else:
            audited += 1
            entry["vuln_count"] = len(vuln_lines)
            entry["vulns"] = vuln_lines[:50]
            total_vulns += len(vuln_lines)
            for v in vuln_lines[:20]:
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"依赖已知漏洞（{t.name}）",
                    severity="medium",
                    evidence=v,
                    remediation="按公告升级/钉住安全版本；警惕自动升级到未知新版本（2026-03 LiteLLM/Axios/Trivy 投毒事件）。",
                ))
        details[str(t)] = entry

    result.findings = findings
    result.details = details
    if audited == 0:
        result.summary = "发现 Python 项目但没有可用的审计工具"
        result.status = "skipped"
    else:
        result.summary = f"{audited}/{len(targets)} 个项目完成审计，共 {total_vulns} 个已知漏洞"
        result.derive_status()
    return result
