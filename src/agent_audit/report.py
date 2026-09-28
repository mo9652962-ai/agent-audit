"""报告渲染：Markdown / JSON / 审计完成标准判定表。"""

from __future__ import annotations

import datetime
import platform
import socket

from .models import SEVERITY_ICONS, SEVERITY_ORDER, CheckResult

# 审计完成标准（来自实战沉淀的验证方式）
CRITERIA = [
    ("所有服务仅监听 127.0.0.1（无 0.0.0.0 通配）", "ports"),
    ("市场导入 skill 外发端点全部为官方 API / 本地回环", "endpoints"),
    ("凭据文件（.env 等）权限仅当前用户", "credentials"),
    ("git 不追踪 .env / config.yaml 且 .gitignore 规则齐备", "git"),
    ("依赖无已知漏洞（uv audit / pip-audit）", "deps"),
    ("MCP server 全部本地/官方，闲置项已禁用", "mcp"),
]

STATUS_ICONS = {"pass": "✅", "warn": "🟡", "fail": "❌", "skipped": "⏭️", "error": "⚠️"}


def overall_verdict(results: list[CheckResult]) -> str:
    worst = None
    for r in results:
        for f in r.findings:
            if worst is None or SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]:
                worst = f.severity
    if worst in ("critical", "high"):
        return "FAIL"
    if worst in ("medium", "low"):
        return "WARN"
    return "PASS"


def _cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_markdown(results: list[CheckResult], threshold: str, scope: str) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    verdict = overall_verdict(results)
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for r in results:
        for f in r.findings:
            counts[f.severity] += 1

    lines: list[str] = []
    lines.append("# AI Agent 环境安全审计报告")
    lines.append("")
    lines.append(f"- **审计时间**：{now}")
    lines.append(f"- **主机**：{socket.gethostname()}（{platform.system()} {platform.release()}）")
    lines.append(f"- **范围**：{_cell(scope)}")
    sev_line = " / ".join(f"{SEVERITY_ICONS[s]} {counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info"))
    lines.append(
        f"- **总体判定**：**{verdict}**（{sev_line}；退出码阻断阈值：{threshold}）"
    )
    lines.append("")

    lines.append("## 审计完成标准")
    lines.append("")
    lines.append("| 判定 | 标准 | 对应检查 |")
    lines.append("|:---:|:-----|:---------|")
    by_name = {r.name: r for r in results}
    for text, name in CRITERIA:
        r = by_name.get(name)
        status = r.status if r else "skipped"
        lines.append(f"| {STATUS_ICONS.get(status, '⏭️')} {status} | {text} | {name} |")
    lines.append("")

    lines.append("## 发现汇总")
    lines.append("")
    lines.append("| 检查 | 状态 | 摘要 |")
    lines.append("|:-----|:---:|:-----|")
    for r in results:
        lines.append(f"| {r.title} | {STATUS_ICONS.get(r.status, '?')} {r.status} | {_cell(r.summary)} |")
    lines.append("")

    lines.append("## 详细发现")
    for r in results:
        lines.append("")
        lines.append(f"### {r.title}（{STATUS_ICONS.get(r.status, '?')} {r.status}）")
        lines.append("")
        lines.append(_cell(r.summary))
        if r.findings:
            lines.append("")
            lines.append("| 严重度 | 发现 | 证据 | 修复建议 |")
            lines.append("|:------|:-----|:-----|:---------|")
            for f in sorted(r.findings, key=lambda x: -SEVERITY_ORDER[x.severity]):
                lines.append(
                    f"| {SEVERITY_ICONS[f.severity]} {f.severity} "
                    f"| {_cell(f.title)} | {_cell(f.evidence)} | {_cell(f.remediation or '—')} |"
                )

    actionable = [
        (f, r)
        for r in results
        for f in r.findings
        if f.severity in ("critical", "high", "medium")
    ]
    actionable.sort(key=lambda p: -SEVERITY_ORDER[p[0].severity])
    if actionable:
        lines.append("")
        lines.append("## 修复优先级清单")
        lines.append("")
        for i, (f, _r) in enumerate(actionable, 1):
            lines.append(f"{i}. **[{f.severity.upper()}] {f.title}** — {f.remediation or f.evidence}")
    lines.append("")
    return "\n".join(lines)


def render_json(results: list[CheckResult], threshold: str, scope: str) -> dict:
    return {
        "tool": "agent-audit",
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "scope": scope,
        "verdict": overall_verdict(results),
        "threshold": threshold,
        "results": [r.to_dict() for r in results],
    }
