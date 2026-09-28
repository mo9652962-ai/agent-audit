"""检查 2：Skill 来源分类审计——市场导入 skill 拥有与用户同等的执行权限，
是供应链风险的核心面。

背景（2026 实战）：ClawHavoc 供应链投毒顶峰期 800+ 恶意 skill 泛滥；Snyk 审计
ClawHub 3984 技能中 13.4% 含严重安全问题、36.8% 有漏洞。
注意：不要只数数量——外发端点白名单（下一检查项）才是决定性证据。
"""

from __future__ import annotations

from pathlib import Path
from ..models import CheckResult, Finding

CHECK_NAME = "skills"
CHECK_TITLE = "Skill 来源分类审计"


def check(ctx: dict) -> CheckResult:
    result = CheckResult(name=CHECK_NAME, title=CHECK_TITLE, summary="")
    findings: list[Finding] = []
    details: dict = {}
    found_any = False
    for d in ctx.get("skills_dirs", []):
        p = Path(d).expanduser()
        entry = {"path": str(p), "exists": p.is_dir(), "market": [], "official": []}
        if p.is_dir():
            found_any = True
            for child in sorted(p.iterdir()):
                if not child.is_dir():
                    continue
                if child.name.startswith("@"):
                    entry["market"].append(child.name)
                else:
                    entry["official"].append(child.name)
            if entry["market"]:
                names = ", ".join(entry["market"][:20]) + ("…" if len(entry["market"]) > 20 else "")
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=f"{len(entry['market'])} 个市场导入 skill（@ 前缀 = 最高供应链风险）",
                    severity="low",
                    evidence=names,
                    remediation="对每个市场 skill 做外发端点白名单复核（下一检查项）；新装前先过 skill-vetter 审查。",
                ))
            else:
                findings.append(Finding(
                    check=CHECK_NAME,
                    title="无市场导入 skill",
                    severity="info",
                    evidence=f"{p} 下全部为官方/自建 skill",
                    remediation="",
                ))
        else:
            findings.append(Finding(
                check=CHECK_NAME,
                title="skills 目录不存在",
                severity="info",
                evidence=str(p),
                remediation="可用 --skills-dir 指定实际目录。",
            ))
        details[str(p)] = entry

    result.findings = findings
    result.details = details
    if not found_any:
        result.summary = "未找到任何 skills 目录（可用 --skills-dir 指定）"
        result.status = "skipped"
    else:
        total_market = sum(len(e["market"]) for e in details.values())
        total_official = sum(len(e["official"]) for e in details.values())
        result.summary = f"市场导入 {total_market} 个 / 官方自建 {total_official} 个"
        result.derive_status()
    return result
