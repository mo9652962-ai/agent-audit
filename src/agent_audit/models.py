"""核心数据模型：Finding / CheckResult / 严重度排序。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def worst_severity(findings: list[Finding]) -> str | None:
    """返回 findings 中最高严重度，无发现时返回 None。"""
    worst = None
    for f in findings:
        if worst is None or SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]:
            worst = f.severity
    return worst


@dataclass
class Finding:
    check: str
    title: str
    severity: str  # critical / high / medium / low / info
    evidence: str
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CheckResult:
    name: str
    title: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    status: str = ""  # pass / warn / fail / skipped / error，由 derive_status 计算

    def derive_status(self) -> str:
        worst = worst_severity(self.findings)
        if worst in ("critical", "high"):
            self.status = "fail"
        elif worst in ("medium", "low"):
            self.status = "warn"
        else:
            self.status = "pass"
        return self.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "status": self.status,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "details": self.details,
        }


def skipped(name: str, title: str, reason: str) -> CheckResult:
    r = CheckResult(name=name, title=title, summary=reason)
    r.status = "skipped"
    return r


def errored(name: str, title: str, reason: str) -> CheckResult:
    r = CheckResult(name=name, title=title, summary=reason)
    r.status = "error"
    return r
