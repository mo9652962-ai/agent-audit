"""检查 5：Git 泄漏——.env/config.yaml 被 git 追踪 = 密钥随 auto-sync 外传。

要点：auto-sync（git add -A 类 cron）会把一切未忽略文件提交 → 密钥文件必须进
.gitignore（*.env、**/.env、config.yaml、**/config.yaml）。
"""

from __future__ import annotations

import re
from pathlib import Path
from ..models import CheckResult, Finding
from .common import run_cmd

CHECK_NAME = "git"
CHECK_TITLE = "Git 泄漏检查"

TRACKED_SECRET_RE = re.compile(
    r"(^|/)\.env(\..+)?$|config\.ya?ml$|\.(pem|key|p12|pfx)$|(^|/)secret",
    re.I,
)
REQUIRED_RULES = [".env", "config.yaml"]


def check(ctx: dict) -> CheckResult:
    result = CheckResult(name=CHECK_NAME, title=CHECK_TITLE, summary="")
    findings: list[Finding] = []
    details: dict = {}
    repo_found = False

    for ws in ctx.get("workspaces", []):
        p = Path(ws).expanduser()
        entry: dict = {"is_repo": False}
        if (p / ".git").exists():
            repo_found = True
            entry["is_repo"] = True
            rc, out, err = run_cmd(["git", "-C", str(p), "ls-files"], timeout=60)
            if rc == 0:
                tracked = [ln for ln in out.splitlines() if ln.strip()]
                hits = [f for f in tracked if TRACKED_SECRET_RE.search(f)]
                entry["tracked_files"] = len(tracked)
                entry["secret_hits"] = hits
                if hits:
                    findings.append(Finding(
                        check=CHECK_NAME,
                        title=f"密钥文件被 git 追踪（{p.name}）",
                        severity="critical",
                        evidence=", ".join(hits[:10]) + ("…" if len(hits) > 10 else ""),
                        remediation=(
                            "git rm --cached 掉这些文件；密钥视为已泄漏，立即轮换；"
                            ".gitignore 补规则（auto-sync 会提交一切未忽略文件）。"
                        ),
                    ))
                else:
                    findings.append(Finding(
                        check=CHECK_NAME,
                        title=f"git 追踪文件无密钥命中（{p.name}）",
                        severity="info",
                        evidence=f"共 {len(tracked)} 个被追踪文件",
                        remediation="",
                    ))
            else:
                entry["error"] = err.strip()

            gi = p / ".gitignore"
            if gi.is_file():
                content = gi.read_text(encoding="utf-8", errors="ignore")
                missing = [r for r in REQUIRED_RULES if r not in content]
                entry["gitignore_missing"] = missing
                if missing:
                    findings.append(Finding(
                        check=CHECK_NAME,
                        title=f".gitignore 缺少密钥规则：{'、'.join(missing)}",
                        severity="medium",
                        evidence=str(gi),
                        remediation="加入 *.env、**/.env、config.yaml、**/config.yaml（防 auto-sync 误提交）。",
                    ))
                else:
                    findings.append(Finding(
                        check=CHECK_NAME,
                        title=".gitignore 密钥规则齐备",
                        severity="info",
                        evidence=str(gi),
                        remediation="",
                    ))
            else:
                findings.append(Finding(
                    check=CHECK_NAME,
                    title=".gitignore 不存在",
                    severity="medium",
                    evidence=str(p),
                    remediation="创建 .gitignore 并加入 *.env、config.yaml 等密钥规则。",
                ))
        details[str(p)] = entry

    result.findings = findings
    result.details = details
    if not repo_found:
        result.summary = "工作区中未发现 git 仓库"
        result.status = "skipped"
    else:
        result.summary = f"{len(ctx.get('workspaces', []))} 个工作区检查完成"
        result.derive_status()
    return result
