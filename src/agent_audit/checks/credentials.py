"""检查 4：凭据权限与明文密钥。

要点（来自实战沉淀）：
- Vidar 窃密变种专偷 agent 配置目录（config/密钥）→ .env 等文件收紧权限是硬性防御
- config.yaml 有真实 key ≠ 必须删：它是正常配置；关键在「是否被 git 追踪/是否外传」
- 记忆文件（MEMORY.md 等）里只放「密钥的位置说明」，不放真实值 → .md 命中即 high
- .env / auth.json 本就是密钥载体，不做明文扫描，只查权限
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from ..models import CheckResult, Finding
from .common import iter_files, run_cmd

CHECK_NAME = "credentials"
CHECK_TITLE = "凭据权限与明文检查"

KEY_PATTERNS = [
    # JSON 键名带引号（"access_token": "..."），冒号前可有闭引号；\b 在下划线处不成立，用 (?<![A-Za-z])
    ("OpenAI 风格密钥 (sk-)", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("api_key 明文赋值", re.compile(r"""(?i)(?<![A-Za-z])api[_-]?key\w*["']?\s*[:=]\s*["']?([A-Za-z0-9_\-.]{20,})""")),
    ("token/secret 赋值", re.compile(r"""(?i)(?<![A-Za-z])(?:token|secret)\w*["']?\s*[:=]\s*["']?([A-Za-z0-9_\-.]{24,})""")),
    ("GitHub PAT", re.compile(r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("AWS AccessKey", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
]
PLACEHOLDER_RE = re.compile(r"(?i)(your[_-]?|xxx+|example|placeholder|<[^>]{1,40}>|\$\{|%s)")

SCAN_EXTS = {".md", ".yaml", ".yml", ".json", ".toml", ".txt"}
# 密钥载体文件：只查权限，不做明文扫描（明文是它们的本职）
CRED_BASENAMES = [".env", ".env.local", ".env.production", "auth.json", "credentials.json", "config.yaml"]


def _mask(value: str) -> str:
    return value[:8] + "…" + value[-4:] if len(value) > 14 else "…"


def _scan_plaintext(roots: list[str], findings: list[Finding], details: dict) -> None:
    for root in roots:
        p = Path(root).expanduser()
        if not p.is_dir():
            continue
        root_entry = details.setdefault(str(p), {})
        for f in iter_files(p):
            if f.name.lower().startswith(".env"):
                continue
            if f.suffix.lower() not in SCAN_EXTS:
                continue
            try:
                if f.stat().st_size > 2 * 1024 * 1024:
                    continue
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for label, pat in KEY_PATTERNS:
                for m in pat.finditer(text):
                    value = m.group(1) if m.groups() else m.group(0)
                    if PLACEHOLDER_RE.search(value):
                        continue
                    line = text[: m.start()].count("\n") + 1
                    ext = f.suffix.lower()
                    sev = "high" if ext in (".md", ".txt") else "medium"
                    findings.append(Finding(
                        check=CHECK_NAME,
                        title=f"明文密钥：{label}",
                        severity=sev,
                        evidence=f"{f.name}:{line} → {_mask(value)}",
                        remediation=(
                            "记忆/文档类文件只放「密钥的位置说明」不放真实值；"
                            "config.yaml 建议改 key_env 引用；确认未被 git 追踪（下一检查项）。"
                        ),
                    ))
                    break  # 每文件每类只报一次
        root_entry["plaintext_scanned"] = True


def _check_perms(path: Path, findings: list[Finding], details: dict) -> None:
    key = str(path)
    if sys.platform == "win32":
        rc, out, err = run_cmd(["icacls", key])
        if rc != 0:
            details[key] = {"error": err.strip() or "icacls failed"}
            return
        wide = [ln.strip() for ln in out.splitlines()
                if re.search(r"(Everyone|BUILTIN\\Users|Authenticated Users)", ln, re.I)]
        inherited = "(I)" in out
        details[key] = {"wide_grants": wide, "inherited": inherited}
        if wide:
            findings.append(Finding(
                check=CHECK_NAME,
                title=f"凭据文件权限过宽：{path.name}",
                severity="high",
                evidence="; ".join(wide[:4]),
                remediation='icacls "<path>" /inheritance:r /grant:r "%USERNAME%:(R)"',
            ))
        elif inherited:
            findings.append(Finding(
                check=CHECK_NAME,
                title=f"凭据文件权限为继承所得（未显式收紧）：{path.name}",
                severity="low",
                evidence="ACL 含 (I) 继承标志，依赖上级目录权限",
                remediation="建议 icacls /inheritance:r 收紧到仅当前用户可读（Vidar 变种专偷 agent 配置目录）。",
            ))
        else:
            findings.append(Finding(
                check=CHECK_NAME,
                title=f"凭据文件权限已收紧：{path.name}",
                severity="info",
                evidence="仅当前用户/系统账户可访问",
                remediation="",
            ))
    else:
        mode = path.stat().st_mode & 0o777
        details[key] = {"mode": oct(mode)}
        if mode & 0o077:
            findings.append(Finding(
                check=CHECK_NAME,
                title=f"凭据文件权限过宽：{path.name}",
                severity="high",
                evidence=f"权限 {oct(mode)}（组/其他用户可访问）",
                remediation=f"chmod 600 {path}",
            ))
        else:
            findings.append(Finding(
                check=CHECK_NAME,
                title=f"凭据文件权限已收紧：{path.name}",
                severity="info",
                evidence=f"权限 {oct(mode)}",
                remediation="",
            ))


def check(ctx: dict) -> CheckResult:
    result = CheckResult(name=CHECK_NAME, title=CHECK_TITLE, summary="")
    findings: list[Finding] = []
    details: dict = {}

    _scan_plaintext(ctx.get("config_dirs", []), findings, details)

    env_checked = 0
    for root in ctx.get("config_dirs", []):
        p = Path(root).expanduser()
        if not p.is_dir():
            continue
        for base in CRED_BASENAMES:
            candidates = [p / base]
            candidates.extend(sorted(p.glob(f"*/{base}"))[:10])
            for cand in candidates:
                if cand.is_file():
                    _check_perms(cand, findings, details)
                    env_checked += 1

    result.findings = findings
    result.details = details
    n_plaintext = sum(1 for f in findings if f.title.startswith("明文密钥"))
    result.summary = f"明文密钥 {n_plaintext} 处；凭据文件权限检查 {env_checked} 个"
    result.derive_status()
    return result
