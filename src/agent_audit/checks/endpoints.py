"""检查 3：外发端点白名单审查——决定性检查。

判定标准（来自实战沉淀）：
  ✅ 通过 = 全部端点均为正规官方 API 或本地回环（127.0.0.1 调用属正常）
  ❌ 可疑 = 未知域名、IP:port 直连、内网穿透隧道（trycloudflare）、短链接
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from ..models import CheckResult, Finding
from .common import is_ip, is_loopback, is_private_ip, iter_files

CHECK_NAME = "endpoints"
CHECK_TITLE = "外发端点白名单审查"

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]-]+")
CODE_EXTS = {".py", ".sh", ".js", ".mjs", ".cjs", ".ts"}
MAX_FILE_SIZE = 2 * 1024 * 1024

TUNNEL_SUFFIX = ("trycloudflare.com", "ngrok.io", "ngrok-free.app", "loca.lt", "localtunnel.me")
SHORTLINK_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "t.me",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}
# 规范/Schema 命名空间：出现在配置与文档中的 XML namespace / spec 链接，不是运行时端点
DOC_SCHEMA_SUFFIX = (
    "w3.org", "whatwg.org", "openxmlformats.org", "schemas.microsoft.com",
    "purl.org", "ietf.org", "rfc-editor.org",
)
# RFC 2606 保留的文档示例域名
RESERVED_DOC_HOSTS = {"example.com", "example.org", "example.net"}

# 正规官方 API 白名单（后缀匹配，host 或 host 子域均算通过）
DEFAULT_WHITELIST = {
    # LLM 提供商
    "api.openai.com", "api.anthropic.com", "api.deepseek.com", "api.moonshot.cn",
    "api.siliconflow.cn", "open.bigmodel.cn", "dashscope.aliyuncs.com",
    "generativelanguage.googleapis.com", "api.mistral.ai", "api.x.ai", "openrouter.ai",
    # 工具 / 数据 / 包管理
    "open.tavily.com", "api.tavily.com", "api.clarivate.net", "api.github.com",
    "huggingface.co", "hf-mirror.com", "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "api.search.brave.com", "serpapi.com",
    "api.telegram.org", "discord.com", "api.notion.com",
    # 代码托管 / Google 生态（skill 文档里最常见的引用域）
    "github.com", "githubusercontent.com", "github.io", "googleapis.com", "gstatic.com",
    # agent 生态官方域（skill 市场 / ComfyUI 云）
    "clawhub.ai", "myclaw.ai", "comfy.org", "openclaw.ai",
    # 文档徽章 / 公共 CDN / 论文
    "shields.io", "jsdelivr.net", "unpkg.com", "arxiv.org",
}


def classify_url(url: str, whitelist: set[str]) -> tuple[str, str]:
    """对单个 URL 判定，返回 (verdict, reason)。

    verdict ∈ ok / info / medium / high / critical
    """
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return "medium", "URL 解析失败，人工复核"
    if not host:
        return "medium", "无主机名，人工复核"
    if is_loopback(host):
        return "ok", "本地回环"
    if host.endswith(TUNNEL_SUFFIX):
        return "critical", "内网穿透隧道（trycloudflare/ngrok 等）"
    if host in SHORTLINK_HOSTS:
        return "high", "短链接域名"
    if is_ip(host):
        if is_private_ip(host):
            return "info", "内网 IP（局域网服务，确认归属）"
        return "high", "公网 IP 直连（绕过域名审计）"
    if host.endswith(DOC_SCHEMA_SUFFIX) or host in RESERVED_DOC_HOSTS:
        return "ok", "规范/Schema 命名空间或文档示例域"
    for wl in whitelist:
        if host == wl or host.endswith("." + wl):
            return "ok", "官方 API 白名单"
    return "medium", "未知域名，需人工复核"


def _remediation(verdict: str, reason: str) -> str:
    if verdict == "critical":
        return "立即禁用该 skill 并隔离审查；内网穿透隧道是数据外传的典型通道。"
    if "短链接" in reason:
        return "解链确认真实目的地前一律视为可疑。"
    if "IP 直连" in reason:
        return "确认 IP 归属；skill 代码中出现公网 IP 直连是投毒常见特征。"
    return "人工确认域名归属：正规官方 API 则加入白名单，否则删除该 skill。"


def check(ctx: dict) -> CheckResult:
    whitelist = set(DEFAULT_WHITELIST) | {str(w).lower().strip(".") for w in ctx.get("whitelist_extra", [])}
    result = CheckResult(name=CHECK_NAME, title=CHECK_TITLE, summary="")
    hits: dict[tuple, dict] = {}  # (skill, url) -> {verdict, reason, count, files}
    verdict_counts: Counter = Counter()
    scanned = 0
    per_dir: dict = {}

    for d in ctx.get("skills_dirs", []):
        p = Path(d).expanduser()
        if not p.is_dir():
            continue
        dir_entry = {"skills": {}}
        for child in sorted(p.iterdir()):
            if not child.is_dir():
                continue
            is_market = child.name.startswith("@")
            for f in iter_files(child):
                ext = f.suffix.lower()
                # 市场导入 skill 额外扫 .md（SKILL.md 里的指令同样会被 agent 执行）
                if ext not in CODE_EXTS and not (is_market and ext == ".md"):
                    continue
                try:
                    if f.stat().st_size > MAX_FILE_SIZE:
                        continue
                    text = f.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                scanned += 1
                rel = str(f.relative_to(p))
                for m in URL_RE.finditer(text):
                    url = m.group(0).rstrip(".,;)")
                    verdict, reason = classify_url(url, whitelist)
                    verdict_counts[verdict] += 1
                    key = (child.name, url)
                    info = hits.setdefault(key, {"verdict": verdict, "reason": reason, "count": 0, "files": []})
                    info["count"] += 1
                    if rel not in info["files"]:
                        info["files"].append(rel)
            skill_hits = {url: v for (s, url), v in hits.items() if s == child.name}
            if skill_hits:
                dir_entry["skills"][child.name] = {
                    url: {"verdict": v["verdict"], "reason": v["reason"], "count": v["count"]}
                    for url, v in skill_hits.items()
                }
        per_dir[str(p)] = dir_entry

    findings: list[Finding] = []
    for (skill, url), info in sorted(hits.items()):
        if info["verdict"] in ("critical", "high", "medium"):
            files_disp = ", ".join(info["files"][:3]) + ("…" if len(info["files"]) > 3 else "")
            findings.append(Finding(
                check=CHECK_NAME,
                title=f"[{skill}] {info['reason']}",
                severity=info["verdict"],
                evidence=f"{url} ← {files_disp}（{info['count']} 次）",
                remediation=_remediation(info["verdict"], info["reason"]),
            ))

    result.findings = findings
    result.details = {"scanned_files": scanned, "verdict_counts": dict(verdict_counts), "dirs": per_dir}
    bad = sum(v for k, v in verdict_counts.items() if k in ("critical", "high", "medium"))
    if scanned == 0:
        result.summary = "未扫描到任何 skill 文件（skills 目录不存在或为空）"
        result.status = "skipped"
    else:
        if bad:
            result.summary = f"扫描 {scanned} 个文件：可疑端点 {bad} 处，需逐条复核"
        else:
            result.summary = f"扫描 {scanned} 个文件：全部端点为官方 API / 本地回环 ✅"
        result.derive_status()
    return result
