"""agent-audit CLI 入口。"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    tomllib = None

from . import __version__
from .checks import ALL_CHECKS, CHECK_FUNCS
from .models import SEVERITY_ORDER, CheckResult
from .report import STATUS_ICONS, overall_verdict, render_json, render_markdown


def _default_paths() -> dict:
    home = Path.home()
    hermes = (home / "AppData/Local/hermes") if sys.platform == "win32" else (home / ".hermes")
    return {
        "config_dirs": [str(hermes)],
        "skills_dirs": [str(hermes / "skills")],
        "workspaces": [str(Path.cwd())],
        "dep_dirs": [],
        "mcp_configs": [],  # 空 = 自动探测（Hermes / Claude Desktop）
    }


def load_config(path: str | None) -> dict:
    if not path:
        return {}
    if tomllib is None:
        print("[warn] Python <3.11 无 tomllib，忽略配置文件", file=sys.stderr)
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def build_ctx(args) -> dict:
    cfg = load_config(args.config)
    paths = cfg.get("paths", {})
    defaults = _default_paths()

    ctx: dict = {}
    for key in ("config_dirs", "skills_dirs", "workspaces", "dep_dirs", "mcp_configs"):
        cli_vals = getattr(args, key, None) or []
        cfg_vals = paths.get(key, [])
        vals = [str(v) for v in (list(cfg_vals) + list(cli_vals))]
        if vals:
            ctx[key] = vals
        elif key in defaults:
            ctx[key] = defaults[key]
        else:
            ctx[key] = []  # dep_dirs 空 = 复用 workspaces；mcp_configs 空 = 自动探测

    ports_cfg = cfg.get("ports", {})
    watch = ports_cfg.get("watch")
    if isinstance(watch, dict):
        ctx["watch_ports"] = {int(k): str(v) for k, v in watch.items()}
    elif isinstance(watch, list):
        ctx["watch_ports"] = {int(p): "" for p in watch}
    else:
        ctx["watch_ports"] = None
    ctx["system_noise_ports"] = set(ports_cfg.get("system_noise") or []) or None
    ctx["whitelist_extra"] = [str(x) for x in cfg.get("endpoints", {}).get("whitelist", [])]
    return ctx


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="agent-audit",
        description="AI Agent 环境安全审计：供应链投毒 / 密钥暴露 / 端口暴露 / MCP server 一键体检",
    )
    ap.add_argument("--version", action="version", version=f"agent-audit {__version__}")
    ap.add_argument("-c", "--config", help="TOML 配置文件（paths / ports / endpoints 段）")
    ap.add_argument("--skills-dir", action="append", dest="skills_dirs",
                    help="skill 目录，可多次指定（默认自动探测 Hermes）")
    ap.add_argument("--config-dir", action="append", dest="config_dirs",
                    help="agent 配置目录（凭据权限 + 明文密钥扫描），可多次指定")
    ap.add_argument("--workspace", action="append", dest="workspaces",
                    help="git 泄漏检查的工作区，可多次指定（默认当前目录）")
    ap.add_argument("--mcp-config", action="append", dest="mcp_configs",
                    help="MCP 配置文件（yaml/json），可多次指定；不指定则自动探测")
    ap.add_argument("--dep-dir", action="append", dest="dep_dirs",
                    help="依赖审计的 Python 项目目录（默认复用 workspaces）")
    ap.add_argument("--checks", default=",".join(ALL_CHECKS),
                    help=f"要运行的检查项，逗号分隔（默认全部：{','.join(ALL_CHECKS)}）")
    ap.add_argument("--format", dest="fmt", default="md,json",
                    help="报告格式：md / json / both（默认 md,json）")
    ap.add_argument("-o", "--output-dir", default="agent-audit-reports",
                    help="报告输出目录（默认 ./agent-audit-reports）")
    ap.add_argument("--severity-threshold", default="high", choices=list(SEVERITY_ORDER),
                    help="触发退出码 1 的最低严重度（默认 high，可用于 CI 门禁）")
    ap.add_argument("-q", "--quiet", action="store_true", help="只输出报告路径与判定")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    names = [s.strip() for s in args.checks.split(",") if s.strip()]
    unknown = [n for n in names if n not in CHECK_FUNCS]
    if unknown:
        print(f"[error] 未知检查项：{', '.join(unknown)}（可选：{', '.join(ALL_CHECKS)}）", file=sys.stderr)
        return 2

    ctx = build_ctx(args)
    results: list[CheckResult] = []
    for name in ALL_CHECKS:
        if name not in names:
            continue
        try:
            r = CHECK_FUNCS[name](ctx)
        except Exception as e:  # noqa: BLE001 —— 单项失败不阻断整体，属设计内
            r = CheckResult(name=name, title=name, summary=f"检查执行出错：{e}")
            r.status = "error"
        results.append(r)
        if not args.quiet:
            print(f"  {STATUS_ICONS.get(r.status, '?')} {r.title:<12} {r.summary}")

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    scope = "; ".join(filter(None, [
        f"skills={ctx['skills_dirs']}",
        f"config={ctx['config_dirs']}",
        f"workspace={ctx['workspaces']}",
    ]))

    fmts = {"md", "json"} if args.fmt in ("both", "all") else {s.strip() for s in args.fmt.split(",") if s.strip()}
    written: list[Path] = []
    if "md" in fmts:
        p = outdir / f"agent-audit-{stamp}.md"
        p.write_text(render_markdown(results, args.severity_threshold, scope), encoding="utf-8")
        written.append(p)
    if "json" in fmts:
        p = outdir / f"agent-audit-{stamp}.json"
        p.write_text(
            json.dumps(render_json(results, args.severity_threshold, scope), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        written.append(p)

    verdict = overall_verdict(results)
    print(f"\nAI Agent 环境安全审计 v{__version__} — 总体判定: {verdict}")
    print(f"报告: {', '.join(str(p) for p in written)}")

    worst = None
    for r in results:
        for f in r.findings:
            if worst is None or SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]:
                worst = f.severity
    breach = worst is not None and SEVERITY_ORDER[worst] >= SEVERITY_ORDER[args.severity_threshold]
    if breach:
        print(f"存在 ≥{args.severity_threshold} 级发现，退出码 1（可用于 CI 门禁）")
    return 1 if breach else 0
