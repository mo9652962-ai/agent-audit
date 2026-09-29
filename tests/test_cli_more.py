"""CLI 分支：未知检查项、单项失败隔离、格式输出、门禁退出码、配置装载。"""
import sys
from pathlib import Path

import pytest

import agent_audit.cli as cli_mod
from agent_audit.cli import build_ctx, build_parser, load_config
from agent_audit.cli import main as cli_main
from agent_audit.models import Finding


def test_cli_unknown_check_rc2(capsys):
    rc = cli_main(["--checks", "no-such-check"])
    assert rc == 2
    assert "未知检查项" in capsys.readouterr().err


def _fake_result(severity=None):
    r = cli_mod.CheckResult(name="ports", title="端口暴露检查", summary="x")
    if severity:
        r.findings = [Finding(check="ports", title="端口 1 监听 0.0.0.0", severity=severity, evidence="e")]
        r.derive_status()
    else:
        r.status = "pass"
    return r


def test_cli_check_exception_isolated(tmp_path, monkeypatch, capsys):
    def boom(ctx):
        raise RuntimeError("boom")

    monkeypatch.setitem(cli_mod.CHECK_FUNCS, "ports", boom)
    rc = cli_main(["--checks", "ports", "-o", str(tmp_path / "reports")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "检查执行出错" in out
    assert (tmp_path / "reports").exists()


def test_cli_format_md_only(tmp_path, monkeypatch):
    monkeypatch.setitem(cli_mod.CHECK_FUNCS, "ports", lambda ctx: _fake_result())
    rc = cli_main(["--checks", "ports", "--format", "md", "-o", str(tmp_path / "reports"), "-q"])
    reports = list((tmp_path / "reports").glob("*"))
    assert rc == 0
    assert len(reports) == 1
    assert reports[0].suffix == ".md"


def test_cli_nonquiet_prints_progress(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(cli_mod.CHECK_FUNCS, "ports", lambda ctx: _fake_result())
    rc = cli_main(["--checks", "ports", "-o", str(tmp_path / "reports")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "端口暴露检查" in out


def test_cli_breach_exit_code(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(cli_mod.CHECK_FUNCS, "ports", lambda ctx: _fake_result("critical"))
    rc = cli_main(["--checks", "ports", "-o", str(tmp_path / "reports"), "-q"])
    assert rc == 1
    assert "退出码 1" in capsys.readouterr().out


def test_cli_no_breach_low_finding(tmp_path, monkeypatch):
    monkeypatch.setitem(cli_mod.CHECK_FUNCS, "ports", lambda ctx: _fake_result("low"))
    rc = cli_main(["--checks", "ports", "-o", str(tmp_path / "reports"), "-q"])
    assert rc == 0


def test_load_config_real_toml(tmp_path):
    cfg = tmp_path / "audit.toml"
    cfg.write_text(
        '[paths]\nworkspaces = ["C:/ws"]\n[ports]\nwatch = [8080, "9090"]\n'
        '[endpoints]\nwhitelist = ["corp.internal"]\n',
        encoding="utf-8",
    )
    data = load_config(str(cfg))
    assert data["paths"]["workspaces"] == ["C:/ws"]
    assert data["ports"]["watch"] == [8080, "9090"]


def test_load_config_no_tomllib_warn(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli_mod, "tomllib", None)
    assert load_config(str(tmp_path / "whatever.toml")) == {}
    assert "[warn]" in capsys.readouterr().err


def test_build_ctx_defaults():
    ctx = build_ctx(build_parser().parse_args([]))
    assert ctx["dep_dirs"] == []
    assert ctx["mcp_configs"] == []
    assert ctx["watch_ports"] is None
    assert ctx["whitelist_extra"] == []
    assert ctx["config_dirs"] and ctx["skills_dirs"]
    assert ctx["workspaces"] == [str(Path.cwd())]


def test_build_ctx_watch_list_and_dict(tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text('[ports]\nwatch = [8080, "9090"]\n', encoding="utf-8")
    ctx = build_ctx(build_parser().parse_args(["-c", str(cfg)]))
    assert ctx["watch_ports"] == {8080: "", 9090: ""}

    cfg2 = tmp_path / "c2.toml"
    cfg2.write_text('[ports]\nwatch = { 8188 = "ComfyUI" }\n', encoding="utf-8")
    ctx2 = build_ctx(build_parser().parse_args(["-c", str(cfg2)]))
    assert ctx2["watch_ports"] == {8188: "ComfyUI"}


def test_build_ctx_cli_flags(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    args = build_parser().parse_args(["--workspace", str(ws), "--dep-dir", str(tmp_path)])
    ctx = build_ctx(args)
    assert ctx["workspaces"] == [str(ws)]
    assert ctx["dep_dirs"] == [str(tmp_path)]


def test_cli_version_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["agent-audit", "--version"])
    with pytest.raises(SystemExit) as ei:
        build_parser().parse_args(["--version"])
    assert ei.value.code == 0
    assert "agent-audit" in capsys.readouterr().out
