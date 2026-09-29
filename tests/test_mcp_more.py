"""mcp 检查补充：解析器选择（json/pyyaml/降级）、judge 边界与 check 编排。"""
import json
import sys
from pathlib import Path

import agent_audit.checks.mcp as mcp_mod
from agent_audit.checks.mcp import _judge, _parse_config, _remediation, _scalar


def test_scalar_variants():
    assert _scalar(" [a, b] ") == ["a", "b"]
    assert _scalar("true") is True
    assert _scalar("False") is False
    assert _scalar("'quoted'") == "quoted"
    assert _scalar("plain") == "plain"


def test_mini_yaml_inline_and_stop():
    text = (
        "mcp_servers:\n"
        "  env: production\n"
        "  # comment\n"
        "\n"
        "  - item\n"
        "  evil:\n"
        "    url: http://127.0.0.1:1\n"
        "other: 1\n"
    )
    servers = mcp_mod._mini_yaml(text)["mcp_servers"]
    assert servers["env"] == {"__inline__": "production"}
    assert servers["evil"]["url"] == "http://127.0.0.1:1"


def test_parse_config_json(tmp_path):
    p = tmp_path / "claude_desktop_config.json"
    p.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx"}}}), encoding="utf-8")
    servers, _toolsets, parser = _parse_config(p)
    assert parser == "json"
    assert servers == {"fs": {"command": "npx"}}


def test_parse_config_json_empty_and_non_dict(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("   \n", encoding="utf-8")
    assert _parse_config(p)[0] == {}
    p2 = tmp_path / "arr.json"
    p2.write_text("[]", encoding="utf-8")
    assert _parse_config(p2)[0] == {}


def test_parse_config_yaml_pyyaml(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("mcp_servers:\n  a:\n    command: node\n", encoding="utf-8")
    servers, _toolsets, parser = _parse_config(p)
    assert parser == "pyyaml"
    assert "a" in servers


def test_parse_config_yaml_regex_fallback(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    p = tmp_path / "config.yaml"
    p.write_text("mcp_servers:\n  a:\n    command: node\n", encoding="utf-8")
    servers, _toolsets, parser = _parse_config(p)
    assert parser == "regex-fallback"
    assert servers["a"]["command"] == "node"


def test_parse_config_servers_not_dict(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("mcp_servers: oops\n", encoding="utf-8")
    assert _parse_config(p)[0] == {}


def test_check_missing_and_broken_configs(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    r = mcp_mod.check({"mcp_configs": [str(tmp_path / "nope.json"), str(bad)]})
    assert "解析失败" in r.details[str(bad)]["error"]
    assert r.status == "skipped"


def test_check_no_configs_uses_default_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("APPDATA", str(tmp_path / "roam"))
    r = mcp_mod.check({})
    assert r.status == "skipped"
    assert "未发现 MCP server 配置" in r.summary


def test_check_disabled_server(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("mcp_servers:\n  idle:\n    command: node\n    enabled: false\n", encoding="utf-8")
    r = mcp_mod.check({"mcp_configs": [str(p)]})
    assert any("已禁用" in f.title for f in r.findings)
    assert r.details[str(p)]["servers"]["idle"]["enabled"] is False
    assert r.status == "pass"


def test_check_inline_string_server(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("mcp_servers:\n  legacy: some-command-string\n", encoding="utf-8")
    r = mcp_mod.check({"mcp_configs": [str(p)]})
    server = r.details[str(p)]["servers"]["legacy"]
    assert server["verdict"] == "info"
    assert server["src"] == "?"


def test_check_toolsets_recorded(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("platform_toolsets:\n  cli: [terminal]\n", encoding="utf-8")
    r = mcp_mod.check({"mcp_configs": [str(p)]})
    assert r.details[str(p)]["platform_toolsets"] == {"cli": ["terminal"]}
    assert r.status == "skipped"


def test_check_all_local_pass(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("mcp_servers:\n  local:\n    command: C:/venv/mcp.exe\n", encoding="utf-8")
    r = mcp_mod.check({"mcp_configs": [str(p)]})
    assert r.status == "pass"
    assert "全部本地/官方" in r.summary


def test_check_regex_fallback_finding(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "yaml", None)
    p = tmp_path / "config.yaml"
    p.write_text("mcp_servers:\n  a:\n    command: node\n", encoding="utf-8")
    r = mcp_mod.check({"mcp_configs": [str(p)]})
    assert any("降级解析" in f.title for f in r.findings)


def test_judge_public_url_error_host_critical():
    v, _ = _judge("x", {"url": "http://["})
    assert v == "critical"


def test_judge_private_ip_medium():
    v, reason = _judge("x", {"url": "http://10.0.0.5:8080"})
    assert v == "medium"
    assert "内网远程" in reason


def test_judge_python_runtime_no_script():
    v, reason = _judge("x", {"command": "python"})
    assert v == "info"
    assert "人工确认脚本来源" in reason


def test_judge_python_with_script():
    v, _ = _judge("x", {"command": "python", "args": ["tool.py"]})
    assert v == "info"


def test_judge_other_command_needs_review():
    v, reason = _judge("x", {"command": "weird-runner"})
    assert v == "info"
    assert "人工复核" in reason


def test_judge_empty_conf():
    v, _ = _judge("x", {})
    assert v == "info"


def test_remediation_branches():
    assert "自建网关" in _remediation("critical", "公网远程")
    assert "npm" in _remediation("high", "未知名 npm 包：foo")
    assert "Bearer" in _remediation("medium", "本地 loopback 但无鉴权字段（headers/token）")
    assert "SSH 隧道" in _remediation("medium", "内网远程 MCP（非 loopback）")
    assert _remediation("info", "x") == ""


def test_default_configs_win(tmp_path, monkeypatch):
    hermes = tmp_path / "AppData/Local/hermes"
    hermes.mkdir(parents=True)
    (hermes / "config.yaml").write_text("x: 1", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path / "roam"))
    cands = mcp_mod._default_configs()
    assert [c.name for c in cands] == ["config.yaml"]


def test_default_configs_posix(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(sys, "platform", "linux")
    assert mcp_mod._default_configs() == []
    hermes = tmp_path / ".hermes"
    hermes.mkdir()
    (hermes / "config.yaml").write_text("x: 1", encoding="utf-8")
    assert len(mcp_mod._default_configs()) == 1
