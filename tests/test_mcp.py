from agent_audit.checks.mcp import _judge, _mini_yaml


def test_remote_public_critical():
    v, reason, = _judge("x", {"url": "https://mcp.evil.io/sse"})
    assert v == "critical"
    assert "远程" in reason


def test_loopback_auth_pass():
    conf = {"url": "http://127.0.0.1:27123", "headers": {"Authorization": "Bearer xxx"}}
    v, reason = _judge("obsidian", conf)
    assert v == "pass"
    assert "鉴权" in reason


def test_loopback_no_auth_medium():
    v, _ = _judge("x", {"url": "http://127.0.0.1:9999"})
    assert v == "medium"


def test_npx_official_pass():
    conf = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:/"]}
    v, _ = _judge("fs", conf)
    assert v == "pass"


def test_npx_unknown_high():
    v, reason = _judge("x", {"command": "npx", "args": ["some-random-mcp-pkg"]})
    assert v == "high"
    assert "npm 包" in reason


def test_local_exe_pass():
    v, _ = _judge("jl", {"command": "C:/venv/Scripts/jlcmcp.exe"})
    assert v == "pass"


def test_local_script_info():
    v, _ = _judge("s", {"command": "node", "args": ["server.js"]})
    assert v == "info"


def test_disabled_info():
    v, reason = _judge("jlceda", {"command": "node", "args": ["x.js"], "enabled": False})
    assert v == "info"
    assert "禁用" in reason


def test_mini_yaml_parses_hermes_style():
    text = """platform_toolsets:
  cli: [terminal]

mcp_servers:
  obsidian:
    url: http://127.0.0.1:27123
  jlceda:
    command: node
    args: [server.js]
    enabled: false
"""
    data = _mini_yaml(text)
    servers = data["mcp_servers"]
    assert "obsidian" in servers and "jlceda" in servers
    assert servers["obsidian"]["url"] == "http://127.0.0.1:27123"
    assert servers["jlceda"]["enabled"] is False
    assert servers["jlceda"]["args"] == ["server.js"]


def test_mini_yaml_no_section():
    assert _mini_yaml("other: 1\nfoo: bar\n") == {}
