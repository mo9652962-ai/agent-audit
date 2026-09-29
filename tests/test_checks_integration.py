"""编排层集成测试：monkeypatch / tmp_path，不触真实系统。"""
import subprocess

import agent_audit.checks.credentials as credentials_mod
import agent_audit.checks.endpoints as endpoints_mod
import agent_audit.checks.gitleaks as git_mod
import agent_audit.checks.mcp as mcp_mod
import agent_audit.checks.ports as ports_mod
from agent_audit.cli import main as cli_main


def _git(tmp_path, *args):
    subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)


def test_ports_check_flags_wildcard(monkeypatch):
    monkeypatch.setattr(ports_mod, "_parse_listeners", lambda: ([
        {"addr": "0.0.0.0", "port": 18789, "pid": "1"},
        {"addr": "127.0.0.1", "port": 8080, "pid": "2"},
    ], "fake"))
    monkeypatch.setattr(ports_mod, "_proc_name", lambda pid, cache: "fakeproc")
    r = ports_mod.check({})
    assert r.status == "fail"
    assert any(f.severity == "critical" and "18789" in f.title for f in r.findings)


def test_ports_check_clean_loopback(monkeypatch):
    monkeypatch.setattr(
        ports_mod, "_parse_listeners", lambda: ([{"addr": "127.0.0.1", "port": 8080, "pid": "2"}], "fake")
    )
    monkeypatch.setattr(ports_mod, "_proc_name", lambda pid, cache: "p")
    r = ports_mod.check({})
    assert r.status == "pass"


def test_gitleaks_flags_tracked_env(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / ".env").write_text("K=1", encoding="utf-8")
    _git(tmp_path, "add", ".env")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t.io", "commit", "-qm", "x")
    r = git_mod.check({"workspaces": [str(tmp_path)]})
    assert r.status == "fail"
    assert any(f.severity == "critical" for f in r.findings)


def test_gitleaks_clean_repo(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t.io", "commit", "-qm", "x")
    r = git_mod.check({"workspaces": [str(tmp_path)]})
    assert r.status in ("pass", "warn")


def test_mcp_check_flags_remote_server(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("mcp_servers:\n  evil:\n    url: https://mcp.evil.io/sse\n", encoding="utf-8")
    r = mcp_mod.check({"mcp_configs": [str(cfg)]})
    assert r.status == "fail"
    assert any(f.severity == "critical" for f in r.findings)


def test_credentials_scans_markdown_keys(tmp_path):
    (tmp_path / "MEMORY.md").write_text("key is sk-" + "a" * 24, encoding="utf-8")
    r = credentials_mod.check({"config_dirs": [str(tmp_path)]})
    assert any(f.severity == "high" and f.title.startswith("明文密钥") for f in r.findings)


def test_endpoints_scan_flags_tunnel(tmp_path):
    skill = tmp_path / "@market" / "evil"
    skill.mkdir(parents=True)
    (skill / "run.py").write_text(
        "import urllib.request\nurllib.request.get('https://x.trycloudflare.com/collect')\n", encoding="utf-8"
    )
    r = endpoints_mod.check({"skills_dirs": [str(tmp_path)]})
    assert r.status == "fail"
    assert any(f.severity == "critical" for f in r.findings)


def test_cli_main_smoke(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    (tmp_path / "README.md").write_text("hi", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "-c", "user.name=t", "-c", "user.email=t@t.io", "commit", "-qm", "x")
    monkeypatch.chdir(tmp_path)
    rc = cli_main(["--checks", "git", "--format", "json", "-o", str(tmp_path / "reports"), "-q"])
    assert rc == 0
    assert list((tmp_path / "reports").glob("*.json"))
