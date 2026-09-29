"""models 辅助函数、common.run_cmd 异常分支与文件遍历剪枝、__main__ 入口。"""
import runpy
import subprocess
import sys

import pytest

import agent_audit.checks.common as common_mod
from agent_audit.models import errored, skipped, worst_severity


def test_skipped_and_errored_helpers():
    s = skipped("ports", "端口暴露检查", "无监听来源")
    assert s.status == "skipped"
    assert s.summary == "无监听来源"
    e = errored("mcp", "MCP Server 审计", "配置解析失败")
    assert e.status == "error"


def test_worst_severity_empty():
    assert worst_severity([]) is None


def test_run_cmd_command_not_found():
    rc, _out, err = common_mod.run_cmd(["no-such-binary-xyz-987"])
    assert rc == 127
    assert "command not found" in err


def test_run_cmd_timeout(monkeypatch):
    def raise_timeout(args, **k):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1)

    monkeypatch.setattr(common_mod.subprocess, "run", raise_timeout)
    rc, _out, err = common_mod.run_cmd(["fake-cmd"])
    assert rc == 124
    assert "timeout" in err


def test_run_cmd_oserror(monkeypatch):
    def raise_oserror(args, **k):
        raise OSError("disk gone")

    monkeypatch.setattr(common_mod.subprocess, "run", raise_oserror)
    rc, _out, err = common_mod.run_cmd(["fake-cmd"])
    assert rc == 126
    assert "disk gone" in err


def test_iter_files_prunes_noise_dirs(tmp_path):
    (tmp_path / "top.txt").write_text("x", encoding="utf-8")
    (tmp_path / "normal").mkdir()
    (tmp_path / "normal" / "a.py").write_text("x", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "b.js").write_text("x", encoding="utf-8")
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "c.txt").write_text("x", encoding="utf-8")
    rel = {p.relative_to(tmp_path).as_posix() for p in common_mod.iter_files(tmp_path)}
    assert rel == {"top.txt", "normal/a.py"}


def test_main_module_version(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["agent-audit", "--version"])
    with pytest.raises(SystemExit) as ei:
        runpy.run_module("agent_audit", run_name="__main__")
    assert ei.value.code == 0
    assert "agent-audit" in capsys.readouterr().out
