"""deps 检查：工具链选择与漏洞解析（run_cmd / shutil.which 全 monkeypatch，不触网）。"""
import json

import agent_audit.checks.dependencies as deps_mod


def _proj(tmp_path, marker="pyproject.toml"):
    p = tmp_path / "proj"
    p.mkdir(exist_ok=True)
    (p / marker).write_text("[project]\nname = 'x'\n", encoding="utf-8")
    return p


def test_parse_text_vulns_filters_and_truncates():
    long = "GHSA-aaaa-bbbb-cccc-dddd " + "x" * 300
    out = deps_mod._parse_text_vulns(f"noise line\n{long}\n  CVE-2026-1234 fix now  \n\n")
    assert len(out) == 2
    assert out[0] == long[:200]
    assert out[1] == "CVE-2026-1234 fix now"


def test_parse_json_dict_fixes_and_aliases():
    data = {"dependencies": [
        {"name": "req", "version": "2.19.0", "vulns": [
            {"id": "GHSA-1", "fixes": [{"version": "2.31.0"}]},
            {"aliases": ["PYSEC-2"], "fixes": []},
        ]},
        "not-a-dict",
        {"name": "clean", "version": "1.0", "vulns": []},
    ]}
    vulns = deps_mod._parse_json_vulns(json.dumps(data))
    assert vulns[0] == "req==2.19.0 GHSA-1 fix: 2.31.0"
    assert vulns[1] == "req==2.19.0 PYSEC-2 fix: 无修复版本"
    assert len(vulns) == 2


def test_parse_json_list_format():
    data = [{"name": "flask", "version": "0.12", "vulns": [{"id": "CVE-2023-1", "fixes": []}]}]
    assert deps_mod._parse_json_vulns(json.dumps(data)) == ["flask==0.12 CVE-2023-1 fix: 无修复版本"]


def test_parse_json_invalid_falls_back_to_text():
    assert deps_mod._parse_json_vulns("GHSA-zz fix soon") == ["GHSA-zz fix soon"]


def test_deps_no_targets_skipped(tmp_path):
    r = deps_mod.check({"dep_dirs": [str(tmp_path)]})
    assert r.status == "skipped"
    assert "未发现 Python 项目" in r.summary


def test_deps_missing_root_ignored(tmp_path):
    r = deps_mod.check({"dep_dirs": [str(tmp_path / "nope"), str(tmp_path / "also-nope")]})
    assert r.status == "skipped"


def test_deps_uv_audit_text_vulns(tmp_path, monkeypatch):
    _proj(tmp_path)
    monkeypatch.setattr(deps_mod.shutil, "which", lambda n: {"uv": "uv"}.get(n))
    monkeypatch.setattr(
        deps_mod, "run_cmd", lambda *a, **k: (1, "found GHSA-aaaa-bbbb-cccc-dddd in req\n", "")
    )
    r = deps_mod.check({"dep_dirs": [str(tmp_path)]})
    assert r.status == "warn"
    assert r.summary == "1/1 个项目完成审计，共 1 个已知漏洞"
    assert r.details[str(tmp_path / "proj")]["tool"] == "uv audit"


def test_deps_uv_audit_clean(tmp_path, monkeypatch):
    _proj(tmp_path)
    monkeypatch.setattr(deps_mod.shutil, "which", lambda n: {"uv": "uv"}.get(n))
    monkeypatch.setattr(deps_mod, "run_cmd", lambda *a, **k: (0, "No known vulnerabilities found\n", ""))
    r = deps_mod.check({"dep_dirs": [str(tmp_path)]})
    assert r.status == "pass"
    assert "共 0 个已知漏洞" in r.summary


def test_deps_uv_fails_fallback_pip_audit(tmp_path, monkeypatch):
    _proj(tmp_path)
    payload = json.dumps({"dependencies": [
        {"name": "req", "version": "2.19.0",
         "vulns": [{"id": "GHSA-1", "fixes": [{"version": "2.31.0"}]}, {"aliases": ["PYSEC-2"]}]},
    ]})

    def fake_run(args, **k):
        if args[0] == "uv":
            return 2, "", "uv audit unsupported"
        return 1, payload, ""

    monkeypatch.setattr(deps_mod.shutil, "which", lambda n: {"uv": "uv", "pip-audit": "pip-audit"}.get(n))
    monkeypatch.setattr(deps_mod, "run_cmd", fake_run)
    r = deps_mod.check({"dep_dirs": [str(tmp_path)]})
    entry = r.details[str(tmp_path / "proj")]
    assert entry["tool"] == "pip-audit"
    assert "回退 pip-audit" in entry["note"]
    assert r.summary == "1/1 个项目完成审计，共 2 个已知漏洞"
    assert any("无修复版本" in f.evidence for f in r.findings)


def test_deps_uvx_fallback_list_json(tmp_path, monkeypatch):
    _proj(tmp_path, marker="requirements.txt")
    payload = json.dumps([{"name": "flask", "version": "0.12", "vulns": [{"id": "CVE-2023-1"}]}])

    def fake_run(args, **k):
        assert args[0] == "uvx"
        return 1, payload, ""

    monkeypatch.setattr(deps_mod.shutil, "which", lambda n: {"uvx": "uvx"}.get(n))
    monkeypatch.setattr(deps_mod, "run_cmd", fake_run)
    r = deps_mod.check({"dep_dirs": [str(tmp_path)]})
    assert r.details[str(tmp_path / "proj")]["tool"] == "uvx pip-audit"
    assert r.summary == "1/1 个项目完成审计，共 1 个已知漏洞"


def test_deps_no_tools_info(tmp_path, monkeypatch):
    _proj(tmp_path)
    monkeypatch.setattr(deps_mod.shutil, "which", lambda n: None)
    r = deps_mod.check({"dep_dirs": [str(tmp_path)]})
    assert r.status == "skipped"
    assert any(f.title == "无可用依赖审计工具" and f.severity == "info" for f in r.findings)


def test_deps_both_tools_fail_notes_joined(tmp_path, monkeypatch):
    _proj(tmp_path)
    monkeypatch.setattr(deps_mod.shutil, "which", lambda n: {"uv": "uv", "pip-audit": "pip-audit"}.get(n))
    monkeypatch.setattr(deps_mod, "run_cmd", lambda *a, **k: (2, "", "boom"))
    r = deps_mod.check({"dep_dirs": [str(tmp_path)]})
    note = r.details[str(tmp_path / "proj")]["note"]
    assert "uv audit 不可用" in note and "pip-audit 执行失败" in note and "；" in note
    assert r.status == "skipped"
    assert any(f.title == "无可用依赖审计工具" for f in r.findings)


def test_deps_multi_target_and_subdir(tmp_path, monkeypatch):
    _proj(tmp_path)
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "uv.lock").write_text("", encoding="utf-8")
    monkeypatch.setattr(deps_mod.shutil, "which", lambda n: {"uv": "uv"}.get(n))
    monkeypatch.setattr(deps_mod, "run_cmd", lambda *a, **k: (0, "clean\n", ""))
    r = deps_mod.check({"dep_dirs": [str(tmp_path)]})
    assert r.summary == "2/2 个项目完成审计，共 0 个已知漏洞"
