"""credentials 的 _check_perms（win/posix 分支）、check 编排与明文扫描分支。"""
import sys
from pathlib import Path
from types import SimpleNamespace

import agent_audit.checks.credentials as cred_mod

_TOK = "AbCdEf" + "123456" * 5  # 33 字符假值，动态拼接避免密钥字面量


def _win(monkeypatch, rc=0, out="", err=""):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(cred_mod, "run_cmd", lambda *a, **k: (rc, out, err))


def test_check_perms_win_wide_grants_high(tmp_path, monkeypatch):
    _win(monkeypatch, 0, "Everyone:(I)(F)\n", "")
    findings, details = [], {}
    cred_mod._check_perms(tmp_path / ".env", findings, details)
    assert findings[0].severity == "high"
    assert "Everyone" in details[str(tmp_path / ".env")]["wide_grants"][0]


def test_check_perms_win_inherited_low(tmp_path, monkeypatch):
    _win(monkeypatch, 0, "(I)\n", "")
    findings, details = [], {}
    cred_mod._check_perms(tmp_path / "auth.json", findings, details)
    assert findings[0].severity == "low"
    assert details[str(tmp_path / "auth.json")]["inherited"] is True


def test_check_perms_win_tightened_info(tmp_path, monkeypatch):
    _win(monkeypatch, 0, "NT AUTHORITY\\SYSTEM:(F)\n", "")
    findings, details = [], {}
    cred_mod._check_perms(tmp_path / ".env", findings, details)
    assert findings[0].severity == "info"
    assert details[str(tmp_path / ".env")]["wide_grants"] == []


def test_check_perms_win_icacls_error(tmp_path, monkeypatch):
    _win(monkeypatch, 1, "", "access denied")
    findings, details = [], {}
    cred_mod._check_perms(tmp_path / ".env", findings, details)
    assert findings == []
    assert details[str(tmp_path / ".env")]["error"] == "access denied"


def test_check_perms_posix_wide_high(tmp_path, monkeypatch):
    f = tmp_path / "auth.json"
    f.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "stat", lambda self: SimpleNamespace(st_mode=0o100644))
    findings, details = [], {}
    cred_mod._check_perms(f, findings, details)
    assert findings[0].severity == "high"
    assert details[str(f)]["mode"] == "0o644"


def test_check_perms_posix_tight_info(tmp_path, monkeypatch):
    f = tmp_path / "auth.json"
    f.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "stat", lambda self: SimpleNamespace(st_mode=0o100600))
    findings, details = [], {}
    cred_mod._check_perms(f, findings, details)
    assert findings[0].severity == "info"
    assert details[str(f)]["mode"] == "0o600"


def test_credentials_check_env_perms_and_missing_dir(tmp_path, monkeypatch):
    a = tmp_path / "a"
    a.mkdir()
    (a / ".env").write_text("K=1", encoding="utf-8")
    (a / "config.yaml").write_text("x: 1", encoding="utf-8")
    (a / "sub").mkdir()
    (a / "sub" / ".env").write_text("K=2", encoding="utf-8")
    _win(monkeypatch, 0, "(I)\n", "")
    r = cred_mod.check({"config_dirs": [str(a), str(tmp_path / "missing")]})
    assert r.summary == "明文密钥 0 处；凭据文件权限检查 3 个"
    assert all(f.severity == "low" for f in r.findings)
    assert str(tmp_path / "missing") not in r.details


def test_scan_skips_envrc_and_unscanned_ext(tmp_path):
    (tmp_path / ".envrc").write_text("K=1", encoding="utf-8")
    (tmp_path / "notes.log").write_text("K=1", encoding="utf-8")
    findings, details = [], {}
    cred_mod._scan_plaintext([str(tmp_path)], findings, details)
    assert findings == []
    assert details[str(tmp_path)]["plaintext_scanned"] is True


def test_scan_missing_root_no_details():
    details = {}
    cred_mod._scan_plaintext(["Z:/definitely-not-here-xyz"], [], details)
    assert details == {}


def test_scan_skips_oversize(tmp_path):
    (tmp_path / "big.md").write_text("x" * (2 * 1024 * 1024 + 1), encoding="utf-8")
    findings, details = [], {}
    cred_mod._scan_plaintext([str(tmp_path)], findings, details)
    assert findings == []


def test_scan_read_error_ignored(tmp_path, monkeypatch):
    (tmp_path / "bad.md").write_text("ok", encoding="utf-8")
    orig = Path.read_text

    def fake(self, *a, **k):
        if self.name == "bad.md":
            raise OSError("denied")
        return orig(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", fake)
    findings, details = [], {}
    cred_mod._scan_plaintext([str(tmp_path)], findings, details)
    assert findings == []


def test_scan_placeholder_skipped(tmp_path):
    (tmp_path / "conf.yaml").write_text('api_key = "' + "x" * 24 + '"', encoding="utf-8")
    findings, details = [], {}
    cred_mod._scan_plaintext([str(tmp_path)], findings, details)
    assert findings == []


def test_scan_medium_severity_for_json(tmp_path):
    (tmp_path / "creds.json").write_text('{"access_' + 'token": "' + _TOK + '"}', encoding="utf-8")
    findings, details = [], {}
    cred_mod._scan_plaintext([str(tmp_path)], findings, details)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
