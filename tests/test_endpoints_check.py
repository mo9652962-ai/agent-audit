"""endpoints.check 的多目录聚合、文件剪枝与 classify/remediation 边界。"""
from pathlib import Path

import agent_audit.checks.endpoints as ep_mod
from agent_audit.checks.endpoints import _remediation, classify_url


def test_endpoints_multi_dir_aggregation(tmp_path):
    r1 = tmp_path / "ws1"
    mkt = r1 / "@market" / "evil"
    mkt.mkdir(parents=True)
    (mkt / "SKILL.md").write_text(
        "see https://abc.trycloudflare.com/x and https://api.openai.com/v1\n", encoding="utf-8"
    )
    r2 = tmp_path / "ws2"
    sk = r2 / "normal"
    sk.mkdir(parents=True)
    (sk / "run.py").write_text("x = 'https://bit.ly/collect'\n", encoding="utf-8")
    r = ep_mod.check({"skills_dirs": [str(r1), str(r2)]})
    assert r.status == "fail"
    skills = {f.title.split("]")[0][1:] for f in r.findings}
    assert skills == {"@market", "normal"}
    assert set(r.details["dirs"]) == {str(r1), str(r2)}
    assert r.details["scanned_files"] == 2


def test_endpoints_clean_pass(tmp_path):
    sk = tmp_path / "ok"
    sk.mkdir()
    (sk / "a.py").write_text("u = 'https://api.openai.com/v1'\n", encoding="utf-8")
    (sk / "notes.txt").write_text("u = 'https://bit.ly/x'\n", encoding="utf-8")
    r = ep_mod.check({"skills_dirs": [str(tmp_path)]})
    assert r.status == "pass"
    assert "全部端点" in r.summary


def test_endpoints_missing_dir_skipped(tmp_path):
    r = ep_mod.check({"skills_dirs": [str(tmp_path / "nope")]})
    assert r.status == "skipped"
    assert "未扫描到" in r.summary


def test_endpoints_top_level_file_ignored(tmp_path):
    (tmp_path / "README.md").write_text("https://bit.ly/x", encoding="utf-8")
    r = ep_mod.check({"skills_dirs": [str(tmp_path)]})
    assert r.status == "skipped"


def test_endpoints_oversize_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(ep_mod, "MAX_FILE_SIZE", 8)
    sk = tmp_path / "s"
    sk.mkdir()
    (sk / "a.py").write_text("u = 'https://api.openai.com/v1'\n", encoding="utf-8")
    r = ep_mod.check({"skills_dirs": [str(tmp_path)]})
    assert r.status == "skipped"
    assert r.details["scanned_files"] == 0


def test_endpoints_read_error_ignored(tmp_path, monkeypatch):
    sk = tmp_path / "s"
    sk.mkdir()
    (sk / "bad.py").write_text("x = 1\n", encoding="utf-8")
    (sk / "good.py").write_text("u = 'https://bit.ly/x'\n", encoding="utf-8")
    orig = Path.read_text

    def fake(self, *a, **k):
        if self.name == "bad.py":
            raise OSError("denied")
        return orig(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", fake)
    r = ep_mod.check({"skills_dirs": [str(tmp_path)]})
    assert r.details["scanned_files"] == 1
    assert any("bit.ly" in f.evidence for f in r.findings)


def test_endpoints_whitelist_extra(tmp_path):
    sk = tmp_path / "s"
    sk.mkdir()
    (sk / "a.py").write_text("u = 'https://svc.corp.internal/api'\n", encoding="utf-8")
    r = ep_mod.check({"skills_dirs": [str(tmp_path)], "whitelist_extra": ["corp.internal"]})
    assert r.status == "pass"


def test_classify_parse_error_and_no_host():
    assert classify_url("http://[", set()) == ("medium", "URL 解析失败，人工复核")
    assert classify_url("http://", set()) == ("medium", "无主机名，人工复核")


def test_classify_doc_and_reserved_ok():
    assert classify_url("https://www.w3.org/2001/xml.xsd", set())[0] == "ok"
    assert classify_url("https://example.com/tutorial", set())[0] == "ok"


def test_remediation_branches():
    assert "隧道" in _remediation("critical", "内网穿透隧道")
    assert "解链" in _remediation("high", "短链接域名")
    assert "IP 归属" in _remediation("high", "公网 IP 直连（绕过域名审计）")
    assert _remediation("medium", "未知域名") == "人工确认域名归属：正规官方 API 则加入白名单，否则删除该 skill。"
