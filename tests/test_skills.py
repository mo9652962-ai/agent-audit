"""skills 检查：市场/官方分类、目录缺失与列表截断分支。"""
import agent_audit.checks.skills as skills_mod


def test_skills_market_and_official(tmp_path):
    (tmp_path / "@market-skill").mkdir()
    (tmp_path / "my-own").mkdir()
    (tmp_path / "loose.txt").write_text("x", encoding="utf-8")
    r = skills_mod.check({"skills_dirs": [str(tmp_path)]})
    assert r.summary == "市场导入 1 个 / 官方自建 1 个"
    assert r.status == "warn"
    assert any(f.severity == "low" and "市场导入" in f.title for f in r.findings)
    entry = r.details[str(tmp_path)]
    assert entry["market"] == ["@market-skill"]
    assert entry["official"] == ["my-own"]


def test_skills_official_only_info(tmp_path):
    (tmp_path / "mine").mkdir()
    r = skills_mod.check({"skills_dirs": [str(tmp_path)]})
    assert r.status == "pass"
    assert any(f.title == "无市场导入 skill" for f in r.findings)


def test_skills_missing_dir_skipped(tmp_path):
    r = skills_mod.check({"skills_dirs": [str(tmp_path / "nope")]})
    assert r.status == "skipped"
    assert any("目录不存在" in f.title for f in r.findings)


def test_skills_market_list_truncated(tmp_path):
    for i in range(25):
        (tmp_path / f"@m{i:02d}").mkdir()
    r = skills_mod.check({"skills_dirs": [str(tmp_path)]})
    assert r.findings[0].evidence.endswith("…")


def test_skills_mixed_existing_and_missing(tmp_path):
    (tmp_path / "a").mkdir()
    r = skills_mod.check({"skills_dirs": [str(tmp_path), str(tmp_path / "nope")]})
    assert r.status == "pass"
    assert str(tmp_path / "nope") in r.details
    assert r.details[str(tmp_path / "nope")]["exists"] is False
