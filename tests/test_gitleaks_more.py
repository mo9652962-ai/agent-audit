"""git 检查补充：ls-files 失败、.gitignore 规则分支、无仓库跳过（.git 用空目录模拟）。"""
import agent_audit.checks.gitleaks as git_mod


def _repo_shell(tmp_path, gitignore=None):
    (tmp_path / ".git").mkdir()
    if gitignore is not None:
        (tmp_path / ".gitignore").write_text(gitignore, encoding="utf-8")


def test_gitleaks_gitignore_missing_rules(tmp_path, monkeypatch):
    _repo_shell(tmp_path, gitignore="*.log\n")
    monkeypatch.setattr(git_mod, "run_cmd", lambda *a, **k: (0, ".env\nREADME.md\n", ""))
    r = git_mod.check({"workspaces": [str(tmp_path)]})
    titles = [f.title for f in r.findings]
    assert any("密钥文件被 git 追踪" in t for t in titles)
    assert any(".gitignore 缺少密钥规则" in t for t in titles)
    assert r.status == "fail"
    assert r.details[str(tmp_path)]["secret_hits"] == [".env"]


def test_gitleaks_gitignore_complete(tmp_path, monkeypatch):
    _repo_shell(tmp_path, gitignore="*.env\nconfig.yaml\n")
    monkeypatch.setattr(git_mod, "run_cmd", lambda *a, **k: (0, "README.md\n", ""))
    r = git_mod.check({"workspaces": [str(tmp_path)]})
    assert any("密钥规则齐备" in f.title for f in r.findings)
    assert any("无密钥命中" in f.title for f in r.findings)
    assert r.status == "pass"


def test_gitleaks_ls_files_error(tmp_path, monkeypatch):
    _repo_shell(tmp_path, gitignore="*.env\nconfig.yaml\n")
    monkeypatch.setattr(git_mod, "run_cmd", lambda *a, **k: (128, "", "fatal: bad"))
    r = git_mod.check({"workspaces": [str(tmp_path)]})
    assert r.details[str(tmp_path)]["error"] == "fatal: bad"
    assert any("密钥规则齐备" in f.title for f in r.findings)


def test_gitleaks_no_repo_skipped(tmp_path):
    r = git_mod.check({"workspaces": [str(tmp_path)]})
    assert r.status == "skipped"
    assert "未发现 git 仓库" in r.summary
    assert r.details[str(tmp_path)]["is_repo"] is False


def test_gitleaks_ignores_example_and_template_files(tmp_path, monkeypatch):
    _repo_shell(tmp_path, gitignore="*.env\nconfig.yaml\n")
    sample_files = ".env.example\n.env.remote.example\nconfig.example.yaml\nREADME.md\n"
    monkeypatch.setattr(git_mod, "run_cmd", lambda *a, **k: (0, sample_files, ""))
    r = git_mod.check({"workspaces": [str(tmp_path)]})
    assert r.details[str(tmp_path)]["secret_hits"] == []
    assert not any("密钥文件被 git 追踪" in f.title for f in r.findings)
    assert r.status == "pass"
