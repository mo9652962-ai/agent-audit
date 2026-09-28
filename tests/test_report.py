from agent_audit.models import CheckResult, Finding
from agent_audit.report import overall_verdict, render_json, render_markdown


def _res(findings):
    r = CheckResult(name="ports", title="端口暴露检查", summary="s")
    r.findings = findings
    r.derive_status()
    return r


def _finding(sev, title="t", evidence="e", remediation="fix it"):
    return Finding(check="ports", title=title, severity=sev, evidence=evidence, remediation=remediation)


def test_verdict_fail_on_critical():
    assert overall_verdict([_res([_finding("critical")])]) == "FAIL"


def test_verdict_fail_on_high():
    assert overall_verdict([_res([_finding("high")])]) == "FAIL"


def test_verdict_warn_on_medium():
    assert overall_verdict([_res([_finding("medium")])]) == "WARN"


def test_verdict_pass_clean():
    assert overall_verdict([_res([]), _res([_finding("info")])]) == "PASS"


def test_status_derivation():
    assert _res([_finding("high")]).status == "fail"
    assert _res([_finding("low")]).status == "warn"
    assert _res([]).status == "pass"


def test_markdown_contains_sections():
    f = _finding("critical", "端口 18789 监听 0.0.0.0", "0.0.0.0:18789")
    md = render_markdown([_res([f])], "high", "test-scope")
    assert "# AI Agent 环境安全审计报告" in md
    assert "审计完成标准" in md
    assert "发现汇总" in md
    assert "详细发现" in md
    assert "修复优先级清单" in md
    assert "0.0.0.0:18789" in md
    assert "**[CRITICAL] 端口 18789 监听 0.0.0.0**" in md


def test_markdown_escapes_pipes():
    f = _finding("medium", "a|b", "x|y")
    md = render_markdown([_res([f])], "high", "s")
    assert "a\\|b" in md and "x\\|y" in md


def test_json_roundtrip():
    import json
    data = render_json([_res([_finding("high")])], "high", "s")
    assert data["verdict"] == "FAIL"
    parsed = json.loads(json.dumps(data, ensure_ascii=False))
    assert parsed["results"][0]["findings"][0]["severity"] == "high"
