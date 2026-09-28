from agent_audit.checks.endpoints import DEFAULT_WHITELIST, classify_url


def test_loopback_ok():
    assert classify_url("http://127.0.0.1:8188/api", set()) == ("ok", "本地回环")
    assert classify_url("http://localhost:27123", set())[0] == "ok"


def test_tunnel_critical():
    v, reason = classify_url("https://abc-def-g.trycloudflare.com/payload", set())
    assert v == "critical"
    assert "隧道" in reason


def test_shortlink_high():
    v, _ = classify_url("https://bit.ly/3xYz", set())
    assert v == "high"


def test_raw_public_ip_high():
    v, reason = classify_url("http://45.33.32.156:8080/exfil", set())
    assert v == "high"
    assert "IP 直连" in reason


def test_private_ip_info():
    v, _ = classify_url("http://192.168.1.10:8188", set())
    assert v == "info"


def test_whitelist_exact_ok():
    v, _ = classify_url("https://api.openai.com/v1/chat", DEFAULT_WHITELIST)
    assert v == "ok"


def test_whitelist_subdomain_ok():
    v, _ = classify_url("https://eu.api.anthropic.com/v1", {"api.anthropic.com"})
    assert v == "ok"


def test_unknown_medium():
    v, reason = classify_url("https://evil-payload.example.xyz/collect", set())
    assert v == "medium"
    assert "未知域名" in reason
