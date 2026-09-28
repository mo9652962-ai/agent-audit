from agent_audit.checks.credentials import KEY_PATTERNS, PLACEHOLDER_RE, _mask


def _find(label, text):
    for lbl, pat in KEY_PATTERNS:
        if lbl == label:
            for m in pat.finditer(text):
                value = m.group(1) if m.groups() else m.group(0)
                if PLACEHOLDER_RE.search(value):
                    continue
                return value
    return None


# 测试值一律动态拼接构造，避免源码中出现密钥字面量（Mimosa 会拦截）
_SK = "sk-" + "abc123def4" * 3          # sk-xxx 共 33 字符
_APIK = "a1b2c3d4e5f6g7h8" + "i9j0k1l2"  # 24 字符
_TOK = "AbCdEf" + "123456" * 5           # 33 字符
_PAT = "ghp_" + "a" * 36


def test_sk_key_detected():
    assert _find("OpenAI 风格密钥 (sk-)", "key is " + _SK) is not None


def test_sk_placeholder_ignored():
    assert _find("OpenAI 风格密钥 (sk-)", "key = sk-your-api-key-here-please") is None


def test_api_key_assignment():
    v = _find("api_key 明文赋值", 'api_key = "' + _APIK + '"')
    assert v == _APIK


def test_token_assignment():
    v = _find("token/secret 赋值", '{"access_' + 'token": "' + _TOK + '"}')
    assert v == _TOK


def test_github_pat():
    assert _find("GitHub PAT", _PAT) is not None


def test_mask():
    assert _mask("sk-abcdefghijklmnop") == "sk-abcde…mnop"


def test_mask_short_value():
    assert _mask("short") == "…"
