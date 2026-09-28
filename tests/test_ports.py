from agent_audit.checks.ports import LOCAL_RE, SYSTEM_NOISE_PORTS, WATCH_PORTS


def test_parse_windows_local_addr():
    m = LOCAL_RE.match("0.0.0.0:18789")
    assert m and m.group(1) == "0.0.0.0" and m.group(2) == "18789"


def test_parse_ipv6_wildcard():
    m = LOCAL_RE.match("[::]:135")
    assert m and m.group(1) == "::" and m.group(2) == "135"


def test_parse_loopback():
    m = LOCAL_RE.match("127.0.0.1:8188")
    assert m and m.group(1) == "127.0.0.1" and m.group(2) == "8188"


def test_parse_star():
    m = LOCAL_RE.match("*:22")
    assert m and m.group(1) == "*"


def test_agent_ports_in_watch():
    assert 18789 in WATCH_PORTS
    assert 8188 in WATCH_PORTS


def test_noise_ports_do_not_overlap_watch():
    assert not (set(WATCH_PORTS) & SYSTEM_NOISE_PORTS)
