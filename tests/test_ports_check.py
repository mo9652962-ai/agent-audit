"""ports 检查：监听解析跨平台分支、进程名解析与 check() 分类分支（全 monkeypatch）。"""
import sys

import agent_audit.checks.ports as ports_mod

WIN_NETSTAT = (
    "\n  TCP    0.0.0.0:18789     0.0.0.0:0    LISTENING    1234"
    "\n  TCP    127.0.0.1:8188      0.0.0.0:0    LISTENING    567"
    "\n  TCP    [::]:135            [::]:0       LISTENING    999"
    "\n  UDP    0.0.0.0:5353        *:*                        42\n"
)

SS_OUT = (
    "State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n"
    "LISTEN 0       128     0.0.0.0:18789       0.0.0.0:*          users:((\"python\",pid=1234,fd=9))\n"
    "LISTEN 0       128     127.0.0.1:8188      0.0.0.0:*\n"
)

NETSTAT_UNIX = (
    "tcp   0   0 0.0.0.0:18789   0.0.0.0:*   LISTEN   1234/python\n"
    "tcp   0   0 127.0.0.1:8188  0.0.0.0:*   LISTEN\n"
)


def test_parse_listeners_win(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ports_mod, "run_cmd", lambda *a, **k: (0, WIN_NETSTAT, ""))
    listeners, source = ports_mod._parse_listeners()
    assert source == "netstat -ano -p tcp"
    assert [(l["addr"], l["port"]) for l in listeners] == [
        ("0.0.0.0", 18789), ("127.0.0.1", 8188), ("::", 135),
    ]


def test_parse_listeners_win_fail(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ports_mod, "run_cmd", lambda *a, **k: (1, "", "net err"))
    assert ports_mod._parse_listeners() == ([], "netstat failed: net err")


def test_parse_listeners_unix_ss(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(ports_mod, "run_cmd", lambda *a, **k: (0, SS_OUT, ""))
    listeners, source = ports_mod._parse_listeners()
    assert source == "ss -tlnp"
    assert listeners[0] == {"addr": "0.0.0.0", "port": 18789, "pid": "1234"}
    assert listeners[1]["pid"] == ""


def test_parse_listeners_unix_netstat_fallback(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    def fake(args, **k):
        if args[0] == "ss":
            return 1, "", "ss missing"
        return 0, NETSTAT_UNIX, ""

    monkeypatch.setattr(ports_mod, "run_cmd", fake)
    listeners, source = ports_mod._parse_listeners()
    assert source == "netstat -tlnp"
    assert listeners[0]["pid"] == "1234"
    assert listeners[1]["pid"] == ""


def test_parse_listeners_unix_both_fail(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(ports_mod, "run_cmd", lambda *a, **k: (1, "", "missing"))
    listeners, source = ports_mod._parse_listeners()
    assert listeners == []
    assert source.startswith("no listener source available")


def test_proc_name_empty_and_cache():
    assert ports_mod._proc_name("", {}) == ""
    cache = {"99": "cached-proc"}
    assert ports_mod._proc_name("99", cache) == "cached-proc"


def test_proc_name_win_tasklist(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    out = '"svchost.exe","4321","svchost","svchost.exe"\n'
    monkeypatch.setattr(ports_mod, "run_cmd", lambda *a, **k: (0, out, ""))
    cache = {}
    assert ports_mod._proc_name("4321", cache) == "svchost.exe"
    assert cache["4321"] == "svchost.exe"


def test_proc_name_win_empty(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ports_mod, "run_cmd", lambda *a, **k: (1, "", ""))
    assert ports_mod._proc_name("7", {}) == ""


def test_proc_name_unix_ps(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(ports_mod, "run_cmd", lambda *a, **k: (0, "nginx\n", ""))
    assert ports_mod._proc_name("42", {}) == "nginx"


def test_proc_name_unix_ps_fail(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(ports_mod, "run_cmd", lambda *a, **k: (1, "", ""))
    assert ports_mod._proc_name("42", {}) == ""


def _check_with(monkeypatch, listeners, proc="app.exe", **ctx):
    monkeypatch.setattr(ports_mod, "_parse_listeners", lambda: (listeners, "ss -tlnp"))
    monkeypatch.setattr(ports_mod, "_proc_name", lambda pid, cache: proc)
    return ports_mod.check(dict(ctx))


def test_check_source_error(monkeypatch):
    monkeypatch.setattr(ports_mod, "_parse_listeners", lambda: ([], "no listener source available: x"))
    r = ports_mod.check({})
    assert r.status == "error"
    assert "无法获取监听列表" in r.summary


def test_check_watch_list_ctx(monkeypatch):
    r = _check_with(monkeypatch, [{"addr": "0.0.0.0", "port": 18789, "pid": "9"}], watch_ports=[18789])
    assert r.findings[0].severity == "critical"
    assert "（" not in r.findings[0].title


def test_check_watch_dict_named(monkeypatch):
    monkeypatch.setattr(ports_mod, "_parse_listeners", lambda: ([{"addr": "0.0.0.0", "port": 8188, "pid": "9"}], "ss"))
    monkeypatch.setattr(ports_mod, "_proc_name", lambda pid, cache: "comfy")
    r = ports_mod.check({"watch_ports": {8188: "ComfyUI"}})
    assert "（ComfyUI）" in r.findings[0].title


def test_check_rpc_system_proc_low(monkeypatch):
    r = _check_with(monkeypatch, [{"addr": "0.0.0.0", "port": 49155, "pid": "7"}], proc="svchost.exe")
    assert r.findings[0].severity == "low"
    assert "RPC" in r.findings[0].title


def test_check_noise_port_low(monkeypatch):
    r = _check_with(monkeypatch, [{"addr": "0.0.0.0", "port": 445, "pid": "7"}], proc="other.exe")
    assert r.findings[0].severity == "low"
    assert "系统服务端口" in r.findings[0].title


def test_check_unknown_wildcard_high(monkeypatch):
    r = _check_with(monkeypatch, [{"addr": "0.0.0.0", "port": 9999, "pid": "7"}])
    assert r.findings[0].severity == "high"
    assert "未知服务端口" in r.findings[0].title


def test_check_specific_nic_medium(monkeypatch):
    r = _check_with(monkeypatch, [{"addr": "192.168.1.5", "port": 8080, "pid": "7"}])
    assert r.findings[0].severity == "medium"
    assert "绑定具体网卡地址" in r.findings[0].title


def test_is_loopback_addr_variants():
    assert ports_mod._is_loopback_addr("::1") is True
    assert ports_mod._is_loopback_addr("127.0.0.1") is True
    assert ports_mod._is_loopback_addr("junk") is False
