"""7 项检查实现，执行顺序与实战沉淀一致（端口最先做）。"""

from .ports import check as ports
from .skills import check as skills
from .endpoints import check as endpoints
from .credentials import check as credentials
from .gitleaks import check as git
from .dependencies import check as deps
from .mcp import check as mcp

ALL_CHECKS = ["ports", "skills", "endpoints", "credentials", "git", "deps", "mcp"]

CHECK_FUNCS = {
    "ports": ports,
    "skills": skills,
    "endpoints": endpoints,
    "credentials": credentials,
    "git": git,
    "deps": deps,
    "mcp": mcp,
}
