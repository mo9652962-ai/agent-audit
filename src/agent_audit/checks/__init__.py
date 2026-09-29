"""7 项检查实现，执行顺序与实战沉淀一致（端口最先做）。

注意：不要用 `from .ports import check as ports` 这类与子模块同名的别名——
属性会遮蔽子模块，破坏 `import agent_audit.checks.ports as m` 的语义。
"""

from .credentials import check as credentials_check
from .dependencies import check as deps_check
from .endpoints import check as endpoints_check
from .gitleaks import check as git_check
from .mcp import check as mcp_check
from .ports import check as ports_check
from .skills import check as skills_check

ALL_CHECKS = ["ports", "skills", "endpoints", "credentials", "git", "deps", "mcp"]

CHECK_FUNCS = {
    "ports": ports_check,
    "skills": skills_check,
    "endpoints": endpoints_check,
    "credentials": credentials_check,
    "git": git_check,
    "deps": deps_check,
    "mcp": mcp_check,
}

