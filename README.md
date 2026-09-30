# agent-audit

> 一键审计本机 AI Agent 环境：供应链投毒 / 密钥暴露 / 端口暴露 / MCP server 体检。
> 运行时零依赖，全程只读，Windows 优先（同时支持 Linux/macOS）。

## 为什么需要它（2026 实战背景）

- **ClawHavoc 供应链投毒**：800+ 恶意 skill 泛滥（2026-02 顶峰）；Snyk 审计 ClawHub 3984 技能中 **13.4% 含严重安全问题，36.8% 有漏洞**。市场导入 skill 拥有与用户同等的执行权限（terminal / file / web）。
- **端口暴露**：OpenClaw 默认监听 `0.0.0.0:18789`，国家应急中心通报 **85% 实例暴露公网**；ComfyUI 1000+ 暴露实例被组僵尸网络挖矿。
- **窃密木马**：Vidar 变种**专偷 agent 配置目录**（token / private key）。
- **依赖投毒**：2026-03 LiteLLM / Axios / Apifox / Trivy 投毒波及多个 agent 应用。
- **MCP 攻击面**：MCP 已成 agent 连接工具数据的事实标准，远程 / 无鉴权 / 未知名 npm 包 MCP server 是新入口（对照 OWASP MCP Security Guide）。

## 快速开始

```bash
pip install agent-env-audit     # PyPI（发行版即将上线；import 包名为 agent_audit）
# 或从源码安装
pip install git+https://github.com/mo9652962-ai/agent-audit.git
# 或免安装直接跑
git clone https://github.com/mo9652962-ai/agent-audit.git && cd agent-audit
PYTHONPATH=src python -m agent_audit

agent-audit                     # 默认审计 Hermes 环境 + 当前工作区
agent-audit --checks ports,mcp  # 只跑指定检查
agent-audit --skills-dir ~/agents/skills --config-dir ~/agents
```

或安装为命令行工具：

```bash
pip install .            # 或 pipx install .
agent-audit --version
```

**全部检查均为只读操作**（netstat / 文件读取 / icacls 查询 / git ls-files），不会修改任何配置。

## 7 项检查

| # | 检查项 | 内容 | 判定标准 |
|---|--------|------|----------|
| 1 | **端口暴露** | 全部 TCP 监听 socket | 严禁 `0.0.0.0` 通配；agent 端口（18789/8188/1042）暴露 = critical |
| 2 | **Skill 来源分类** | 市场导入（`@` 前缀）vs 官方/自建 | 数量盘点 + 风险提示（决定性证据在下一项） |
| 3 | **外发端点白名单** | skill 代码里的所有 URL | ✅ 全部官方 API/本地回环；❌ 未知域名、IP 直连、内网穿透隧道、短链接 |
| 4 | **凭据权限与明文** | .env 权限（icacls/chmod）+ 记忆/配置文件明文密钥 | .env 仅当前用户可读；MEMORY.md 命中真实 key = high |
| 5 | **Git 泄漏** | .env / config.yaml 是否被追踪 + .gitignore 规则 | 被 auto-sync 提交 = critical |
| 6 | **依赖漏洞** | uv audit / pip-audit（自动回退） | 无已知漏洞；工具缺失给出安装指引 |
| 7 | **MCP Server 审计** | 对照 OWASP MCP Security Guide | 全部本地/官方、带鉴权、闲置已禁用 |

判定哲学：**不要只数 skill 数量——外发端点白名单才是决定性证据**（数量多 ≠ 有问题，端点全白名单 = 安全）。

## 报告

输出 Markdown + JSON 双格式到 `agent-audit-reports/`：

- **审计完成标准表**：6 条来自实战的验证标准，逐条 ✅/❌
- **详细发现**：严重度 / 证据 / 修复建议，每条发现都带可执行的修复命令
- **修复优先级清单**：critical → medium 排序
- JSON 报告含全部结构化细节（监听列表、端点分类计数、MCP 逐 server 判定）

退出码：`0` 通过 / `1` 存在 ≥ 阈值的发现（默认 high，可作 CI 门禁）/ `2` 参数错误。

```bash
# CI 门禁用法
python -m agent_audit --severity-threshold high || exit 1
```

## 配置文件（可选）

```toml
# audit.toml
[paths]
skills_dirs = ["C:/Users/me/AppData/Local/hermes/skills"]
config_dirs = ["C:/Users/me/AppData/Local/hermes"]
workspaces  = ["D:/my-vault"]
mcp_configs = ["C:/Users/me/AppData/Local/hermes/config.yaml"]

[ports]
watch   = { 18789 = "OpenClaw 网关", 8188 = "ComfyUI" }
system_noise = [135, 445]

[endpoints]
whitelist = ["api.my-company.com"]
```

```bash
python -m agent_audit -c audit.toml
```

默认路径自动探测：Hermes（`%LOCALAPPDATA%/hermes`，非 Windows 为 `~/.hermes`）、Claude Desktop（`%APPDATA%/Claude`）；`--skills-dir` / `--config-dir` / `--mcp-config` / `--workspace` 可多次指定，叠加在配置文件之后。

## 文档

- [MCP Server 安全审计白皮书](docs/mcp-security-audit-whitepaper.md) — 5 项 OWASP 对齐判定清单，可直接落地
- [系列文章：我给自己的 AI Agent 环境做了次安全审计](blog/01-self-audit-report.md) — 真实机器的完整审计记录

## 方法论依据

MCP 审计判定清单（检查 7）与以下权威指南对齐（2026-09 核对）：

- [OWASP: A Practical Guide for Secure MCP Server Development](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/) — 安全架构、鉴权、输入校验与会话隔离
- [NSA Cybersecurity Information Sheet: MCP Security（2026-06）](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF) — 真实部署中的观测性问题清单
- [MCP 官方 Security Best Practices（2026-07-28 spec）](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) — 协议规范的官方安全考量

已工具化覆盖：来源可信（未知名 npm 包 / 公网 URL）、远程暴露（非 loopback 判 critical）、
鉴权字段缺失、闲置未禁用。NSA 清单中尚未工具化的项（tool poisoning / shadowing、
token passthrough 检测）见 Roadmap。

## 设计原则

- **零运行时依赖**：安全审计工具自己先做好供应链（PyYAML 可选，缺失时自动降级解析）。
- **全程只读**：只查询、不修改；修复动作以命令形式写在报告里，由人决定是否执行。
- **Windows 优先**：icacls / netstat / tasklist 一等公民——大部分 agent 安全工具默认 Linux，Windows 用户的 agent 环境没人管。
- **证据导向**：每条发现附带证据（文件:行号、URL、ACL）与修复命令，不吓唬人。

## Roadmap

- [ ] `skill-vetter` 集成：skill 安装前审查
- [ ] `--fix` 模式：一键收紧权限 / 改监听（带确认）
- [ ] OWASP Agentic AI Top 10 完整映射
- [ ] GitHub Action：PR 时自动跑依赖 + git 泄漏检查
- [ ] MCP 检查扩展：tool poisoning / shadowing（工具描述注入）、token passthrough、MCP 配置文件权限（NSA CSI 清单）

## License

MIT
