# MCP Server 安全审计白皮书

> 版本：1.0（2026-09）
> 适用对象：运行 AI Agent 的企业安全团队、平台工程团队、独立审计人员
> 依据：OWASP MCP Security Guide、实战审计沉淀（2026-08/09 多次真实环境审计）
> 配套工具：[agent-audit](https://github.com/mo9652962-ai/agent-audit)（`--checks mcp`，自动化执行本清单）

## 1. 摘要

Model Context Protocol（MCP）已成为 AI Agent 连接工具与数据的事实标准。每一个被启用的 MCP server 都是 Agent 执行环境中的一个**特权扩展点**：它以 Agent 的身份读写数据、调用外部服务，且其配置通常由用户或平台管理员手工添加，**缺少默认的供应链审查**。

本白皮书给出一份可直接落地的 MCP server 审计清单：5 项判定 × 明确的通过标准与反例，配套加固命令与自动化方案。整个审计过程只读、可在生产环境执行。

## 2. 为什么 MCP 是新的攻击面

传统应用安全中，"工具调用"是编译期确定的代码；而 MCP 把它变成了**运行期可插拔的配置**。这带来三个信任模型变化：

1. **来源多元**：server 可以来自官方包、任意 npm 注册表、公司内网、或一段 URL——它们最终获得相同的执行地位；
2. **权限继承**：MCP server 天然继承 Agent 的运行身份与文件系统权限，一个恶意 server 即等价于一次持久化的权限扩张；
3. **配置即攻击面**：配置文件（yaml/json）本身成为投毒目标——**Vidar 窃密木马变种已出现专门窃取 agent 配置目录的行为**，而配置目录里往往同时躺着 MCP 定义与 API key。

与之对应的风险事件已经出现：npx 临时执行的未审计 npm 包、借助 trycloudflare 等内网隧道外传数据的 skill/脚本、以及无鉴权的远程 MCP 端点。

## 3. 审计判定清单

对**每一个已配置的 MCP server**，逐项判定：

| # | 检查项 | 通过标准 | 反例（任一命中即不通过） |
|:--|:-------|:---------|:-------------------------|
| 1 | 来源可信 | 本地 venv/exe、官方 `@modelcontextprotocol/*` 包、经审查的本地脚本 | 未知名 npm 包（尤其 `npx` 临时执行）、来历不明的脚本 |
| 2 | 无远程 MCP | 全部 loopback（`127.0.0.1`）或本地进程 | `http(s)://` 且非 loopback 的远程端点 |
| 3 | 鉴权 | loopback MCP 携带鉴权字段（如 Bearer token） | 任何无鉴权的服务端点 |
| 4 | 未使用即禁用 | `enabled: false` | 闲置 MCP 保持启用（扩大攻击面） |
| 5 | 权限面 | 已记录（如 filesystem 根目录范围）并知悉接受 | 无记录直接放行 |

**判定原则：来源与传输层是硬门槛（1、2 项任一反例即为高危），鉴权与闲置启用是配置卫生（3、4 项为 medium），权限面是有意识的取舍（5 项要求"记录并知悉"而非"必须最小"）。**

## 4. 逐项展开

### 4.1 来源可信

**风险**：`npx <pkg>` 每次执行都从 npm 注册表拉取包，仓库侧无法审计其内容；npm 投毒事件（含 2026-03 LiteLLM/Axios/Trivy 波及 agent 应用的事件链）证明该通道是现实的。

**判定**：优先级从高到低——本地 venv 中的可执行文件 > 官方 `@modelcontextprotocol/*` 作用域包 > 已审查的本地脚本 > 其他一切（默认不通过）。

**加固**：
```bash
# 列出所有通过 npx 启动的 MCP server
grep -A2 '"command": *"npx"' claude_desktop_config.json
# 官方作用域包白名单核对
npx --yes @modelcontextprotocol/server-filesystem --help   # 仅使用该作用域下的包
```

### 4.2 无远程 MCP

**风险**：非 loopback 的远程 MCP 意味着 Agent 的工具调用数据（往往含内部文档、代码、客户信息）流经第三方网络路径；`trycloudflare`/`ngrok` 类内网隧道地址的出现几乎总是数据外传通道。

**判定**：URL 的 host 必须是 `127.0.0.1`、`localhost` 或 `::1`；内网 IP（10/172.16-12/192.168 段）判定为 medium 并要求说明；公网域名判定为 critical。

**加固**：确需远程能力时，自建网关并强制鉴权 + TLS；或用 SSH 隧道把远程服务转到本机 loopback。

### 4.3 鉴权

**风险**：无鉴权的本地服务（哪怕只监听 127.0.0.1）可被同机运行的任意进程（包括被投毒的 skill）直接调用，形成横向移动路径。

**判定**：MCP 配置中应包含 `headers`/`token`/`auth` 字段；同时端口只监听 127.0.0.1（与端口暴露审计联动）。

**加固**：
```yaml
mcp_servers:
  obsidian:
    url: http://127.0.0.1:27123
    headers:
      Authorization: Bearer <token>   # token 从密钥服务/环境变量注入，勿写死
```

### 4.4 未使用即禁用

**风险**：闲置 MCP 是零维护成本的常驻攻击面：依赖更新、配置漂移、或者下一次 npm 投毒波及时，你甚至不知道它在。

**判定**：90 天未使用的 MCP server 必须置 `enabled: false` 或删除。禁用而非卸载是合理中间态——保留审计记录，但不参与运行。

### 4.5 权限面

**风险**：`filesystem` 类 MCP 的根目录若为用户主目录，则该 server 的任何漏洞或投毒都等价于全盘暴露。

**判定**：不要求"必须最小"，但**必须记录并知悉接受**。每一条宽权限都应有对应的存在理由（设计需求/成本约束），并落入审计报告。无记录直接放行 = 不通过。

## 5. 审计执行

### 5.1 手工流程（约 15 分钟）

```bash
# 1. 定位配置文件（Hermes 为 yaml，Claude Desktop 为 json）
ls ~/AppData/Local/hermes/config.yaml "$APPDATA/Claude/claude_desktop_config.json"

# 2. 提取全部 MCP server 及启用状态
python -c "
import yaml
cfg = yaml.safe_load(open(r'<config 路径>', encoding='utf-8'))
for name, conf in cfg.get('mcp_servers', {}).items():
    src = conf.get('command', conf.get('url', '?'))
    print(f\"{name}: enabled={conf.get('enabled', True)} | src={src}\")
"

# 3. 对每个 server 过第 3 节清单，记录判定与理由
# 4. 汇总为报告（模板见第 6 节）
```

### 5.2 自动化（推荐）

```bash
agent-audit --checks mcp                    # 自动探测 Hermes / Claude Desktop 配置
agent-audit --checks mcp --mcp-config my.yaml --format json   # 自定义配置 + 机读报告
```

自动审计逐 server 输出 `enabled / src / verdict / reason`，verdict 取值 `pass / info / medium / high / critical`，与第 3 节清单一一对应；报告中的 finding 均附带修复建议。无 PyYAML 环境自动降级为内置解析（建议安装以获得完整解析）。

## 6. 报告模板

```markdown
## MCP Server 审计结论（<日期>）

| Server | 状态 | 来源 | 判定 | 说明 |
|:-------|:-----|:-----|:-----|:-----|
| code-review-graph | 启用 | 本地 venv exe | pass | 来源可信 |
| filesystem        | 启用 | 本地 venv exe | pass* | *观察项：根目录=用户主目录（设计需求，知悉接受） |
| github            | 启用 | @modelcontextprotocol/server-github | pass | 官方包 |
| obsidian          | 启用 | 127.0.0.1 + Bearer token | pass | loopback 带鉴权 |
| <已停用项>         | 禁用 | — | info | 闲置未启用，符合最小攻击面 |

总体判定：启用 N 项全部本地/官方；观察项 1 条（已记录）；无远程 MCP。
```

真实样例：2026-08-30 某生产环境审计（6 启用 + 1 禁用，全部通过，唯一观察项为 filesystem 根目录）即按此模板出具。

## 7. 严重度模型与处置

| verdict | 含义 | 建议处置时限 |
|:--------|:-----|:-------------|
| critical | 公网远程 MCP / 内网隧道 | 立即禁用，事后重建 |
| high | 未知名 npm 包 / 来源不明脚本 | 24h 内替换为本地或官方实现 |
| medium | 内网非 loopback / loopback 无鉴权 | 一个迭代内加固 |
| info / pass | 本地、官方、已禁用、已记录的观察项 | 无需动作 |

## 8. 参考资料

- OWASP MCP Security Guide
- OWASP Top 10 for LLM Applications（2026 版）
- OWASP Agentic Security Initiative（Top 10 for Agentic Applications）
- 事件背景：ClawHavoc 供应链投毒（2026-02）、Vidar 窃密变种针对 agent 配置目录、2026-03 LiteLLM/Axios/Trivy npm 投毒波及 agent 应用

---

*本白皮书随 agent-audit 项目维护，审计清单修订以仓库为准。反馈与误报样例欢迎提 issue。*
