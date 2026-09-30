# agent-audit GitHub Action

把 [agent-audit](../README.md) 作为 CI 安全门禁：对仓库跑 **git 泄漏检查**（密钥被追踪、
.gitignore 缺规则）与**依赖已知漏洞扫描**，发现达到阈值时让 workflow 失败。

> **Marketplace 版已独立成仓：[agent-audit-action](https://github.com/mo9652962-ai/agent-audit-action)**
> （GitHub Marketplace 要求 action.yml 在仓库根目录 + semver tag）。推荐引用：
>
> ```yaml
> - uses: mo9652962-ai/agent-audit-action@v1.0.0
> ```
>
> 本目录是同款 action 的仓内副本（`uses: ./action` 本地引用仍可用），两份内容保持同步。

## 用法

```yaml
name: security
on: [pull_request, push]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v5
      - uses: mo9652962-ai/agent-audit-action@v1.0.0
        with:
          severity-threshold: high   # low/medium/high/critical
```

判定 PASS/WARN 时通过；存在 ≥ 阈值级发现时 step 失败并给出报告路径。报告
（md + json）自动上传为 `agent-audit-reports` artifact。

## 也可以审 agent 资产

仓库里自带 agent skill / MCP 配置的话，开启对应检查项：

```yaml
      - uses: mo9652962-ai/agent-audit/action@action-v1.0.0
        with:
          checks: git,deps,skills,endpoints,mcp
          config: .github/audit.toml   # 可选：指定 skills 目录等
```

## 输入

| 输入 | 默认 | 说明 |
|:---|:---|:---|
| `checks` | `git,deps` | 检查项，逗号分隔（ports,skills,endpoints,credentials,git,deps,mcp） |
| `severity-threshold` | `high` | 触发失败的最低严重度 |
| `version` | `0.1.1` | agent-env-audit 的 PyPI 版本（显式锁定，防缓存漂移） |
| `config` | （空） | TOML 配置文件路径 |
| `output-dir` | `agent-audit-reports` | 报告输出目录 |
| `upload-artifact` | `true` | 上传报告为 artifact |

## 输出

| 输出 | 说明 |
|:---|:---|
| `verdict` | PASS / WARN / FAIL |
| `report-md` / `report-json` | 报告文件路径（可交给后续 step 使用，如 PR comment） |

## 设计说明

- **默认只跑 `git,deps`**：其余检查面向「本机 agent 环境」（端口/进程/MCP 配置），
  在 CI 的临时 runner 上没有意义；仓库内自带 agent 资产时再显式开启。
- 工具本体从 PyPI 安装（`uvx --from agent-env-audit@<version>`），与被审计仓库隔离，
  不受消费方 Python 环境影响；版本显式锁定。
- 只读原则在 CI 同样成立：本 action 不修改仓库，只产出报告与退出码。
