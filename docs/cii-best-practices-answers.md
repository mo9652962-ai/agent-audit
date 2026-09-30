# CII Best Practices（passing 级）申请答案清单

> 用途：在 [bestpractices.dev](https://www.bestpractices.dev) 申请 CII Best Practices
> badge 时逐条填写。判据以 passing 级（60 条）为准；`esq-builder-mcp` 与
> `skill-maintenance-mcp` 可复用本清单，差异在文末。
> 整理日期：2026-09-30。**项目页已创建：[bestpractices.dev/projects/15101](https://www.bestpractices.dev/projects/15101)（in progress 24%）**，徽章已挂 README；按本清单把剩余判据勾选完，badge 自动转 passing。

## Basics（项目基础）

| 判据 | 回答 | 证据 |
|:---|:---|:---|
| description_good | ✅ | README 开头一句话描述 + 英文摘要段 |
| interact | ✅ | README：安装 / 用法 / Roadmap / CONTRIBUTING 链接 |
| contribution | ✅ | [CONTRIBUTING.md](../CONTRIBUTING.md)（PR 流程 + 提交规范） |
| contribution_requirements | ✅ | CONTRIBUTING「约定」节（SHA 固定 / 测试政策 / 密钥卫生） |
| floss_license | ✅ | MIT |
| floss_license_osi | ✅ | MIT 是 OSI 批准许可证 |
| license_location | ✅ | 仓库根 LICENSE |
| documentation_basics | ✅ | README（安装/用法/配置/报告解读） |
| documentation_interface | ✅ | README 检查项表 + `--help` + [action/README.md](../action/README.md) |
| sites_https | ✅ | GitHub / PyPI 均 HTTPS |
| discussion | ✅ | GitHub Issues（URL 可寻址、可检索） |
| english | ⚠️ 部分 | README 含英文概览 + 接受英文 issue；完整英文文档在 Roadmap |
| maintained | ✅ | 提交与 release 记录连续（2026-09 活跃） |

## Change Control（变更控制）

| 判据 | 回答 | 证据 |
|:---|:---|:---|
| repo_public | ✅ | github.com/mo9652962-ai/agent-audit |
| repo_track | ✅ | git 全量历史 |
| repo_interim | ✅ | main 分支承载中间版本，PR 可见 |
| repo_distributed | ✅ | git + GitHub + 本地克隆 |
| version_unique | ✅ | pyproject version + PyPI（同版本不可重传） |
| version_semver | ✅ | 0.1.x 语义化版本 |
| version_tags | ✅ | v0.1.0 / v0.1.1 tag（发布走 tag 触发） |
| release_notes | ✅ | GitHub Release notes + CHANGELOG.md |
| release_notes_vulns | ✅ | 目前无已修复 CVE；有则记入 CHANGELOG（约定） |

## Reporting（缺陷与漏洞报告）

| 判据 | 回答 | 证据 |
|:---|:---|:---|
| report_process | ✅ | GitHub Issues + CONTRIBUTING |
| report_tracker | ✅ | GitHub Issues |
| report_responses | ✅ | 当前 issue 全部有响应（维护者活跃） |
| enhancement_responses | ✅ | Roadmap 由 issue/调研驱动，均有回应 |
| report_archive | ✅ | Issues 公开可检索、永久存档 |
| vulnerability_report_process | ✅ | [SECURITY.md](../SECURITY.md)：GitHub Security Advisories / 邮件双渠道 |
| vulnerability_report_private | ✅ | SECURITY.md 指引 GitHub Security Advisories 私密报告 |
| vulnerability_report_response | ✅ | SECURITY.md 承诺 **7 天**内响应（优于判据要求的 14 天） |

## Quality（质量）

| 判据 | 回答 | 证据 |
|:---|:---|:---|
| build | ✅ | `uv sync --extra dev && uv build`；纯 Python 无编译步骤 |
| build_common_tools | ✅ | setuptools + uv（业界标准工具链） |
| build_floss_tools | ✅ | 全 FLOSS 工具链 |
| test | ✅ | pytest 152 例（公开、CI 运行） |
| test_invocation | ✅ | CONTRIBUTING 与 README 给出标准命令 |
| test_most | ✅ | 覆盖率 99.68%（棘轮 97），编排层全覆盖 |
| test_continuous_integration | ✅ | GitHub Actions：test×2 OS + lint + deps-audit + CodeQL + dogfood |
| test_policy | ✅ | CONTRIBUTING「测试政策」——新功能必须带测试 |
| tests_are_added | ✅ | git 历史：每次功能/修复 commit 均含测试（覆盖率 35%→99.68% 轨迹） |
| tests_documented_added | ⚠️ 部分 | 政策已写入 CONTRIBUTING；变更提案暂以 PR 描述承载 |
| warnings | ✅ | ruff（line-length 100）+ bandit 全量通过 |
| warnings_fixed | ✅ | lint 清零（发现项全修或带真实理由豁免） |
| warnings_strict | ✅ | ruff 默认规则集 + bandit；考虑升级 ruff `--preview`（Roadmap） |

## Security（安全）

| 判据 | 回答 | 证据 |
|:---|:---|:---|
| know_secure_design | ✅ | 本工具即安全审计方法论的产品化（OWASP/NSA 对齐，见 README 方法论依据） |
| know_common_errors | ✅ | 7 项检查覆盖 CWE 常见类：CWE-778/312（密钥）、CWE-16（权限）、CWE-829（供应链）等 |
| crypto_published | ✅ | 不实现密码学；仅用 hashlib SHA-256 做内容指纹 |
| crypto_call | ✅ | 哈希用标准库，未自研 |
| crypto_floss | ✅ | 全 FLOSS 实现 |
| crypto_keylength | ✅ | SHA-256（满足 NIST 最低要求） |
| crypto_working | ✅ | 未使用任何破损算法 |
| crypto_weaknesses | ✅ | 未使用弱算法 |
| crypto_pfs | ✅ N/A | 不涉及传输协议 |
| crypto_password_storage | ✅ N/A | 不存储口令 |
| crypto_random | ✅ N/A | 不生成密钥/nonce |
| delivery_mitm | ✅ | PyPI / GitHub 均强制 HTTPS |
| delivery_unsigned | ✅ | 无 http 裸哈希分发；PyPI 侧另有 PEP 740 attestation |
| vulnerabilities_fixed_60_days | ✅ | deps-audit（pip-audit）每 push 扫描，当前零已知漏洞 |
| vulnerabilities_critical_fixed | ✅ | 同上，扫描门禁在 CI |
| no_leaked_credentials | ✅ | 自家 git 泄漏检查 dogfood + 密钥卫生约定 + gitleaks 类扫描 |

## Analysis（分析）

| 判据 | 回答 | 证据 |
|:---|:---|:---|
| static_analysis | ✅ | ruff + bandit（每次提交） |
| static_analysis_common_vulnerabilities | ✅ | CodeQL security-extended（每周 + push/PR） |
| static_analysis_fixed | ✅ | lint 清零；CodeQL 告警由分支保护门禁 |
| static_analysis_often | ✅ | 每次 push/PR 运行 |
| dynamic_analysis | ⚠️ 部分 | pytest 集成测试（tmp 仓库 + 假监听数据）承担动态验证；无模糊测试（CLI 小工具性价比低，如实声明） |
| dynamic_analysis_unsafe | ✅ N/A | 纯 Python，无内存安全问题面 |
| dynamic_analysis_enable_assertions | ✅ | 测试默认开启断言 |
| dynamic_analysis_fixed | ✅ | 测试失败即 CI 失败（分支保护门禁） |

## esq-builder-mcp / skill-maintenance-mcp 的差异

两仓与本清单基本一致，差异点：
- `test_most`：esq 111 例 / 99%（棘轮 97）；skill 33 例 / 100%（棘轮 98）
- `static_analysis_common_vulnerabilities`：两仓 CodeQL 已于 2026-09-30 批次补齐（security-extended）
- `release_notes`：esq 含 PyInstaller exe 分发说明；skill 同 agent-audit 模式
- `english`：两仓 README 为中文（英文摘要仅 agent-audit 有）——如需三仓同过，可把英文摘要段复制过去
