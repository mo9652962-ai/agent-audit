# CII Badge 问卷粘贴文本（passing 级逐条）

> 配合 [cii-best-practices-answers.md](cii-best-practices-answers.md) 使用：
> 每题选「满足」后，把对应文本整块贴进黄色解释框。本项目页：
> https://www.bestpractices.dev/projects/15101
> 整理日期：2026-09-30。

## Basics

**description_good（网站简洁描述软件做什么）**

```
README 开头一句话定位 + 特性清单 + 7 项检查表：
https://github.com/mo9652962-ai/agent-audit#agent-audit
```

**interact（说明如何获取、反馈、贡献）**

```
README「快速开始」给出 pip install / 源码 / GitHub Action 三种获取方式，
Issues 用于反馈，CONTRIBUTING 给出贡献流程：
https://github.com/mo9652962-ai/agent-audit#快速开始
https://github.com/mo9652962-ai/agent-audit/blob/main/CONTRIBUTING.md
```

**contribution（解释贡献流程）**

```
CONTRIBUTING.md：开发环境（uv sync）、约定、提交规范（PR 前 pytest、
commit message 祈使句），分支保护要求 CI 通过后合并：
https://github.com/mo9652962-ai/agent-audit/blob/main/CONTRIBUTING.md
```

**contribution_requirements（可接受贡献的要求）**

```
贡献指南 CONTRIBUTING.md「约定」节明确列出全部要求：Actions 全量 SHA 固定、
覆盖率棘轮（--cov-fail-under=97 只升不降）、测试政策（新功能必须带测试）、
运行时零依赖、只读原则、密钥卫生（密钥字面量不得入库，测试值动态构造）、
提交规范：
https://github.com/mo9652962-ai/agent-audit/blob/main/CONTRIBUTING.md
```

**floss_license（以 FLOSS 发布）**

```
MIT 许可证：
https://github.com/mo9652962-ai/agent-audit/blob/main/LICENSE
```

**floss_license_osi（OSI 批准许可证）**

```
MIT 是 OSI 批准许可证：
https://opensource.org/license/mit
https://github.com/mo9652962-ai/agent-audit/blob/main/LICENSE
```

**license_location（许可证在标准位置）**

```
仓库根目录 LICENSE 文件（GitHub 自动识别为 MIT）：
https://github.com/mo9652962-ai/agent-audit/blob/main/LICENSE
```

**documentation_basics（基础文档）**

```
README 覆盖安装、7 项检查说明、输出报告解读、配置文件、CI 门禁用法：
https://github.com/mo9652962-ai/agent-audit#agent-audit
```

**documentation_interface（外部接口参考文档）**

```
CLI 参数由 --help 输出；README 给出全部选项（--checks/--format/
--severity-threshold/-c）与报告字段说明；GitHub Action 输入输出表：
https://github.com/mo9652962-ai/agent-audit#agent-audit
https://github.com/mo9652962-ai/agent-audit/blob/main/action/README.md
```

**sites_https（HTTPS）**

```
项目全部站点（GitHub、PyPI）均强制 HTTPS：
https://github.com/mo9652962-ai/agent-audit
https://pypi.org/project/agent-env-audit/
```

**discussion（可检索的公开讨论机制）**

```
GitHub Issues，URL 可寻址、全文可检索：
https://github.com/mo9652962-ai/agent-audit/issues
```

**english（英文文档与缺陷报告能力）**

```
部分满足（如实声明）：README 含英文概览段（项目定位 + 安装 + 用法），
接受英文 issue；文档主体为中文，完整英文翻译在 Roadmap：
https://github.com/mo9652962-ai/agent-audit#english
```

**maintained（活跃维护）**

```
2026-09 连续提交与发版（v0.1.0 / v0.1.1），CI 每次 push 运行：
https://github.com/mo9652962-ai/agent-audit/releases
https://github.com/mo9652962-ai/agent-audit/actions
```

## Change Control

**repo_public（公开仓库）**

```
公开 GitHub 仓库：
https://github.com/mo9652962-ai/agent-audit
```

**repo_track（追踪 who/what/when）**

```
git 全量历史（作者、变更、时间戳）：
https://github.com/mo9652962-ai/agent-audit/commits/main
```

**repo_interim（发布间的中间版本）**

```
main 分支承载中间版本，push 即跑全量 CI（test×2 OS + lint + deps-audit +
CodeQL + action-dogfood）：
https://github.com/mo9652962-ai/agent-audit/commits/main
```

**repo_distributed（分布式 VCS）**

```
git + GitHub，本地多克隆开发：
https://github.com/mo9652962-ai/agent-audit
```

**version_unique（唯一版本号）**

```
pyproject version 唯一且不可重传（PyPI 强制）：
https://github.com/mo9652962-ai/agent-audit/blob/main/pyproject.toml
https://pypi.org/project/agent-env-audit/
```

**version_semver（语义化版本）**

```
0.1.x 语义化版本（patch 递进，CHANGELOG 按版本记录）：
https://github.com/mo9652962-ai/agent-audit/blob/main/CHANGELOG.md
```

**version_tags（VCS tag 发布）**

```
发布由 v* tag 触发（v0.1.0 / v0.1.1）：
https://github.com/mo9652962-ai/agent-audit/tags
```

**release_notes（每版本人类可读发布说明）**

```
GitHub Release notes + CHANGELOG.md 双记录：
https://github.com/mo9652962-ai/agent-audit/releases
https://github.com/mo9652962-ai/agent-audit/blob/main/CHANGELOG.md
```

**release_notes_vulns（发布说明标注已修 CVE）**

```
当前无已修复 CVE；项目约定（CHANGELOG Keep a Changelog 格式）：
安全修复将记录于对应版本条目：
https://github.com/mo9652962-ai/agent-audit/blob/main/CHANGELOG.md
```

## Reporting

**report_process（缺陷提交流程）**

```
GitHub Issues + CONTRIBUTING 说明：
https://github.com/mo9652962-ai/agent-audit/issues
https://github.com/mo9652962-ai/agent-audit/blob/main/CONTRIBUTING.md
```

**report_tracker（使用缺陷跟踪器）**

```
GitHub Issues：
https://github.com/mo9652962-ai/agent-audit/issues
```

**report_responses（多数缺陷报告有响应）**

```
全部 issue 均有维护者响应（项目活跃，CI 每日运行）：
https://github.com/mo9652962-ai/agent-audit/issues?q=is%3Aissue
```

**enhancement_responses（多数增强请求有回应）**

```
增强请求以 Roadmap 承载并有明确状态（已完成项勾选）：
https://github.com/mo9652962-ai/agent-audit#roadmap
```

**report_archive（公开可检索存档）**

```
Issues 永久公开存档、支持全文检索：
https://github.com/mo9652962-ai/agent-audit/issues
```

**vulnerability_report_process（漏洞报告流程）**

```
SECURITY.md 定义漏洞报告流程（不开公开 issue）：
https://github.com/mo9652962-ai/agent-audit/blob/main/SECURITY.md
```

**vulnerability_report_private（私密报告渠道）**

```
GitHub Security Advisories 私密报告：
https://github.com/mo9652962-ai/agent-audit/security/advisories/new
https://github.com/mo9652962-ai/agent-audit/blob/main/SECURITY.md
```

**vulnerability_report_response（14 天内首次响应）**

```
SECURITY.md 承诺 7 天内响应（优于判据要求的 14 天）：
https://github.com/mo9652962-ai/agent-audit/blob/main/SECURITY.md
```

## Quality

**build（可工作的构建系统）**

```
纯 Python：uv sync --extra dev && uv build（sdist + wheel）：
https://github.com/mo9652962-ai/agent-audit/blob/main/pyproject.toml
```

**build_common_tools（常用构建工具）**

```
setuptools + uv 标准工具链：
https://github.com/mo9652962-ai/agent-audit/blob/main/pyproject.toml
```

**build_floss_tools（FLOSS 工具可构建）**

```
全 FLOSS 工具链（Python/uv/setuptools/GitHub Actions）：
https://github.com/mo9652962-ai/agent-audit/blob/main/pyproject.toml
```

**test（至少一个公开自动化测试套件）**

```
pytest 152 例，CI（ubuntu+windows 矩阵）每次 push 运行：
https://github.com/mo9652962-ai/agent-audit/tree/main/tests
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/ci.yml
```

**test_invocation（标准调用方式）**

```
CONTRIBUTING 给出标准命令：uv run pytest -q --cov=agent_audit：
https://github.com/mo9652962-ai/agent-audit/blob/main/CONTRIBUTING.md
```

**test_most（广泛覆盖）**

```
覆盖率 99.68%，CI 棘轮 --cov-fail-under=97（只升不降）；编排层与全部
检查分支入测：
https://github.com/mo9652962-ai/agent-audit/actions
```

**test_continuous_integration（已实现 CI）**

```
GitHub Actions：test（ubuntu+windows）+ lint + deps-audit + CodeQL +
action-dogfood，push/PR 触发，分支保护要求通过：
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/ci.yml
```

**test_policy（新功能需测试的政策）**

```
CONTRIBUTING「测试政策」：新功能 / 缺口修复必须随附测试，分支保护强制 CI：
https://github.com/mo9652962-ai/agent-audit/blob/main/CONTRIBUTING.md
```

**tests_are_added（政策被遵循的证据）**

```
git 历史：覆盖率轨迹 35%→66%→99.68%，每次功能 commit 均含测试：
https://github.com/mo9652962-ai/agent-audit/commits/main
```

**tests_documented_added（政策在变更提案中文档化）**

```
部分满足（如实声明）：测试要求已写入 CONTRIBUTING；变更提案以 PR 描述
承载（单人维护项目，无正式提案模板）：
https://github.com/mo9652962-ai/agent-audit/blob/main/CONTRIBUTING.md
```

**warnings（启用编译警告/linter）**

```
ruff（line-length 100）+ bandit 安全扫描，CI 每次运行：
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/ci.yml
```

**warnings_fixed（警告已处理）**

```
ruff 与 bandit 零未处理发现（发现项全修或带真实理由豁免，豁免注释含理由）：
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/ci.yml
```

**warnings_strict（尽可能严格）**

```
ruff 默认规则集 + bandit + CodeQL security-extended 叠加门禁：
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/codeql.yml
```

## Security

**know_secure_design（开发者掌握安全设计）**

```
本工具本身即安全审计方法论的产品化：判定清单对照 OWASP / NSA CSI（2026-06）/
MCP 官方 Security Best Practices（2026-07-28 spec）：
https://github.com/mo9652962-ai/agent-audit#方法论依据
```

**know_common_errors（掌握常见漏洞与缓解）**

```
7 项检查覆盖常见 CWE 类：CWE-778/312（凭据存储）、CWE-16（权限配置）、
CWE-829/1357（供应链）、CWE-200（信息暴露）——见白皮书：
https://github.com/mo9652962-ai/agent-audit/blob/main/docs/mcp-security-audit-whitepaper.md
```

**crypto_published（仅用公开且经审查的密码学）**

```
不实现密码学协议；仅使用 hashlib SHA-256 做内容指纹（公开算法、标准库实现）：
https://github.com/mo9652962-ai/agent-audit
```

**crypto_call（用密码学库而非自研）**

```
哈希全部调用 Python 标准库 hashlib，无自研密码学代码：
https://github.com/mo9652962-ai/agent-audit
```

**crypto_floss（密码学功能可由 FLOSS 实现）**

```
标准库实现，全 FLOSS：
https://github.com/mo9652962-ai/agent-audit
```

**crypto_keylength（NIST 最低密钥长度）**

```
仅使用 SHA-256，满足 NIST 最低要求：
https://github.com/mo9652962-ai/agent-audit
```

**crypto_working（无破损算法）**

```
未使用 MD5/SHA1 等破损算法：
https://github.com/mo9652962-ai/agent-audit
```

**crypto_weaknesses（避免严重削弱算法）**

```
不涉及；仅 SHA-256 指纹计算：
https://github.com/mo9652962-ai/agent-audit
```

**crypto_pfs（完美前向保密）** —— N/A

```
不适用：本工具不实现网络传输协议（只读本地审计，不联网）。
```

**crypto_password_storage（迭代加盐口令哈希）** —— N/A

```
不适用：不存储或处理任何口令。
```

**crypto_random（密码学安全随机数）** —— N/A

```
不适用：不生成密钥或 nonce。
```

**delivery_mitm（抗 MITM 交付）**

```
唯一分发渠道 PyPI 与 GitHub 均强制 HTTPS：
https://pypi.org/project/agent-env-audit/
```

**delivery_unsigned（无 http 裸哈希）**

```
无 http 分发；PyPI 产物带 PEP 740 provenance attestation（OIDC 签名）：
https://pypi.org/project/agent-env-audit/
```

**vulnerabilities_fixed_60_days（60 天内修复已知中高危）**

```
deps-audit（pip-audit）每次 push 扫描，当前零已知漏洞；CodeQL security-
extended 门禁：
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/ci.yml
```

**vulnerabilities_critical_fixed（快速修复 critical）**

```
同上：扫描在 CI 门禁内，SECURITY.md 承诺 7 天响应：
https://github.com/mo9652962-ai/agent-audit/blob/main/SECURITY.md
```

**no_leaked_credentials（无泄漏凭据）**

```
自家 git 泄漏检查 dogfood（CI action-dogfood 每次 push 运行）+ 密钥卫生
约定（测试值动态构造）：
https://github.com/mo9652962-ai/agent-audit#在-ci-里用github-action
```

## Analysis

**static_analysis（重大发布前静态分析）**

```
ruff + bandit 全量通过是发布门禁（publish workflow 先跑测试再发布）：
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/publish.yml
```

**static_analysis_common_vulnerabilities（漏洞导向规则）**

```
CodeQL security-extended 查询集（push/PR/每周）：
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/codeql.yml
```

**static_analysis_fixed（及时修复中高危发现）**

```
ruff/bandit 零未处理发现；CodeQL 告警由分支保护门禁阻断合并：
https://github.com/mo9652962-ai/agent-audit/security/code-scanning
```

**static_analysis_often（每次提交/每日运行）**

```
push/PR 触发 + 每周一 cron 全量：
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/codeql.yml
```

**dynamic_analysis（重大发布前动态分析）**

```
部分满足（如实声明）：pytest 集成测试（tmp 仓库 + 假监听/Monkeypatch）
承担动态验证；无模糊测试——纯 Python 只读 CLI，攻击面为静态扫描本身，
fuzzing 性价比低已声明：
https://github.com/mo9652962-ai/agent-audit/tree/main/tests
```

**dynamic_analysis_unsafe（内存安全工具）** —— N/A

```
不适用：纯 Python 实现，无内存安全问题面。
```

**dynamic_analysis_enable_assertions（开启断言）**

```
pytest 默认开启断言重写，全部测试在断言启用状态运行：
https://github.com/mo9652962-ai/agent-audit/tree/main/tests
```

**dynamic_analysis_fixed（及时修复动态分析发现）**

```
测试失败即 CI 失败，分支保护阻断合并：
https://github.com/mo9652962-ai/agent-audit/blob/main/.github/workflows/ci.yml
```
