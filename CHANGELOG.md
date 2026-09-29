# Changelog

本项目的所有重要变更记录于此。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.0] - 2026-09-28

### Added

- 7 项只读检查：端口暴露 / skill 来源分类 / 外发端点白名单 / 凭据权限与明文 / git 泄漏 / 依赖漏洞 / MCP server 审计（对照 OWASP MCP Security Guide）
- CLI：`agent-audit`（--checks / --format md,json / --severity-threshold 退出码门禁 / TOML 配置）
- Markdown + JSON 双报告，含审计完成标准表与修复优先级清单
- 运行时零依赖（PyYAML 可选，缺失自动降级解析）
- CI：ubuntu+windows 矩阵 + 覆盖率棘轮 + pip-audit 依赖扫描
- Publish to PyPI（Trusted Publishing/OIDC 免 token，Actions SHA 固定）+ CycloneDX SBOM
