# 贡献指南

## 开发环境

```bash
git clone https://github.com/mo9652962-ai/agent-audit.git && cd agent-audit
uv sync --extra dev
uv run pytest -q --cov=agent_audit --cov-report=term-missing
```

## 约定

- **Actions SHA 固定**：`.github/workflows/` 内所有 `uses:` 必须钉全量 commit SHA（安全工具的供应链纪律）；PR 引入浮动 tag 会被要求修改。
- **覆盖率棘轮**：CI 设 `--cov-fail-under`（当前 97%，实测 99.68%），只升不降；新增功能必须带测试。
- **测试政策**：新功能 / 缺口修复必须随附测试；分支保护要求 CI（test×2 OS + lint + deps-audit）通过才能合并。动机：覆盖率棘轮与编排层历史缺口（35%→66%→99.68%）的教训。
- **运行时零依赖**：`src/agent_audit` 不引入运行时依赖；开发依赖只进 `dev` extras。
- **只读原则**：检查项不得修改用户系统；修复动作以命令形式写入报告，由人执行。
- **密钥卫生**：任何密钥字面量（真实或形似）不得入库；测试值动态构造。

## 提交

PR 前跑 `uv run pytest -q`；commit message 用祈使句。
