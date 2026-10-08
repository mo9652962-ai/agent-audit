# Privacy Policy for agent-audit

**Last Updated:** October 2026

`agent-audit` is a local-first security auditing CLI for AI agent development environments, aligned with OWASP Top 10 for LLM and NSA CSI guidance.

## 1. Strictly Read-Only & Zero-Exfiltration
- `agent-audit` inspects local Git history, package dependency lockfiles, exposed local ports, and MCP configuration files.
- **Zero Data Exfiltration:** All security findings, detected secret signatures, file paths, and environment metrics execute strictly in memory and display to stdout/SARIF. No scan findings are ever transmitted to external servers.

## 2. Zero External Telemetry
- `agent-audit` contains no analytics beacons, tracking telemetry, or remote reporting mechanisms.

## 3. Data Ownership
- All scan reports and identified security posture details remain under the sole custody of the developer or organization.

## 4. Contact & Responsible Disclosure
Please refer to [SECURITY.md](SECURITY.md) to report vulnerabilities or contact `mo9652962-ai@users.noreply.github.com`.
