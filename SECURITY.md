# Security Policy

## Reporting a Vulnerability
Please report vulnerabilities privately via GitHub Security Advisories of
`koal0308/AEraLogin-Human-and-A2A`. Do not open public issues for security bugs.

## Secrets
- Never commit `.env`, private keys, agent key files, databases or logs
  (enforced by `.gitignore`, `tools/repo_audit.py`, `tools/secret_scan.py`, CI).
- Use `.env.example` as a template only; it contains placeholders.
- A retired legacy token secret appears intentionally in denylists
  (`server.py`, `telegram_group_bot.py`, `agent/tokens.py`) and in tests that
  assert it is rejected. It is not valid for any deployment.

## Agent Keys
Agent Runtime private keys are generated and stored locally by the runtime.
AEra only receives public keys. Enrollment codes are short-lived and single-use.

## Known Limitations
- `/static` mount exposes the project directory in local setups.
- `/docs/` serves internal markdown files.
- Enrollment code as CLI argument is visible in shell history / `ps`.
