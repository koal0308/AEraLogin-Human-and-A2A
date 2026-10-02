# Security Policy

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities through public GitHub Issues.

Report security issues privately through the repository's configured GitHub security reporting mechanism.

Include:

- affected component or file
- reproducible steps or proof of concept
- expected and observed behavior
- impact assessment where known
- relevant version, commit or tag

Do not include real credentials, private keys, production databases or personal data in a report.

## Scope

Security-sensitive areas include:

- Human Identity ownership checks
- Agent ownership and lifecycle authorization
- Runtime key registration and verification
- A2A credentials and peer trust
- replay protection
- capability authorization
- authentication/session handling
- public-file and endpoint exposure

## Disclosure

Please allow maintainers reasonable time to investigate and remediate a vulnerability before public disclosure.

This repository is a frozen reference implementation. Security fixes made in future active development may not be backported here unless explicitly released as part of the reference line.

## Historical credentials

Credentials or secrets that may have appeared in historical development material must be treated as compromised until independently confirmed otherwise and rotated where applicable. Never reuse historical repository credentials in a deployment.
