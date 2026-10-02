# Quickstart

This document describes the frozen public reference implementation.

## Requirements

- Python 3.11+
- Git
- a clean virtual environment

## Install

```bash
git clone https://github.com/koal0308/AEraLogin-Human-and-A2A.git
cd AEraLogin-Human-and-A2A
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Copy the environment template:

```bash
cp .env.example .env
```

Set all required authentication secrets to fresh random values. Never reuse values found in historical repository documentation.

## Run tests

```bash
python -m pytest tests/ -q
```

## Reference components

The main reference implementation is divided into:

- `identity/`
- `agent/`
- `agent_runtime/`
- `a2a_gateway/`

Security and interoperability testing is provided by `aera-agent-security-lab/`.

This repository is frozen. New features should not be added here; use the active AEraLogIn development repository instead.
