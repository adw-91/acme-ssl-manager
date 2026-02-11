# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Azure ACME Certificate Manager — automated SSL certificate renewal using Azure Functions (Durable), ACME protocol (DNS-01 challenges), and Azure Key Vault. Certificates tagged `acme-managed=true` in Key Vault are monitored and renewed automatically.

## Development Commands

```bash
# NOTE: If pytest/ruff aren't on PATH, prefix with `python -m`
# e.g. python -m pytest, python -m ruff check .

# Activate virtual environment
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux/macOS

# Install dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run a single test file
pytest tests/test_config.py

# Run a specific test
pytest tests/test_config.py::test_function_name -v

# Lint
ruff check .

# Format
ruff format .
```

## Architecture

**Runtime**: Azure Functions v2 (Python) with Durable Functions for orchestration.

**Entry point**: `function_app.py` defines all triggers and activity functions:
- Timer trigger (daily) starts the Durable orchestrator
- Orchestrator fans out per certificate: ACME order → DNS challenge → validation → download → upload
- Blob trigger on `/certs` container handles certificate onboarding (PFX/PEM import)

**Core library** (`src/cert_manager/`):
- `config.py` — env var loading and validation
- `keyvault.py` — scan certs by tag, upload PFX
- `acme_client.py` — ACME account registration, order creation, challenge handling, cert download (uses certbot `acme` library)
- `certificate.py` — cert parsing (SANs, expiry, metadata)
- `dns/base.py` — `DnsProvider` ABC with `create_txt_record` / `delete_txt_record`
- `dns/azure_dns.py` — Azure DNS implementation (`azure-mgmt-dns`)
- `dns/cloudflare.py` — Cloudflare REST API implementation
- `models.py` — data classes (`CertificateInfo`, `RenewalRequest`, `RenewalResult`, `DnsChallengeInfo`, `AcmeOrderContext`) passed between activity functions

**IaC**: `deploy/main.bicep` — Function App, Storage Account, Key Vault, RBAC assignments.

## Key Design Decisions

- **Auth**: Managed Identity via `DefaultAzureCredential` everywhere
- **DNS provider selection**: single default via `DNS_PROVIDER` env var; per-cert override via `acme-dns-provider` tag on the Key Vault certificate
- **CA selection**: configurable default ACME directory URL; per-cert override via `acme-ca` tag
- **Certificate discovery**: tag-based (`acme-managed=true`), domain/SAN parsed from existing cert
- **Testing**: pytest + unittest.mock; no live Azure calls in tests

## Configuration

Required env vars: `AZURE_KEYVAULT_URL`, `DNS_PROVIDER`, `ACME_CONTACT_EMAIL`

Optional: `ACME_DIRECTORY_URL` (defaults to Let's Encrypt), `RENEWAL_WINDOW_DAYS` (default 3), `CLOUDFLARE_API_TOKEN`, `ACME_ACCOUNT_KEY` (JWK JSON — reuse existing ACME account), `ACME_ACCOUNT_URI` (account URL — must be set with `ACME_ACCOUNT_KEY`)

## Certificate Tags

| Tag | Required | Purpose |
|---|---|---|
| `acme-managed` | Yes | Must be `true` to opt in |
| `acme-dns-provider` | No | Override default DNS provider |
| `acme-ca` | No | Override default ACME CA |

## Known Issues (from code review of stages 1-3)

No outstanding issues — all 7 findings from the stages 1-3 review have been resolved.

## Implementation Stages

Development follows staged milestones defined in `docs/PROJECT_PLAN.md`:
1. ~~Project scaffolding & core models~~ (complete)
2. ~~Key Vault integration~~ (complete)
3. ~~ACME client~~ (complete)
4. DNS providers
5. Orchestrator & wiring
6. Blob onboarding
7. IaC & deployment
