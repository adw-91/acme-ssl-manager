"""Configuration loading and validation from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

_LETS_ENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
_DEFAULT_RENEWAL_WINDOW_DAYS = 3


@dataclass(frozen=True)
class AppConfig:
    """Application configuration loaded from environment variables."""

    keyvault_url: str
    dns_provider: str
    contact_email: str
    acme_directory_url: str = _LETS_ENCRYPT_DIRECTORY
    renewal_window_days: int = _DEFAULT_RENEWAL_WINDOW_DAYS
    cloudflare_api_token: str | None = None


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Required environment variable {name} is not set")
    return value


def load_config() -> AppConfig:
    """Load and validate application configuration from environment variables."""
    keyvault_url = _require_env("AZURE_KEYVAULT_URL")
    dns_provider = _require_env("DNS_PROVIDER")
    contact_email = _require_env("ACME_CONTACT_EMAIL")
    acme_directory_url = os.environ.get("ACME_DIRECTORY_URL", _LETS_ENCRYPT_DIRECTORY)

    raw_window = os.environ.get("RENEWAL_WINDOW_DAYS", str(_DEFAULT_RENEWAL_WINDOW_DAYS))
    try:
        renewal_window_days = int(raw_window)
    except ValueError:
        raise ValueError(f"RENEWAL_WINDOW_DAYS must be an integer, got: {raw_window!r}")
    if renewal_window_days < 1:
        raise ValueError(f"RENEWAL_WINDOW_DAYS must be a positive integer, got: {renewal_window_days}")

    cloudflare_api_token = os.environ.get("CLOUDFLARE_API_TOKEN")

    return AppConfig(
        keyvault_url=keyvault_url,
        dns_provider=dns_provider,
        contact_email=contact_email,
        acme_directory_url=acme_directory_url,
        renewal_window_days=renewal_window_days,
        cloudflare_api_token=cloudflare_api_token,
    )
