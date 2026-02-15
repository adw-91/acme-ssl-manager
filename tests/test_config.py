"""Tests for cert_manager.config."""

import pytest


def test_load_config_all_required_vars(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("DNS_PROVIDER", "azure")
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")

    cfg = load_config()
    assert cfg.keyvault_url == "https://myvault.vault.azure.net"
    assert cfg.dns_provider == "azure"
    assert cfg.contact_email == "admin@example.com"


def test_load_config_defaults(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("DNS_PROVIDER", "azure")
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")

    cfg = load_config()
    assert cfg.acme_directory_url == "https://acme-v02.api.letsencrypt.org/directory"
    assert cfg.renewal_window_days == 3


def test_load_config_custom_optionals(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")
    monkeypatch.setenv("ACME_DIRECTORY_URL", "https://acme.zerossl.com/v2/DV90")
    monkeypatch.setenv("RENEWAL_WINDOW_DAYS", "30")
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token-123")

    cfg = load_config()
    assert cfg.acme_directory_url == "https://acme.zerossl.com/v2/DV90"
    assert cfg.renewal_window_days == 30
    assert cfg.cloudflare_api_token == "cf-token-123"


def test_load_config_missing_keyvault_url(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.delenv("AZURE_KEYVAULT_URL", raising=False)
    monkeypatch.setenv("DNS_PROVIDER", "azure")
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")

    with pytest.raises(ValueError, match="AZURE_KEYVAULT_URL"):
        load_config()


def test_load_config_missing_dns_provider(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.delenv("DNS_PROVIDER", raising=False)
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")

    with pytest.raises(ValueError, match="DNS_PROVIDER"):
        load_config()


def test_load_config_missing_contact_email(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("DNS_PROVIDER", "azure")
    monkeypatch.delenv("ACME_CONTACT_EMAIL", raising=False)

    with pytest.raises(ValueError, match="ACME_CONTACT_EMAIL"):
        load_config()


def test_load_config_invalid_renewal_window(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("DNS_PROVIDER", "azure")
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")
    monkeypatch.setenv("RENEWAL_WINDOW_DAYS", "not-a-number")

    with pytest.raises(ValueError, match="RENEWAL_WINDOW_DAYS"):
        load_config()


def test_load_config_zero_renewal_window(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("DNS_PROVIDER", "azure")
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")
    monkeypatch.setenv("RENEWAL_WINDOW_DAYS", "0")

    with pytest.raises(ValueError, match="RENEWAL_WINDOW_DAYS must be a positive integer"):
        load_config()


def test_load_config_negative_renewal_window(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("DNS_PROVIDER", "azure")
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")
    monkeypatch.setenv("RENEWAL_WINDOW_DAYS", "-5")

    with pytest.raises(ValueError, match="RENEWAL_WINDOW_DAYS must be a positive integer"):
        load_config()


def test_load_config_azure_dns_fields(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("DNS_PROVIDER", "azure")
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")
    monkeypatch.setenv("AZURE_DNS_RESOURCE_GROUP", "rg-dns")

    cfg = load_config()
    assert cfg.azure_subscription_id == "sub-123"
    assert cfg.azure_dns_resource_group == "rg-dns"


def test_load_config_azure_dns_fields_default_none(monkeypatch):
    from cert_manager.config import load_config

    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://myvault.vault.azure.net")
    monkeypatch.setenv("DNS_PROVIDER", "cloudflare")
    monkeypatch.setenv("ACME_CONTACT_EMAIL", "admin@example.com")
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-tok")

    cfg = load_config()
    assert cfg.azure_subscription_id is None
    assert cfg.azure_dns_resource_group is None
