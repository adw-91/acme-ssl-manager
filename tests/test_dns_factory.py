"""Tests for DNS provider factory."""

from unittest.mock import patch

import pytest

from cert_manager.config import AppConfig
from cert_manager.dns import get_dns_provider


def _make_config(**overrides) -> AppConfig:
    defaults = {
        "keyvault_url": "https://v.vault.azure.net",
        "dns_provider": "azure",
        "contact_email": "a@b.com",
        "azure_subscription_id": "sub-1",
        "azure_dns_resource_group": "rg-1",
    }
    defaults.update(overrides)
    return AppConfig(**defaults)


class TestGetDnsProvider:
    @patch("cert_manager.dns.AzureDnsProvider")
    @patch("cert_manager.dns._get_credential")
    def test_returns_azure_provider(self, mock_cred, mock_azure_cls):
        config = _make_config(dns_provider="azure")
        provider = get_dns_provider(config)

        mock_azure_cls.assert_called_once_with(
            credential=mock_cred.return_value,
            subscription_id="sub-1",
            resource_group="rg-1",
        )
        assert provider is mock_azure_cls.return_value

    @patch("cert_manager.dns.CloudflareDnsProvider")
    def test_returns_cloudflare_provider(self, mock_cf_cls):
        config = _make_config(dns_provider="cloudflare", cloudflare_api_token="tok")
        provider = get_dns_provider(config)

        mock_cf_cls.assert_called_once_with(api_token="tok")
        assert provider is mock_cf_cls.return_value

    def test_raises_on_unknown_provider(self):
        config = _make_config(dns_provider="route53")
        with pytest.raises(ValueError, match="Unknown DNS provider: 'route53'"):
            get_dns_provider(config)

    def test_raises_when_azure_missing_subscription_id(self):
        config = _make_config(dns_provider="azure", azure_subscription_id=None)
        with pytest.raises(ValueError, match="AZURE_SUBSCRIPTION_ID"):
            get_dns_provider(config)

    def test_raises_when_azure_missing_resource_group(self):
        config = _make_config(dns_provider="azure", azure_dns_resource_group=None)
        with pytest.raises(ValueError, match="AZURE_DNS_RESOURCE_GROUP"):
            get_dns_provider(config)

    def test_raises_when_cloudflare_missing_token(self):
        config = _make_config(dns_provider="cloudflare", cloudflare_api_token=None)
        with pytest.raises(ValueError, match="CLOUDFLARE_API_TOKEN"):
            get_dns_provider(config)

    @patch("cert_manager.dns.AzureDnsProvider")
    @patch("cert_manager.dns._get_credential")
    def test_provider_name_override(self, mock_cred, mock_azure_cls):
        config = _make_config(dns_provider="cloudflare")
        provider = get_dns_provider(config, provider_name="azure")

        mock_azure_cls.assert_called_once()
        assert provider is mock_azure_cls.return_value
