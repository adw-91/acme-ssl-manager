"""DNS provider factory — resolve provider name to concrete implementation."""

from __future__ import annotations

from cert_manager.auth import get_credential as _get_credential
from cert_manager.config import AppConfig
from cert_manager.dns.azure_dns import AzureDnsProvider
from cert_manager.dns.base import DnsProvider
from cert_manager.dns.cloudflare import CloudflareDnsProvider


def get_dns_provider(config: AppConfig, provider_name: str | None = None) -> DnsProvider:
    """Instantiate a DNS provider by name.

    Args:
        config: Application configuration.
        provider_name: Override the default provider from config. Used for per-cert
            overrides via the ``acme-dns-provider`` certificate tag.

    Returns:
        A configured DnsProvider instance.
    """
    name = (provider_name or config.dns_provider).lower()

    if name == "azure":
        if not config.azure_subscription_id:
            raise ValueError("AZURE_SUBSCRIPTION_ID is required when DNS_PROVIDER=azure")
        if not config.azure_dns_resource_group:
            raise ValueError("AZURE_DNS_RESOURCE_GROUP is required when DNS_PROVIDER=azure")
        return AzureDnsProvider(
            credential=_get_credential(),
            subscription_id=config.azure_subscription_id,
            resource_group=config.azure_dns_resource_group,
        )

    if name == "cloudflare":
        if not config.cloudflare_api_token:
            raise ValueError("CLOUDFLARE_API_TOKEN is required when DNS_PROVIDER=cloudflare")
        return CloudflareDnsProvider(api_token=config.cloudflare_api_token)

    raise ValueError(f"Unknown DNS provider: '{name}'")
