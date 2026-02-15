"""Cloudflare DNS provider — create/delete TXT records via Cloudflare REST API."""

from __future__ import annotations

import logging

import httpx

from cert_manager.dns.base import DnsProvider

logger = logging.getLogger(__name__)

_API_BASE = "https://api.cloudflare.com/client/v4"
_CHALLENGE_TTL = 60


class CloudflareDnsProvider(DnsProvider):
    """DNS provider backed by the Cloudflare API."""

    def __init__(
        self,
        api_token: str,
        _http_client: httpx.Client | None = None,
    ) -> None:
        self._client = _http_client or httpx.Client(
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=30,
        )

    def _get_zone_id(self, zone: str) -> str:
        """Look up the Cloudflare zone ID for a domain name."""
        resp = self._client.get(f"{_API_BASE}/zones", params={"name": zone})
        resp.raise_for_status()
        results = resp.json()["result"]
        if not results:
            raise ValueError(f"No Cloudflare zone found for '{zone}'")
        return results[0]["id"]

    def create_txt_record(self, zone: str, record_name: str, value: str) -> None:
        zone_id = self._get_zone_id(zone)
        fqdn = f"{record_name}.{zone}"
        # Delete any existing TXT records for idempotency (Durable Functions may replay)
        self._delete_records_by_name(zone_id, fqdn)
        resp = self._client.post(
            f"{_API_BASE}/zones/{zone_id}/dns_records",
            json={"type": "TXT", "name": fqdn, "content": value, "ttl": _CHALLENGE_TTL},
        )
        resp.raise_for_status()
        logger.info("Created TXT record %s in Cloudflare zone %s", fqdn, zone)

    def _delete_records_by_name(self, zone_id: str, fqdn: str) -> int:
        """Delete all TXT records matching the FQDN. Returns count of records deleted."""
        resp = self._client.get(
            f"{_API_BASE}/zones/{zone_id}/dns_records",
            params={"type": "TXT", "name": fqdn},
        )
        resp.raise_for_status()
        records = resp.json()["result"]
        for record in records:
            self._client.delete(
                f"{_API_BASE}/zones/{zone_id}/dns_records/{record['id']}",
            ).raise_for_status()
        return len(records)

    def delete_txt_record(self, zone: str, record_name: str) -> None:
        zone_id = self._get_zone_id(zone)
        fqdn = f"{record_name}.{zone}"
        count = self._delete_records_by_name(zone_id, fqdn)
        if count == 0:
            logger.warning("TXT record %s not found in Cloudflare — skipping delete", fqdn)
        else:
            logger.info("Deleted TXT record %s from Cloudflare zone %s", fqdn, zone)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()
