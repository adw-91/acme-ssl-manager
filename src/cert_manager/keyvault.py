"""Key Vault operations — scan certificates and upload PFX."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta

from azure.keyvault.certificates import CertificateClient

from cert_manager.auth import get_credential as _get_credential
from cert_manager.config import AppConfig
from cert_manager.models import CertificateInfo

logger = logging.getLogger(__name__)


def _extract_cn(subject: str | None) -> str | None:
    """Extract CN value from an X.500 subject string like 'CN=example.com'."""
    if not subject:
        return None
    match = re.search(r"CN=([^,]+)", subject)
    return match.group(1).strip() if match else None


def scan_certificates(config: AppConfig) -> list[CertificateInfo]:
    """List Key Vault certs tagged acme-managed=true that are within the renewal window.

    Filtering order: tag → expiry → get_certificate (for SANs/CN).
    Certs with expires_on=None are included (abnormal, needs attention).
    Certs with no extractable domains are skipped (can't renew via ACME).

    A new CertificateClient is created per call because Durable Functions
    activities may run in separate processes — client sharing is not possible.
    """
    client = CertificateClient(config.keyvault_url, _get_credential())
    cutoff = datetime.now(UTC) + timedelta(days=config.renewal_window_days)
    results: list[CertificateInfo] = []

    all_props = list(client.list_properties_of_certificates())
    managed = [p for p in all_props if (p.tags or {}).get("acme-managed") == "true"]
    logger.info("Found %d certificates, %d acme-managed", len(all_props), len(managed))

    for props in managed:
        if props.expires_on is None:
            logger.warning("Certificate '%s' has no expiry date — including for renewal", props.name)
        elif props.expires_on > cutoff:
            continue

        cert = client.get_certificate(props.name)
        policy = cert.policy

        domains: list[str] = []
        if policy and policy.san_dns_names:
            domains = list(policy.san_dns_names)
        elif policy:
            cn = _extract_cn(policy.subject)
            if cn:
                domains = [cn]

        if not domains:
            logger.warning("Certificate '%s' has no extractable domains — skipping", props.name)
            continue

        results.append(
            CertificateInfo(
                name=props.name,
                vault_url=props.vault_url,
                domains=domains,
                expires_on=props.expires_on or datetime.max.replace(tzinfo=UTC),
                tags=dict(props.tags or {}),
            )
        )

    logger.info("%d certificate(s) due for renewal", len(results))
    return results


def upload_certificate(config: AppConfig, cert_name: str, pfx_data: bytes) -> None:
    """Import a PFX certificate into Key Vault, creating a new version.

    Exceptions propagate to the caller — the orchestrator's retry policy
    (Stage 5) handles transient failures like permission errors or throttling.
    """
    client = CertificateClient(config.keyvault_url, _get_credential())
    client.import_certificate(certificate_name=cert_name, certificate_bytes=pfx_data)
    logger.info("Uploaded certificate '%s'", cert_name)
