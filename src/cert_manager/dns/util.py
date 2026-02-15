"""DNS utility functions."""

from __future__ import annotations


def split_record_name(fqdn: str, domain: str) -> tuple[str, str]:
    """Split an FQDN into (zone, relative_record_name) based on the certificate domain.

    The zone is derived from the domain (stripping any wildcard prefix).
    The relative record name is the FQDN with the zone suffix removed.

    Note: This assumes the DNS zone matches the cert domain. If the cert domain
    is a subdomain but the DNS zone is a parent (e.g. cert ``sub.example.com``
    in zone ``example.com``), the caller must handle zone mapping separately.

    Args:
        fqdn: Fully qualified record name (e.g. "_acme-challenge.example.com").
        domain: Certificate domain (e.g. "example.com" or "*.example.com").

    Returns:
        Tuple of (zone, relative_name).
    """
    zone = domain.removeprefix("*.")
    suffix = f".{zone}"
    if not fqdn.endswith(suffix):
        raise ValueError(f"Record '{fqdn}' is not under zone '{zone}'")
    relative = fqdn.removesuffix(suffix)
    return zone, relative
