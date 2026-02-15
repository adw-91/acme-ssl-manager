"""Azure DNS provider — create/delete TXT records via azure-mgmt-dns."""

from __future__ import annotations

import logging

from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, TxtRecord

from cert_manager.dns.base import DnsProvider

logger = logging.getLogger(__name__)

_CHALLENGE_TTL = 60


class AzureDnsProvider(DnsProvider):
    """DNS provider backed by Azure DNS zones."""

    def __init__(
        self,
        credential,
        subscription_id: str,
        resource_group: str,
        _dns_client: DnsManagementClient | None = None,
    ) -> None:
        self._resource_group = resource_group
        self._dns_client = _dns_client or DnsManagementClient(credential, subscription_id)

    def create_txt_record(self, zone: str, record_name: str, value: str) -> None:
        record_set = RecordSet(
            ttl=_CHALLENGE_TTL,
            txt_records=[TxtRecord(value=[value])],
        )
        self._dns_client.record_sets.create_or_update(
            resource_group_name=self._resource_group,
            zone_name=zone,
            relative_record_set_name=record_name,
            record_type="TXT",
            parameters=record_set,
        )
        logger.info("Created TXT record %s.%s", record_name, zone)

    def delete_txt_record(self, zone: str, record_name: str) -> None:
        self._dns_client.record_sets.delete(
            resource_group_name=self._resource_group,
            zone_name=zone,
            relative_record_set_name=record_name,
            record_type="TXT",
        )
        logger.info("Deleted TXT record %s.%s", record_name, zone)
