"""Abstract base class for DNS providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Self


class DnsProvider(ABC):
    """Interface for DNS providers that manage ACME DNS-01 challenge TXT records."""

    def close(self) -> None:
        """Release resources. Override in subclasses that hold open connections."""

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @abstractmethod
    def create_txt_record(self, zone: str, record_name: str, value: str) -> None:
        """Create a TXT record for DNS-01 challenge validation.

        Args:
            zone: DNS zone name (e.g. "example.com").
            record_name: Relative record name within the zone (e.g. "_acme-challenge").
            value: TXT record value (the ACME challenge token).
        """

    @abstractmethod
    def delete_txt_record(self, zone: str, record_name: str) -> None:
        """Delete a TXT record after DNS-01 challenge validation.

        Args:
            zone: DNS zone name (e.g. "example.com").
            record_name: Relative record name within the zone (e.g. "_acme-challenge").
        """
