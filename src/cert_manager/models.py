"""Data classes passed between Durable Functions activity functions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class CertificateInfo:
    """Metadata about a certificate discovered in Key Vault."""

    name: str
    vault_url: str
    domains: list[str]
    expires_on: datetime
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vault_url": self.vault_url,
            "domains": list(self.domains),
            "expires_on": self.expires_on.isoformat(),
            "tags": dict(self.tags),
        }

    @classmethod
    def from_dict(cls, data: dict) -> CertificateInfo:
        return cls(
            name=data["name"],
            vault_url=data["vault_url"],
            domains=list(data["domains"]),
            expires_on=datetime.fromisoformat(data["expires_on"]),
            tags=dict(data.get("tags", {})),
        )


@dataclass(frozen=True)
class RenewalRequest:
    """Input for a single certificate renewal activity chain."""

    cert_name: str
    vault_url: str
    domains: list[str]
    dns_provider: str
    acme_directory_url: str
    contact_email: str

    def to_dict(self) -> dict:
        return {
            "cert_name": self.cert_name,
            "vault_url": self.vault_url,
            "domains": list(self.domains),
            "dns_provider": self.dns_provider,
            "acme_directory_url": self.acme_directory_url,
            "contact_email": self.contact_email,
        }

    @classmethod
    def from_dict(cls, data: dict) -> RenewalRequest:
        return cls(
            cert_name=data["cert_name"],
            vault_url=data["vault_url"],
            domains=list(data["domains"]),
            dns_provider=data["dns_provider"],
            acme_directory_url=data["acme_directory_url"],
            contact_email=data["contact_email"],
        )


@dataclass(frozen=True)
class RenewalResult:
    """Output from a single certificate renewal attempt."""

    cert_name: str
    success: bool
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "cert_name": self.cert_name,
            "success": self.success,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict) -> RenewalResult:
        return cls(
            cert_name=data["cert_name"],
            success=data["success"],
            error=data.get("error"),
        )


@dataclass(frozen=True)
class DnsChallengeInfo:
    """DNS-01 challenge details for a single domain."""

    domain: str
    record_name: str
    record_value: str

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "record_name": self.record_name,
            "record_value": self.record_value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> DnsChallengeInfo:
        return cls(
            domain=data["domain"],
            record_name=data["record_name"],
            record_value=data["record_value"],
        )


@dataclass(frozen=True)
class AcmeOrderContext:
    """Serializable state passed between create_acme_order and finalize_acme_order activities."""

    account_key_json: str
    account_uri: str
    directory_url: str
    order_url: str
    csr_pem: str
    private_key_pem: str
    challenges: tuple[DnsChallengeInfo, ...] = ()

    def to_dict(self) -> dict:
        return {
            "account_key_json": self.account_key_json,
            "account_uri": self.account_uri,
            "directory_url": self.directory_url,
            "order_url": self.order_url,
            "csr_pem": self.csr_pem,
            "private_key_pem": self.private_key_pem,
            "challenges": [c.to_dict() for c in self.challenges],
        }

    @classmethod
    def from_dict(cls, data: dict) -> AcmeOrderContext:
        return cls(
            account_key_json=data["account_key_json"],
            account_uri=data["account_uri"],
            directory_url=data["directory_url"],
            order_url=data["order_url"],
            csr_pem=data["csr_pem"],
            private_key_pem=data["private_key_pem"],
            challenges=tuple(DnsChallengeInfo.from_dict(c) for c in data.get("challenges", [])),
        )
