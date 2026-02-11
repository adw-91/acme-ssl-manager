"""Tests for cert_manager.models."""

from datetime import UTC, datetime


def test_certificate_info_creation():
    from cert_manager.models import CertificateInfo

    cert = CertificateInfo(
        name="my-cert",
        vault_url="https://myvault.vault.azure.net",
        domains=["example.com", "www.example.com"],
        expires_on=datetime(2026, 3, 1, tzinfo=UTC),
        tags={"acme-managed": "true"},
    )
    assert cert.name == "my-cert"
    assert cert.domains == ["example.com", "www.example.com"]
    assert cert.tags == {"acme-managed": "true"}


def test_certificate_info_to_dict_roundtrip():
    from cert_manager.models import CertificateInfo

    cert = CertificateInfo(
        name="my-cert",
        vault_url="https://myvault.vault.azure.net",
        domains=["example.com"],
        expires_on=datetime(2026, 3, 1, tzinfo=UTC),
        tags={},
    )
    d = cert.to_dict()
    assert d["name"] == "my-cert"
    assert d["domains"] == ["example.com"]
    assert d["expires_on"] == "2026-03-01T00:00:00+00:00"

    restored = CertificateInfo.from_dict(d)
    assert restored == cert


def test_renewal_request_creation():
    from cert_manager.models import RenewalRequest

    req = RenewalRequest(
        cert_name="my-cert",
        vault_url="https://myvault.vault.azure.net",
        domains=["example.com"],
        dns_provider="azure",
        acme_directory_url="https://acme-v02.api.letsencrypt.org/directory",
        contact_email="admin@example.com",
    )
    assert req.cert_name == "my-cert"
    assert req.dns_provider == "azure"


def test_renewal_request_to_dict_roundtrip():
    from cert_manager.models import RenewalRequest

    req = RenewalRequest(
        cert_name="my-cert",
        vault_url="https://myvault.vault.azure.net",
        domains=["example.com"],
        dns_provider="cloudflare",
        acme_directory_url="https://acme-v02.api.letsencrypt.org/directory",
        contact_email="admin@example.com",
    )
    d = req.to_dict()
    restored = RenewalRequest.from_dict(d)
    assert restored == req


def test_renewal_result_success():
    from cert_manager.models import RenewalResult

    result = RenewalResult(cert_name="my-cert", success=True)
    assert result.success is True
    assert result.error is None


def test_renewal_result_failure():
    from cert_manager.models import RenewalResult

    result = RenewalResult(cert_name="my-cert", success=False, error="ACME order failed")
    assert result.success is False
    assert result.error == "ACME order failed"


def test_renewal_result_to_dict_roundtrip():
    from cert_manager.models import RenewalResult

    result = RenewalResult(cert_name="my-cert", success=True, error=None)
    d = result.to_dict()
    restored = RenewalResult.from_dict(d)
    assert restored == result


# --- DnsChallengeInfo tests ---


def test_dns_challenge_info_round_trip():
    from cert_manager.models import DnsChallengeInfo

    info = DnsChallengeInfo(
        domain="example.com",
        record_name="_acme-challenge.example.com",
        record_value="abc123token",
    )
    restored = DnsChallengeInfo.from_dict(info.to_dict())
    assert restored == info


# --- AcmeOrderContext tests ---


def test_acme_order_context_round_trip():
    from cert_manager.models import AcmeOrderContext, DnsChallengeInfo

    ctx = AcmeOrderContext(
        account_key_json='{"n": "abc", "e": "AQAB", "kty": "RSA"}',
        account_uri="https://acme.example.com/acct/123",
        directory_url="https://acme.example.com/directory",
        order_url="https://acme.example.com/order/456",
        csr_pem="-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----\n",
        private_key_pem="-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----\n",
        challenges=(
            DnsChallengeInfo(
                domain="example.com",
                record_name="_acme-challenge.example.com",
                record_value="token123",
            ),
        ),
    )
    restored = AcmeOrderContext.from_dict(ctx.to_dict())
    assert restored == ctx
    assert restored.challenges == ctx.challenges
