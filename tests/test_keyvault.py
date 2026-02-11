"""Tests for cert_manager.keyvault."""

import logging
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from cert_manager.config import AppConfig
from cert_manager.models import CertificateInfo


def _make_config(**overrides):
    defaults = {
        "keyvault_url": "https://myvault.vault.azure.net",
        "dns_provider": "azure",
        "contact_email": "admin@example.com",
        "renewal_window_days": 30,
    }
    defaults.update(overrides)
    return AppConfig(**defaults)


def _make_cert_properties(name, tags=None, expires_on=None):
    props = MagicMock()
    props.name = name
    props.tags = tags
    props.expires_on = expires_on or (datetime.now(UTC) + timedelta(days=10))
    props.vault_url = "https://myvault.vault.azure.net"
    return props


def _make_kv_certificate(name, san_dns_names=None, subject=None, tags=None, expires_on=None):
    cert = MagicMock()
    cert.name = name
    cert.policy = MagicMock()
    cert.policy.san_dns_names = san_dns_names
    cert.policy.subject = subject
    cert.properties = _make_cert_properties(name, tags=tags, expires_on=expires_on)
    return cert


# --- scan_certificates tests ---


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_filters_by_acme_managed_tag(mock_cred, mock_client_cls):
    from cert_manager.keyvault import scan_certificates

    config = _make_config()
    soon = datetime.now(UTC) + timedelta(days=5)

    managed = _make_cert_properties("managed-cert", tags={"acme-managed": "true"}, expires_on=soon)
    unmanaged = _make_cert_properties("other-cert", tags={"team": "devops"}, expires_on=soon)
    no_tags = _make_cert_properties("bare-cert", tags=None, expires_on=soon)

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = [managed, unmanaged, no_tags]
    mock_client.get_certificate.return_value = _make_kv_certificate(
        "managed-cert",
        san_dns_names=["example.com"],
        tags={"acme-managed": "true"},
        expires_on=soon,
    )

    results = scan_certificates(config)

    assert len(results) == 1
    assert results[0].name == "managed-cert"
    mock_client.get_certificate.assert_called_once_with("managed-cert")


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_no_managed_certs_returns_empty(mock_cred, mock_client_cls):
    from cert_manager.keyvault import scan_certificates

    config = _make_config()
    soon = datetime.now(UTC) + timedelta(days=5)

    unmanaged = _make_cert_properties("other-cert", tags={"team": "devops"}, expires_on=soon)

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = [unmanaged]

    results = scan_certificates(config)

    assert results == []
    mock_client.get_certificate.assert_not_called()


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_filters_by_renewal_window(mock_cred, mock_client_cls):
    from cert_manager.keyvault import scan_certificates

    config = _make_config(renewal_window_days=30)
    within_window = datetime.now(UTC) + timedelta(days=10)
    outside_window = datetime.now(UTC) + timedelta(days=60)

    expiring_soon = _make_cert_properties("expiring-cert", tags={"acme-managed": "true"}, expires_on=within_window)
    not_yet = _make_cert_properties("healthy-cert", tags={"acme-managed": "true"}, expires_on=outside_window)

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = [expiring_soon, not_yet]
    mock_client.get_certificate.return_value = _make_kv_certificate(
        "expiring-cert",
        san_dns_names=["example.com"],
        tags={"acme-managed": "true"},
        expires_on=within_window,
    )

    results = scan_certificates(config)

    assert len(results) == 1
    assert results[0].name == "expiring-cert"
    mock_client.get_certificate.assert_called_once_with("expiring-cert")


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_extracts_domains_from_sans(mock_cred, mock_client_cls):
    from cert_manager.keyvault import scan_certificates

    config = _make_config(renewal_window_days=30)
    soon = datetime.now(UTC) + timedelta(days=5)

    props = _make_cert_properties("multi-san", tags={"acme-managed": "true"}, expires_on=soon)

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = [props]
    mock_client.get_certificate.return_value = _make_kv_certificate(
        "multi-san",
        san_dns_names=["example.com", "www.example.com", "api.example.com"],
        tags={"acme-managed": "true"},
        expires_on=soon,
    )

    results = scan_certificates(config)

    assert len(results) == 1
    assert results[0].domains == ["example.com", "www.example.com", "api.example.com"]


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_falls_back_to_cn_when_no_sans(mock_cred, mock_client_cls):
    from cert_manager.keyvault import scan_certificates

    config = _make_config(renewal_window_days=30)
    soon = datetime.now(UTC) + timedelta(days=5)

    props = _make_cert_properties("cn-only", tags={"acme-managed": "true"}, expires_on=soon)

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = [props]
    mock_client.get_certificate.return_value = _make_kv_certificate(
        "cn-only",
        san_dns_names=None,
        subject="CN=example.com",
        tags={"acme-managed": "true"},
        expires_on=soon,
    )

    results = scan_certificates(config)

    assert len(results) == 1
    assert results[0].domains == ["example.com"]


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_falls_back_to_cn_when_sans_empty_list(mock_cred, mock_client_cls):
    """Empty list (not None) for san_dns_names should also fall back to CN."""
    from cert_manager.keyvault import scan_certificates

    config = _make_config(renewal_window_days=30)
    soon = datetime.now(UTC) + timedelta(days=5)

    props = _make_cert_properties("empty-sans", tags={"acme-managed": "true"}, expires_on=soon)

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = [props]
    mock_client.get_certificate.return_value = _make_kv_certificate(
        "empty-sans",
        san_dns_names=[],
        subject="CN=example.com",
        tags={"acme-managed": "true"},
        expires_on=soon,
    )

    results = scan_certificates(config)

    assert len(results) == 1
    assert results[0].domains == ["example.com"]


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_includes_cert_with_no_expiry(mock_cred, mock_client_cls, caplog):
    """A managed cert with expires_on=None is abnormal — include it and warn."""
    from cert_manager.keyvault import scan_certificates

    config = _make_config(renewal_window_days=30)

    props = _make_cert_properties("no-expiry", tags={"acme-managed": "true"})
    props.expires_on = None

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = [props]
    mock_client.get_certificate.return_value = _make_kv_certificate(
        "no-expiry",
        san_dns_names=["example.com"],
        tags={"acme-managed": "true"},
    )

    with caplog.at_level(logging.WARNING):
        results = scan_certificates(config)

    assert len(results) == 1
    assert results[0].name == "no-expiry"
    assert results[0].expires_on == datetime.max.replace(tzinfo=UTC)
    assert "no-expiry" in caplog.text
    assert "no expiry" in caplog.text.lower()


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_skips_cert_with_no_extractable_domains(mock_cred, mock_client_cls, caplog):
    """A cert with no SANs and no CN can't be renewed — skip it, log warning."""
    from cert_manager.keyvault import scan_certificates

    config = _make_config(renewal_window_days=30)
    soon = datetime.now(UTC) + timedelta(days=5)

    props = _make_cert_properties("no-domains", tags={"acme-managed": "true"}, expires_on=soon)

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = [props]
    mock_client.get_certificate.return_value = _make_kv_certificate(
        "no-domains",
        san_dns_names=None,
        subject="O=Example Inc",
        tags={"acme-managed": "true"},
        expires_on=soon,
    )

    with caplog.at_level(logging.WARNING):
        results = scan_certificates(config)

    assert results == []
    assert "no-domains" in caplog.text


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_returns_serializable_dicts(mock_cred, mock_client_cls):
    """Verify scan output round-trips through CertificateInfo.from_dict()."""
    from cert_manager.keyvault import scan_certificates

    config = _make_config(renewal_window_days=30)
    soon = datetime.now(UTC) + timedelta(days=5)

    props = _make_cert_properties("roundtrip", tags={"acme-managed": "true"}, expires_on=soon)

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = [props]
    mock_client.get_certificate.return_value = _make_kv_certificate(
        "roundtrip",
        san_dns_names=["example.com"],
        tags={"acme-managed": "true"},
        expires_on=soon,
    )

    results = scan_certificates(config)
    dicts = [c.to_dict() for c in results]

    assert len(dicts) == 1
    restored = CertificateInfo.from_dict(dicts[0])
    assert restored.name == "roundtrip"
    assert restored.domains == ["example.com"]


# --- upload_certificate tests ---


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_upload_certificate_calls_import(mock_cred, mock_client_cls):
    from cert_manager.keyvault import upload_certificate

    config = _make_config()
    pfx_data = b"\x00\x01\x02\x03"

    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    upload_certificate(config, "my-cert", pfx_data)

    mock_client.import_certificate.assert_called_once_with(certificate_name="my-cert", certificate_bytes=pfx_data)


@patch("cert_manager.keyvault.CertificateClient")
@patch("cert_manager.keyvault.DefaultAzureCredential")
def test_scan_and_upload_share_credential_within_module(mock_cred, mock_client_cls):
    """DefaultAzureCredential should be created once per module, not per call."""
    from cert_manager.keyvault import scan_certificates, upload_certificate

    config = _make_config(renewal_window_days=30)
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_properties_of_certificates.return_value = []

    scan_certificates(config)
    upload_certificate(config, "cert", b"\x00")

    # Credential should be instantiated once (module-level), not per function call
    assert mock_cred.call_count == 1


# --- _extract_cn tests ---


def test_extract_cn_returns_cn_value():
    from cert_manager.keyvault import _extract_cn

    assert _extract_cn("CN=example.com") == "example.com"


def test_extract_cn_with_other_attributes():
    from cert_manager.keyvault import _extract_cn

    assert _extract_cn("CN=example.com, O=Example Inc, C=US") == "example.com"


def test_extract_cn_returns_none_for_none():
    from cert_manager.keyvault import _extract_cn

    assert _extract_cn(None) is None


def test_extract_cn_returns_none_for_empty_string():
    from cert_manager.keyvault import _extract_cn

    assert _extract_cn("") is None


def test_extract_cn_returns_none_when_no_cn():
    from cert_manager.keyvault import _extract_cn

    assert _extract_cn("O=Example Inc, C=US") is None


def test_extract_cn_strips_whitespace():
    from cert_manager.keyvault import _extract_cn

    assert _extract_cn("CN= example.com ") == "example.com"
