"""Tests for function_app activity functions."""

from base64 import b64encode
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from cert_manager.models import CertificateInfo

# --- scan_keyvault_certificates ---


@patch("function_app.scan_certificates")
@patch("function_app.load_config")
def test_scan_keyvault_certificates_returns_dicts(mock_load_config, mock_scan):
    from function_app import scan_keyvault_certificates

    mock_config = MagicMock()
    mock_load_config.return_value = mock_config

    cert = CertificateInfo(
        name="my-cert",
        vault_url="https://vault.azure.net",
        domains=["example.com"],
        expires_on=datetime(2026, 3, 1, tzinfo=UTC),
        tags={"acme-managed": "true"},
    )
    mock_scan.return_value = [cert]

    result = scan_keyvault_certificates(None)

    mock_load_config.assert_called_once()
    mock_scan.assert_called_once_with(mock_config)
    assert len(result) == 1
    assert result[0]["name"] == "my-cert"
    assert result[0]["domains"] == ["example.com"]


# --- upload_certificate_to_keyvault ---


@patch("function_app.upload_certificate")
@patch("function_app.load_config")
def test_upload_certificate_to_keyvault_decodes_b64(mock_load_config, mock_upload):
    from function_app import upload_certificate_to_keyvault

    mock_config = MagicMock()
    mock_load_config.return_value = mock_config

    pfx_data = b"\x00\x01\x02\x03"
    input_dict = {
        "cert_name": "my-cert",
        "pfx_b64": b64encode(pfx_data).decode(),
    }

    upload_certificate_to_keyvault(input_dict)

    mock_upload.assert_called_once_with(mock_config, "my-cert", pfx_data)
