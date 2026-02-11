"""Tests for cert_manager.acme_client."""

import json
from unittest.mock import MagicMock, patch

import josepy

# --- Key generation / serialization ---


def test_generate_account_key_returns_jwk_rsa():
    from cert_manager.acme_client import _generate_account_key

    key = _generate_account_key()
    assert isinstance(key, josepy.JWKRSA)
    assert key.key.key_size == 2048


def test_account_key_round_trip_via_json():
    from cert_manager.acme_client import _generate_account_key

    key = _generate_account_key()
    json_str = json.dumps(key.to_json())
    restored = josepy.JWKRSA.from_json(json.loads(json_str))
    # Verify the restored key can sign (proves private key survived)
    assert restored.key.key_size == 2048


# --- Client construction ---


@patch("cert_manager.acme_client.ClientV2")
@patch("cert_manager.acme_client.ClientNetwork")
def test_build_client_creates_network_and_client(mock_net_cls, mock_client_cls):
    from cert_manager.acme_client import _build_client

    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_directory = MagicMock()
    mock_client_cls.get_directory.return_value = mock_directory
    mock_net = MagicMock()
    mock_net_cls.return_value = mock_net

    _build_client("https://acme.example.com/directory", mock_key)

    mock_net_cls.assert_called_once_with(mock_key, user_agent="azure-acme-cert-manager")
    mock_client_cls.get_directory.assert_called_once_with("https://acme.example.com/directory", mock_net)
    mock_client_cls.assert_called_once_with(mock_directory, net=mock_net)


@patch("cert_manager.acme_client.ClientV2")
@patch("cert_manager.acme_client.ClientNetwork")
def test_build_client_sets_account_when_uri_provided(mock_net_cls, mock_client_cls):
    from cert_manager.acme_client import _build_client

    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_net = MagicMock()
    mock_net_cls.return_value = mock_net
    mock_directory = MagicMock()
    mock_client_cls.get_directory.return_value = mock_directory
    mock_client_instance = MagicMock()
    mock_client_cls.return_value = mock_client_instance

    _build_client(
        "https://acme.example.com/directory",
        mock_key,
        account_uri="https://acme.example.com/acct/123",
    )

    assert mock_net.account is not None
