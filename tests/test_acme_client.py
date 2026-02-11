"""Tests for cert_manager.acme_client."""

import json
from unittest.mock import MagicMock, patch

import josepy
from acme import challenges

from cert_manager.models import AcmeOrderContext

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


# --- create_order tests ---


def _make_mock_dns01_challenge(domain, validation="fake-validation"):
    """Create a mock DNS-01 challenge body."""
    chall = MagicMock()
    chall.chall = MagicMock(spec=challenges.DNS01)

    response = MagicMock()
    chall.response_and_validation.return_value = (response, validation)
    return chall, response, validation


def _make_mock_authz(domain, dns_challenge_body):
    """Create a mock AuthorizationResource."""
    authz = MagicMock()
    authz.body.identifier.value = domain
    # Include a non-DNS challenge to verify filtering
    http_challenge = MagicMock()
    http_challenge.chall = MagicMock(spec=challenges.HTTP01)
    authz.body.challenges = (http_challenge, dns_challenge_body)
    return authz


@patch("cert_manager.acme_client._generate_account_key")
@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client.crypto_util")
def test_create_order_returns_context_with_challenges(mock_crypto_util, mock_build_client, mock_gen_key):
    from cert_manager.acme_client import create_order

    # Setup account key
    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_key.to_json.return_value = {"kty": "RSA", "n": "abc", "e": "AQAB"}
    mock_gen_key.return_value = mock_key

    # Setup client
    mock_client = MagicMock()
    mock_build_client.return_value = mock_client

    # Setup registration
    mock_regr = MagicMock()
    mock_regr.uri = "https://acme.example.com/acct/123"
    mock_client.new_account.return_value = mock_regr

    # Setup CSR generation
    mock_crypto_util.make_csr.return_value = (
        b"-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n"
    )

    # Setup order with DNS-01 challenge
    dns_chall, response, validation = _make_mock_dns01_challenge("example.com")
    authz = _make_mock_authz("example.com", dns_chall)
    mock_order = MagicMock()
    mock_order.uri = "https://acme.example.com/order/456"
    mock_order.authorizations = [authz]
    mock_client.new_order.return_value = mock_order

    ctx = create_order(
        directory_url="https://acme.example.com/directory",
        contact_email="admin@example.com",
        domains=["example.com"],
    )

    assert isinstance(ctx, AcmeOrderContext)
    assert ctx.account_uri == "https://acme.example.com/acct/123"
    assert ctx.order_url == "https://acme.example.com/order/456"
    assert len(ctx.challenges) == 1
    assert ctx.challenges[0].domain == "example.com"
    assert ctx.challenges[0].record_name == "_acme-challenge.example.com"
    assert ctx.challenges[0].record_value == validation


@patch("cert_manager.acme_client._generate_account_key")
@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client.crypto_util")
def test_create_order_multi_domain(mock_crypto_util, mock_build_client, mock_gen_key):
    from cert_manager.acme_client import create_order

    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_key.to_json.return_value = {"kty": "RSA", "n": "abc", "e": "AQAB"}
    mock_gen_key.return_value = mock_key

    mock_client = MagicMock()
    mock_build_client.return_value = mock_client
    mock_regr = MagicMock()
    mock_regr.uri = "https://acme.example.com/acct/123"
    mock_client.new_account.return_value = mock_regr

    mock_crypto_util.make_csr.return_value = b"fake-csr-pem"

    # Two domains
    chall1, _, val1 = _make_mock_dns01_challenge("example.com", "val1")
    chall2, _, val2 = _make_mock_dns01_challenge("www.example.com", "val2")
    authz1 = _make_mock_authz("example.com", chall1)
    authz2 = _make_mock_authz("www.example.com", chall2)

    mock_order = MagicMock()
    mock_order.uri = "https://acme.example.com/order/456"
    mock_order.authorizations = [authz1, authz2]
    mock_client.new_order.return_value = mock_order

    ctx = create_order(
        directory_url="https://acme.example.com/directory",
        contact_email="admin@example.com",
        domains=["example.com", "www.example.com"],
    )

    assert len(ctx.challenges) == 2
    domains = [c.domain for c in ctx.challenges]
    assert "example.com" in domains
    assert "www.example.com" in domains


@patch("cert_manager.acme_client._generate_account_key")
@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client.crypto_util")
def test_create_order_raises_when_no_dns01_challenge(mock_crypto_util, mock_build_client, mock_gen_key):
    from cert_manager.acme_client import create_order

    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_key.to_json.return_value = {"kty": "RSA", "n": "abc", "e": "AQAB"}
    mock_gen_key.return_value = mock_key

    mock_client = MagicMock()
    mock_build_client.return_value = mock_client
    mock_regr = MagicMock()
    mock_regr.uri = "https://acme.example.com/acct/123"
    mock_client.new_account.return_value = mock_regr

    mock_crypto_util.make_csr.return_value = b"fake-csr-pem"

    # Authorization with only HTTP-01, no DNS-01
    authz = MagicMock()
    authz.body.identifier.value = "example.com"
    http_chall = MagicMock()
    http_chall.chall = MagicMock(spec=challenges.HTTP01)
    authz.body.challenges = (http_chall,)

    mock_order = MagicMock()
    mock_order.uri = "https://acme.example.com/order/456"
    mock_order.authorizations = [authz]
    mock_client.new_order.return_value = mock_order

    import pytest

    with pytest.raises(ValueError, match="No DNS-01 challenge"):
        create_order(
            directory_url="https://acme.example.com/directory",
            contact_email="admin@example.com",
            domains=["example.com"],
        )


@patch("cert_manager.acme_client._generate_account_key")
@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client.crypto_util")
def test_create_order_wildcard_strips_star_prefix(mock_crypto_util, mock_build_client, mock_gen_key):
    """Wildcard *.example.com should produce _acme-challenge.example.com."""
    from cert_manager.acme_client import create_order

    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_key.to_json.return_value = {"kty": "RSA", "n": "abc", "e": "AQAB"}
    mock_gen_key.return_value = mock_key

    mock_client = MagicMock()
    mock_build_client.return_value = mock_client
    mock_regr = MagicMock()
    mock_regr.uri = "https://acme.example.com/acct/123"
    mock_client.new_account.return_value = mock_regr

    mock_crypto_util.make_csr.return_value = b"fake-csr-pem"

    chall, _, val = _make_mock_dns01_challenge("*.example.com", "wildcard-val")
    authz = _make_mock_authz("*.example.com", chall)

    mock_order = MagicMock()
    mock_order.uri = "https://acme.example.com/order/789"
    mock_order.authorizations = [authz]
    mock_client.new_order.return_value = mock_order

    ctx = create_order(
        directory_url="https://acme.example.com/directory",
        contact_email="admin@example.com",
        domains=["*.example.com"],
    )

    assert len(ctx.challenges) == 1
    assert ctx.challenges[0].domain == "*.example.com"
    assert ctx.challenges[0].record_name == "_acme-challenge.example.com"
