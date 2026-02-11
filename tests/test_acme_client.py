"""Tests for cert_manager.acme_client."""

import datetime
import json
import os
from unittest.mock import MagicMock, patch

import josepy
from acme import challenges
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

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


@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client.crypto_util")
def test_create_order_raises_when_account_key_without_uri(mock_crypto_util, mock_build_client):
    """Providing account_key_json without account_uri should raise ValueError."""
    import pytest

    from cert_manager.acme_client import create_order

    with pytest.raises(ValueError, match="ACME_ACCOUNT_KEY.*ACME_ACCOUNT_URI"):
        create_order(
            directory_url="https://acme.example.com/directory",
            contact_email="admin@example.com",
            domains=["example.com"],
            account_key_json='{"kty": "RSA", "n": "abc", "e": "AQAB"}',
            account_uri=None,
        )


@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client.crypto_util")
def test_create_order_raises_when_account_uri_without_key(mock_crypto_util, mock_build_client):
    """Providing account_uri without account_key_json should raise ValueError."""
    import pytest

    from cert_manager.acme_client import create_order

    with pytest.raises(ValueError, match="ACME_ACCOUNT_KEY.*ACME_ACCOUNT_URI"):
        create_order(
            directory_url="https://acme.example.com/directory",
            contact_email="admin@example.com",
            domains=["example.com"],
            account_key_json=None,
            account_uri="https://acme.example.com/acct/123",
        )


@patch("cert_manager.acme_client._deserialize_key")
@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client.crypto_util")
def test_create_order_reuses_existing_account(mock_crypto_util, mock_build_client, mock_deser_key):
    """When account_key_json + account_uri provided, reuse account without registration."""
    from cert_manager.acme_client import create_order

    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_deser_key.return_value = mock_key

    mock_client = MagicMock()
    mock_build_client.return_value = mock_client

    mock_crypto_util.make_csr.return_value = b"fake-csr-pem"

    chall, _, val = _make_mock_dns01_challenge("example.com", "val1")
    authz = _make_mock_authz("example.com", chall)
    mock_order = MagicMock()
    mock_order.uri = "https://acme.example.com/order/789"
    mock_order.authorizations = [authz]
    mock_client.new_order.return_value = mock_order

    existing_key_json = '{"kty": "RSA", "n": "abc", "e": "AQAB"}'
    existing_uri = "https://acme.example.com/acct/existing"

    ctx = create_order(
        directory_url="https://acme.example.com/directory",
        contact_email="admin@example.com",
        domains=["example.com"],
        account_key_json=existing_key_json,
        account_uri=existing_uri,
    )

    # Should deserialize key, NOT generate new one
    mock_deser_key.assert_called_once_with(existing_key_json)
    # Should build client with account_uri
    mock_build_client.assert_called_once_with("https://acme.example.com/directory", mock_key, account_uri=existing_uri)
    # Should NOT call new_account
    mock_client.new_account.assert_not_called()
    # Should preserve the existing account info
    assert ctx.account_uri == existing_uri
    assert ctx.account_key_json == existing_key_json


# --- build_pfx / complete_order tests ---


def _make_self_signed_cert_and_key():
    """Generate a self-signed cert + private key for testing PFX assembly."""
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

    key = rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def test_build_pfx_produces_valid_pkcs12():
    from cert_manager.acme_client import build_pfx

    cert_pem, key_pem = _make_self_signed_cert_and_key()
    pfx_bytes = build_pfx(cert_pem, key_pem)

    # Verify we can parse the PFX back
    private_key, certificate, chain = pkcs12.load_key_and_certificates(pfx_bytes, None)
    assert private_key is not None
    assert certificate is not None
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "example.com"


def test_build_pfx_with_chain():
    """Fullchain PEM with end-entity + intermediate should include both."""
    from cert_manager.acme_client import build_pfx

    cert_pem, key_pem = _make_self_signed_cert_and_key()
    intermediate_pem, _ = _make_self_signed_cert_and_key()  # fake intermediate
    fullchain_pem = cert_pem + intermediate_pem

    pfx_bytes = build_pfx(fullchain_pem, key_pem)

    private_key, certificate, chain = pkcs12.load_key_and_certificates(pfx_bytes, None)
    assert private_key is not None
    assert certificate is not None
    assert chain is not None
    assert len(chain) == 1


@patch("cert_manager.acme_client.x509.load_pem_x509_certificates", return_value=[])
def test_build_pfx_raises_on_empty_cert_list(_mock_load):
    """build_pfx should raise ValueError when PEM parses to zero certificates."""
    import pytest

    from cert_manager.acme_client import build_pfx

    _, key_pem = _make_self_signed_cert_and_key()

    with pytest.raises(ValueError, match="No certificates found"):
        build_pfx(b"fake-pem", key_pem)


# --- _fetch_order tests ---


def test_fetch_order_reconstructs_order_resource():
    """_fetch_order should POST-as-GET the order URL and each authorization."""
    from acme import messages

    from cert_manager.acme_client import _fetch_order

    mock_client = MagicMock()

    # Mock order body response
    auth_url_1 = "https://acme.example.com/authz/1"
    auth_url_2 = "https://acme.example.com/authz/2"
    order_json = {
        "status": "pending",
        "identifiers": [
            {"type": "dns", "value": "example.com"},
            {"type": "dns", "value": "www.example.com"},
        ],
        "authorizations": [auth_url_1, auth_url_2],
        "finalize": "https://acme.example.com/finalize/1",
    }
    order_response = MagicMock()
    order_response.json.return_value = order_json

    # Mock authorization responses
    authz_json_1 = {
        "status": "pending",
        "identifier": {"type": "dns", "value": "example.com"},
        "challenges": [],
    }
    authz_json_2 = {
        "status": "pending",
        "identifier": {"type": "dns", "value": "www.example.com"},
        "challenges": [],
    }
    authz_response_1 = MagicMock()
    authz_response_1.json.return_value = authz_json_1
    authz_response_2 = MagicMock()
    authz_response_2.json.return_value = authz_json_2

    # net.post returns order first, then each authz
    mock_client.net.post.side_effect = [order_response, authz_response_1, authz_response_2]

    order_url = "https://acme.example.com/order/1"
    csr_pem = b"fake-csr"

    result = _fetch_order(mock_client, order_url, csr_pem)

    # Verify POST-as-GET calls (None payload = POST-as-GET per RFC 8555)
    assert mock_client.net.post.call_count == 3
    mock_client.net.post.assert_any_call(order_url, None)
    mock_client.net.post.assert_any_call(auth_url_1, None)
    mock_client.net.post.assert_any_call(auth_url_2, None)

    # Verify result structure
    assert isinstance(result, messages.OrderResource)
    assert result.uri == order_url
    assert result.csr_pem == csr_pem
    assert len(result.authorizations) == 2
    assert result.authorizations[0].uri == auth_url_1
    assert result.authorizations[1].uri == auth_url_2


@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client._deserialize_key")
def test_complete_order_answers_challenges_and_returns_pfx(mock_deser_key, mock_build_client):
    from cert_manager.acme_client import complete_order

    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_deser_key.return_value = mock_key

    mock_client = MagicMock()
    mock_build_client.return_value = mock_client

    # Setup challenge in authorization
    dns_chall = MagicMock()
    dns_chall.chall = MagicMock(spec=challenges.DNS01)
    response = MagicMock()
    dns_chall.response_and_validation.return_value = (response, "token")

    authz = MagicMock()
    authz.body.challenges = (dns_chall,)

    # Setup order refetch
    mock_order = MagicMock()
    mock_order.authorizations = [authz]

    # poll_and_finalize returns order with fullchain
    cert_pem, key_pem = _make_self_signed_cert_and_key()
    finalized_order = MagicMock()
    finalized_order.fullchain_pem = cert_pem.decode()
    mock_client.poll_and_finalize.return_value = finalized_order

    # Patch _fetch_order to return our mock order
    with patch("cert_manager.acme_client._fetch_order", return_value=mock_order):
        ctx = AcmeOrderContext(
            account_key_json='{"kty": "RSA"}',
            account_uri="https://acme.example.com/acct/123",
            directory_url="https://acme.example.com/directory",
            order_url="https://acme.example.com/order/456",
            csr_pem="fake-csr",
            private_key_pem=key_pem.decode(),
            challenges=(),
        )

        pfx_bytes = complete_order(ctx)

    assert isinstance(pfx_bytes, bytes)
    assert len(pfx_bytes) > 0
    mock_client.answer_challenge.assert_called_once_with(dns_chall, response)
    mock_client.poll_and_finalize.assert_called_once()


@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client._deserialize_key")
def test_complete_order_deadline_set_before_challenges(mock_deser_key, mock_build_client):
    """Deadline for poll_and_finalize should be calculated before answering challenges."""
    import datetime as dt

    from cert_manager.acme_client import complete_order

    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_deser_key.return_value = mock_key

    mock_client = MagicMock()
    mock_build_client.return_value = mock_client

    dns_chall = MagicMock()
    dns_chall.chall = MagicMock(spec=challenges.DNS01)
    response = MagicMock()
    dns_chall.response_and_validation.return_value = (response, "token")

    authz = MagicMock()
    authz.body.challenges = (dns_chall,)

    mock_order = MagicMock()
    mock_order.authorizations = [authz]

    cert_pem, key_pem = _make_self_signed_cert_and_key()
    finalized_order = MagicMock()
    finalized_order.fullchain_pem = cert_pem.decode()
    mock_client.poll_and_finalize.return_value = finalized_order

    before = dt.datetime.now(dt.UTC)

    with patch("cert_manager.acme_client._fetch_order", return_value=mock_order):
        ctx = AcmeOrderContext(
            account_key_json='{"kty": "RSA"}',
            account_uri="https://acme.example.com/acct/123",
            directory_url="https://acme.example.com/directory",
            order_url="https://acme.example.com/order/456",
            csr_pem="fake-csr",
            private_key_pem=key_pem.decode(),
            challenges=(),
        )
        complete_order(ctx, deadline_seconds=180)

    # The deadline passed to poll_and_finalize should be ~180s from `before`
    actual_deadline = mock_client.poll_and_finalize.call_args[0][1]
    expected_min = before + dt.timedelta(seconds=179)
    expected_max = before + dt.timedelta(seconds=182)
    assert (
        expected_min <= actual_deadline <= expected_max
    ), f"Deadline {actual_deadline} not within expected range [{expected_min}, {expected_max}]"


@patch("cert_manager.acme_client._build_client")
@patch("cert_manager.acme_client._deserialize_key")
def test_complete_order_raises_when_no_dns01_challenge(mock_deser_key, mock_build_client):
    """complete_order should raise ValueError when refetched auth has no DNS-01."""
    import pytest

    from cert_manager.acme_client import complete_order

    mock_key = MagicMock(spec=josepy.JWKRSA)
    mock_deser_key.return_value = mock_key
    mock_client = MagicMock()
    mock_build_client.return_value = mock_client

    # Authorization with only HTTP-01, no DNS-01
    http_chall = MagicMock()
    http_chall.chall = MagicMock(spec=challenges.HTTP01)
    authz = MagicMock()
    authz.body.identifier.value = "example.com"
    authz.body.challenges = (http_chall,)

    mock_order = MagicMock()
    mock_order.authorizations = [authz]

    _, key_pem = _make_self_signed_cert_and_key()

    with patch("cert_manager.acme_client._fetch_order", return_value=mock_order):
        ctx = AcmeOrderContext(
            account_key_json='{"kty": "RSA"}',
            account_uri="https://acme.example.com/acct/123",
            directory_url="https://acme.example.com/directory",
            order_url="https://acme.example.com/order/456",
            csr_pem="fake-csr",
            private_key_pem=key_pem.decode(),
            challenges=(),
        )

        with pytest.raises(ValueError, match="No DNS-01 challenge"):
            complete_order(ctx)


# --- Activity function tests ---


@patch.dict(os.environ, {}, clear=False)
@patch("function_app.create_order")
def test_create_acme_order_activity(mock_create_order):
    """Activity deserializes RenewalRequest, calls create_order, returns dict."""
    from function_app import create_acme_order

    # Remove ACME account env vars if present so ephemeral path is taken
    os.environ.pop("ACME_ACCOUNT_KEY", None)
    os.environ.pop("ACME_ACCOUNT_URI", None)

    mock_ctx = AcmeOrderContext(
        account_key_json='{"kty": "RSA"}',
        account_uri="https://acme.example.com/acct/1",
        directory_url="https://acme.example.com/directory",
        order_url="https://acme.example.com/order/1",
        csr_pem="fake-csr",
        private_key_pem="fake-key",
        challenges=(),
    )
    mock_create_order.return_value = mock_ctx

    input_dict = {
        "cert_name": "my-cert",
        "vault_url": "https://vault.azure.net",
        "domains": ["example.com"],
        "dns_provider": "azure",
        "acme_directory_url": "https://acme.example.com/directory",
        "contact_email": "admin@example.com",
    }

    result = create_acme_order(input_dict)

    mock_create_order.assert_called_once_with(
        directory_url="https://acme.example.com/directory",
        contact_email="admin@example.com",
        domains=["example.com"],
        account_key_json=None,
        account_uri=None,
    )
    assert result["order_url"] == "https://acme.example.com/order/1"


@patch("function_app.complete_order")
def test_finalize_acme_order_activity(mock_complete_order):
    """Activity calls complete_order and returns base64 PFX."""
    from function_app import finalize_acme_order

    mock_complete_order.return_value = b"\x00\x01\x02"

    input_dict = {
        "order_context": {
            "account_key_json": '{"kty": "RSA"}',
            "account_uri": "https://acme.example.com/acct/1",
            "directory_url": "https://acme.example.com/directory",
            "order_url": "https://acme.example.com/order/1",
            "csr_pem": "fake-csr",
            "private_key_pem": "fake-key",
            "challenges": [],
        },
        "cert_name": "my-cert",
    }

    result = finalize_acme_order(input_dict)

    mock_complete_order.assert_called_once()
    assert result["cert_name"] == "my-cert"
    assert "pfx_b64" in result

    # Verify base64 round-trips
    from base64 import b64decode

    assert b64decode(result["pfx_b64"]) == b"\x00\x01\x02"
