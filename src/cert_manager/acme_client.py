"""ACME protocol operations — account registration, order management, certificate download."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import josepy
from acme import challenges, crypto_util, messages
from acme.client import ClientNetwork, ClientV2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from cert_manager.models import AcmeOrderContext, DnsChallengeInfo

logger = logging.getLogger(__name__)

_USER_AGENT = "azure-acme-cert-manager"


def _generate_account_key() -> josepy.JWKRSA:
    """Generate a new 2048-bit RSA key wrapped as a JWK."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return josepy.JWKRSA(key=private_key)


def _serialize_key(key: josepy.JWKRSA) -> str:
    """Serialize a JWK RSA key to a JSON string."""
    return json.dumps(key.to_json())


def _deserialize_key(key_json: str) -> josepy.JWKRSA:
    """Deserialize a JWK RSA key from a JSON string."""
    return josepy.JWKRSA.from_json(json.loads(key_json))


def _build_client(
    directory_url: str,
    account_key: josepy.JWKRSA,
    account_uri: str | None = None,
) -> ClientV2:
    """Construct a ClientV2 instance, optionally with an existing account."""
    net = ClientNetwork(account_key, user_agent=_USER_AGENT)
    directory = ClientV2.get_directory(directory_url, net)
    client = ClientV2(directory, net=net)

    if account_uri:
        net.account = messages.RegistrationResource(uri=account_uri, body=messages.Registration())

    return client


def _generate_private_key_pem() -> bytes:
    """Generate a 2048-bit RSA private key and return PEM bytes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _extract_dns01_challenges(
    order_resource: messages.OrderResource,
    account_key: josepy.JWKRSA,
) -> list[DnsChallengeInfo]:
    """Extract DNS-01 challenge details from all authorizations in the order."""
    result: list[DnsChallengeInfo] = []
    for authz in order_resource.authorizations:
        domain = authz.body.identifier.value
        # RFC 8555 §7.1.3: wildcard *.example.com → _acme-challenge.example.com
        base_domain = domain.removeprefix("*.")
        for challb in authz.body.challenges:
            if isinstance(challb.chall, challenges.DNS01):
                _response, validation = challb.response_and_validation(account_key)
                result.append(
                    DnsChallengeInfo(
                        domain=domain,
                        record_name=f"_acme-challenge.{base_domain}",
                        record_value=validation,
                    )
                )
                break
        else:
            raise ValueError(f"No DNS-01 challenge found for domain {domain}")
    return result


def create_order(
    directory_url: str,
    contact_email: str,
    domains: list[str],
    account_key_json: str | None = None,
    account_uri: str | None = None,
) -> AcmeOrderContext:
    """Register ACME account (or reuse existing), create order, extract DNS-01 challenges.

    If account_key_json and account_uri are provided, the existing account is
    reused without calling new_account.  Otherwise a new ephemeral account is
    registered.

    Returns an AcmeOrderContext with all state needed to finalize the order
    after DNS records have been provisioned.
    """
    if bool(account_key_json) != bool(account_uri):
        raise ValueError("ACME_ACCOUNT_KEY and ACME_ACCOUNT_URI must both be set or both be unset")

    if account_key_json and account_uri:
        account_key = _deserialize_key(account_key_json)
        client = _build_client(directory_url, account_key, account_uri=account_uri)
        logger.info("Reusing existing ACME account %s", account_uri)
    else:
        account_key = _generate_account_key()
        client = _build_client(directory_url, account_key)
        regr = client.new_account(messages.NewRegistration.from_data(email=contact_email, terms_of_service_agreed=True))
        account_uri = regr.uri
        account_key_json = _serialize_key(account_key)
        logger.info("Registered new ACME account %s", account_uri)

    private_key_pem = _generate_private_key_pem()
    csr_pem = crypto_util.make_csr(private_key_pem, domains)

    order = client.new_order(csr_pem)
    logger.info("Created ACME order %s for %s", order.uri, domains)

    challenge_infos = _extract_dns01_challenges(order, account_key)

    return AcmeOrderContext(
        account_key_json=account_key_json,
        account_uri=account_uri,
        directory_url=directory_url,
        order_url=order.uri,
        csr_pem=csr_pem.decode() if isinstance(csr_pem, bytes) else csr_pem,
        private_key_pem=private_key_pem.decode() if isinstance(private_key_pem, bytes) else private_key_pem,
        challenges=tuple(challenge_infos),
    )


def build_pfx(fullchain_pem: bytes | str, private_key_pem: bytes | str) -> bytes:
    """Assemble a PFX (PKCS#12) archive from fullchain PEM and private key PEM.

    The fullchain PEM should contain the end-entity certificate first,
    followed by any intermediate certificates.
    """
    if isinstance(fullchain_pem, str):
        fullchain_pem = fullchain_pem.encode()
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode()

    certs = x509.load_pem_x509_certificates(fullchain_pem)
    if not certs:
        raise ValueError("No certificates found in fullchain PEM data")
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    end_entity = certs[0]
    intermediates = certs[1:] or None

    return pkcs12.serialize_key_and_certificates(
        name=None,
        key=private_key,
        cert=end_entity,
        cas=intermediates,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _fetch_order(
    client: ClientV2,
    order_url: str,
    csr_pem: bytes,
) -> messages.OrderResource:
    """Reconstruct an OrderResource by fetching the order and its authorizations.

    The ACME server is the source of truth — we refetch the order body
    and each authorization rather than trying to serialize them between activities.

    Uses ``client.net.post`` for POST-as-GET (JWS-signed empty payload per RFC 8555).
    """
    # POST-as-GET to fetch order body
    order_response = client.net.post(order_url, None)
    order_body = messages.Order.from_json(order_response.json())

    # Fetch each authorization
    authzrs = []
    for auth_url in order_body.authorizations:
        auth_response = client.net.post(auth_url, None)
        authz_body = messages.Authorization.from_json(auth_response.json())
        authzrs.append(messages.AuthorizationResource(body=authz_body, uri=auth_url))

    return messages.OrderResource(
        body=order_body,
        uri=order_url,
        authorizations=authzrs,
        csr_pem=csr_pem,
    )


def complete_order(order_context: AcmeOrderContext, deadline_seconds: int = 180) -> bytes:
    """Answer DNS-01 challenges, poll for validation, finalize order, and build PFX.

    Call this after DNS TXT records have been provisioned for all challenges
    returned by create_order.
    """
    account_key = _deserialize_key(order_context.account_key_json)
    client = _build_client(
        order_context.directory_url,
        account_key,
        account_uri=order_context.account_uri,
    )

    csr_pem = order_context.csr_pem.encode() if isinstance(order_context.csr_pem, str) else order_context.csr_pem
    order = _fetch_order(client, order_context.order_url, csr_pem)

    # Calculate deadline before answering challenges so the full window is available for polling
    deadline = datetime.now(UTC) + timedelta(seconds=deadline_seconds)

    # Answer all DNS-01 challenges
    for authz in order.authorizations:
        domain = authz.body.identifier.value
        for challb in authz.body.challenges:
            if isinstance(challb.chall, challenges.DNS01):
                response, _validation = challb.response_and_validation(account_key)
                client.answer_challenge(challb, response)
                logger.info("Answered DNS-01 challenge for %s", domain)
                break
        else:
            raise ValueError(f"No DNS-01 challenge found for domain {domain}")

    # Poll for authorization + finalize
    logger.info("Polling for %d authorization(s) — deadline in %d seconds", len(order.authorizations), deadline_seconds)
    finalized = client.poll_and_finalize(order, deadline)
    logger.info("Order finalized: %s", order.uri)

    return build_pfx(finalized.fullchain_pem, order_context.private_key_pem)
