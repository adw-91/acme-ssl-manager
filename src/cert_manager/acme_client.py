"""ACME protocol operations — account registration, order management, certificate download."""

from __future__ import annotations

import json
import logging

import josepy
from acme import messages
from acme.client import ClientNetwork, ClientV2
from cryptography.hazmat.primitives.asymmetric import rsa

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
