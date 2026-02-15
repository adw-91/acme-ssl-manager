"""Shared Azure credential management."""

from __future__ import annotations

from azure.identity import DefaultAzureCredential

_credential: DefaultAzureCredential | None = None


def get_credential() -> DefaultAzureCredential:
    """Return a cached DefaultAzureCredential instance."""
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential
