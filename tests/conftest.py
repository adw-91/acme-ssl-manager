"""Shared test fixtures for azure-acme-cert-manager."""

import cert_manager.auth as _auth


def pytest_runtest_setup(item):
    """Reset module-level caches between tests."""
    _auth._credential = None
