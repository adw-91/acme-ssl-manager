"""Shared test fixtures for azure-acme-cert-manager."""

import cert_manager.keyvault as _kv


def pytest_runtest_setup(item):
    """Reset module-level caches between tests."""
    _kv._credential = None
