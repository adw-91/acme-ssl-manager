"""Tests for DnsProvider ABC."""

import pytest

from cert_manager.dns.base import DnsProvider


def test_cannot_instantiate_abc():
    with pytest.raises(TypeError, match="abstract"):
        DnsProvider()


def test_concrete_subclass_works():
    class FakeProvider(DnsProvider):
        def create_txt_record(self, zone, record_name, value):
            pass

        def delete_txt_record(self, zone, record_name):
            pass

    provider = FakeProvider()
    assert isinstance(provider, DnsProvider)
