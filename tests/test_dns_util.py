"""Tests for DNS utility functions."""

import pytest

from cert_manager.dns.util import split_record_name


class TestSplitRecordName:
    def test_base_domain(self):
        zone, relative = split_record_name("_acme-challenge.example.com", "example.com")
        assert zone == "example.com"
        assert relative == "_acme-challenge"

    def test_wildcard_domain(self):
        zone, relative = split_record_name("_acme-challenge.example.com", "*.example.com")
        assert zone == "example.com"
        assert relative == "_acme-challenge"

    def test_subdomain(self):
        zone, relative = split_record_name("_acme-challenge.sub.example.com", "sub.example.com")
        assert zone == "sub.example.com"
        assert relative == "_acme-challenge"

    def test_deep_subdomain(self):
        zone, relative = split_record_name("_acme-challenge.a.b.example.com", "a.b.example.com")
        assert zone == "a.b.example.com"
        assert relative == "_acme-challenge"

    def test_wildcard_subdomain(self):
        zone, relative = split_record_name("_acme-challenge.sub.example.com", "*.sub.example.com")
        assert zone == "sub.example.com"
        assert relative == "_acme-challenge"

    def test_record_name_not_under_domain_raises(self):
        with pytest.raises(ValueError, match="not under zone"):
            split_record_name("_acme-challenge.other.com", "example.com")
