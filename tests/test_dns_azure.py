"""Tests for Azure DNS provider."""

from unittest.mock import MagicMock, patch

from cert_manager.dns.azure_dns import AzureDnsProvider


class TestAzureDnsProviderCreateTxtRecord:
    def test_creates_record_set_with_correct_params(self):
        mock_client = MagicMock()
        provider = AzureDnsProvider(
            credential=MagicMock(),
            subscription_id="sub-123",
            resource_group="rg-dns",
            _dns_client=mock_client,
        )

        provider.create_txt_record("example.com", "_acme-challenge", "token123")

        mock_client.record_sets.create_or_update.assert_called_once()
        call_kwargs = mock_client.record_sets.create_or_update.call_args
        assert call_kwargs.kwargs["resource_group_name"] == "rg-dns"
        assert call_kwargs.kwargs["zone_name"] == "example.com"
        assert call_kwargs.kwargs["relative_record_set_name"] == "_acme-challenge"
        assert call_kwargs.kwargs["record_type"] == "TXT"
        record_set = call_kwargs.kwargs["parameters"]
        assert record_set.ttl == 60
        assert record_set.txt_records[0].value == ["token123"]

    def test_uses_short_ttl(self):
        mock_client = MagicMock()
        provider = AzureDnsProvider(
            credential=MagicMock(),
            subscription_id="sub-123",
            resource_group="rg-dns",
            _dns_client=mock_client,
        )

        provider.create_txt_record("example.com", "_acme-challenge", "val")

        record_set = mock_client.record_sets.create_or_update.call_args.kwargs["parameters"]
        assert record_set.ttl == 60


class TestAzureDnsProviderDeleteTxtRecord:
    def test_deletes_record_set(self):
        mock_client = MagicMock()
        provider = AzureDnsProvider(
            credential=MagicMock(),
            subscription_id="sub-123",
            resource_group="rg-dns",
            _dns_client=mock_client,
        )

        provider.delete_txt_record("example.com", "_acme-challenge")

        mock_client.record_sets.delete.assert_called_once_with(
            resource_group_name="rg-dns",
            zone_name="example.com",
            relative_record_set_name="_acme-challenge",
            record_type="TXT",
        )


class TestAzureDnsProviderDefaultClient:
    @patch("cert_manager.dns.azure_dns.DnsManagementClient")
    def test_creates_dns_client_from_credential(self, mock_dns_cls):
        cred = MagicMock()
        provider = AzureDnsProvider(
            credential=cred,
            subscription_id="sub-123",
            resource_group="rg-dns",
        )

        mock_dns_cls.assert_called_once_with(cred, "sub-123")
        assert provider._dns_client is mock_dns_cls.return_value
