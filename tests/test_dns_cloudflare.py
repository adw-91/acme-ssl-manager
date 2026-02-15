"""Tests for Cloudflare DNS provider."""

from unittest.mock import MagicMock, patch

import pytest

from cert_manager.dns.cloudflare import CloudflareDnsProvider

_BASE = "https://api.cloudflare.com/client/v4"


class TestCloudflareGetZoneId:
    def test_returns_zone_id_from_api(self):
        mock_client = MagicMock()
        mock_client.get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "success": True,
                    "result": [{"id": "zone-abc-123"}],
                }
            ),
            raise_for_status=MagicMock(),
        )
        provider = CloudflareDnsProvider(api_token="tok", _http_client=mock_client)

        zone_id = provider._get_zone_id("example.com")

        assert zone_id == "zone-abc-123"
        mock_client.get.assert_called_once_with(
            f"{_BASE}/zones",
            params={"name": "example.com"},
        )

    def test_raises_on_no_matching_zone(self):
        mock_client = MagicMock()
        mock_client.get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"success": True, "result": []}),
            raise_for_status=MagicMock(),
        )
        provider = CloudflareDnsProvider(api_token="tok", _http_client=mock_client)

        with pytest.raises(ValueError, match="No Cloudflare zone found for 'missing.com'"):
            provider._get_zone_id("missing.com")


class TestCloudflareCreateTxtRecord:
    def test_creates_record_via_api(self):
        mock_client = MagicMock()
        # First GET: _get_zone_id; second GET: list existing records (none found)
        mock_client.get.side_effect = [
            MagicMock(
                status_code=200,
                json=MagicMock(
                    return_value={
                        "success": True,
                        "result": [{"id": "zone-123"}],
                    }
                ),
                raise_for_status=MagicMock(),
            ),
            MagicMock(
                status_code=200,
                json=MagicMock(return_value={"success": True, "result": []}),
                raise_for_status=MagicMock(),
            ),
        ]
        mock_client.post.return_value = MagicMock(
            status_code=200,
            raise_for_status=MagicMock(),
        )
        provider = CloudflareDnsProvider(api_token="tok", _http_client=mock_client)

        provider.create_txt_record("example.com", "_acme-challenge", "token-val")

        mock_client.post.assert_called_once_with(
            f"{_BASE}/zones/zone-123/dns_records",
            json={
                "type": "TXT",
                "name": "_acme-challenge.example.com",
                "content": "token-val",
                "ttl": 60,
            },
        )

    def test_deletes_existing_record_before_creating(self):
        """Idempotency: if a TXT record already exists, delete it before creating."""
        mock_client = MagicMock()
        mock_client.get.side_effect = [
            MagicMock(
                status_code=200,
                json=MagicMock(
                    return_value={
                        "success": True,
                        "result": [{"id": "zone-123"}],
                    }
                ),
                raise_for_status=MagicMock(),
            ),
            MagicMock(
                status_code=200,
                json=MagicMock(
                    return_value={
                        "success": True,
                        "result": [{"id": "old-rec-789"}],
                    }
                ),
                raise_for_status=MagicMock(),
            ),
        ]
        mock_client.delete.return_value = MagicMock(
            status_code=200,
            raise_for_status=MagicMock(),
        )
        mock_client.post.return_value = MagicMock(
            status_code=200,
            raise_for_status=MagicMock(),
        )
        provider = CloudflareDnsProvider(api_token="tok", _http_client=mock_client)

        provider.create_txt_record("example.com", "_acme-challenge", "new-token")

        # Old record deleted first
        mock_client.delete.assert_called_once_with(
            f"{_BASE}/zones/zone-123/dns_records/old-rec-789",
        )
        # Then new record created
        mock_client.post.assert_called_once()


class TestCloudflareDeleteTxtRecord:
    def test_finds_and_deletes_record(self):
        mock_client = MagicMock()
        # First call: _get_zone_id; second call: list records
        mock_client.get.side_effect = [
            MagicMock(
                status_code=200,
                json=MagicMock(
                    return_value={
                        "success": True,
                        "result": [{"id": "zone-123"}],
                    }
                ),
                raise_for_status=MagicMock(),
            ),
            MagicMock(
                status_code=200,
                json=MagicMock(
                    return_value={
                        "success": True,
                        "result": [{"id": "rec-456"}],
                    }
                ),
                raise_for_status=MagicMock(),
            ),
        ]
        mock_client.delete.return_value = MagicMock(
            status_code=200,
            raise_for_status=MagicMock(),
        )
        provider = CloudflareDnsProvider(api_token="tok", _http_client=mock_client)

        provider.delete_txt_record("example.com", "_acme-challenge")

        # Verify list call to find the record
        list_call = mock_client.get.call_args_list[1]
        assert list_call.args[0] == f"{_BASE}/zones/zone-123/dns_records"
        assert list_call.kwargs["params"] == {
            "type": "TXT",
            "name": "_acme-challenge.example.com",
        }

        mock_client.delete.assert_called_once_with(
            f"{_BASE}/zones/zone-123/dns_records/rec-456",
        )

    def test_skips_delete_when_record_not_found(self):
        mock_client = MagicMock()
        mock_client.get.side_effect = [
            MagicMock(
                status_code=200,
                json=MagicMock(
                    return_value={
                        "success": True,
                        "result": [{"id": "zone-123"}],
                    }
                ),
                raise_for_status=MagicMock(),
            ),
            MagicMock(
                status_code=200,
                json=MagicMock(return_value={"success": True, "result": []}),
                raise_for_status=MagicMock(),
            ),
        ]
        provider = CloudflareDnsProvider(api_token="tok", _http_client=mock_client)

        provider.delete_txt_record("example.com", "_acme-challenge")

        mock_client.delete.assert_not_called()


class TestCloudflareAuthHeader:
    def test_client_uses_bearer_token(self):
        with patch("cert_manager.dns.cloudflare.httpx.Client") as mock_cls:
            CloudflareDnsProvider(api_token="my-secret-token")
            mock_cls.assert_called_once()
            headers = mock_cls.call_args.kwargs["headers"]
            assert headers["Authorization"] == "Bearer my-secret-token"


class TestCloudflareClose:
    def test_close_closes_http_client(self):
        mock_client = MagicMock()
        provider = CloudflareDnsProvider(api_token="tok", _http_client=mock_client)

        provider.close()

        mock_client.close.assert_called_once()
