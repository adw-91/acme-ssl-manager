"""Tests for DNS activity functions in function_app.py."""

from unittest.mock import MagicMock, patch


class TestCreateDnsTxtRecordActivity:
    @patch("function_app.get_dns_provider")
    @patch("function_app.load_config")
    def test_creates_record_via_provider(self, mock_config, mock_get_provider):
        from function_app import create_dns_txt_record

        mock_provider = MagicMock()
        mock_get_provider.return_value = mock_provider

        input_data = {
            "dns_provider": "azure",
            "domain": "example.com",
            "record_name": "_acme-challenge.example.com",
            "record_value": "token123",
        }

        create_dns_txt_record(input_data)

        mock_get_provider.assert_called_once_with(mock_config.return_value, provider_name="azure")
        mock_provider.create_txt_record.assert_called_once_with("example.com", "_acme-challenge", "token123")

    @patch("function_app.get_dns_provider")
    @patch("function_app.load_config")
    def test_handles_wildcard_domain(self, mock_config, mock_get_provider):
        from function_app import create_dns_txt_record

        mock_provider = MagicMock()
        mock_get_provider.return_value = mock_provider

        input_data = {
            "dns_provider": "cloudflare",
            "domain": "*.example.com",
            "record_name": "_acme-challenge.example.com",
            "record_value": "wc-token",
        }

        create_dns_txt_record(input_data)

        mock_provider.create_txt_record.assert_called_once_with("example.com", "_acme-challenge", "wc-token")


class TestDeleteDnsTxtRecordActivity:
    @patch("function_app.get_dns_provider")
    @patch("function_app.load_config")
    def test_deletes_record_via_provider(self, mock_config, mock_get_provider):
        from function_app import delete_dns_txt_record

        mock_provider = MagicMock()
        mock_get_provider.return_value = mock_provider

        input_data = {
            "dns_provider": "azure",
            "domain": "example.com",
            "record_name": "_acme-challenge.example.com",
        }

        delete_dns_txt_record(input_data)

        mock_get_provider.assert_called_once_with(mock_config.return_value, provider_name="azure")
        mock_provider.delete_txt_record.assert_called_once_with("example.com", "_acme-challenge")
