# tests/test_http_client.py
"""
SDK HTTP client tests — mock-based HTTP testing.
Tests both sync HTTPClient and shared error-handling functions.
"""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from pynukez._http import HTTPClient, handle_error_response, parse_json_response, parse_error_response
from pynukez.errors import (
    NukezError, AuthenticationError, NukezFileNotFoundError,
    RateLimitError, PaymentRequiredError, TransactionNotFoundError,
    URLExpiredError,
)


class MockResponse:
    """Mock HTTP response — compatible with both httpx.Response and requests.Response interface."""
    def __init__(self, status_code=200, json_data=None, text="", headers=None, url="https://api.nukez.xyz/test"):
        self.status_code = status_code
        self._json = json_data
        self.text = text
        self.headers = headers or {}
        self.url = url
        # Ensure content is truthy when json_data is provided (so parse_error_response reads it)
        if json_data is not None and not text:
            import json
            self.content = json.dumps(json_data).encode()
        else:
            self.content = text.encode() if isinstance(text, str) else text

    def json(self):
        if self._json is None:
            raise ValueError("No JSON")
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


class TestStandardHeaders:
    """The shared header block must always advertise the real SDK version."""

    def test_user_agent_derives_from_package_version(self):
        """The User-Agent string is built from pynukez.__version__, so the
        two can never drift apart the way the hardcoded 4.0.21 literal did
        while the package was already versioned 4.0.22."""
        import pynukez
        from pynukez._http import STANDARD_HEADERS

        assert STANDARD_HEADERS["User-Agent"] == f"nukez-sdk/{pynukez.__version__}"

    def test_package_version_matches_pyproject(self):
        """pyproject.toml and pynukez.__version__ must agree, since the
        User-Agent (and any other derived string) follows the package
        version."""
        import re
        from pathlib import Path

        import pynukez

        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        match = re.search(
            r'^version\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE,
        )
        assert match is not None, "pyproject.toml is missing a version field"
        assert match.group(1) == pynukez.__version__


class TestNukezHTTPInit:
    """HTTP client initialization tests."""

    def test_default_base_url(self):
        http = HTTPClient(base_url="https://api.nukez.xyz")
        assert "nukez" in http.base_url.lower()

    def test_custom_base_url(self):
        http = HTTPClient(base_url="https://custom.example.com")
        assert http.base_url == "https://custom.example.com"

    def test_trailing_slash_stripped(self):
        http = HTTPClient(base_url="https://api.nukez.xyz/")
        assert http.base_url == "https://api.nukez.xyz"

    def test_has_required_methods(self):
        """HTTP client must have get, post, put, delete methods."""
        http = HTTPClient(base_url="https://api.nukez.xyz")
        for method in ("get", "post", "put", "delete", "close"):
            assert hasattr(http, method), f"Missing {method} method"

    def test_context_manager(self):
        with HTTPClient(base_url="https://api.nukez.xyz") as http:
            assert http.base_url == "https://api.nukez.xyz"


# -----------------------------------------------------------------------
# Shared error-handling function tests (used by both sync and async)
# -----------------------------------------------------------------------

class TestSharedErrorHandling:
    """Test module-level error functions that both HTTPClient and AsyncHTTPClient use."""

    def test_401_raises_auth_error(self):
        resp = MockResponse(
            status_code=401,
            json_data={"error_code": "SIGNED_ENVELOPE_REQUIRED", "message": "Auth needed"},
        )
        with pytest.raises(AuthenticationError):
            handle_error_response(resp)

    def test_403_raises_auth_error(self):
        resp = MockResponse(
            status_code=403,
            json_data={"message": "Forbidden"},
        )
        with pytest.raises(AuthenticationError):
            handle_error_response(resp)

    def test_403_expired_url_raises_url_expired(self):
        resp = MockResponse(
            status_code=403,
            json_data={"message": "URL has expired"},
        )
        with pytest.raises(URLExpiredError):
            handle_error_response(resp)

    def test_404_generic_raises_nukez_error(self):
        resp = MockResponse(
            status_code=404,
            json_data={"error_code": "NOT_FOUND", "message": "Not found"},
        )
        with pytest.raises(NukezError):
            handle_error_response(resp)

    def test_404_file_raises_file_not_found(self):
        resp = MockResponse(
            status_code=404,
            json_data={"error_code": "FILE_NOT_FOUND", "message": "File not found", "filename": "test.txt"},
        )
        with pytest.raises(NukezFileNotFoundError):
            handle_error_response(resp)

    def test_402_raises_payment_required(self):
        resp = MockResponse(
            status_code=402,
            json_data={
                "pay_req_id": "pr_123",
                "pay_to_address": "addr_456",
                "amount_sol": 0.01,
                "network": "devnet",
            },
        )
        with pytest.raises(PaymentRequiredError) as exc_info:
            handle_error_response(resp)
        assert exc_info.value.pay_req_id == "pr_123"

    def test_402_evm_fields(self):
        resp = MockResponse(
            status_code=402,
            json_data={
                "pay_req_id": "pr_evm",
                "pay_to_address": "0xabc",
                "pay_asset": "USDC",
                "amount": "5.00",
                "amount_raw": 5000000,
                "token_address": "0xtoken",
                "token_decimals": 6,
                "network": "monad-testnet",
            },
        )
        with pytest.raises(PaymentRequiredError) as exc_info:
            handle_error_response(resp)
        assert exc_info.value.pay_asset == "USDC"
        assert exc_info.value.amount_raw == 5000000

    def test_409_with_tx_sig_raises_tx_not_found(self):
        resp = MockResponse(
            status_code=409,
            json_data={"tx_sig": "abc123"},
        )
        with pytest.raises(TransactionNotFoundError):
            handle_error_response(resp)

    def test_409_without_tx_sig_raises_nukez_error(self):
        resp = MockResponse(
            status_code=409,
            json_data={"message": "Conflict"},
        )
        with pytest.raises(NukezError):
            handle_error_response(resp)

    def test_429_raises_rate_limit(self):
        resp = MockResponse(
            status_code=429,
            json_data={"error_code": "RATE_LIMITED", "message": "Slow down"},
            headers={"Retry-After": "30"},
        )
        with pytest.raises(RateLimitError) as exc_info:
            handle_error_response(resp)
        assert exc_info.value.retryable is True

    def test_500_raises_retryable_error(self):
        resp = MockResponse(
            status_code=500,
            json_data={"message": "Internal server error"},
        )
        with pytest.raises(NukezError) as exc_info:
            handle_error_response(resp)
        assert exc_info.value.retryable is True

    def test_503_raises_retryable_error(self):
        resp = MockResponse(status_code=503)
        with pytest.raises(NukezError) as exc_info:
            handle_error_response(resp)
        assert exc_info.value.retryable is True

    def test_parse_json_empty_content(self):
        resp = MockResponse(status_code=200, text="")
        result = parse_json_response(resp, "GET", "/test")
        assert result == {}

    def test_parse_json_valid(self):
        resp = MockResponse(status_code=200, json_data={"key": "value"})
        resp.content = b'{"key": "value"}'
        result = parse_json_response(resp, "GET", "/test")
        assert result == {"key": "value"}

    def test_parse_json_invalid_raises(self):
        resp = MockResponse(status_code=200)
        resp.content = b"not json"
        resp._json = None
        with pytest.raises(NukezError, match="Invalid JSON"):
            parse_json_response(resp, "GET", "/test")

    def test_parse_error_response_empty(self):
        resp = MockResponse(status_code=400, text="")
        result = parse_error_response(resp)
        assert result == {}

    def test_parse_error_response_non_dict(self):
        resp = MockResponse(status_code=400)
        resp._json = ["not", "a", "dict"]
        resp.content = b'["not","a","dict"]'
        result = parse_error_response(resp)
        assert result == {}


class TestHTTPMethods:
    """HTTP method delegation tests."""

    @patch.object(HTTPClient, "__init__", lambda self, **kwargs: None)
    def test_get_method_exists(self):
        http = HTTPClient.__new__(HTTPClient)
        assert callable(getattr(http, "get", None))

    @patch.object(HTTPClient, "__init__", lambda self, **kwargs: None)
    def test_post_method_exists(self):
        http = HTTPClient.__new__(HTTPClient)
        assert callable(getattr(http, "post", None))
