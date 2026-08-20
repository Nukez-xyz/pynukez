# tests/test_errors.py
"""
Batch 4B: SDK error class tests.

Tests all exception classes and backward-compat aliases.
"""
import pytest
from pynukez.errors import (
    NukezError,
    PaymentRequiredError,
    TransactionNotFoundError,
    AuthenticationError,
    NukezFileNotFoundError,
    URLExpiredError,
    NukezNotProvisionedError,
    RateLimitError,
)


class TestNukezError:
    """Base error class tests."""

    def test_basic_construction(self):
        err = NukezError("something broke")
        assert str(err) == "something broke"
        assert err.message == "something broke"

    def test_details_default(self):
        err = NukezError("test")
        assert err.details is None or isinstance(err.details, dict)

    def test_is_exception(self):
        assert issubclass(NukezError, Exception)


class TestRetryableErrors:
    """Errors that should be retryable."""

    def test_transaction_not_found_retryable(self):
        err = TransactionNotFoundError("sig123")
        assert err.retryable is True
        assert err.tx_sig == "sig123"
        assert err.suggested_delay == 2

    def test_url_expired_retryable(self):
        err = URLExpiredError("upload")
        assert err.retryable is True
        assert err.operation == "upload"

    def test_rate_limit_retryable(self):
        err = RateLimitError(retry_after=30)
        assert err.retryable is True
        assert err.retry_after == 30


class TestNonRetryableErrors:
    """Errors that should NOT be retryable."""

    def test_authentication_not_retryable(self):
        err = AuthenticationError(message="bad sig")
        assert err.retryable is False

    def test_not_provisioned_not_retryable(self):
        err = NukezNotProvisionedError("rid123")
        assert err.retryable is False
        assert err.receipt_id == "rid123"

    def test_file_not_found_not_retryable(self):
        err = NukezFileNotFoundError("test.txt", "locker_abc")
        assert err.retryable is False
        assert err.filename == "test.txt"


class TestBackwardCompatAlias:
    """Backward compatibility aliases."""

    def test_file_not_found_alias(self):
        """FileNotFound should be importable as alias."""
        try:
            from pynukez.errors import FileNotFound
            assert FileNotFound is NukezFileNotFoundError
        except ImportError:
            # Alias may not exist — skip
            pytest.skip("FileNotFound alias not defined")


class TestNotProvisionedWiring:
    """The 4.0.23 release wired the long-exported NukezNotProvisionedError
    into the HTTP layer's 404 handling: a gateway 404 whose error code
    names the locker (LOCKER_NOT_FOUND) means the receipt is real but
    provision_locker() has not been called. These tests pin that branch
    against the gateway's flat AppError shape
    {"error_code", "message", "details", "request_id"}."""

    class _Resp:
        def __init__(self, status_code, json_data, url="https://api.nukez.xyz/v1/lockers/locker_ab/files"):
            import json as _json

            class _URL:
                def __init__(self, raw):
                    self.path = raw.split("://", 1)[-1].split("/", 1)[-1]

            self.status_code = status_code
            self._json = json_data
            self.text = _json.dumps(json_data)
            self.content = self.text.encode()
            self.headers = {}
            self.url = _URL(url)

        def json(self):
            return self._json

    def test_locker_not_found_raises_not_provisioned(self):
        from pynukez._http import handle_error_response

        resp = self._Resp(404, {
            "error_code": "LOCKER_NOT_FOUND",
            "message": "Locker not found",
            "details": {"locker_id": "locker_ab12cd34ef56"},
            "request_id": "req-1",
        })
        with pytest.raises(NukezNotProvisionedError) as ei:
            handle_error_response(resp)
        # The gateway's details carry locker_id rather than receipt_id, so
        # the receipt_id attribute is empty in practice — pinned here so a
        # future change to populate it is a conscious one.
        assert ei.value.receipt_id == ""

    def test_receipt_id_populated_when_gateway_provides_it(self):
        from pynukez._http import handle_error_response

        resp = self._Resp(404, {
            "error_code": "LOCKER_NOT_FOUND",
            "message": "Locker not found",
            "details": {"receipt_id": "rcpt_42"},
            "request_id": "req-2",
        })
        with pytest.raises(NukezNotProvisionedError) as ei:
            handle_error_response(resp)
        assert ei.value.receipt_id == "rcpt_42"

    def test_plain_file_404_still_raises_file_not_found(self):
        from pynukez._http import handle_error_response

        resp = self._Resp(404, {
            "error_code": "FILE_NOT_FOUND",
            "message": "File not found in locker",
            "details": {"filename": "a.bin", "locker_id": "locker_ab12cd34ef56"},
            "request_id": "req-3",
        })
        with pytest.raises(NukezFileNotFoundError):
            handle_error_response(resp)
