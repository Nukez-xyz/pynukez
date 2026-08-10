# tests/test_confirm_signing.py
"""
Confirm-endpoint signing tests.

The gateway's /v1/files/confirm and /v1/files/confirm-batch routes are
authenticated with a payer-signed envelope carrying ops=["locker:write"],
the same authority as the create_file step that precedes them. These tests
verify that both clients build that envelope, bind it to the exact query
string they send, and refuse to call confirm without a signer.
"""
import base64
import hashlib
import json
from urllib.parse import urlencode

import pytest
from unittest.mock import MagicMock, AsyncMock

from pynukez.errors import NukezError


def _decode_envelope(headers: dict) -> dict:
    """Decode the X-Nukez-Envelope header back into the envelope dict."""
    raw = headers["X-Nukez-Envelope"]
    padded = raw + "=" * (-len(raw) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


_EMPTY_BODY_SHA256 = hashlib.sha256(b"{}").hexdigest()


class TestSyncConfirmSigning:
    def test_confirm_file_sends_signed_envelope(self, sync_client):
        """confirm_file signs an envelope bound to the fallback path + query."""
        sync_client.http.post = MagicMock(return_value={
            "filename": "a.txt",
            "content_hash": "sha256:abc",
            "size_bytes": 3,
        })

        result = sync_client.confirm_file("r1", "a.txt")

        assert result.confirmed is True
        args, kwargs = sync_client.http.post.call_args
        assert args[0] == "/v1/files/confirm"
        assert kwargs["params"] == {"receipt_id": "r1", "filename": "a.txt"}
        assert kwargs["content"] == b"{}"

        env = _decode_envelope(kwargs["headers"])
        assert env["method"] == "POST"
        assert env["path"] == "/v1/files/confirm"
        assert env["ops"] == ["locker:write"]
        assert env["receipt_id"] == "r1"
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filename": "a.txt"}, doseq=True,
        )
        assert env["body_sha256"] == _EMPTY_BODY_SHA256
        assert kwargs["headers"]["X-Nukez-Signature"] == "FakeSignature"

    def test_confirm_file_with_confirm_url_binds_url_query(self, sync_client):
        """confirm_file binds the envelope to the confirm_url's own path+query."""
        confirm_url = (
            "https://api.nukez.xyz/v1/files/confirm"
            "?receipt_id=r1&filename=a.txt"
        )
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "filename": "a.txt",
            "content_hash": "sha256:abc",
            "size_bytes": 3,
        }
        sync_client._raw_client = MagicMock()
        sync_client._raw_client.post = MagicMock(return_value=resp)

        result = sync_client.confirm_file("r1", "a.txt", confirm_url=confirm_url)

        assert result.confirmed is True
        args, kwargs = sync_client._raw_client.post.call_args
        assert args[0] == confirm_url
        assert kwargs["content"] == b"{}"

        env = _decode_envelope(kwargs["headers"])
        assert env["path"] == "/v1/files/confirm"
        assert env["query"] == "receipt_id=r1&filename=a.txt"
        assert env["ops"] == ["locker:write"]

    def test_confirm_files_batch_binds_filenames(self, sync_client):
        """confirm_files binds every repeated filenames pair into the query."""
        sync_client.http.post = MagicMock(return_value={
            "results": [
                {"filename": "a.txt", "content_hash": "sha256:a", "size_bytes": 1},
                {"filename": "b.txt", "content_hash": "sha256:b", "size_bytes": 2},
            ],
            "confirmed": 2,
            "failed": 0,
        })

        result = sync_client.confirm_files("r1", ["a.txt", "b.txt"])

        assert result.confirmed_count == 2
        args, kwargs = sync_client.http.post.call_args
        assert args[0] == "/v1/files/confirm-batch"

        env = _decode_envelope(kwargs["headers"])
        assert env["path"] == "/v1/files/confirm-batch"
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filenames": ["a.txt", "b.txt"]}, doseq=True,
        )
        assert "filenames=a.txt&filenames=b.txt" in env["query"]

    def test_confirm_files_with_matching_batch_url_binds_url_query(self, sync_client):
        """When confirm_batch_url's filenames match the request, the URL is
        posted as-is with the envelope bound to its query."""
        batch_url = (
            "https://api.nukez.xyz/v1/files/confirm-batch"
            "?receipt_id=r1&filenames=a.txt&filenames=b.txt"
        )
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"results": [], "confirmed": 2, "errors": 0}
        sync_client._raw_client = MagicMock()
        sync_client._raw_client.post = MagicMock(return_value=resp)

        sync_client.confirm_files(
            "r1", ["b.txt", "a.txt"], confirm_batch_url=batch_url,
        )

        args, kwargs = sync_client._raw_client.post.call_args
        assert args[0] == batch_url
        env = _decode_envelope(kwargs["headers"])
        assert env["query"] == "receipt_id=r1&filenames=a.txt&filenames=b.txt"

    def test_confirm_files_batch_url_filename_mismatch_falls_back(self, sync_client):
        """confirm_batch_url pre-encodes the ENTIRE created batch. When the
        caller confirms a subset (partial upload failure), the URL must NOT
        be used — otherwise never-uploaded files get confirmed, re-recording
        stale bytes. The SDK falls back to the hardcoded path with exactly
        the requested filenames."""
        batch_url = (
            "https://api.nukez.xyz/v1/files/confirm-batch"
            "?receipt_id=r1&filenames=a.txt&filenames=b.txt&filenames=c.txt"
        )
        sync_client._raw_client = MagicMock()
        sync_client.http.post = MagicMock(return_value={
            "results": [], "confirmed": 1, "errors": 0,
        })

        sync_client.confirm_files(
            "r1", ["a.txt"], confirm_batch_url=batch_url,
        )

        sync_client._raw_client.post.assert_not_called()
        args, kwargs = sync_client.http.post.call_args
        assert args[0] == "/v1/files/confirm-batch"
        env = _decode_envelope(kwargs["headers"])
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filenames": ["a.txt"]}, doseq=True,
        )

    def test_confirm_batch_url_receipt_id_mismatch_falls_back(self, sync_client):
        """A batch URL whose receipt_id differs from the caller's must not be
        signed — the payer envelope would bind a locker the caller never
        chose. The SDK falls back to the client-constructed request."""
        batch_url = (
            "https://api.nukez.xyz/v1/files/confirm-batch"
            "?receipt_id=r2&filenames=a.txt"
        )
        sync_client._raw_client = MagicMock()
        sync_client.http.post = MagicMock(return_value={
            "results": [], "confirmed": 1, "errors": 0,
        })

        sync_client.confirm_files("r1", ["a.txt"], confirm_batch_url=batch_url)

        sync_client._raw_client.post.assert_not_called()
        args, kwargs = sync_client.http.post.call_args
        assert args[0] == "/v1/files/confirm-batch"
        env = _decode_envelope(kwargs["headers"])
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filenames": ["a.txt"]}, doseq=True,
        )

    def test_confirm_url_with_poisoned_host_falls_back(self, sync_client):
        """A confirm_url pointing at a foreign host must never be signed —
        a poisoned create response would otherwise obtain a payer-signed
        locker:write envelope for an attacker-chosen server. The SDK falls
        back to the canonical client-constructed request."""
        poisoned = (
            "https://evil.example.com/v1/files/confirm"
            "?receipt_id=r1&filename=a.txt"
        )
        sync_client._raw_client = MagicMock()
        sync_client.http.post = MagicMock(return_value={
            "filename": "a.txt", "content_hash": "sha256:abc", "size_bytes": 3,
        })

        sync_client.confirm_file("r1", "a.txt", confirm_url=poisoned)

        sync_client._raw_client.post.assert_not_called()
        args, kwargs = sync_client.http.post.call_args
        assert args[0] == "/v1/files/confirm"
        env = _decode_envelope(kwargs["headers"])
        assert env["path"] == "/v1/files/confirm"
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filename": "a.txt"}, doseq=True,
        )

    def test_confirm_url_with_poisoned_path_falls_back(self, sync_client):
        """A confirm_url whose path is not exactly /v1/files/confirm must
        never be signed, even on the right host — the envelope would grant
        locker:write on an arbitrary gateway path."""
        poisoned = (
            "https://api.nukez.xyz/v1/lockers/export"
            "?receipt_id=r1&filename=a.txt"
        )
        sync_client._raw_client = MagicMock()
        sync_client.http.post = MagicMock(return_value={
            "filename": "a.txt", "content_hash": "sha256:abc", "size_bytes": 3,
        })

        sync_client.confirm_file("r1", "a.txt", confirm_url=poisoned)

        sync_client._raw_client.post.assert_not_called()
        args, kwargs = sync_client.http.post.call_args
        assert args[0] == "/v1/files/confirm"
        env = _decode_envelope(kwargs["headers"])
        assert env["path"] == "/v1/files/confirm"

    def test_confirm_batch_url_with_poisoned_host_falls_back(self, sync_client):
        """The batch branch applies the same host validation as the
        single-file branch: a foreign-host batch URL is ignored even when
        its filenames and receipt_id match the request."""
        poisoned = (
            "https://evil.example.com/v1/files/confirm-batch"
            "?receipt_id=r1&filenames=a.txt"
        )
        sync_client._raw_client = MagicMock()
        sync_client.http.post = MagicMock(return_value={
            "results": [], "confirmed": 1, "errors": 0,
        })

        sync_client.confirm_files("r1", ["a.txt"], confirm_batch_url=poisoned)

        sync_client._raw_client.post.assert_not_called()
        args, kwargs = sync_client.http.post.call_args
        assert args[0] == "/v1/files/confirm-batch"
        env = _decode_envelope(kwargs["headers"])
        assert env["path"] == "/v1/files/confirm-batch"

    def test_confirm_batch_url_with_poisoned_path_falls_back(self, sync_client):
        """A batch URL on the right host but the wrong path (here the
        single-file confirm path) must not be signed by confirm_files."""
        poisoned = (
            "https://api.nukez.xyz/v1/files/confirm"
            "?receipt_id=r1&filenames=a.txt"
        )
        sync_client._raw_client = MagicMock()
        sync_client.http.post = MagicMock(return_value={
            "results": [], "confirmed": 1, "errors": 0,
        })

        sync_client.confirm_files("r1", ["a.txt"], confirm_batch_url=poisoned)

        sync_client._raw_client.post.assert_not_called()
        args, kwargs = sync_client.http.post.call_args
        assert args[0] == "/v1/files/confirm-batch"

    def test_confirm_files_surfaces_gateway_reported_failures(self, sync_client):
        """The gateway's confirm-batch response has no "failed" key: it
        reports successes in "results" plus a separate "errors" count and
        "error_details" list. A mixed batch must surface those failures
        instead of reporting full success."""
        error_details = [
            {
                "filename": "b.txt",
                "error": "HASH_MISMATCH",
                "details": {"expected_hash": "sha256:x", "computed_hash": "sha256:y"},
            },
        ]
        sync_client.http.post = MagicMock(return_value={
            "locker_id": "locker_abc",
            "confirmed": 1,
            "errors": 1,
            "results": [
                {"filename": "a.txt", "content_hash": "sha256:a", "size_bytes": 1},
            ],
            "error_details": error_details,
        })

        result = sync_client.confirm_files("r1", ["a.txt", "b.txt"])

        assert result.confirmed_count == 1
        assert result.errors == 1
        assert result.failed_count == 1
        assert result.error_details == error_details
        assert [r.filename for r in result.results] == ["a.txt"]
        assert all(r.confirmed for r in result.results)

    def test_confirm_files_clean_batch_reports_no_errors(self, sync_client):
        """A fully successful batch parses with errors=0 and
        error_details=None, matching the gateway's null."""
        sync_client.http.post = MagicMock(return_value={
            "locker_id": "locker_abc",
            "confirmed": 2,
            "errors": 0,
            "results": [
                {"filename": "a.txt", "content_hash": "sha256:a", "size_bytes": 1},
                {"filename": "b.txt", "content_hash": "sha256:b", "size_bytes": 2},
            ],
            "error_details": None,
        })

        result = sync_client.confirm_files("r1", ["a.txt", "b.txt"])

        assert result.confirmed_count == 2
        assert result.errors == 0
        assert result.failed_count == 0
        assert result.error_details is None
        assert len(result.results) == 2

    def test_confirm_file_refuses_without_signer(self):
        """A keyless client cannot confirm — a signing key is required."""
        from pynukez import Nukez
        client = Nukez()
        client.http = MagicMock()

        with pytest.raises(NukezError):
            client.confirm_file("r1", "a.txt")
        client.http.post.assert_not_called()

    def test_confirm_files_refuses_without_signer(self):
        from pynukez import Nukez
        client = Nukez()
        client.http = MagicMock()

        with pytest.raises(NukezError):
            client.confirm_files("r1", ["a.txt"])
        client.http.post.assert_not_called()


class TestAsyncConfirmSigning:
    async def test_confirm_file_sends_signed_envelope(self, async_client):
        async_client.http.post = AsyncMock(return_value={
            "filename": "a.txt",
            "content_hash": "sha256:abc",
            "size_bytes": 3,
        })

        result = await async_client.confirm_file("r1", "a.txt")

        assert result.confirmed is True
        args, kwargs = async_client.http.post.call_args
        assert args[0] == "/v1/files/confirm"
        assert kwargs["params"] == {"receipt_id": "r1", "filename": "a.txt"}
        assert kwargs["content"] == b"{}"

        env = _decode_envelope(kwargs["headers"])
        assert env["method"] == "POST"
        assert env["path"] == "/v1/files/confirm"
        assert env["ops"] == ["locker:write"]
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filename": "a.txt"}, doseq=True,
        )
        assert env["body_sha256"] == _EMPTY_BODY_SHA256

    async def test_confirm_files_batch_binds_filenames(self, async_client):
        async_client.http.post = AsyncMock(return_value={
            "results": [
                {"filename": "a.txt", "content_hash": "sha256:a", "size_bytes": 1},
            ],
            "confirmed": 1,
            "failed": 0,
        })

        result = await async_client.confirm_files("r1", ["a.txt"])

        assert result.confirmed_count == 1
        args, kwargs = async_client.http.post.call_args
        env = _decode_envelope(kwargs["headers"])
        assert env["path"] == "/v1/files/confirm-batch"
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filenames": ["a.txt"]}, doseq=True,
        )

    async def test_confirm_file_with_confirm_url_binds_url_query(self, async_client):
        """The async confirm_url branch mirrors the sync one: envelope bound
        to the URL's own path+query, canonical empty body sent."""
        confirm_url = (
            "https://api.nukez.xyz/v1/files/confirm"
            "?receipt_id=r1&filename=a.txt"
        )
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "filename": "a.txt",
            "content_hash": "sha256:abc",
            "size_bytes": 3,
        }
        async_client._raw_client.post = AsyncMock(return_value=resp)

        result = await async_client.confirm_file(
            "r1", "a.txt", confirm_url=confirm_url,
        )

        assert result.confirmed is True
        args, kwargs = async_client._raw_client.post.call_args
        assert args[0] == confirm_url
        assert kwargs["content"] == b"{}"
        env = _decode_envelope(kwargs["headers"])
        assert env["path"] == "/v1/files/confirm"
        assert env["query"] == "receipt_id=r1&filename=a.txt"
        assert env["ops"] == ["locker:write"]

    async def test_confirm_files_batch_url_filename_mismatch_falls_back(self, async_client):
        batch_url = (
            "https://api.nukez.xyz/v1/files/confirm-batch"
            "?receipt_id=r1&filenames=a.txt&filenames=b.txt"
        )
        async_client._raw_client.post = AsyncMock()
        async_client.http.post = AsyncMock(return_value={
            "results": [], "confirmed": 1, "errors": 0,
        })

        await async_client.confirm_files(
            "r1", ["a.txt"], confirm_batch_url=batch_url,
        )

        async_client._raw_client.post.assert_not_called()
        args, kwargs = async_client.http.post.call_args
        assert args[0] == "/v1/files/confirm-batch"
        env = _decode_envelope(kwargs["headers"])
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filenames": ["a.txt"]}, doseq=True,
        )

    async def test_confirm_batch_url_receipt_id_mismatch_falls_back(self, async_client):
        """The async twin of the receipt_id binding check: a batch URL that
        names a different receipt must fall back to the canonical request."""
        batch_url = (
            "https://api.nukez.xyz/v1/files/confirm-batch"
            "?receipt_id=r2&filenames=a.txt"
        )
        async_client._raw_client.post = AsyncMock()
        async_client.http.post = AsyncMock(return_value={
            "results": [], "confirmed": 1, "errors": 0,
        })

        await async_client.confirm_files(
            "r1", ["a.txt"], confirm_batch_url=batch_url,
        )

        async_client._raw_client.post.assert_not_called()
        args, kwargs = async_client.http.post.call_args
        assert args[0] == "/v1/files/confirm-batch"
        env = _decode_envelope(kwargs["headers"])
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filenames": ["a.txt"]}, doseq=True,
        )

    async def test_confirm_url_with_poisoned_host_falls_back(self, async_client):
        """The async twin of the host validation: a foreign-host confirm_url
        is never signed; the canonical request is sent instead."""
        poisoned = (
            "https://evil.example.com/v1/files/confirm"
            "?receipt_id=r1&filename=a.txt"
        )
        async_client._raw_client.post = AsyncMock()
        async_client.http.post = AsyncMock(return_value={
            "filename": "a.txt", "content_hash": "sha256:abc", "size_bytes": 3,
        })

        await async_client.confirm_file("r1", "a.txt", confirm_url=poisoned)

        async_client._raw_client.post.assert_not_called()
        args, kwargs = async_client.http.post.call_args
        assert args[0] == "/v1/files/confirm"
        env = _decode_envelope(kwargs["headers"])
        assert env["path"] == "/v1/files/confirm"
        assert env["query"] == urlencode(
            {"receipt_id": "r1", "filename": "a.txt"}, doseq=True,
        )

    async def test_confirm_url_with_poisoned_path_falls_back(self, async_client):
        """The async twin of the path validation: right host, wrong path is
        never signed."""
        poisoned = (
            "https://api.nukez.xyz/v1/lockers/export"
            "?receipt_id=r1&filename=a.txt"
        )
        async_client._raw_client.post = AsyncMock()
        async_client.http.post = AsyncMock(return_value={
            "filename": "a.txt", "content_hash": "sha256:abc", "size_bytes": 3,
        })

        await async_client.confirm_file("r1", "a.txt", confirm_url=poisoned)

        async_client._raw_client.post.assert_not_called()
        args, kwargs = async_client.http.post.call_args
        assert args[0] == "/v1/files/confirm"
        env = _decode_envelope(kwargs["headers"])
        assert env["path"] == "/v1/files/confirm"

    async def test_confirm_batch_url_with_poisoned_host_falls_back(self, async_client):
        """The async batch branch also refuses to sign a foreign-host URL."""
        poisoned = (
            "https://evil.example.com/v1/files/confirm-batch"
            "?receipt_id=r1&filenames=a.txt"
        )
        async_client._raw_client.post = AsyncMock()
        async_client.http.post = AsyncMock(return_value={
            "results": [], "confirmed": 1, "errors": 0,
        })

        await async_client.confirm_files(
            "r1", ["a.txt"], confirm_batch_url=poisoned,
        )

        async_client._raw_client.post.assert_not_called()
        args, kwargs = async_client.http.post.call_args
        assert args[0] == "/v1/files/confirm-batch"

    async def test_confirm_files_surfaces_gateway_reported_failures(self, async_client):
        """The async twin of the mixed-batch parse: gateway-reported
        failures must show up in errors/error_details, not vanish."""
        error_details = [
            {
                "filename": "b.txt",
                "error": "DOWNLOAD_FAILED",
                "details": {"status": 404},
            },
        ]
        async_client.http.post = AsyncMock(return_value={
            "locker_id": "locker_abc",
            "confirmed": 1,
            "errors": 1,
            "results": [
                {"filename": "a.txt", "content_hash": "sha256:a", "size_bytes": 1},
            ],
            "error_details": error_details,
        })

        result = await async_client.confirm_files("r1", ["a.txt", "b.txt"])

        assert result.confirmed_count == 1
        assert result.errors == 1
        assert result.failed_count == 1
        assert result.error_details == error_details
        assert [r.filename for r in result.results] == ["a.txt"]

    async def test_confirm_file_refuses_without_signer(self):
        from pynukez import AsyncNukez
        client = AsyncNukez()
        client.http = AsyncMock()

        with pytest.raises(NukezError):
            await client.confirm_file("r1", "a.txt")
        client.http.post.assert_not_called()


class TestValidatedConfirmUrl:
    """Unit tests for the shared confirm-URL validation helper."""

    def test_exact_match_is_accepted(self):
        from pynukez._helpers import _validated_confirm_url
        url = "https://api.nukez.xyz/v1/files/confirm?receipt_id=r1"
        assert _validated_confirm_url(
            url, "/v1/files/confirm", "https://api.nukez.xyz",
        ) == url

    def test_relative_url_is_accepted(self):
        from pynukez._helpers import _validated_confirm_url
        url = "/v1/files/confirm?receipt_id=r1"
        assert _validated_confirm_url(
            url, "/v1/files/confirm", "https://api.nukez.xyz",
        ) == url

    def test_host_case_is_insensitive(self):
        from pynukez._helpers import _validated_confirm_url
        url = "https://API.NUKEZ.XYZ/v1/files/confirm?receipt_id=r1"
        assert _validated_confirm_url(
            url, "/v1/files/confirm", "https://api.nukez.xyz",
        ) == url

    def test_foreign_host_is_rejected(self):
        from pynukez._helpers import _validated_confirm_url
        url = "https://evil.example.com/v1/files/confirm?receipt_id=r1"
        assert _validated_confirm_url(
            url, "/v1/files/confirm", "https://api.nukez.xyz",
        ) is None

    def test_wrong_path_is_rejected(self):
        from pynukez._helpers import _validated_confirm_url
        url = "https://api.nukez.xyz/v1/receipts/export?receipt_id=r1"
        assert _validated_confirm_url(
            url, "/v1/files/confirm", "https://api.nukez.xyz",
        ) is None

    def test_userinfo_smuggling_is_rejected(self):
        """A URL whose netloc smuggles the expected host into the userinfo
        portion must not pass the host comparison."""
        from pynukez._helpers import _validated_confirm_url
        url = "https://api.nukez.xyz@evil.example.com/v1/files/confirm"
        assert _validated_confirm_url(
            url, "/v1/files/confirm", "https://api.nukez.xyz",
        ) is None

    def test_port_variation_is_rejected(self):
        from pynukez._helpers import _validated_confirm_url
        url = "https://api.nukez.xyz:8443/v1/files/confirm?receipt_id=r1"
        assert _validated_confirm_url(
            url, "/v1/files/confirm", "https://api.nukez.xyz",
        ) is None

    def test_scheme_downgrade_is_rejected(self):
        """Matching host over plain HTTP must not be signed either — the
        envelope would travel over a downgraded transport."""
        from pynukez._helpers import _validated_confirm_url
        url = "http://api.nukez.xyz/v1/files/confirm?receipt_id=r1"
        assert _validated_confirm_url(
            url, "/v1/files/confirm", "https://api.nukez.xyz",
        ) is None
