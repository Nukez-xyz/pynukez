# tests/test_client_methods.py
"""
Batch 4D: SDK client method tests — verifies method signatures and public API surface.
"""
import pytest
from unittest.mock import MagicMock, patch, call
from pynukez.client import Nukez
from pynukez.auth import _ReceiptState
from pynukez.errors import NukezError


class TestClientInit:
    """Client initialization tests."""

    @patch("pynukez.client.Keypair")
    def test_default_base_url(self, mock_kp):
        """Client defaults to nukez API URL."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        assert "nukez" in client.http.base_url.lower()

    @patch("pynukez.client.Keypair")
    def test_custom_base_url(self, mock_kp):
        """Custom base URL is respected."""
        client = Nukez(
            keypair_path="~/.config/solana/id.json",
            base_url="https://custom.example.com",
        )
        assert client.http.base_url == "https://custom.example.com"

    @patch("pynukez.client.Keypair")
    def test_default_network(self, mock_kp):
        """Default network is devnet."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        assert client.network == "devnet"


class TestClientPublicMethods:
    """Verify the public API surface exists."""

    @patch("pynukez.client.Keypair")
    def test_has_storage_flow_methods(self, mock_kp):
        """Client has get_price, request_storage, confirm_storage."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        for method in ("get_price", "request_storage", "confirm_storage"):
            assert hasattr(client, method), f"Missing method: {method}"

    @patch("pynukez.client.Keypair")
    def test_has_file_methods(self, mock_kp):
        """Client has create_file, upload_bytes, list_files, delete_file, confirm_file."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        for method in (
            "create_file",
            "upload_bytes",
            "list_files",
            "delete_file",
            "confirm_file",
        ):
            assert hasattr(client, method), f"Missing method: {method}"

    @patch("pynukez.client.Keypair")
    def test_has_provision_locker(self, mock_kp):
        """Client has provision_locker method."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        assert hasattr(client, "provision_locker")

    @patch("pynukez.client.Keypair")
    def test_has_verify_methods(self, mock_kp):
        """Client has receipt, storage, and merkle verification helpers."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        for method in (
            "get_receipt",
            "verify_receipt_hash",
            "receipt_hash_matches",
            "verify_storage",
            "get_merkle_proof",
        ):
            assert hasattr(client, method), f"Missing method: {method}"

    @patch("pynukez.client.Keypair")
    def test_receipt_hash_helpers(self, mock_kp):
        """Receipt hash helpers wrap the canonical receipt endpoints."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.http = MagicMock()
        client.http.get.side_effect = [
            {"id": "rid_123", "receipt_hash": "hash_abc"},
            {"computed_hash": "hash_abc"},
        ]

        result = client.verify_receipt_hash("rid_123")

        assert result.receipt_id == "rid_123"
        assert result.stored_hash == "hash_abc"
        assert result.computed_hash == "hash_abc"
        assert result.matches is True
        assert result.ok is True
        assert result.status == "verified"
        assert client.http.get.call_args_list == [
            call("/v1/receipts/rid_123"),
            call("/v1/receipts/rid_123/verify"),
        ]

    @patch("pynukez.client.Keypair")
    def test_receipt_hash_matches_returns_bool(self, mock_kp):
        """receipt_hash_matches returns a bool for concise guide examples."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.http = MagicMock()
        client.http.get.side_effect = [
            {"id": "rid_123", "receipt_hash": "hash_abc"},
            {"computed_hash": "hash_def"},
        ]

        assert client.receipt_hash_matches("rid_123") is False

    @patch("pynukez.client.Keypair")
    def test_has_batch_methods(self, mock_kp):
        """Client has batch operations."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        for method in ("confirm_files", "create_files_batch"):
            assert hasattr(client, method), f"Missing method: {method}"

    @patch("pynukez.client.Keypair")
    def test_has_download_methods(self, mock_kp):
        """Client has download_bytes and download_files."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        for method in ("download_bytes", "download_files"):
            assert hasattr(client, method), f"Missing method: {method}"


class TestClientFileInfoExpansion:
    """Verify list_files returns expanded FileInfo objects (Phase 2 Step 2.1)."""

    @patch("pynukez.client.build_signed_envelope")
    @patch("pynukez.client.Keypair")
    def test_list_files_returns_fileinfo_with_size(self, mock_kp_cls, mock_env):
        """list_files result includes size_bytes, content_hash, provider_ref."""
        from pynukez.types import FileInfo

        mock_env.return_value = MagicMock(
            headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"}
        )
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.http = MagicMock()
        client.http.get.return_value = {
            "files": [
                {
                    "filename": "test.txt",
                    "size_bytes": 42,
                    "content_hash": "sha256:abc",
                    "provider_ref": "ref_123",
                    "content_type": "text/plain",
                }
            ]
        }

        files = client.list_files("test_receipt")

        assert len(files) == 1
        f = files[0]
        assert isinstance(f, FileInfo)
        assert f.size_bytes == 42
        assert f.content_hash == "sha256:abc"
        assert f.provider_ref == "ref_123"

    @patch("pynukez.client.build_signed_envelope")
    @patch("pynukez.client.Keypair")
    def test_list_files_defaults_missing_fields(self, mock_kp_cls, mock_env):
        """list_files handles missing optional fields gracefully."""
        from pynukez.types import FileInfo

        mock_env.return_value = MagicMock(
            headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"}
        )
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.http = MagicMock()
        client.http.get.return_value = {
            "files": [{"filename": "bare.txt"}]
        }

        files = client.list_files("test_receipt")

        assert len(files) == 1
        f = files[0]
        assert f.size_bytes == 0
        assert f.content_hash is None
        assert f.provider_ref is None


class TestDownloadBytesRetry:
    """Verify download_bytes retries on 404 for content-addressed propagation."""

    @patch("pynukez.client.Keypair")
    def test_download_succeeds_first_try(self, mock_kp):
        """No retries when download succeeds immediately."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"hello world"
        mock_resp.raise_for_status = MagicMock()

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(return_value=mock_resp)
        result = client.download_bytes("https://storage.googleapis.com/bucket/obj")

        assert result == b"hello world"
        assert client._raw_client.get.call_count == 1

    @patch("pynukez.client.time.sleep")
    @patch("pynukez.client.Keypair")
    def test_download_retries_on_404_then_succeeds(self, mock_kp, mock_sleep):
        """Download retries on 404 and succeeds on second attempt."""
        client = Nukez(keypair_path="~/.config/solana/id.json")

        resp_404 = MagicMock()
        resp_404.status_code = 404

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.content = b"propagated data"
        resp_200.raise_for_status = MagicMock()

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(side_effect=[resp_404, resp_200])
        result = client.download_bytes("https://storage.googleapis.com/bucket/obj")

        assert result == b"propagated data"
        assert client._raw_client.get.call_count == 2
        mock_sleep.assert_called_once_with(2.0)

    @patch("pynukez.client.time.sleep")
    @patch("pynukez.client.Keypair")
    def test_download_exhausts_retries_raises(self, mock_kp, mock_sleep):
        """Download raises NukezError after all retries exhausted on 404."""
        from httpx import HTTPStatusError
        from unittest.mock import MagicMock as _MagicMock

        client = Nukez(keypair_path="~/.config/solana/id.json")

        mock_err_resp = MagicMock()
        mock_err_resp.status_code = 404
        last_err = HTTPStatusError(message="error", request=_MagicMock(), response=mock_err_resp)

        resp_404_ok = MagicMock()
        resp_404_ok.status_code = 404

        resp_404_final = MagicMock()
        resp_404_final.status_code = 404
        resp_404_final.raise_for_status.side_effect = last_err

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(
            side_effect=[resp_404_ok, resp_404_ok, resp_404_ok, resp_404_final]
        )
        with pytest.raises(NukezError, match="404"):
            client.download_bytes("https://storage.googleapis.com/bucket/obj")

        # 3 retries → sleeps at 2s, 4s, 8s
        assert mock_sleep.call_count == 3
        mock_sleep.assert_any_call(2.0)
        mock_sleep.assert_any_call(4.0)
        mock_sleep.assert_any_call(8.0)

    @patch("pynukez.client.Keypair")
    def test_download_no_retry_on_403(self, mock_kp):
        """403 (expired URL) does not trigger retry — raises immediately."""
        from httpx import HTTPStatusError
        from unittest.mock import MagicMock as _MagicMock

        client = Nukez(keypair_path="~/.config/solana/id.json")

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = HTTPStatusError(message="error", request=_MagicMock(), response=mock_resp)

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(return_value=mock_resp)
        with pytest.raises(NukezError, match="expired or malformed"):
            client.download_bytes("https://storage.googleapis.com/bucket/obj")

        assert client._raw_client.get.call_count == 1

    @patch("pynukez.client.time.sleep")
    @patch("pynukez.client.Keypair")
    def test_download_retry_disabled_with_zero(self, mock_kp, mock_sleep):
        """max_retries=0 disables retry — single attempt only."""
        from httpx import HTTPStatusError
        from unittest.mock import MagicMock as _MagicMock

        client = Nukez(keypair_path="~/.config/solana/id.json")

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.raise_for_status.side_effect = HTTPStatusError(message="error", request=_MagicMock(), response=mock_resp)

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(return_value=mock_resp)
        with pytest.raises(NukezError, match="404"):
            client.download_bytes(
                "https://storage.googleapis.com/bucket/obj", max_retries=0
            )

        assert client._raw_client.get.call_count == 1
        mock_sleep.assert_not_called()

    @patch("pynukez.client.time.sleep")
    @patch("pynukez.client.Keypair")
    def test_download_exponential_backoff_timing(self, mock_kp, mock_sleep):
        """Verify exponential backoff doubles each retry: 2s, 4s, 8s."""
        client = Nukez(keypair_path="~/.config/solana/id.json")

        resp_404 = MagicMock()
        resp_404.status_code = 404

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.content = b"ok"
        resp_200.raise_for_status = MagicMock()

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(
            side_effect=[resp_404, resp_404, resp_404, resp_200]
        )
        result = client.download_bytes("https://storage.googleapis.com/bucket/obj")

        assert result == b"ok"
        assert mock_sleep.call_args_list == [call(2.0), call(4.0), call(8.0)]

    @patch("pynukez.client.time.sleep")
    @patch("pynukez.client.Keypair")
    def test_download_propagation_error_parsed_from_gateway(self, mock_kp, mock_sleep):
        """Gateway CONTENT_PROPAGATION_PENDING response is parsed into NukezError details."""
        from httpx import HTTPStatusError
        from unittest.mock import MagicMock as _MagicMock

        client = Nukez(keypair_path="~/.config/solana/id.json")

        gateway_body = {
            "error_code": "CONTENT_PROPAGATION_PENDING",
            "message": "File upload confirmed but data is not yet available.",
            "details": {
                "retryable": True,
                "provider": "arweave",
                "suggested_delay": 15,
                "filename": "test.txt",
            },
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.json.return_value = gateway_body
        mock_resp.raise_for_status.side_effect = HTTPStatusError(message="error", request=_MagicMock(), response=mock_resp)

        resp_404 = MagicMock()
        resp_404.status_code = 404

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(
            side_effect=[resp_404, resp_404, resp_404, mock_resp]
        )
        with pytest.raises(NukezError) as exc_info:
            client.download_bytes("https://storage.googleapis.com/bucket/obj")

        err = exc_info.value
        assert "arweave" in err.message
        assert "propagating" in err.message
        assert err.details.get("error_code") == "CONTENT_PROPAGATION_PENDING"
        assert err.details.get("provider") == "arweave"
        assert err.details.get("suggested_delay") == 15
        assert err.details.get("retryable") is True

    @patch("pynukez.client.time.sleep")
    @patch("pynukez.client.Keypair")
    def test_download_generic_404_when_no_json_body(self, mock_kp, mock_sleep):
        """Non-JSON 404 response falls back to generic propagation message."""
        from httpx import HTTPStatusError
        from unittest.mock import MagicMock as _MagicMock

        client = Nukez(keypair_path="~/.config/solana/id.json")

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.json.side_effect = ValueError("No JSON")
        mock_resp.raise_for_status.side_effect = HTTPStatusError(message="error", request=_MagicMock(), response=mock_resp)

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(return_value=mock_resp)
        with pytest.raises(NukezError) as exc_info:
            client.download_bytes(
                "https://storage.googleapis.com/signed-url", max_retries=0
            )

        err = exc_info.value
        assert "404" in err.message
        assert "confirm_file" in err.message
        assert err.details.get("retryable") is True
        # Should NOT have propagation-specific fields
        assert "error_code" not in err.details

    @patch("pynukez.client.Keypair")
    def test_download_bytes_preflights_short_url_and_downloads_from_resolved(self, mock_kp):
        """Gateway short URL triggers preflight GET that resolves to the
        underlying signed storage URL; the body download runs against the
        resolved URL, bypassing Cloud Run."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        resolved = "https://storage.googleapis.com/bucket/obj?X-Goog-Signature=abc"

        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": resolved}

        body_resp = MagicMock()
        body_resp.status_code = 200
        body_resp.content = b"x" * (40 * 1024 * 1024)  # 40 MB
        body_resp.raise_for_status = MagicMock()

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(side_effect=[preflight, body_resp])

        result = client.download_bytes("https://api.nukez.xyz/f/abcdef")

        # Preflight: bodyless GET to short URL with follow_redirects=False
        preflight_call = client._raw_client.get.call_args_list[0]
        assert preflight_call.args[0] == "https://api.nukez.xyz/f/abcdef"
        assert preflight_call.kwargs["follow_redirects"] is False

        # Body download: plain GET to resolved URL
        body_call = client._raw_client.get.call_args_list[1]
        assert body_call.args[0] == resolved

        assert result == body_resp.content
        assert len(result) == 40 * 1024 * 1024

    @patch("pynukez.client.Keypair")
    def test_download_bytes_raises_on_redirect_without_location(self, mock_kp):
        """Gateway 307 with no Location header → NukezError, no body download."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {}
        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(return_value=preflight)

        with pytest.raises(NukezError, match="no Location header"):
            client.download_bytes("https://api.nukez.xyz/f/abcdef")

        # Only the preflight ran — no body download attempted.
        assert client._raw_client.get.call_count == 1


class TestDownloadToFile:
    """Verify the streaming download_to_file method."""

    @patch("pynukez.client.Keypair")
    def test_download_to_file_streams_to_disk(self, mock_kp, tmp_path):
        """download_to_file streams chunks into a destination file and returns
        size/hash metadata. No body is buffered in memory (no .content access)."""
        import hashlib as _hashlib

        client = Nukez(keypair_path="~/.config/solana/id.json")
        payload = b"".join(bytes([i % 256] * 1024) for i in range(1024))  # 1 MB
        expected_hash = _hashlib.sha256(payload).hexdigest()

        stream_resp = MagicMock()
        stream_resp.status_code = 200
        stream_resp.raise_for_status = MagicMock()
        stream_resp.iter_bytes = MagicMock(return_value=iter([payload[:512 * 1024], payload[512 * 1024:]]))

        stream_ctx = MagicMock()
        stream_ctx.__enter__ = MagicMock(return_value=stream_resp)
        stream_ctx.__exit__ = MagicMock(return_value=False)

        client._raw_client = MagicMock()
        client._raw_client.stream = MagicMock(return_value=stream_ctx)

        dest = tmp_path / "out.bin"
        result = client.download_to_file(
            "https://storage.googleapis.com/bucket/obj",
            dest,
        )

        # stream() was called with GET and the URL (no preflight for non-short URL)
        client._raw_client.stream.assert_called_once()
        call = client._raw_client.stream.call_args
        assert call.args[0] == "GET"
        assert call.args[1] == "https://storage.googleapis.com/bucket/obj"

        # File written to disk
        assert dest.exists()
        assert dest.read_bytes() == payload

        # Return metadata
        assert result["dest_path"] == str(dest)
        assert result["size_bytes"] == len(payload)
        assert result["content_hash"] == f"sha256:{expected_hash}"
        assert result["download_url"] == "https://storage.googleapis.com/bucket/obj"
        assert result["attempts"] == 1

    @patch("pynukez.client.Keypair")
    def test_download_to_file_preflights_short_url(self, mock_kp, tmp_path):
        """download_to_file resolves the 307 redirect for gateway short URLs,
        then streams from the resolved URL."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        resolved = "https://storage.googleapis.com/bucket/obj?X-Goog-Signature=xyz"

        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": resolved}

        stream_resp = MagicMock()
        stream_resp.status_code = 200
        stream_resp.raise_for_status = MagicMock()
        stream_resp.iter_bytes = MagicMock(return_value=iter([b"chunk"]))

        stream_ctx = MagicMock()
        stream_ctx.__enter__ = MagicMock(return_value=stream_resp)
        stream_ctx.__exit__ = MagicMock(return_value=False)

        client._raw_client = MagicMock()
        client._raw_client.get = MagicMock(return_value=preflight)
        client._raw_client.stream = MagicMock(return_value=stream_ctx)

        dest = tmp_path / "out.bin"
        result = client.download_to_file(
            "https://api.nukez.xyz/f/abcdef",
            dest,
            verify_hash=False,
        )

        # Preflight GET fired once with follow_redirects=False
        client._raw_client.get.assert_called_once()
        pf_call = client._raw_client.get.call_args
        assert pf_call.args[0] == "https://api.nukez.xyz/f/abcdef"
        assert pf_call.kwargs["follow_redirects"] is False

        # Stream targeted the resolved URL, not the short URL
        stream_call = client._raw_client.stream.call_args
        assert stream_call.args[1] == resolved

        assert dest.read_bytes() == b"chunk"
        # Original URL returned, not resolved
        assert result["download_url"] == "https://api.nukez.xyz/f/abcdef"
        assert result["size_bytes"] == 5
        # verify_hash=False → empty content_hash
        assert result["content_hash"] == ""

    @patch("pynukez.client.Keypair")
    def test_download_to_file_raises_if_parent_missing(self, mock_kp, tmp_path):
        """download_to_file refuses to stream into a non-existent directory."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client._raw_client = MagicMock()

        missing_dir = tmp_path / "does_not_exist"
        with pytest.raises(NukezError, match="Parent directory does not exist"):
            client.download_to_file(
                "https://storage.googleapis.com/bucket/obj",
                missing_dir / "out.bin",
            )

        # No HTTP calls made — rejected at validation.
        client._raw_client.stream.assert_not_called()


class TestUploadBytesContentType:
    """Verify upload_bytes Content-Type header behavior after requests→httpx migration."""

    @patch("pynukez.client.Keypair")
    def test_default_content_type_is_octet_stream(self, mock_kp):
        """upload_bytes defaults to application/octet-stream, matching create_file's default.

        GCS signed URLs include content-type in X-Goog-SignedHeaders.
        The Content-Type must match what create_file signed into the URL.
        create_file defaults to application/octet-stream, so upload_bytes must too.
        """
        client = Nukez(keypair_path="~/.config/solana/id.json")
        # Preflight: gateway 307s to resolved storage URL.
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": "https://storage.googleapis.com/signed-url"}
        # Real upload: 200 OK.
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.raise_for_status = MagicMock()
        client._raw_client = MagicMock()
        client._raw_client.put = MagicMock(side_effect=[preflight, upload_resp])

        client.upload_bytes("https://api.nukez.xyz/f/token", b"Hello!")

        # The real upload (second call) carries the Content-Type header.
        upload_call = client._raw_client.put.call_args_list[1]
        assert upload_call.kwargs["headers"]["Content-Type"] == "application/octet-stream"

    @patch("pynukez.client.Keypair")
    def test_content_type_header_sent_when_specified(self, mock_kp):
        """upload_bytes sends Content-Type when caller provides it."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": "https://storage.googleapis.com/signed-url"}
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.raise_for_status = MagicMock()
        client._raw_client = MagicMock()
        client._raw_client.put = MagicMock(side_effect=[preflight, upload_resp])

        client.upload_bytes(
            "https://api.nukez.xyz/f/token", b"Hello!", content_type="text/plain"
        )

        # Both calls carry the same Content-Type: the preflight (for signed
        # headers) and the real upload (for GCS to validate).
        for call in client._raw_client.put.call_args_list:
            assert call.kwargs["headers"]["Content-Type"] == "text/plain"

    @patch("pynukez.client.Keypair")
    def test_upload_bytes_uses_raw_client(self, mock_kp):
        """upload_bytes uses self._raw_client for both preflight and body PUT."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": "https://storage.googleapis.com/signed-url"}
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.raise_for_status = MagicMock()
        client._raw_client = MagicMock()
        client._raw_client.put = MagicMock(side_effect=[preflight, upload_resp])

        client.upload_bytes("https://api.nukez.xyz/f/token", b"data")

        # Two PUTs: one bodyless preflight, one body PUT to resolved URL.
        assert client._raw_client.put.call_count == 2

    @patch("pynukez.client.Keypair")
    def test_upload_bytes_preflights_short_url_and_uploads_to_resolved(self, mock_kp):
        """upload_bytes resolves the 307 redirect and PUTs the body to the
        gateway-provided Location, bypassing Cloud Run's 32 MB request limit.
        """
        client = Nukez(keypair_path="~/.config/solana/id.json")
        resolved = "https://storage.googleapis.com/bucket/obj?X-Goog-Signature=abc"
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": resolved}
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.raise_for_status = MagicMock()
        client._raw_client = MagicMock()
        client._raw_client.put = MagicMock(side_effect=[preflight, upload_resp])

        payload = b"x" * (40 * 1024 * 1024)  # 40 MB — above Cloud Run's limit
        result = client.upload_bytes(
            "https://api.nukez.xyz/f/abcdef", payload, content_type="application/pdf"
        )

        # Preflight: bodyless PUT to short URL, follow_redirects=False
        preflight_call = client._raw_client.put.call_args_list[0]
        assert preflight_call.args[0] == "https://api.nukez.xyz/f/abcdef"
        assert preflight_call.kwargs["content"] == b""
        assert preflight_call.kwargs["follow_redirects"] is False

        # Real upload: body PUT to resolved GCS URL
        upload_call = client._raw_client.put.call_args_list[1]
        assert upload_call.args[0] == resolved
        assert upload_call.kwargs["content"] == payload

        # Result reports the original short URL, not the resolved GCS URL
        assert result.upload_url == "https://api.nukez.xyz/f/abcdef"
        assert result.size_bytes == len(payload)
        assert result.content_type == "application/pdf"

    @patch("pynukez.client.Keypair")
    def test_upload_bytes_raises_on_redirect_without_location(self, mock_kp):
        """Gateway 307 without Location header → NukezError, don't send body."""
        from pynukez.errors import NukezError

        client = Nukez(keypair_path="~/.config/solana/id.json")
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {}  # no Location
        client._raw_client = MagicMock()
        client._raw_client.put = MagicMock(return_value=preflight)

        with pytest.raises(NukezError, match="no Location header"):
            client.upload_bytes("https://api.nukez.xyz/f/token", b"data")

        # Only the preflight was attempted — no body ever sent.
        assert client._raw_client.put.call_count == 1

    @patch("pynukez.client.Keypair")
    def test_upload_bytes_skips_preflight_for_non_short_url(self, mock_kp):
        """Non-gateway URLs (e.g. pre-resolved GCS URL) skip the preflight."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.raise_for_status = MagicMock()
        client._raw_client = MagicMock()
        client._raw_client.put = MagicMock(return_value=upload_resp)

        client.upload_bytes(
            "https://storage.googleapis.com/bucket/obj?X-Goog-Signature=abc",
            b"data",
        )

        # Only one PUT — direct, no preflight.
        assert client._raw_client.put.call_count == 1
        call = client._raw_client.put.call_args_list[0]
        assert call.args[0] == "https://storage.googleapis.com/bucket/obj?X-Goog-Signature=abc"
        assert call.kwargs["content"] == b"data"
        # follow_redirects was NOT overridden — no preflight kwarg on this call
        assert "follow_redirects" not in call.kwargs

    @patch("pynukez.client.Keypair")
    def test_upload_bytes_surfaces_preflight_4xx_errors(self, mock_kp):
        """Preflight 4xx (expired URL, bad token) surfaces via raise_for_status."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        preflight = MagicMock()
        preflight.status_code = 410  # expired signed URL
        preflight.raise_for_status = MagicMock(side_effect=RuntimeError("410 Gone"))
        client._raw_client = MagicMock()
        client._raw_client.put = MagicMock(return_value=preflight)

        with pytest.raises(RuntimeError, match="410 Gone"):
            client.upload_bytes("https://api.nukez.xyz/f/expired", b"data")

        # Body never sent — failed during preflight.
        assert client._raw_client.put.call_count == 1


class TestDelegatingFlag:
    """Verify _is_delegating and delegating= threading to build_signed_envelope."""

    @patch("pynukez.client.Keypair")
    def test_is_delegating_returns_true_when_signer_differs(self, mock_kp):
        """Operator signer (different identity) → _is_delegating returns True."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        # Simulate: signer is an operator, owner is someone else
        mock_signer = MagicMock()
        mock_signer.identity = "operator_pubkey_abc"
        client._signer = mock_signer
        client._receipt_state["receipt_123"] = _ReceiptState(
            owner_identity="owner_pubkey_xyz", sig_alg="ed25519"
        )

        assert client._is_delegating("receipt_123") is True

    @patch("pynukez.client.Keypair")
    def test_is_delegating_returns_false_when_signer_is_owner(self, mock_kp):
        """Owner signer (same identity) → _is_delegating returns False."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        mock_signer = MagicMock()
        mock_signer.identity = "owner_pubkey_xyz"
        client._signer = mock_signer
        client._receipt_state["receipt_123"] = _ReceiptState(
            owner_identity="owner_pubkey_xyz", sig_alg="ed25519"
        )

        assert client._is_delegating("receipt_123") is False

    @patch("pynukez.client.Keypair")
    def test_is_delegating_defaults_true_when_owner_unknown_single_key(self, mock_kp):
        """Single-key client + unknown owner → True (legacy safe default preserved)."""
        client = Nukez(keypair_path="~/.config/solana/id.json")
        mock_signer = MagicMock()
        mock_signer.identity = "operator_pubkey_abc"
        client._signer = mock_signer
        # No entry in _receipt_state, no _evm_signer → legacy default
        assert client._evm_signer is None
        assert client._is_delegating("unknown_receipt") is True

    @patch("pynukez.client.Keypair")
    def test_is_delegating_raises_on_cold_dual_key(self, mock_kp):
        """Dual-key client + unknown receipt → ReceiptStateNotBoundError."""
        from pynukez.errors import ReceiptStateNotBoundError

        client = Nukez(keypair_path="~/.config/solana/id.json")
        # Simulate dual-key by stubbing an EVM signer onto the client.
        client._evm_signer = MagicMock()
        client._evm_signer.identity = "0x" + "a" * 40
        with pytest.raises(ReceiptStateNotBoundError) as exc_info:
            client._is_delegating("unknown_receipt")
        assert exc_info.value.receipt_id == "unknown_receipt"

    @patch("pynukez.client.build_signed_envelope")
    @patch("pynukez.client.Keypair")
    def test_data_plane_passes_delegating_true_for_operator(self, mock_kp_cls, mock_build):
        """Data-plane method (list_files) passes delegating=True when signer != owner."""
        mock_build.return_value = MagicMock(
            headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"},
        )
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.http = MagicMock()
        client.http.get.return_value = {"files": []}

        # Set up operator scenario: signer != owner
        mock_signer = MagicMock()
        mock_signer.identity = "operator_pubkey_abc"
        client._signer = mock_signer
        client._receipt_state["receipt_123"] = _ReceiptState(
            owner_identity="owner_pubkey_xyz", sig_alg="ed25519"
        )

        client.list_files("receipt_123")

        # Verify build_signed_envelope was called with delegating=True
        assert mock_build.call_args.kwargs["delegating"] is True

    @patch("pynukez.client.build_signed_envelope")
    @patch("pynukez.client.Keypair")
    def test_data_plane_passes_delegating_false_for_owner(self, mock_kp_cls, mock_build):
        """Data-plane method (list_files) passes delegating=False when signer == owner."""
        mock_build.return_value = MagicMock(
            headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"},
        )
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.http = MagicMock()
        client.http.get.return_value = {"files": []}

        # Set up owner scenario: signer == owner
        mock_signer = MagicMock()
        mock_signer.identity = "owner_pubkey_xyz"
        client._signer = mock_signer
        client._receipt_state["receipt_123"] = _ReceiptState(
            owner_identity="owner_pubkey_xyz", sig_alg="ed25519"
        )

        client.list_files("receipt_123")

        # Verify build_signed_envelope was called with delegating=False
        assert mock_build.call_args.kwargs["delegating"] is False

    @patch("pynukez.client.build_signed_envelope")
    @patch("pynukez.client.Keypair")
    def test_admin_op_does_not_pass_delegating(self, mock_kp_cls, mock_build):
        """Admin method (add_operator) does NOT pass delegating — owner-only."""
        mock_build.return_value = MagicMock(
            headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"},
        )
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.http = MagicMock()
        client.http.post.return_value = {"ok": True, "operator_ids": []}

        client.add_operator("receipt_123", "some_operator_pubkey")

        # Admin ops should NOT have delegating in kwargs (defaults to False)
        assert "delegating" not in mock_build.call_args.kwargs


class TestKeypairDualInit:
    """Keypair is still initialized when signing_key is injected."""

    @patch("pynukez.client.Keypair")
    def test_keypair_initialized_with_signing_key(self, mock_kp):
        mock_signer = MagicMock()
        mock_signer.identity = "external-signer-id"
        mock_signer.sig_alg = "ed25519"
        client = Nukez(
            keypair_path="~/.config/solana/id.json",
            signing_key=mock_signer,
        )
        assert client._signer is mock_signer
        mock_kp.assert_called_once_with("~/.config/solana/id.json")
        assert client.keypair is mock_kp.return_value

    @patch("pynukez.client.Keypair")
    def test_keypair_none_without_keypair_path(self, mock_kp):
        mock_signer = MagicMock()
        mock_signer.identity = "external-signer-id"
        mock_signer.sig_alg = "ed25519"
        client = Nukez(signing_key=mock_signer)
        assert client._signer is mock_signer
        assert client.keypair is None


class TestSetOwner:
    """set_owner() pre-seeds owner identity via bind_receipt()."""

    @patch("pynukez.client.Keypair")
    def test_set_owner_uses_signer_identity(self, mock_kp):
        # Use a real-format base58 Ed25519 pubkey so sig_alg can be inferred.
        real_ed25519 = "BhBeSkwKyqysZstzkqdf4qAcYfS9r27wEMmouvSVfp1U"
        mock_kp.return_value.identity = real_ed25519
        mock_kp.return_value.sig_alg = "ed25519"
        mock_kp.return_value.sign.return_value = "sig"
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.set_owner("receipt-123")
        state = client._receipt_state["receipt-123"]
        assert state.owner_identity == real_ed25519
        assert state.sig_alg == "ed25519"
        assert client._is_delegating("receipt-123") is False

    @patch("pynukez.client.Keypair")
    def test_set_owner_explicit_identity(self, mock_kp):
        real_ed25519_owner = "BhBeSkwKyqysZstzkqdf4qAcYfS9r27wEMmouvSVfp1U"
        mock_kp.return_value.identity = "DifferentKeyHereMockedForSignerXxxxxxxxxx"
        mock_kp.return_value.sig_alg = "ed25519"
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.set_owner("receipt-123", identity=real_ed25519_owner)
        assert client._receipt_state["receipt-123"].owner_identity == real_ed25519_owner

    def test_set_owner_no_signer_raises(self):
        client = Nukez()
        with pytest.raises(NukezError, match="requires either an explicit identity"):
            client.set_owner("receipt-123")

    def test_set_owner_no_signer_with_explicit_identity(self):
        client = Nukez()
        real_owner = "0x" + "c" * 40
        client.set_owner("receipt-123", identity=real_owner)
        state = client._receipt_state["receipt-123"]
        assert state.owner_identity == real_owner
        assert state.sig_alg == "secp256k1"  # inferred from 0x prefix


class TestUploadFilesConfirmFailure:
    """upload_files() must not swallow confirm failures.

    Routine attestation trusts the manifest's recorded content_hash and does
    not recompute hashes, so a file whose confirm silently failed would stay
    unverified forever while being reported as an upload success. A confirm
    failure must count the file as failed and record the error, the same way
    bulk_upload_paths propagates confirm failures.
    """

    @patch("pynukez.client.Keypair")
    def test_confirm_failure_counts_file_as_failed(self, mock_kp):
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.create_file = MagicMock(return_value=MagicMock(
            upload_url="https://storage.example/upload",
        ))
        client.upload_bytes = MagicMock(return_value=MagicMock())

        def _confirm(receipt_id, fname):
            if fname == "b.txt":
                raise NukezError("confirm exploded")
            return MagicMock()

        client.confirm_file = MagicMock(side_effect=_confirm)

        files = [
            {"filename": "a.txt", "content": b"aa"},
            {"filename": "b.txt", "content": b"bb"},
        ]
        result = client.upload_files("r1", files, workers=1)

        assert result.total == 2
        assert result.uploaded == 1
        assert result.failed == 1
        errors = dict(result.errors)
        assert "b.txt" in errors
        assert "confirm exploded" in errors["b.txt"]

    @patch("pynukez.client.Keypair")
    def test_confirm_success_still_counts_as_uploaded(self, mock_kp):
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.create_file = MagicMock(return_value=MagicMock(
            upload_url="https://storage.example/upload",
        ))
        client.upload_bytes = MagicMock(return_value=MagicMock())
        client.confirm_file = MagicMock(return_value=MagicMock())

        result = client.upload_files(
            "r1", [{"filename": "a.txt", "content": b"aa"}], workers=1,
        )

        assert result.uploaded == 1
        assert result.failed == 0
        client.confirm_file.assert_called_once_with("r1", "a.txt")
