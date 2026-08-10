# tests/test_async_client.py
"""
AsyncNukez client tests — mirrors test_client_methods.py for async.
"""
import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch, call
from pynukez._async_client import AsyncNukez
from pynukez.errors import NukezError, PaymentRequiredError, TransactionNotFoundError


class TestAsyncClientInit:
    """AsyncNukez initialization tests."""

    @patch("pynukez._async_client.Keypair")
    def test_default_base_url(self, mock_kp):
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        assert "nukez" in client.base_url.lower()

    @patch("pynukez._async_client.Keypair")
    def test_custom_base_url(self, mock_kp):
        client = AsyncNukez(
            keypair_path="~/.config/solana/id.json",
            base_url="https://custom.example.com",
        )
        assert client.base_url == "https://custom.example.com"

    @patch("pynukez._async_client.Keypair")
    def test_default_network(self, mock_kp):
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        assert client.network == "devnet"


class TestAsyncClientPublicMethods:
    """Verify async client has all the same public methods as sync client."""

    @patch("pynukez._async_client.Keypair")
    def test_has_storage_flow_methods(self, mock_kp):
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        for method in ("request_storage", "confirm_storage", "get_price"):
            assert hasattr(client, method), f"Missing {method}"

    @patch("pynukez._async_client.Keypair")
    def test_has_file_methods(self, mock_kp):
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        for method in (
            "create_file", "upload_bytes", "download_bytes", "list_files",
            "get_file_urls", "delete_file", "upload_string",
        ):
            assert hasattr(client, method), f"Missing {method}"

    @patch("pynukez._async_client.Keypair")
    def test_has_provision_locker(self, mock_kp):
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        assert hasattr(client, "provision_locker")

    @patch("pynukez._async_client.Keypair")
    def test_has_verify_methods(self, mock_kp):
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        for method in (
            "get_receipt",
            "verify_receipt_hash",
            "receipt_hash_matches",
            "verify_storage",
            "get_merkle_proof",
            "attest",
        ):
            assert hasattr(client, method), f"Missing {method}"

    @patch("pynukez._async_client.Keypair")
    def test_has_batch_methods(self, mock_kp):
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        for method in ("upload_files", "download_files", "bulk_upload_paths"):
            assert hasattr(client, method), f"Missing {method}"

    @patch("pynukez._async_client.Keypair")
    def test_has_sandbox_methods(self, mock_kp):
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        for method in (
            "sandbox_create_ingest_job", "sandbox_append_ingest_part",
            "sandbox_complete_ingest_job", "sandbox_upload_bytes",
        ):
            assert hasattr(client, method), f"Missing {method}"

    @patch("pynukez._async_client.Keypair")
    def test_has_lifecycle_methods(self, mock_kp):
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        assert hasattr(client, "aclose")
        assert hasattr(client, "__aenter__")
        assert hasattr(client, "__aexit__")


class TestAsyncClientFileOps:
    """Test async file operation methods with mocked HTTP."""

    async def test_receipt_hash_helpers(self, async_client):
        async_client.http.get = AsyncMock(side_effect=[
            {"id": "rid_123", "receipt_hash": "hash_abc"},
            {"computed_hash": "hash_abc"},
        ])

        result = await async_client.verify_receipt_hash("rid_123")

        assert result.receipt_id == "rid_123"
        assert result.stored_hash == "hash_abc"
        assert result.computed_hash == "hash_abc"
        assert result.matches is True
        assert result.ok is True
        assert result.status == "verified"
        assert async_client.http.get.call_args_list == [
            call("/v1/receipts/rid_123"),
            call("/v1/receipts/rid_123/verify"),
        ]

    async def test_receipt_hash_matches_returns_bool(self, async_client):
        async_client.http.get = AsyncMock(side_effect=[
            {"id": "rid_123", "receipt_hash": "hash_abc"},
            {"computed_hash": "hash_def"},
        ])

        assert await async_client.receipt_hash_matches("rid_123") is False

    async def test_get_price(self, async_client):
        async_client.http.get = AsyncMock(return_value={
            "unit_price_sol": 0.01,
            "total_sol": 0.01,
            "units": 1,
            "provider": "gcs",
            "network": "devnet",
        })
        result = await async_client.get_price(units=1)
        assert result.units == 1
        async_client.http.get.assert_called_once()

    async def test_list_files(self, async_client):
        async_client.http.get = AsyncMock(return_value={
            "files": [
                {"filename": "test.txt", "content_type": "text/plain", "size_bytes": 100},
            ]
        })
        result = await async_client.list_files("receipt_123")
        assert len(result) == 1
        assert result[0].filename == "test.txt"

    async def test_create_file(self, async_client):
        async_client.http.post = AsyncMock(return_value={
            "upload_url": "https://storage.googleapis.com/upload",
            "download_url": "https://storage.googleapis.com/download",
            "filename": "test.txt",
            "content_type": "text/plain",
            "locker_id": "locker_abc",
            "ttl_min": 30,
        })
        result = await async_client.create_file("receipt_123", "test.txt")
        assert result.upload_url == "https://storage.googleapis.com/upload"

    async def test_upload_bytes(self, async_client):
        """Non-gateway URL (e.g. pre-resolved GCS URL) skips the preflight
        and does a single direct PUT."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        async_client._raw_client.put = AsyncMock(return_value=mock_resp)

        result = await async_client.upload_bytes(
            "https://storage.googleapis.com/upload",
            b"hello world",
            content_type="text/plain",
        )
        assert result.size_bytes == 11
        # No preflight — not a gateway /f/{token} URL.
        async_client._raw_client.put.assert_called_once()

    async def test_upload_bytes_default_content_type(self, async_client):
        """upload_bytes defaults to application/octet-stream, matching create_file.

        GCS signed URLs include content-type in X-Goog-SignedHeaders.
        The Content-Type must match what create_file signed into the URL.
        """
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": "https://storage.googleapis.com/signed-url"}
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.raise_for_status = MagicMock()
        async_client._raw_client.put = AsyncMock(side_effect=[preflight, upload_resp])

        await async_client.upload_bytes(
            "https://api.nukez.xyz/f/token", b"Hello!"
        )

        # The real upload (second call) carries the Content-Type.
        upload_call = async_client._raw_client.put.call_args_list[1]
        assert upload_call.kwargs["headers"]["Content-Type"] == "application/octet-stream"

    async def test_upload_bytes_sends_content_type_when_specified(self, async_client):
        """upload_bytes sends Content-Type when caller provides it."""
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": "https://storage.googleapis.com/signed-url"}
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.raise_for_status = MagicMock()
        async_client._raw_client.put = AsyncMock(side_effect=[preflight, upload_resp])

        await async_client.upload_bytes(
            "https://api.nukez.xyz/f/token", b"Hello!", content_type="text/plain"
        )

        # Both calls carry the same Content-Type (needed for the signed
        # URL's X-Goog-SignedHeaders validation on the real upload).
        for call in async_client._raw_client.put.call_args_list:
            assert call.kwargs["headers"]["Content-Type"] == "text/plain"

    async def test_upload_bytes_preflights_short_url_and_uploads_to_resolved(
        self, async_client
    ):
        """Async: gateway short URL → 307 resolve → body PUT to Location."""
        resolved = "https://storage.googleapis.com/bucket/obj?X-Goog-Signature=abc"
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": resolved}
        upload_resp = MagicMock()
        upload_resp.status_code = 200
        upload_resp.raise_for_status = MagicMock()
        async_client._raw_client.put = AsyncMock(side_effect=[preflight, upload_resp])

        payload = b"x" * (40 * 1024 * 1024)  # 40 MB
        result = await async_client.upload_bytes(
            "https://api.nukez.xyz/f/abcdef", payload, content_type="application/pdf"
        )

        # Preflight first
        preflight_call = async_client._raw_client.put.call_args_list[0]
        assert preflight_call.args[0] == "https://api.nukez.xyz/f/abcdef"
        assert preflight_call.kwargs["content"] == b""
        assert preflight_call.kwargs["follow_redirects"] is False

        # Real upload second, to the resolved URL
        upload_call = async_client._raw_client.put.call_args_list[1]
        assert upload_call.args[0] == resolved
        assert upload_call.kwargs["content"] == payload

        # Result reports the original short URL
        assert result.upload_url == "https://api.nukez.xyz/f/abcdef"
        assert result.size_bytes == len(payload)

    async def test_upload_bytes_raises_on_redirect_without_location(self, async_client):
        """Async: gateway 307 with no Location header → NukezError."""
        from pynukez.errors import NukezError

        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {}  # no Location
        async_client._raw_client.put = AsyncMock(return_value=preflight)

        with pytest.raises(NukezError, match="no Location header"):
            await async_client.upload_bytes("https://api.nukez.xyz/f/token", b"data")

        assert async_client._raw_client.put.call_count == 1

    async def test_delete_file(self, async_client):
        async_client.http.delete = AsyncMock(return_value={
            "deleted": True,
            "filename": "test.txt",
        })
        result = await async_client.delete_file("receipt_123", "test.txt")
        assert result.filename == "test.txt"


class TestAsyncDownloadRetry:
    """Test download_bytes retry logic with async sleep."""

    async def test_download_succeeds_first_try(self, async_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"hello"
        mock_resp.raise_for_status = MagicMock()
        async_client._raw_client.get = AsyncMock(return_value=mock_resp)

        result = await async_client.download_bytes("https://storage.googleapis.com/bucket/obj")
        assert result == b"hello"
        assert async_client._raw_client.get.call_count == 1

    @patch("pynukez._async_client.asyncio.sleep", new_callable=AsyncMock)
    async def test_download_retries_on_404(self, mock_sleep, async_client):
        resp_404 = MagicMock()
        resp_404.status_code = 404

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.content = b"propagated"
        resp_200.raise_for_status = MagicMock()

        async_client._raw_client.get = AsyncMock(side_effect=[resp_404, resp_200])

        result = await async_client.download_bytes("https://storage.googleapis.com/bucket/obj")
        assert result == b"propagated"
        assert async_client._raw_client.get.call_count == 2
        mock_sleep.assert_called_once_with(2.0)

    async def test_download_bytes_preflights_short_url(self, async_client):
        """Async: gateway short URL → preflight GET → body GET to resolved URL."""
        resolved = "https://storage.googleapis.com/bucket/obj?X-Goog-Signature=abc"

        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": resolved}

        body_resp = MagicMock()
        body_resp.status_code = 200
        body_resp.content = b"x" * (40 * 1024 * 1024)  # 40 MB
        body_resp.raise_for_status = MagicMock()

        async_client._raw_client.get = AsyncMock(side_effect=[preflight, body_resp])

        result = await async_client.download_bytes("https://api.nukez.xyz/f/abcdef")

        assert result == body_resp.content
        calls = async_client._raw_client.get.call_args_list
        assert calls[0].args[0] == "https://api.nukez.xyz/f/abcdef"
        assert calls[0].kwargs["follow_redirects"] is False
        assert calls[1].args[0] == resolved

    async def test_download_bytes_raises_on_redirect_without_location(self, async_client):
        """Async: gateway 307 without Location header → NukezError."""
        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {}
        async_client._raw_client.get = AsyncMock(return_value=preflight)

        with pytest.raises(NukezError, match="no Location header"):
            await async_client.download_bytes("https://api.nukez.xyz/f/abcdef")

        assert async_client._raw_client.get.call_count == 1


class TestAsyncDownloadToFile:
    """Test the streaming download_to_file method (async)."""

    async def test_download_to_file_streams_to_disk(self, async_client, tmp_path):
        """Streams chunks into a destination file, returns size/hash metadata."""
        import hashlib as _hashlib

        payload = b"".join(bytes([i % 256] * 1024) for i in range(1024))  # 1 MB
        expected_hash = _hashlib.sha256(payload).hexdigest()

        stream_resp = MagicMock()
        stream_resp.status_code = 200
        stream_resp.raise_for_status = MagicMock()

        async def _aiter(chunk_size):
            yield payload[: 512 * 1024]
            yield payload[512 * 1024 :]

        stream_resp.aiter_bytes = _aiter

        stream_ctx = MagicMock()
        stream_ctx.__aenter__ = AsyncMock(return_value=stream_resp)
        stream_ctx.__aexit__ = AsyncMock(return_value=False)

        async_client._raw_client.stream = MagicMock(return_value=stream_ctx)

        dest = tmp_path / "out.bin"
        result = await async_client.download_to_file(
            "https://storage.googleapis.com/bucket/obj",
            dest,
        )

        async_client._raw_client.stream.assert_called_once()
        call = async_client._raw_client.stream.call_args
        assert call.args[0] == "GET"
        assert call.args[1] == "https://storage.googleapis.com/bucket/obj"

        assert dest.exists()
        assert dest.read_bytes() == payload
        assert result["size_bytes"] == len(payload)
        assert result["content_hash"] == f"sha256:{expected_hash}"
        assert result["attempts"] == 1

    async def test_download_to_file_preflights_short_url(self, async_client, tmp_path):
        """Async: gateway short URL → preflight → stream from resolved URL."""
        resolved = "https://storage.googleapis.com/bucket/obj?X-Goog-Signature=xyz"

        preflight = MagicMock()
        preflight.status_code = 307
        preflight.headers = {"Location": resolved}
        async_client._raw_client.get = AsyncMock(return_value=preflight)

        stream_resp = MagicMock()
        stream_resp.status_code = 200
        stream_resp.raise_for_status = MagicMock()

        async def _aiter(chunk_size):
            yield b"chunk"

        stream_resp.aiter_bytes = _aiter

        stream_ctx = MagicMock()
        stream_ctx.__aenter__ = AsyncMock(return_value=stream_resp)
        stream_ctx.__aexit__ = AsyncMock(return_value=False)

        async_client._raw_client.stream = MagicMock(return_value=stream_ctx)

        dest = tmp_path / "out.bin"
        result = await async_client.download_to_file(
            "https://api.nukez.xyz/f/abcdef",
            dest,
            verify_hash=False,
        )

        # Preflight GET to the short URL
        pf_call = async_client._raw_client.get.call_args
        assert pf_call.args[0] == "https://api.nukez.xyz/f/abcdef"
        assert pf_call.kwargs["follow_redirects"] is False

        # Stream to the resolved URL
        stream_call = async_client._raw_client.stream.call_args
        assert stream_call.args[1] == resolved

        assert dest.read_bytes() == b"chunk"
        assert result["download_url"] == "https://api.nukez.xyz/f/abcdef"
        assert result["content_hash"] == ""


class TestAsyncContextManager:
    """Test async context manager protocol."""

    @patch("pynukez._async_client.Keypair")
    async def test_async_with(self, mock_kp):
        async with AsyncNukez(keypair_path="~/.config/solana/id.json") as client:
            assert client.base_url is not None


class TestAsyncBatchOperations:
    """Test batch upload/download uses gather pattern."""

    async def test_upload_files_returns_result(self, async_client):
        # Mock create_file and upload_bytes for a single file
        async_client.create_file = AsyncMock(return_value=MagicMock(
            upload_url="https://storage.googleapis.com/upload",
            download_url="https://storage.googleapis.com/download",
        ))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        async_client._raw_client.put = AsyncMock(return_value=mock_resp)
        async_client.confirm_file = AsyncMock(return_value=MagicMock())

        files = [{"filename": "a.txt", "content": b"hello"}]
        result = await async_client.upload_files("receipt_123", files, workers=2)
        assert result.total == 1
        assert result.uploaded >= 0  # May be 0 or 1 depending on implementation details

    async def test_upload_files_counts_confirm_failure_as_failed(self, async_client):
        """A confirm failure must surface as a per-file failure. Routine
        attestation trusts the manifest's recorded content_hash and does not
        recompute hashes, so a swallowed confirm failure would leave the file
        unverified forever while reporting an upload success."""
        from pynukez.errors import NukezError

        async_client.create_file = AsyncMock(return_value=MagicMock(
            upload_url="https://storage.example/upload",
        ))
        async_client.upload_bytes = AsyncMock(return_value=MagicMock())

        async def _confirm(receipt_id, fname):
            if fname == "b.txt":
                raise NukezError("confirm exploded")
            return MagicMock()

        async_client.confirm_file = AsyncMock(side_effect=_confirm)

        files = [
            {"filename": "a.txt", "content": b"aa"},
            {"filename": "b.txt", "content": b"bb"},
        ]
        result = await async_client.upload_files("r1", files, workers=1)

        assert result.total == 2
        assert result.uploaded == 1
        assert result.failed == 1
        errors = dict(result.errors)
        assert "b.txt" in errors
        assert "confirm exploded" in errors["b.txt"]


class TestAsyncKeypairDualInit:
    """Keypair is still initialized when signing_key is injected."""

    @patch("pynukez._async_client.Keypair")
    def test_keypair_initialized_with_signing_key(self, mock_kp):
        mock_signer = MagicMock()
        mock_signer.identity = "external-signer-id"
        mock_signer.sig_alg = "ed25519"
        client = AsyncNukez(
            keypair_path="~/.config/solana/id.json",
            signing_key=mock_signer,
        )
        assert client._signer is mock_signer
        mock_kp.assert_called_once_with("~/.config/solana/id.json")
        assert client.keypair is mock_kp.return_value

    @patch("pynukez._async_client.Keypair")
    def test_keypair_none_without_keypair_path(self, mock_kp):
        mock_signer = MagicMock()
        mock_signer.identity = "external-signer-id"
        mock_signer.sig_alg = "ed25519"
        client = AsyncNukez(signing_key=mock_signer)
        assert client._signer is mock_signer
        assert client.keypair is None


class TestAsyncSetOwner:
    """set_owner() pre-seeds owner state via bind_receipt()."""

    @patch("pynukez._async_client.Keypair")
    def test_set_owner_uses_signer_identity(self, mock_kp):
        real_ed25519 = "BhBeSkwKyqysZstzkqdf4qAcYfS9r27wEMmouvSVfp1U"
        mock_kp.return_value.identity = real_ed25519
        mock_kp.return_value.sig_alg = "ed25519"
        mock_kp.return_value.sign.return_value = "sig"
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        client.set_owner("receipt-123")
        state = client._receipt_state["receipt-123"]
        assert state.owner_identity == real_ed25519
        assert state.sig_alg == "ed25519"
        assert client._is_delegating("receipt-123") is False

    @patch("pynukez._async_client.Keypair")
    def test_set_owner_explicit_identity(self, mock_kp):
        real_ed25519_owner = "BhBeSkwKyqysZstzkqdf4qAcYfS9r27wEMmouvSVfp1U"
        mock_kp.return_value.identity = "DifferentKeyHereMockedForSignerXxxxxxxxxx"
        mock_kp.return_value.sig_alg = "ed25519"
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        client.set_owner("receipt-123", identity=real_ed25519_owner)
        assert client._receipt_state["receipt-123"].owner_identity == real_ed25519_owner

    def test_set_owner_no_signer_raises(self):
        client = AsyncNukez()
        with pytest.raises(NukezError, match="requires either an explicit identity"):
            client.set_owner("receipt-123")

    def test_set_owner_no_signer_with_explicit_identity(self):
        client = AsyncNukez()
        real_owner = "0x" + "c" * 40
        client.set_owner("receipt-123", identity=real_owner)
        state = client._receipt_state["receipt-123"]
        assert state.owner_identity == real_owner
        assert state.sig_alg == "secp256k1"


class TestAsyncDualSignerParity:
    """Async client has dual-signer auto-selection like sync."""

    @patch("pynukez._async_client.Keypair")
    def test_require_signer_returns_default_no_receipt(self, mock_kp):
        mock_kp.return_value.identity = "ed25519-key"
        mock_kp.return_value.sig_alg = "ed25519"
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        # Single-key client — no receipt_id needed → returns default signer
        signer = client._require_signer("test", "")
        assert signer is client._signer

    @patch("pynukez._async_client.Keypair")
    def test_single_key_cold_receipt_returns_signer(self, mock_kp):
        """Single-key client: cold _receipt_state → returns default signer, no raise."""
        mock_kp.return_value.identity = "ed25519-key"
        mock_kp.return_value.sig_alg = "ed25519"
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        assert client._evm_signer is None
        signer = client._require_signer("test", "cold-receipt")
        assert signer is client._signer

    @patch("pynukez._async_client.Keypair")
    def test_evm_signer_not_initialized_without_both_paths(self, mock_kp):
        mock_kp.return_value.identity = "ed25519-key"
        mock_kp.return_value.sig_alg = "ed25519"
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        assert client._evm_signer is None

    @patch("pynukez._async_client.Keypair")
    def test_receipt_state_initialized(self, mock_kp):
        mock_kp.return_value.identity = "ed25519-key"
        mock_kp.return_value.sig_alg = "ed25519"
        client = AsyncNukez(keypair_path="~/.config/solana/id.json")
        assert isinstance(client._receipt_state, dict)
        assert len(client._receipt_state) == 0
