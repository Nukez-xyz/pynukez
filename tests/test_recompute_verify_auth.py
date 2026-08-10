# tests/test_recompute_verify_auth.py
"""
recompute_verify authentication tests (§11.1b).

GET /v1/storage/recompute-verify is a signed gateway endpoint
(ops=["locker:read"]): it makes the gateway re-download file bytes from
storage, so the SDK must build and send a payer-signed envelope with the
receipt_id query string bound. These tests verify that both clients refuse
to call without a signing key (the same "requires a signing key" error the
other signed methods raise) and that, with a signer, the envelope binds the
exact GET request and the envelope headers reach the wire.
"""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from pynukez.errors import NukezError


_GATEWAY_RESPONSE = {
    "match": True,
    "receipt_id": "rcpt_1",
    "locker_id": "locker_abc",
    "computed": "sha256:aa",
    "stored": "sha256:aa",
    "file_count": 2,
    "recompute_ms": 42,
}


class TestSyncRecomputeVerifyAuth:
    def test_no_signer_raises(self, mock_keypair):
        from pynukez import Nukez
        client = Nukez(keypair_path="~/.config/solana/id.json")
        client.keypair = None
        client._signer = None  # simulate no signing key
        with pytest.raises(NukezError, match="requires a signing key"):
            client.recompute_verify("rcpt_1")

    def test_envelope_binds_get_request(self, sync_client):
        sync_client.http.get.return_value = dict(_GATEWAY_RESPONSE)
        with patch("pynukez.client.build_signed_envelope") as mock_env:
            mock_env.return_value = MagicMock(
                headers={
                    "X-Nukez-Envelope": "env_val",
                    "X-Nukez-Signature": "sig_val",
                },
                canonical_body=None,
            )
            result = sync_client.recompute_verify("rcpt_1")

        env_kwargs = mock_env.call_args[1]
        assert env_kwargs["method"] == "GET"
        assert env_kwargs["path"] == "/v1/storage/recompute-verify"
        assert env_kwargs["query"] == "receipt_id=rcpt_1"
        assert env_kwargs["ops"] == ["locker:read"]

        call_kwargs = sync_client.http.get.call_args[1]
        assert call_kwargs["headers"]["X-Nukez-Envelope"] == "env_val"
        assert call_kwargs["headers"]["X-Nukez-Signature"] == "sig_val"
        assert call_kwargs["params"] == {"receipt_id": "rcpt_1"}

        assert result.match is True
        assert result.file_count == 2
        assert result.recompute_ms == 42

    def test_timeout_flows_through(self, sync_client):
        sync_client.http.get.return_value = dict(_GATEWAY_RESPONSE)
        with patch("pynukez.client.build_signed_envelope") as mock_env:
            mock_env.return_value = MagicMock(
                headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"},
                canonical_body=None,
            )
            sync_client.recompute_verify("rcpt_1", timeout=300)
        assert sync_client.http.get.call_args[1]["timeout"] == 300


class TestAsyncRecomputeVerifyAuth:
    async def test_no_signer_raises(self, async_client):
        async_client.keypair = None
        async_client._signer = None  # simulate no signing key
        with pytest.raises(NukezError, match="requires a signing key"):
            await async_client.recompute_verify("rcpt_1")

    async def test_envelope_binds_get_request(self, async_client):
        async_client.http.get = AsyncMock(return_value=dict(_GATEWAY_RESPONSE))
        with patch("pynukez._async_client.build_signed_envelope") as mock_env:
            mock_env.return_value = MagicMock(
                headers={
                    "X-Nukez-Envelope": "env_val",
                    "X-Nukez-Signature": "sig_val",
                },
                canonical_body=None,
            )
            result = await async_client.recompute_verify("rcpt_1")

        env_kwargs = mock_env.call_args[1]
        assert env_kwargs["method"] == "GET"
        assert env_kwargs["path"] == "/v1/storage/recompute-verify"
        assert env_kwargs["query"] == "receipt_id=rcpt_1"
        assert env_kwargs["ops"] == ["locker:read"]

        call_kwargs = async_client.http.get.call_args[1]
        assert call_kwargs["headers"]["X-Nukez-Envelope"] == "env_val"
        assert call_kwargs["headers"]["X-Nukez-Signature"] == "sig_val"
        assert call_kwargs["params"] == {"receipt_id": "rcpt_1"}

        assert result.match is True
        assert result.file_count == 2
