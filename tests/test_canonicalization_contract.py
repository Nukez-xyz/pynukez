# tests/test_canonicalization_contract.py
"""
ASCII-vs-UTF-8 canonicalization contract tests.

The gateway verifies envelope signatures over its own re-canonicalization of
the received envelope::

    json.dumps(obj, separators=(",", ":"), sort_keys=True,
               ensure_ascii=False).encode("utf-8")

(see gateway/app/core/signed_requests.py, canonical_json_bytes). The client
must therefore sign exactly that byte stream. For pure-ASCII envelopes the
ensure_ascii=True and ensure_ascii=False serializations are byte-identical,
which is why ASCII-only traffic always worked; any non-ASCII envelope value
(for example a filename with an accented character or an emoji) produces
different bytes under ensure_ascii=True and breaks verification.

These tests replicate the gateway formula in-test and assert, for both the
auth-layer builders and the client envelope-construction paths (confirm,
attest, recompute-verify, in both the sync and async clients), that:

  1. a representative all-ASCII envelope serializes to exactly the same
     bytes as the legacy ensure_ascii=True form (the fix changes nothing
     for ASCII inputs), and
  2. for envelopes containing non-ASCII values, the client-signed bytes
     equal the gateway-formula bytes and the Ed25519 signature verifies
     over them.
"""
import base64
import hashlib
import json

import base58
import pytest
from nacl.signing import SigningKey, VerifyKey
from unittest.mock import AsyncMock, MagicMock

from pynukez.auth import Keypair, build_signed_envelope, build_unsigned_envelope


# A deterministic Ed25519 seed so the test keypair is stable across runs.
_SEED = bytes(range(32))

# A filename carrying both an accented character and an emoji — the two
# non-ASCII classes the contract must survive.
_NON_ASCII_FILENAME = "café-🚀.txt"

# A receipt identifier carrying non-ASCII characters. Receipt IDs flow
# verbatim into the envelope's receipt_id field, so this plants non-ASCII
# bytes inside every envelope built for the receipt.
_NON_ASCII_RECEIPT = "r-café-🚀"


def _gateway_canonical_bytes(obj) -> bytes:
    """Replicate the gateway's canonical_json_bytes() formula exactly."""
    return json.dumps(
        obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False,
    ).encode("utf-8")


def _decode_envelope_bytes(headers: dict) -> bytes:
    """Return the raw bytes the X-Nukez-Envelope header encodes.

    These are exactly the bytes the client signed, because the header is the
    base64url encoding of the canonical envelope JSON.
    """
    raw = headers["X-Nukez-Envelope"]
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def _assert_gateway_verifiable(headers: dict, pubkey_b58: str) -> dict:
    """Assert the signed bytes equal the gateway-formula bytes and verify.

    Decodes the envelope header, re-canonicalizes the decoded object with
    the gateway's exact formula, asserts byte equality, and verifies the
    Ed25519 signature over the gateway-formula bytes — precisely what the
    gateway does before trusting a request. Returns the decoded envelope.
    """
    raw = _decode_envelope_bytes(headers)
    env = json.loads(raw)
    gateway_bytes = _gateway_canonical_bytes(env)
    assert raw == gateway_bytes
    VerifyKey(base58.b58decode(pubkey_b58)).verify(
        gateway_bytes,
        base58.b58decode(headers["X-Nukez-Signature"]),
    )
    return env


@pytest.fixture
def keypair_file(tmp_path):
    """Write a deterministic Solana-format keypair file and return its path."""
    signing_key = SigningKey(_SEED)
    secret = list(_SEED + signing_key.verify_key.encode())
    path = tmp_path / "id.json"
    path.write_text(json.dumps(secret))
    return str(path)


@pytest.fixture
def keypair(keypair_file):
    return Keypair(keypair_file)


@pytest.fixture
def sync_signing_client(keypair_file):
    """A sync client holding a real Ed25519 keypair, with HTTP mocked out."""
    from pynukez import Nukez

    client = Nukez(keypair_path=keypair_file)
    client.http = MagicMock()
    client._raw_client = MagicMock()
    return client


@pytest.fixture
async def async_signing_client(keypair_file):
    """An async client holding a real Ed25519 keypair, with HTTP mocked out."""
    from pynukez import AsyncNukez

    client = AsyncNukez(keypair_path=keypair_file)
    client.http = AsyncMock()
    client._raw_client = AsyncMock()
    return client


class TestAuthLayerCanonicalization:
    """Contract tests against the envelope builders in pynukez.auth."""

    def test_ascii_envelope_bytes_unchanged_by_utf8_canonicalization(self, keypair):
        """For a representative all-ASCII envelope, the serialized bytes must
        be byte-for-byte identical to the legacy ensure_ascii=True form, so
        the canonicalization fix cannot disturb existing ASCII traffic."""
        envelope = build_signed_envelope(
            signer=keypair,
            receipt_id="receipt-ascii-1",
            method="POST",
            path="/v1/files/confirm",
            query="receipt_id=receipt-ascii-1&filename=a.txt",
            ops=["locker:write"],
            body={},
        )
        raw = _decode_envelope_bytes(envelope.headers)
        obj = json.loads(raw)
        legacy_bytes = json.dumps(
            obj, separators=(",", ":"), sort_keys=True, ensure_ascii=True,
        ).encode("utf-8")
        assert raw == legacy_bytes
        assert envelope.canonical_body == "{}"

    def test_non_ascii_signed_envelope_matches_gateway_bytes(self, keypair):
        """An envelope carrying non-ASCII values must serialize to exactly
        the gateway-formula bytes, with the signature verifying over them."""
        query = f"receipt_id={_NON_ASCII_RECEIPT}&filename={_NON_ASCII_FILENAME}"
        envelope = build_signed_envelope(
            signer=keypair,
            receipt_id=_NON_ASCII_RECEIPT,
            method="POST",
            path="/v1/files/confirm",
            query=query,
            ops=["locker:write"],
            body={"filename": _NON_ASCII_FILENAME},
        )

        env = _assert_gateway_verifiable(envelope.headers, keypair.pubkey_b58)
        assert env["receipt_id"] == _NON_ASCII_RECEIPT
        assert env["query"] == query
        # The canonical bytes must contain raw UTF-8, not \uXXXX escapes.
        assert "café".encode("utf-8") in _decode_envelope_bytes(envelope.headers)

    def test_non_ascii_body_hash_matches_gateway_formula(self, keypair):
        """The canonical body and its hash must match what the gateway
        computes when it re-canonicalizes the parsed request body."""
        body = {"filename": _NON_ASCII_FILENAME, "note": "café"}
        envelope = build_signed_envelope(
            signer=keypair,
            receipt_id="receipt-1",
            method="POST",
            path="/v1/lockers/provision",
            ops=["locker:write"],
            body=body,
        )

        gateway_body_bytes = _gateway_canonical_bytes(body)
        assert envelope.canonical_body.encode("utf-8") == gateway_body_bytes

        env = _assert_gateway_verifiable(envelope.headers, keypair.pubkey_b58)
        assert env["body_sha256"] == hashlib.sha256(gateway_body_bytes).hexdigest()

    def test_non_ascii_unsigned_envelope_matches_gateway_bytes(self, keypair):
        """The relay-signing builder must expose exactly the gateway-formula
        bytes as the string to sign, so an external signer that signs
        envelope_json produces a signature the gateway accepts."""
        unsigned = build_unsigned_envelope(
            signer_identity=keypair.pubkey_b58,
            sig_alg="ed25519",
            receipt_id=_NON_ASCII_RECEIPT,
            method="POST",
            path="/v1/storage/attest",
            query="receipt_id=x&sync=true",
            ops=["locker:attest"],
            body={"filename": _NON_ASCII_FILENAME},
        )

        gateway_bytes = _gateway_canonical_bytes(unsigned.envelope)
        assert unsigned.envelope_json.encode("utf-8") == gateway_bytes

        b64 = unsigned.envelope_b64
        assert base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)) == gateway_bytes

        # An external signer signing envelope_json yields a signature that
        # verifies over the gateway-formula bytes.
        signature = SigningKey(_SEED).sign(
            unsigned.envelope_json.encode("utf-8")
        ).signature
        VerifyKey(base58.b58decode(keypair.pubkey_b58)).verify(
            gateway_bytes, signature,
        )


class TestSyncClientEnvelopeCanonicalization:
    """The sync client's envelope construction paths must produce
    gateway-verifiable bytes for non-ASCII inputs."""

    def test_confirm_envelope_with_non_ascii_query_verifies(self, sync_signing_client):
        """The confirm path binds the confirm URL's own query verbatim; a
        query holding an accented-and-emoji filename must still produce
        gateway-verifiable signed bytes."""
        confirm_url = (
            "https://api.nukez.xyz/v1/files/confirm"
            f"?receipt_id=r1&filename={_NON_ASCII_FILENAME}"
        )
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "filename": _NON_ASCII_FILENAME,
            "content_hash": "sha256:abc",
            "size_bytes": 3,
        }
        sync_signing_client._raw_client.post = MagicMock(return_value=resp)

        sync_signing_client.confirm_file(
            "r1", _NON_ASCII_FILENAME, confirm_url=confirm_url,
        )

        args, kwargs = sync_signing_client._raw_client.post.call_args
        assert args[0] == confirm_url
        env = _assert_gateway_verifiable(
            kwargs["headers"], sync_signing_client.keypair.pubkey_b58,
        )
        assert env["path"] == "/v1/files/confirm"
        assert env["query"] == f"receipt_id=r1&filename={_NON_ASCII_FILENAME}"

    def test_attest_envelope_with_non_ascii_receipt_verifies(self, sync_signing_client):
        sync_signing_client.http.post = MagicMock(return_value={
            "merkle_root": "sha256:root",
            "file_count": 1,
            "att_code": 3,
            "push_result": {"ok": True, "tx_signature": "sig", "slot": 9},
        })

        sync_signing_client.attest(_NON_ASCII_RECEIPT)

        args, kwargs = sync_signing_client.http.post.call_args
        assert args[0] == "/v1/storage/attest"
        env = _assert_gateway_verifiable(
            kwargs["headers"], sync_signing_client.keypair.pubkey_b58,
        )
        assert env["receipt_id"] == _NON_ASCII_RECEIPT
        assert env["ops"] == ["locker:attest"]

    def test_recompute_verify_envelope_with_non_ascii_receipt_verifies(self, sync_signing_client):
        sync_signing_client.http.get = MagicMock(return_value={
            "match": True,
            "computed": "sha256:x",
            "stored": "sha256:x",
            "file_count": 1,
            "recompute_ms": 12,
        })

        sync_signing_client.recompute_verify(_NON_ASCII_RECEIPT)

        args, kwargs = sync_signing_client.http.get.call_args
        assert args[0] == "/v1/storage/recompute-verify"
        env = _assert_gateway_verifiable(
            kwargs["headers"], sync_signing_client.keypair.pubkey_b58,
        )
        assert env["receipt_id"] == _NON_ASCII_RECEIPT
        assert env["ops"] == ["locker:read"]


class TestAsyncClientEnvelopeCanonicalization:
    """The async client twins must satisfy the same byte contract."""

    async def test_confirm_envelope_with_non_ascii_query_verifies(self, async_signing_client):
        confirm_url = (
            "https://api.nukez.xyz/v1/files/confirm"
            f"?receipt_id=r1&filename={_NON_ASCII_FILENAME}"
        )
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "filename": _NON_ASCII_FILENAME,
            "content_hash": "sha256:abc",
            "size_bytes": 3,
        }
        async_signing_client._raw_client.post = AsyncMock(return_value=resp)

        await async_signing_client.confirm_file(
            "r1", _NON_ASCII_FILENAME, confirm_url=confirm_url,
        )

        args, kwargs = async_signing_client._raw_client.post.call_args
        assert args[0] == confirm_url
        env = _assert_gateway_verifiable(
            kwargs["headers"], async_signing_client.keypair.pubkey_b58,
        )
        assert env["path"] == "/v1/files/confirm"
        assert env["query"] == f"receipt_id=r1&filename={_NON_ASCII_FILENAME}"

    async def test_attest_envelope_with_non_ascii_receipt_verifies(self, async_signing_client):
        async_signing_client.http.post = AsyncMock(return_value={
            "merkle_root": "sha256:root",
            "file_count": 1,
            "att_code": 3,
            "push_result": {"ok": True, "tx_signature": "sig", "slot": 9},
        })

        await async_signing_client.attest(_NON_ASCII_RECEIPT)

        args, kwargs = async_signing_client.http.post.call_args
        assert args[0] == "/v1/storage/attest"
        env = _assert_gateway_verifiable(
            kwargs["headers"], async_signing_client.keypair.pubkey_b58,
        )
        assert env["receipt_id"] == _NON_ASCII_RECEIPT
        assert env["ops"] == ["locker:attest"]

    async def test_recompute_verify_envelope_with_non_ascii_receipt_verifies(self, async_signing_client):
        async_signing_client.http.get = AsyncMock(return_value={
            "match": True,
            "computed": "sha256:x",
            "stored": "sha256:x",
            "file_count": 1,
            "recompute_ms": 12,
        })

        await async_signing_client.recompute_verify(_NON_ASCII_RECEIPT)

        args, kwargs = async_signing_client.http.get.call_args
        assert args[0] == "/v1/storage/recompute-verify"
        env = _assert_gateway_verifiable(
            kwargs["headers"], async_signing_client.keypair.pubkey_b58,
        )
        assert env["receipt_id"] == _NON_ASCII_RECEIPT
        assert env["ops"] == ["locker:read"]
