# tests/test_auth.py
"""
Batch 4B: SDK auth tests — compute_locker_id, signed envelopes.
"""
import hashlib
import os
import json
import tempfile

import pytest
from pynukez.auth import (
    compute_locker_id,
    Keypair,
    build_signed_envelope,
    build_unsigned_envelope,
    attach_signature,
    UnsignedEnvelope,
)


class TestComputeLockerId:
    """Deterministic locker ID computation."""

    def test_deterministic(self):
        """Same receipt_id always produces same locker_id."""
        lid1 = compute_locker_id("test_receipt")
        lid2 = compute_locker_id("test_receipt")
        assert lid1 == lid2

    def test_prefix(self):
        """Locker ID starts with 'locker_'."""
        lid = compute_locker_id("test_receipt")
        assert lid.startswith("locker_")

    def test_different_receipts_different_lockers(self):
        """Different receipt_ids produce different locker_ids."""
        lid1 = compute_locker_id("receipt_a")
        lid2 = compute_locker_id("receipt_b")
        assert lid1 != lid2

    def test_hash_length(self):
        """Locker ID hash portion is 12 hex chars."""
        lid = compute_locker_id("test")
        hash_part = lid[len("locker_"):]
        assert len(hash_part) == 12
        # Verify it's valid hex
        int(hash_part, 16)


class TestKeypair:
    """Keypair loading and signing."""

    @pytest.fixture
    def keypair_path(self):
        """Create a test keypair file (Solana format: JSON array of 64 bytes)."""
        path = os.path.expanduser("~/.config/solana/id.json")
        if os.path.exists(path):
            return path
        pytest.skip("No Solana keypair available at ~/.config/solana/id.json")

    def test_load_keypair(self, keypair_path):
        """Can load keypair from file."""
        kp = Keypair(keypair_path)
        assert kp.pubkey_b58 is not None
        assert len(kp.pubkey_b58) > 20  # Base58 pubkey is ~44 chars

    def test_sign_message(self, keypair_path):
        """Can sign a message and get a signature."""
        kp = Keypair(keypair_path)
        sig = kp.sign_message(b"test message")
        assert isinstance(sig, str)
        assert len(sig) > 40  # Base58 signature is ~88 chars


class TestBuildSignedEnvelope:
    """Signed envelope construction."""

    @pytest.fixture
    def keypair(self):
        path = os.path.expanduser("~/.config/solana/id.json")
        if os.path.exists(path):
            return Keypair(path)
        pytest.skip("No Solana keypair available")

    def test_get_envelope_has_headers(self, keypair):
        """GET envelope includes required headers."""
        env = build_signed_envelope(
            keypair=keypair,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        assert "X-Nukez-Envelope" in env.headers
        assert "X-Nukez-Signature" in env.headers

    def test_post_envelope_with_body(self, keypair):
        """POST envelope includes canonical body hash."""
        env = build_signed_envelope(
            keypair=keypair,
            receipt_id="test_rid",
            method="POST",
            path="/v1/files/confirm",
            ops=["file:confirm"],
            body={"filename": "test.txt"},
        )
        assert env.canonical_body is not None


class TestBuildSignedEnvelopeGeneralized:
    """Phase 2B: generalized build_signed_envelope with Signer protocol."""

    @pytest.fixture
    def keypair(self):
        path = os.path.expanduser("~/.config/solana/id.json")
        if os.path.exists(path):
            return Keypair(path)
        pytest.skip("No Solana keypair available")

    @pytest.fixture
    def evm_signer(self):
        try:
            from pynukez.signer import EVMSigner
            return EVMSigner(
                private_key="0x4c0883a69102937d6231471b5dbb6204fe512961708279f9d92f2e20d8c563b6"
            )
        except ImportError:
            pytest.skip("eth_account not installed")

    def _decode_envelope(self, env):
        """Decode envelope JSON from headers."""
        import base64 as b64
        raw = env.headers["X-Nukez-Envelope"]
        # Restore padding
        raw += "=" * (-len(raw) % 4)
        return json.loads(b64.urlsafe_b64decode(raw))

    def test_ed25519_sig_alg_in_envelope(self, keypair):
        """Ed25519 envelope includes sig_alg: ed25519."""
        env = build_signed_envelope(
            signer=keypair,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        decoded = self._decode_envelope(env)
        assert decoded["sig_alg"] == "ed25519"

    def test_evm_sig_alg_in_envelope(self, evm_signer):
        """EVM envelope includes sig_alg: secp256k1."""
        env = build_signed_envelope(
            signer=evm_signer,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        decoded = self._decode_envelope(env)
        assert decoded["sig_alg"] == "secp256k1"

    def test_evm_signature_is_0x_hex(self, evm_signer):
        """EVM envelope signature is 0x-prefixed hex."""
        env = build_signed_envelope(
            signer=evm_signer,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        sig = env.headers["X-Nukez-Signature"]
        assert sig.startswith("0x")
        assert len(sig) == 132

    def test_ed25519_signature_is_base58(self, keypair):
        """Ed25519 envelope signature is base58 (regression)."""
        env = build_signed_envelope(
            signer=keypair,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        sig = env.headers["X-Nukez-Signature"]
        assert not sig.startswith("0x")
        assert len(sig) > 40

    def test_deprecated_keypair_kwarg(self, keypair):
        """keypair= kwarg still works (backward compat)."""
        env = build_signed_envelope(
            keypair=keypair,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        assert "X-Nukez-Envelope" in env.headers

    def test_no_signer_raises(self):
        """No signer or keypair raises NukezError."""
        from pynukez.errors import NukezError
        with pytest.raises(NukezError, match="requires a signer"):
            build_signed_envelope(
                receipt_id="test_rid",
                method="GET",
                path="/test",
                ops=["locker:list"],
            )

    def test_delegating_false_no_signer_field(self, keypair):
        """delegating=False omits signer from envelope."""
        env = build_signed_envelope(
            signer=keypair,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
            delegating=False,
        )
        decoded = self._decode_envelope(env)
        assert "signer" not in decoded

    def test_delegating_true_includes_signer_field(self, keypair):
        """delegating=True includes signer identity in envelope."""
        env = build_signed_envelope(
            signer=keypair,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
            delegating=True,
        )
        decoded = self._decode_envelope(env)
        assert decoded["signer"] == keypair.identity

    def test_sig_alg_always_present(self, keypair):
        """sig_alg is always present in envelope."""
        env = build_signed_envelope(
            signer=keypair,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        decoded = self._decode_envelope(env)
        assert "sig_alg" in decoded

    def test_query_included_when_set(self, keypair):
        """A non-empty query string is bound into the envelope."""
        env = build_signed_envelope(
            signer=keypair,
            receipt_id="test_rid",
            method="POST",
            path="/v1/storage/attest",
            query="receipt_id=test_rid&sync=true",
            ops=["locker:attest"],
            body={},
        )
        decoded = self._decode_envelope(env)
        assert decoded["query"] == "receipt_id=test_rid&sync=true"

    def test_query_omitted_when_empty(self, keypair):
        """No query field is emitted when query is empty (default)."""
        env = build_signed_envelope(
            signer=keypair,
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        decoded = self._decode_envelope(env)
        assert "query" not in decoded


class TestBuildUnsignedEnvelope:
    """Unsigned envelope construction for relay/external signing."""

    def _decode_envelope(self, unsigned):
        """Decode envelope JSON from base64url."""
        import base64 as b64
        raw = unsigned.envelope_b64
        raw += "=" * (-len(raw) % 4)
        return json.loads(b64.urlsafe_b64decode(raw))

    def test_returns_unsigned_envelope(self):
        """Returns an UnsignedEnvelope dataclass."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        assert isinstance(env, UnsignedEnvelope)

    def test_envelope_has_required_fields(self):
        """Envelope dict contains all required authentication fields."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/lockers/locker_test/files",
            ops=["locker:list"],
        )
        d = env.envelope
        assert d["v"] == 1
        assert d["receipt_id"] == "test_rid"
        assert d["method"] == "GET"
        assert d["path"] == "/v1/lockers/locker_test/files"
        assert d["ops"] == ["locker:list"]
        assert d["sig_alg"] == "ed25519"
        assert "nonce" in d
        assert "iat" in d
        assert "exp" in d
        assert "body_sha256" in d
        assert "locker_id" in d

    def test_b64_matches_json(self):
        """base64url envelope decodes to the same dict."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/test",
            ops=[],
        )
        decoded = self._decode_envelope(env)
        assert decoded == env.envelope

    def test_canonical_json_is_sorted(self):
        """envelope_json uses sorted keys and no whitespace."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/test",
            ops=[],
        )
        assert " " not in env.envelope_json
        reparsed = json.loads(env.envelope_json)
        assert reparsed == env.envelope

    def test_post_requires_body(self):
        """POST without body raises NukezError."""
        from pynukez.errors import NukezError
        with pytest.raises(NukezError, match="REQUIRED for POST"):
            build_unsigned_envelope(
                signer_identity="FakePubkey123",
                sig_alg="ed25519",
                receipt_id="test_rid",
                method="POST",
                path="/v1/test",
                ops=[],
            )

    def test_post_with_body(self):
        """POST with body sets canonical_body and body_sha256."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="POST",
            path="/v1/test",
            ops=["locker:write"],
            body={"filename": "test.txt"},
        )
        assert env.canonical_body is not None
        expected_hash = hashlib.sha256(env.canonical_body.encode()).hexdigest()
        assert env.envelope["body_sha256"] == expected_hash

    def test_delegating_includes_signer(self):
        """delegating=True includes signer identity in envelope."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/test",
            ops=[],
            delegating=True,
        )
        assert env.envelope["signer"] == "FakePubkey123"

    def test_not_delegating_omits_signer(self):
        """delegating=False omits signer from envelope."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/test",
            ops=[],
            delegating=False,
        )
        assert "signer" not in env.envelope

    def test_secp256k1_sig_alg(self):
        """EVM sig_alg is correctly set."""
        env = build_unsigned_envelope(
            signer_identity="0x1234abcd",
            sig_alg="secp256k1",
            receipt_id="test_rid",
            method="GET",
            path="/v1/test",
            ops=[],
        )
        assert env.envelope["sig_alg"] == "secp256k1"

    def test_locker_id_matches_compute(self):
        """Locker ID in envelope matches compute_locker_id."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/test",
            ops=[],
        )
        assert env.locker_id == compute_locker_id("test_rid")
        assert env.envelope["locker_id"] == compute_locker_id("test_rid")

    def test_query_included_when_set(self):
        """A non-empty query string is bound into the unsigned envelope."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="POST",
            path="/v1/storage/attest",
            query="receipt_id=test_rid&sync=true",
            ops=["locker:attest"],
            body={},
        )
        assert env.envelope["query"] == "receipt_id=test_rid&sync=true"

    def test_query_omitted_when_empty(self):
        """No query field is emitted when query is empty (default)."""
        env = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/test",
            ops=[],
        )
        assert "query" not in env.envelope


class TestAttachSignature:
    """Attach external signature to unsigned envelope."""

    def test_produces_signed_envelope(self):
        """attach_signature returns a SignedEnvelope with correct headers."""
        unsigned = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/test",
            ops=[],
        )
        signed = attach_signature(unsigned, "FakeSignature123")
        assert signed.headers["X-Nukez-Envelope"] == unsigned.envelope_b64
        assert signed.headers["X-Nukez-Signature"] == "FakeSignature123"
        assert signed.locker_id == unsigned.locker_id
        assert signed.canonical_body == unsigned.canonical_body

    def test_post_preserves_canonical_body(self):
        """attach_signature preserves canonical body from POST envelope."""
        unsigned = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="POST",
            path="/v1/test",
            ops=[],
            body={"key": "value"},
        )
        signed = attach_signature(unsigned, "Sig456")
        assert signed.canonical_body == unsigned.canonical_body
        assert signed.canonical_body is not None

    def test_roundtrip_matches_build_signed(self):
        """Unsigned envelope + attach_signature produces same structure as build_signed_envelope."""
        # Both paths should produce headers with the same keys
        unsigned = build_unsigned_envelope(
            signer_identity="FakePubkey123",
            sig_alg="ed25519",
            receipt_id="test_rid",
            method="GET",
            path="/v1/test",
            ops=["locker:list"],
        )
        signed = attach_signature(unsigned, "TestSig")
        assert set(signed.headers.keys()) == {"X-Nukez-Envelope", "X-Nukez-Signature"}
