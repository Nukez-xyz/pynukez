# tests/test_renovation_readers.py
"""
Reader tests for the provider-neutral proof fields.

Newer gateways describe the on-chain anchor of a record with an ``anchor``
object, report separate ``verification`` facts, serve a portable evidence
bundle, publish their signing keys, and accept a payer-signed confirm
intent. Older gateways do none of this. These tests check three things.

The first is that the SDK fills the new fields when the gateway sends them.
The second is that a response from an older gateway is read exactly as it
was read before. The third is that a historical Switchboard-era record still
works, and that a newer anchor is never labelled as a Switchboard anchor.

Every test uses plain dict fixtures and mocked HTTP. No test needs the
network or a real key file.
"""
import hashlib
import json

import base58
import pytest
from nacl.signing import SigningKey
from unittest.mock import AsyncMock, MagicMock, patch

from pynukez import verify as nukez_verify
from pynukez._helpers import (
    _attest_anchor_fields,
    _attest_outcome_from_verification,
    _confirm_error_from_response,
    _sign_confirm_intent,
    confirm_intent_message,
)
from pynukez.errors import AuthenticationError, NukezError
from pynukez.types import AttestResult, VerificationResult


# ---------------------------------------------------------------------------
# Fixtures: gateway responses as plain dicts
# ---------------------------------------------------------------------------

_MERKLE_ROOT = "sha256:" + "ab" * 32
_ANCHOR_TX = "5NewAnchorTransactionSignature"

_SAS_ANCHOR = {
    "type": "solana_sas_v1",
    "chain": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "tx": _ANCHOR_TX,
    "slot": 425597054,
    "block_time": 1789654076,
    "signer": "GatewayPublicationKey",
    "fee_lamports": 20000,
    "commitment": "confirmed",
    "finalized": False,
    "statement_digest": "cd" * 32,
    "snapshot_id": "ef" * 32,
    "envelope_version": 2,
}

_SWITCHBOARD_ANCHOR = {
    "type": "switchboard_v2",
    "chain": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "tx": "4HistoricalSwitchboardTransaction",
    "slot": 300000001,
    "account": "SwitchboardFeedPubkey",
    "envelope_version": 1,
}


def _facts(anchor_confirmed: str) -> dict:
    """Build a verification facts object with the given anchor fact."""
    return {
        "commitment_computed": "passed",
        "signature_valid": "passed",
        "anchor_submitted": "passed" if anchor_confirmed == "passed" else "not_checked",
        "anchor_confirmed": anchor_confirmed,
        "anchor_finalized": "not_checked",
        "payment_verified": "not_checked",
        "bytes_checked": "not_checked",
        "witness": "not_checked",
    }


def _attestation(**extra) -> dict:
    """Build the stored attestation object that the verify endpoint nests."""
    base = {
        "result_hash": "sha256:" + "12" * 32,
        "att_code": 123456789,
        "attested_at": "2026-09-21T10:00:00Z",
        "merkle_root": _MERKLE_ROOT,
        "manifest_signature": "34" * 64,
        "file_count": 2,
        "files": [
            {"filename": "a.txt", "content_hash": "sha256:aa", "size_bytes": 5},
            {"filename": "b.txt", "content_hash": "sha256:bb", "size_bytes": 5},
        ],
    }
    base.update(extra)
    return base


def _old_gateway_verify_response(**attestation_extra) -> dict:
    """A verify response from a gateway that predates the new fields."""
    return {
        "receipt": {"id": "r1"},
        "attestation": _attestation(**attestation_extra),
        "verified": True,
        "locker_id": "locker_abc",
        "verify_url": "https://nukez.xyz/verify/r1",
    }


def _new_gateway_verify_response(anchor, anchor_confirmed: str, **attestation_extra) -> dict:
    """A verify response from a gateway that sends the new fields."""
    response = _old_gateway_verify_response(proof_id="9f" * 16, **attestation_extra)
    response["anchor"] = anchor
    response["verification"] = _facts(anchor_confirmed)
    return response


_OLD_FIELD_NAMES = (
    "receipt_id", "verified", "result_hash", "att_code", "verified_at",
    "merkle_root", "manifest_signature", "file_count", "files", "locker_id",
    "verify_url",
)


# ---------------------------------------------------------------------------
# types.py: the dataclasses stay backward compatible
# ---------------------------------------------------------------------------

class TestResultTypes:
    def test_attest_result_defaults_are_unchanged(self):
        """An AttestResult built the old way gets None for every new field."""
        result = AttestResult(
            receipt_id="r1", merkle_root=_MERKLE_ROOT, file_count=2,
            att_code=1, push_ok=True, tx_signature="t", switchboard_slot=7,
        )
        assert result.switchboard_slot == 7
        assert result.anchor is None
        assert result.anchor_type is None
        assert result.anchor_slot is None
        assert result.verification is None

    def test_verification_result_defaults_are_unchanged(self):
        """A VerificationResult built the old way reports no anchor."""
        result = VerificationResult(receipt_id="r1", verified=True, result_hash="h", merkle_root=_MERKLE_ROOT)
        assert result.status == "verified"
        assert result.attested is True
        assert result.anchor is None
        assert result.verification is None
        assert result.proof_id is None
        assert result.anchored is False
        assert result.anchor_tx is None

    def test_anchored_uses_the_fact_when_it_is_present(self):
        """The fact decides, even when a historical transaction is recorded."""
        result = VerificationResult(
            receipt_id="r1", verified=True, result_hash="h", merkle_root=_MERKLE_ROOT,
            verification=_facts("not_checked"), switchboard_tx="4Historical",
        )
        assert result.anchored is False
        result.verification = _facts("passed")
        assert result.anchored is True

    def test_anchored_falls_back_to_the_legacy_signal(self):
        """Without facts, a recorded Switchboard transaction means anchored."""
        result = VerificationResult(
            receipt_id="r1", verified=True, result_hash="h", switchboard_tx="4Historical",
        )
        assert result.anchored is True
        assert result.anchor_tx == "4Historical"

    def test_anchor_tx_prefers_the_anchor_object(self):
        result = VerificationResult(
            receipt_id="r1", verified=True, result_hash="h",
            anchor=dict(_SAS_ANCHOR), switchboard_tx="4Historical",
        )
        assert result.anchor_tx == _ANCHOR_TX


# ---------------------------------------------------------------------------
# verify_storage
# ---------------------------------------------------------------------------

class TestSyncVerifyStorage:
    def test_new_fields_are_populated_when_present(self, sync_client):
        sync_client.http.get = MagicMock(
            return_value=_new_gateway_verify_response(dict(_SAS_ANCHOR), "passed")
        )

        result = sync_client.verify_storage("r1")

        assert result.anchor == _SAS_ANCHOR
        assert result.anchor["type"] == "solana_sas_v1"
        assert result.verification["anchor_confirmed"] == "passed"
        assert result.proof_id == "9f" * 16
        assert result.anchored is True
        assert result.anchor_tx == _ANCHOR_TX
        assert result.switchboard_tx is None
        # The existing fields keep their values.
        assert result.verified is True
        assert result.merkle_root == _MERKLE_ROOT
        assert result.att_code == "123456789"
        assert result.file_count == 2

    def test_old_gateway_response_reads_exactly_as_before(self, sync_client):
        response = _old_gateway_verify_response()
        sync_client.http.get = MagicMock(return_value=response)

        result = sync_client.verify_storage("r1")

        expected = VerificationResult(
            receipt_id="r1",
            verified=True,
            result_hash=response["attestation"]["result_hash"],
            att_code="123456789",
            verified_at="2026-09-21T10:00:00Z",
            merkle_root=_MERKLE_ROOT,
            manifest_signature=response["attestation"]["manifest_signature"],
            file_count=2,
            files=response["attestation"]["files"],
            locker_id="locker_abc",
            verify_url="https://nukez.xyz/verify/r1",
        )
        for name in _OLD_FIELD_NAMES:
            assert getattr(result, name) == getattr(expected, name), name
        assert result == expected
        assert result.status == "verified"
        assert result.attested is True
        assert result.anchored is False
        assert result.anchor_tx is None
        sync_client.http.get.assert_called_once_with(
            "/v1/storage/verify", params={"receipt_id": "r1"}
        )

    def test_pending_record_without_attestation_is_tolerated(self, sync_client):
        sync_client.http.get = MagicMock(return_value={
            "receipt": {"id": "r1"}, "attestation": None, "verified": False,
            "anchor": None,
            "verification": {"commitment_computed": "not_checked", "anchor_confirmed": "not_checked"},
        })

        result = sync_client.verify_storage("r1")

        assert result.verified is False
        assert result.merkle_root == ""
        assert result.anchor is None
        assert result.anchored is False
        assert result.proof_id is None

    def test_historical_switchboard_record_from_an_old_gateway(self, sync_client):
        """An older gateway sends only the historical fields."""
        sync_client.http.get = MagicMock(return_value=_old_gateway_verify_response(
            switchboard_tx="4HistoricalSwitchboardTransaction",
            switchboard_slot=300000001,
            switchboard_feed="SwitchboardFeedPubkey",
        ))

        result = sync_client.verify_storage("r1")

        assert result.anchor is None
        assert result.verification is None
        assert result.switchboard_tx == "4HistoricalSwitchboardTransaction"
        assert result.anchored is True
        assert result.anchor_tx == "4HistoricalSwitchboardTransaction"

    def test_historical_switchboard_record_from_a_new_gateway(self, sync_client):
        """A newer gateway describes the same record with its historical type."""
        sync_client.http.get = MagicMock(return_value=_new_gateway_verify_response(
            dict(_SWITCHBOARD_ANCHOR), "passed",
            switchboard_tx="4HistoricalSwitchboardTransaction",
            switchboard_slot=300000001,
        ))

        result = sync_client.verify_storage("r1")

        assert result.anchor["type"] == "switchboard_v2"
        assert result.anchored is True
        assert result.anchor_tx == "4HistoricalSwitchboardTransaction"

    def test_anchor_inside_the_attestation_is_used_when_the_top_level_has_none(self, sync_client):
        response = _old_gateway_verify_response(anchor=dict(_SAS_ANCHOR))
        sync_client.http.get = MagicMock(return_value=response)

        result = sync_client.verify_storage("r1")

        assert result.anchor == _SAS_ANCHOR
        assert result.anchor_tx == _ANCHOR_TX


class TestAsyncVerifyStorage:
    async def test_new_fields_are_populated_when_present(self, async_client):
        async_client.http.get = AsyncMock(
            return_value=_new_gateway_verify_response(dict(_SAS_ANCHOR), "passed")
        )

        result = await async_client.verify_storage("r1")

        assert result.anchor == _SAS_ANCHOR
        assert result.verification["anchor_confirmed"] == "passed"
        assert result.proof_id == "9f" * 16
        assert result.anchored is True
        assert result.anchor_tx == _ANCHOR_TX

    async def test_old_gateway_response_reads_exactly_as_before(self, async_client):
        response = _old_gateway_verify_response()
        async_client.http.get = AsyncMock(return_value=response)

        result = await async_client.verify_storage("r1")

        assert result == VerificationResult(
            receipt_id="r1",
            verified=True,
            result_hash=response["attestation"]["result_hash"],
            att_code="123456789",
            verified_at="2026-09-21T10:00:00Z",
            merkle_root=_MERKLE_ROOT,
            manifest_signature=response["attestation"]["manifest_signature"],
            file_count=2,
            files=response["attestation"]["files"],
            locker_id="locker_abc",
            verify_url="https://nukez.xyz/verify/r1",
        )
        assert result.anchored is False

    async def test_historical_switchboard_record_from_an_old_gateway(self, async_client):
        async_client.http.get = AsyncMock(return_value=_old_gateway_verify_response(
            switchboard_tx="4HistoricalSwitchboardTransaction",
        ))

        result = await async_client.verify_storage("r1")

        assert result.anchored is True
        assert result.anchor_tx == "4HistoricalSwitchboardTransaction"


# ---------------------------------------------------------------------------
# attest
# ---------------------------------------------------------------------------

def _attest_response(push_result=None, **extra) -> dict:
    response = {"merkle_root": _MERKLE_ROOT, "file_count": 2, "att_code": 123456789}
    if push_result is not None:
        response["push_result"] = push_result
    response.update(extra)
    return response


class TestSyncAttest:
    def test_anchor_fields_come_from_push_result(self, sync_client):
        sync_client.http.post = MagicMock(return_value=_attest_response({
            "ok": True, "tx_signature": _ANCHOR_TX, "slot": 425597054,
            "anchor": dict(_SAS_ANCHOR), "anchor_type": "solana_sas_v1",
        }))

        result = sync_client.attest("r1")

        assert result.status == "complete"
        assert result.push_ok is True
        assert result.tx_signature == _ANCHOR_TX
        assert result.anchor == _SAS_ANCHOR
        assert result.anchor_type == "solana_sas_v1"
        assert result.anchor_slot == 425597054
        # The historical field keeps its old source for backward compatibility.
        assert result.switchboard_slot == 425597054

    def test_old_gateway_response_reads_exactly_as_before(self, sync_client):
        sync_client.http.post = MagicMock(return_value=_attest_response({
            "ok": True, "tx_signature": "4Historical", "slot": 300000001,
            "feed_pubkey": "SwitchboardFeedPubkey",
        }))

        result = sync_client.attest("r1")

        assert result == AttestResult(
            receipt_id="r1", merkle_root=_MERKLE_ROOT, file_count=2,
            att_code=123456789, status="complete", push_ok=True,
            tx_signature="4Historical", switchboard_slot=300000001,
            anchor=None, anchor_type=None, anchor_slot=300000001, verification=None,
        )

    def test_accepted_response_without_push_result(self, sync_client):
        sync_client.http.post = MagicMock(return_value={"status": "accepted"})

        result = sync_client.attest("r1", sync=False)

        assert result == AttestResult(
            receipt_id="r1", merkle_root="", file_count=0, att_code=None,
            status="accepted", push_ok=False, tx_signature=None, switchboard_slot=None,
        )

    def test_top_level_anchor_is_used_when_the_push_succeeded(self, sync_client):
        """The queued sync path names the anchor type and repeats the anchor at the top level."""
        sync_client.http.post = MagicMock(return_value=_attest_response(
            {"ok": True, "tx_signature": _ANCHOR_TX, "slot": 425597054, "anchor_type": "solana_sas_v1"},
            anchor=dict(_SAS_ANCHOR),
        ))

        result = sync_client.attest("r1")

        assert result.anchor == _SAS_ANCHOR
        assert result.anchor_type == "solana_sas_v1"

    def test_top_level_anchor_is_ignored_when_the_push_did_not_land(self, sync_client):
        sync_client.http.post = MagicMock(return_value=_attest_response(
            {"ok": False, "error": "push_did_not_land"},
            anchor=dict(_SAS_ANCHOR),
        ))

        result = sync_client.attest("r1")

        assert result.push_ok is False
        assert result.tx_signature is None
        assert result.anchor is None
        assert result.anchor_type is None
        assert result.anchor_slot is None


class TestAsyncAttest:
    async def test_anchor_fields_come_from_push_result(self, async_client):
        async_client.http.post = AsyncMock(return_value=_attest_response({
            "ok": True, "tx_signature": _ANCHOR_TX, "slot": 425597054,
            "anchor": dict(_SAS_ANCHOR), "anchor_type": "solana_sas_v1",
        }))

        result = await async_client.attest("r1")

        assert result.push_ok is True
        assert result.tx_signature == _ANCHOR_TX
        assert result.anchor == _SAS_ANCHOR
        assert result.anchor_type == "solana_sas_v1"
        assert result.anchor_slot == 425597054
        assert result.switchboard_slot == 425597054

    async def test_old_gateway_response_reads_exactly_as_before(self, async_client):
        async_client.http.post = AsyncMock(return_value=_attest_response({
            "ok": True, "tx_signature": "4Historical", "slot": 300000001,
        }))

        result = await async_client.attest("r1")

        assert result.push_ok is True
        assert result.tx_signature == "4Historical"
        assert result.switchboard_slot == 300000001
        assert result.anchor is None
        assert result.anchor_type is None


# ---------------------------------------------------------------------------
# attest_async
# ---------------------------------------------------------------------------

class TestSyncAttestAsync:
    def test_computed_but_unanchored_record_does_not_report_push_ok(self, sync_client):
        """A merkle root and an attestation code exist, but no anchor is confirmed."""
        sync_client.http.post = MagicMock(return_value={"status": "accepted"})
        sync_client.http.get = MagicMock(
            return_value=_new_gateway_verify_response(None, "not_checked")
        )

        result = sync_client.attest_async("r1", poll_interval=0, max_wait=5)

        assert result.status == "complete"
        assert result.merkle_root == _MERKLE_ROOT
        assert result.att_code == 123456789
        assert result.push_ok is False
        assert result.tx_signature is None
        assert result.anchor is None
        assert result.switchboard_slot is None
        assert result.verification["anchor_confirmed"] == "not_checked"

    def test_anchored_record_reports_the_anchor(self, sync_client):
        sync_client.http.post = MagicMock(return_value={"status": "accepted"})
        sync_client.http.get = MagicMock(
            return_value=_new_gateway_verify_response(dict(_SAS_ANCHOR), "passed")
        )

        result = sync_client.attest_async("r1", poll_interval=0, max_wait=5)

        assert result.push_ok is True
        assert result.tx_signature == _ANCHOR_TX
        assert result.anchor == _SAS_ANCHOR
        assert result.anchor_type == "solana_sas_v1"
        assert result.anchor_slot == 425597054
        # A newer anchor is never reported through the Switchboard field.
        assert result.switchboard_slot is None

    def test_historical_anchor_fills_the_historical_slot(self, sync_client):
        sync_client.http.post = MagicMock(return_value={"status": "accepted"})
        sync_client.http.get = MagicMock(
            return_value=_new_gateway_verify_response(dict(_SWITCHBOARD_ANCHOR), "passed")
        )

        result = sync_client.attest_async("r1", poll_interval=0, max_wait=5)

        assert result.push_ok is True
        assert result.anchor_type == "switchboard_v2"
        assert result.switchboard_slot == 300000001
        assert result.tx_signature == "4HistoricalSwitchboardTransaction"

    def test_old_gateway_keeps_the_old_behaviour_exactly(self, sync_client):
        sync_client.http.post = MagicMock(return_value={"status": "accepted"})
        sync_client.http.get = MagicMock(return_value=_old_gateway_verify_response())

        result = sync_client.attest_async("r1", poll_interval=0, max_wait=5)

        assert result == AttestResult(
            receipt_id="r1", merkle_root=_MERKLE_ROOT, file_count=2,
            att_code=123456789, status="complete", push_ok=True,
            tx_signature=None, switchboard_slot=None,
        )

    def test_old_gateway_without_an_attestation_code(self, sync_client):
        sync_client.http.post = MagicMock(return_value={"status": "accepted"})
        sync_client.http.get = MagicMock(return_value=_old_gateway_verify_response(att_code=""))

        result = sync_client.attest_async("r1", poll_interval=0, max_wait=5)

        assert result.push_ok is False
        assert result.att_code is None

    def test_timeout_is_unchanged(self, sync_client):
        sync_client.http.post = MagicMock(return_value={"status": "accepted"})
        sync_client.http.get = MagicMock(return_value={"attestation": None, "verified": False})

        with pytest.raises(NukezError, match="attest_timeout"):
            sync_client.attest_async("r1", poll_interval=0, max_wait=0.05)


class TestAsyncAttestAsync:
    async def test_computed_but_unanchored_record_does_not_report_push_ok(self, async_client):
        async_client.http.post = AsyncMock(return_value={"status": "accepted"})
        async_client.http.get = AsyncMock(
            return_value=_new_gateway_verify_response(None, "not_checked")
        )

        result = await async_client.attest_async("r1", poll_interval=0, max_wait=5)

        assert result.merkle_root == _MERKLE_ROOT
        assert result.push_ok is False
        assert result.tx_signature is None

    async def test_anchored_record_reports_the_anchor(self, async_client):
        async_client.http.post = AsyncMock(return_value={"status": "accepted"})
        async_client.http.get = AsyncMock(
            return_value=_new_gateway_verify_response(dict(_SAS_ANCHOR), "passed")
        )

        result = await async_client.attest_async("r1", poll_interval=0, max_wait=5)

        assert result.push_ok is True
        assert result.tx_signature == _ANCHOR_TX
        assert result.anchor_type == "solana_sas_v1"
        assert result.switchboard_slot is None

    async def test_old_gateway_keeps_the_old_behaviour_exactly(self, async_client):
        async_client.http.post = AsyncMock(return_value={"status": "accepted"})
        async_client.http.get = AsyncMock(return_value=_old_gateway_verify_response())

        result = await async_client.attest_async("r1", poll_interval=0, max_wait=5)

        assert result == AttestResult(
            receipt_id="r1", merkle_root=_MERKLE_ROOT, file_count=2,
            att_code=123456789, status="complete", push_ok=True,
            tx_signature=None, switchboard_slot=None,
        )


class TestReaderHelpers:
    def test_attest_anchor_fields_tolerate_bad_input(self):
        assert _attest_anchor_fields(None) == {
            "anchor": None, "anchor_type": None, "anchor_slot": None, "verification": None,
        }
        assert _attest_anchor_fields({"push_result": "not a dict"})["anchor"] is None

    def test_top_level_anchor_must_name_the_same_transaction(self):
        fields = _attest_anchor_fields({
            "push_result": {"ok": True, "tx_signature": "a different transaction"},
            "anchor": dict(_SAS_ANCHOR),
        })
        assert fields["anchor"] is None

    def test_outcome_with_an_anchor_but_no_facts_keeps_the_legacy_push_ok(self):
        verification_result = VerificationResult(
            receipt_id="r1", verified=True, result_hash="h", att_code="",
            merkle_root=_MERKLE_ROOT, anchor=dict(_SAS_ANCHOR),
        )
        outcome = _attest_outcome_from_verification(verification_result)
        assert outcome["push_ok"] is False
        assert outcome["tx_signature"] == _ANCHOR_TX


# ---------------------------------------------------------------------------
# get_evidence_bundle and get_signing_keys
# ---------------------------------------------------------------------------

class TestNewReadMethods:
    def test_sync_get_evidence_bundle(self, sync_client):
        sync_client.http.get = MagicMock(return_value={"schema": "nukez/evidence-bundle/v2"})

        bundle = sync_client.get_evidence_bundle("r1")

        assert bundle["schema"] == "nukez/evidence-bundle/v2"
        sync_client.http.get.assert_called_once_with(
            "/v1/storage/evidence-bundle", params={"receipt_id": "r1"}
        )

    def test_sync_get_signing_keys(self, sync_client):
        sync_client.http.get = MagicMock(return_value={"schema": "nukez/signing-keys/v1", "keys": []})

        keys = sync_client.get_signing_keys()

        assert keys["keys"] == []
        sync_client.http.get.assert_called_once_with("/v1/keys")

    async def test_async_get_evidence_bundle(self, async_client):
        async_client.http.get = AsyncMock(return_value={"schema": "nukez/evidence-bundle/v2"})

        bundle = await async_client.get_evidence_bundle("r1")

        assert bundle["schema"] == "nukez/evidence-bundle/v2"
        async_client.http.get.assert_called_once_with(
            "/v1/storage/evidence-bundle", params={"receipt_id": "r1"}
        )

    async def test_async_get_signing_keys(self, async_client):
        async_client.http.get = AsyncMock(return_value={"schema": "nukez/signing-keys/v1", "keys": []})

        keys = await async_client.get_signing_keys()

        assert keys["schema"] == "nukez/signing-keys/v1"
        async_client.http.get.assert_called_once_with("/v1/keys")


# ---------------------------------------------------------------------------
# confirm_storage: payer-signed confirm intent and the newer error codes
# ---------------------------------------------------------------------------

def _confirm_ok_response():
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "receipt_id": "r_123",
        "receipt": {"units": 1, "payer_pubkey": "payer_pk", "network": "devnet", "provider": "gcs"},
    }
    return response


def _confirm_error_response(status_code: int, body: dict):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = body
    response.text = json.dumps(body)
    return response


class _Ed25519TestSigner:
    """A throwaway Ed25519 signer that follows the SDK's Signer protocol."""

    def __init__(self):
        self._key = SigningKey.generate()

    @property
    def verify_key(self):
        return self._key.verify_key

    @property
    def identity(self) -> str:
        return base58.b58encode(self._key.verify_key.encode()).decode()

    @property
    def sig_alg(self) -> str:
        return "ed25519"

    def sign(self, message: bytes) -> str:
        return base58.b58encode(self._key.sign(message).signature).decode()


class TestConfirmIntentMessage:
    def test_exact_bytes_with_an_operator(self):
        assert confirm_intent_message("pr_1", "5Sig", "OperatorKey") == b"nukez/confirm/v1|pr_1|5Sig|OperatorKey"

    def test_a_hyphen_stands_in_for_a_missing_operator(self):
        assert confirm_intent_message("pr_1", "5Sig", None) == b"nukez/confirm/v1|pr_1|5Sig|-"
        assert confirm_intent_message("pr_1", " 5Sig ", "") == b"nukez/confirm/v1|pr_1|5Sig|-"

    def test_real_signature_verifies_over_the_exact_message(self):
        signer = _Ed25519TestSigner()

        signature = _sign_confirm_intent(
            pay_req_id="pr_1", tx_sig="5SolanaSig", operator_pubkey="OperatorKey", signers=[signer],
        )

        signer.verify_key.verify(
            b"nukez/confirm/v1|pr_1|5SolanaSig|OperatorKey", base58.b58decode(signature)
        )

    def test_no_signature_without_an_operator(self):
        signer = _Ed25519TestSigner()
        assert _sign_confirm_intent(pay_req_id="pr_1", tx_sig="5Sig", operator_pubkey=None, signers=[signer]) is None

    def test_no_signature_when_the_key_is_the_operator(self):
        signer = _Ed25519TestSigner()
        assert _sign_confirm_intent(
            pay_req_id="pr_1", tx_sig="5Sig", operator_pubkey=signer.identity, signers=[signer],
        ) is None

    def test_no_signature_when_the_key_does_not_match_the_chain(self):
        signer = _Ed25519TestSigner()
        assert _sign_confirm_intent(
            pay_req_id="pr_1", tx_sig="0xabc123", operator_pubkey="OperatorKey", signers=[signer],
        ) is None

    def test_a_failing_signer_never_raises(self):
        signer = MagicMock()
        signer.sig_alg = "ed25519"
        signer.identity = "SomeKey"
        signer.sign.side_effect = RuntimeError("the signing device is unavailable")
        assert _sign_confirm_intent(
            pay_req_id="pr_1", tx_sig="5Sig", operator_pubkey="OperatorKey", signers=[None, signer],
        ) is None


class TestSyncConfirmStorageIntent:
    @patch("pynukez.client._httpx.post")
    def test_explicit_payer_signature_is_passed_through(self, mock_post, sync_client):
        mock_post.return_value = _confirm_ok_response()

        sync_client.confirm_storage("pr_1", "5SolanaSig", operator_pubkey="op_1", payer_signature="ExplicitSig")

        payload = mock_post.call_args[1]["json"]
        assert payload["operator_pubkey"] == "op_1"
        assert payload["payer_signature"] == "ExplicitSig"
        sync_client.keypair.sign.assert_not_called()

    @patch("pynukez.client._httpx.post")
    def test_the_held_key_signs_when_an_operator_is_bound(self, mock_post, sync_client):
        mock_post.return_value = _confirm_ok_response()

        sync_client.confirm_storage("pr_1", "5SolanaSig", operator_pubkey="op_1")

        payload = mock_post.call_args[1]["json"]
        assert payload["payer_signature"] == "FakeSignature"
        sync_client.keypair.sign.assert_called_once_with(b"nukez/confirm/v1|pr_1|5SolanaSig|op_1")

    @patch("pynukez.client._httpx.post")
    def test_no_signature_without_an_operator(self, mock_post, sync_client):
        mock_post.return_value = _confirm_ok_response()

        sync_client.confirm_storage("pr_1", "5SolanaSig")

        payload = mock_post.call_args[1]["json"]
        assert payload == {"pay_req_id": "pr_1"}
        sync_client.keypair.sign.assert_not_called()

    @patch("pynukez.client._httpx.post")
    def test_evm_auto_bind_is_not_signed_by_the_ed25519_key(self, mock_post, sync_client):
        mock_post.return_value = _confirm_ok_response()

        with pytest.warns(DeprecationWarning):
            sync_client.confirm_storage("pr_1", "0xabc123")

        payload = mock_post.call_args[1]["json"]
        assert payload["operator_pubkey"] == "FakePublicKey123456789"
        assert "payer_signature" not in payload

    @patch("pynukez.client._httpx.post")
    def test_a_signing_failure_never_fails_the_confirm(self, mock_post, sync_client):
        mock_post.return_value = _confirm_ok_response()
        sync_client.keypair.sign.side_effect = RuntimeError("the signing device is unavailable")

        receipt = sync_client.confirm_storage("pr_1", "5SolanaSig", operator_pubkey="op_1")

        assert receipt.id == "r_123"
        assert "payer_signature" not in mock_post.call_args[1]["json"]


class TestSyncConfirmStorageErrors:
    @patch("pynukez.client.time.sleep")
    @patch("pynukez.client._httpx.post")
    def test_payment_already_allocated_is_raised_at_once(self, mock_post, mock_sleep, sync_client):
        mock_post.return_value = _confirm_error_response(409, {
            "error_code": "PAYMENT_ALREADY_ALLOCATED",
            "message": "This transaction has already paid for a different request.",
            "details": {"tx": "5SolanaSig", "pay_req_id": "pr_2"},
        })

        with pytest.raises(NukezError) as raised:
            sync_client.confirm_storage("pr_2", "5SolanaSig")

        assert raised.value.details["error_code"] == "PAYMENT_ALREADY_ALLOCATED"
        assert raised.value.retryable is False
        assert mock_post.call_count == 1
        mock_sleep.assert_not_called()

    @patch("pynukez.client.time.sleep")
    @patch("pynukez.client._httpx.post")
    def test_confirm_intent_required_maps_to_authentication_error(self, mock_post, mock_sleep, sync_client):
        mock_post.return_value = _confirm_error_response(401, {
            "error_code": "CONFIRM_INTENT_REQUIRED",
            "message": "Binding an operator requires the payer's signature over the confirm intent.",
            "details": {"sign_this": "nukez/confirm/v1|pr_1|0xabc123|op_1"},
        })

        with pytest.raises(AuthenticationError) as raised:
            sync_client.confirm_storage("pr_1", "0xabc123", operator_pubkey="op_1")

        assert raised.value.details["error_code"] == "CONFIRM_INTENT_REQUIRED"
        assert raised.value.details["sign_this"] == "nukez/confirm/v1|pr_1|0xabc123|op_1"
        assert mock_post.call_count == 1
        mock_sleep.assert_not_called()

    @patch("pynukez.client.time.sleep")
    @patch("pynukez.client._httpx.post")
    def test_payment_outside_quote_window_is_not_retried(self, mock_post, mock_sleep, sync_client):
        mock_post.return_value = _confirm_error_response(402, {
            "error_code": "PAYMENT_OUTSIDE_QUOTE_WINDOW",
            "message": "",
            "details": {"reason": "paid_before_quote:86400s"},
        })

        with pytest.raises(NukezError) as raised:
            sync_client.confirm_storage("pr_1", "5SolanaSig")

        assert raised.value.details["error_code"] == "PAYMENT_OUTSIDE_QUOTE_WINDOW"
        assert mock_post.call_count == 1
        mock_sleep.assert_not_called()

    def test_other_error_codes_keep_the_existing_handling(self):
        assert _confirm_error_from_response(409, {"error_code": "SOMETHING_ELSE"}) is None
        assert _confirm_error_from_response(500, None) is None
        assert _confirm_error_from_response(422, {"error_code": "INVALID_OPERATOR_PUBKEY"}) is None

    def test_payment_option_not_in_quote(self):
        error = _confirm_error_from_response(422, {
            "error_code": "PAYMENT_OPTION_NOT_IN_QUOTE", "message": "This quote did not offer SOL.",
        })
        assert isinstance(error, NukezError)
        assert not isinstance(error, AuthenticationError)
        assert error.details["status_code"] == 422


class TestAsyncConfirmStorage:
    async def test_the_held_key_signs_when_an_operator_is_bound(self, async_client):
        async_client._raw_client.post = AsyncMock(return_value=_confirm_ok_response())

        await async_client.confirm_storage("pr_1", "5SolanaSig", operator_pubkey="op_1")

        payload = async_client._raw_client.post.call_args[1]["json"]
        assert payload["payer_signature"] == "FakeSignature"
        async_client.keypair.sign.assert_called_once_with(b"nukez/confirm/v1|pr_1|5SolanaSig|op_1")

    async def test_explicit_payer_signature_is_passed_through(self, async_client):
        async_client._raw_client.post = AsyncMock(return_value=_confirm_ok_response())

        await async_client.confirm_storage("pr_1", "5SolanaSig", operator_pubkey="op_1", payer_signature="ExplicitSig")

        assert async_client._raw_client.post.call_args[1]["json"]["payer_signature"] == "ExplicitSig"

    async def test_no_signature_without_an_operator(self, async_client):
        async_client._raw_client.post = AsyncMock(return_value=_confirm_ok_response())

        await async_client.confirm_storage("pr_1", "5SolanaSig")

        assert async_client._raw_client.post.call_args[1]["json"] == {"pay_req_id": "pr_1"}

    async def test_payment_already_allocated_is_raised_at_once(self, async_client):
        async_client._raw_client.post = AsyncMock(return_value=_confirm_error_response(409, {
            "error_code": "PAYMENT_ALREADY_ALLOCATED",
            "message": "This transaction has already paid for a different request.",
        }))

        with patch("pynukez._async_client.asyncio.sleep", new=AsyncMock()) as mock_sleep:
            with pytest.raises(NukezError) as raised:
                await async_client.confirm_storage("pr_2", "5SolanaSig")

        assert raised.value.details["error_code"] == "PAYMENT_ALREADY_ALLOCATED"
        assert async_client._raw_client.post.call_count == 1
        mock_sleep.assert_not_called()

    async def test_confirm_intent_invalid_maps_to_authentication_error(self, async_client):
        async_client._raw_client.post = AsyncMock(return_value=_confirm_error_response(401, {
            "error_code": "CONFIRM_INTENT_INVALID",
            "message": "Binding an operator requires the payer's signature over the confirm intent.",
            "details": {"sign_this": "nukez/confirm/v1|pr_1|5SolanaSig|op_1"},
        }))

        with pytest.raises(AuthenticationError) as raised:
            await async_client.confirm_storage("pr_1", "5SolanaSig", operator_pubkey="op_1")

        assert raised.value.details["sign_this"] == "nukez/confirm/v1|pr_1|5SolanaSig|op_1"
        assert async_client._raw_client.post.call_count == 1


# ---------------------------------------------------------------------------
# pynukez.verify: the vendored verifier
# ---------------------------------------------------------------------------

_HASH_A = hashlib.sha256(b"hello").hexdigest()
_HASH_B = hashlib.sha256(b"world").hexdigest()

# These values were computed by hand with hashlib. Each leaf is the SHA-256 of
# the text "filename:size:hash". The root is the SHA-256 of the two leaf hex
# strings joined together, with the leaves sorted by filename.
_LEAF_A = "ca9901e1dcc20c6475aa7e52a50e622fd3acdc040228ea71fbb19dd0b7238a6c"
_LEAF_B = "bd248f81ccf091fe01b8c4d94a2f2dd2b88e677e34cb61f1da5e5cfa57958118"
_TWO_FILE_ROOT = "7946729dcc6467d40886a08d35f9e0155cbbc38220824559e72ee7106915c44c"


def _two_files() -> list:
    # The files are listed out of order on purpose, because the algorithm sorts them.
    return [
        {"filename": "b.txt", "size_bytes": 5, "content_hash": "sha256:" + _HASH_B},
        {"filename": "a.txt", "size_bytes": 5, "content_hash": _HASH_A},
    ]


def _build_v2_bundle(signing_key: SigningKey) -> dict:
    """Build a version two evidence bundle signed with a throwaway key."""
    files = [
        {"filename": "a.txt", "size_bytes": 5, "content_hash": _HASH_A},
        {"filename": "b.txt", "size_bytes": 5, "content_hash": _HASH_B},
    ]
    body = {
        "schema": "nukez/evidence/v2",
        "policy_version": "1",
        "proof_id": "9f" * 16,
        "snapshot_id": "ef" * 32,
        "sequence": 1,
        "prev_statement_digest": None,
        "merkle_algorithm": "nukez-merkle-v1",
        "merkle_root": "sha256:" + _TWO_FILE_ROOT,
        "file_count": 2,
        "manifest_file_count": 2,
        "total_bytes": "10",
        "check_mode": "recorded_hashes",
        "issued_at": "2026-09-21T10:00:00Z",
        "issued_at_unix": 1790000000,
        "issuer_key_id": "ed25519:test",
        "nonce": "00" * 16,
    }
    digest = hashlib.sha256(nukez_verify.canonicalize(body)).digest()
    signature = signing_key.sign(b"NUKEZ_CONTENT_ENVELOPE_V2\x00" + digest).signature
    public_key_hex = signing_key.verify_key.encode().hex()
    return {
        "schema": "nukez/evidence-bundle/v2",
        "bundle_version": 2,
        "receipt_id": "r1",
        "proof_id": "9f" * 16,
        "commitment": {"merkle_root": "sha256:" + _TWO_FILE_ROOT, "file_count": 2},
        "files": files,
        "envelope": {
            "body": body,
            "statement_digest": digest.hex(),
            "signature": signature.hex(),
            "sig_alg": "ed25519",
            "issuer_pubkey": public_key_hex,
        },
        "v1_signature": None,
        "anchor": None,
        "verification": _facts("not_checked"),
        "signing_keys": [{"key_id": "ed25519:test", "alg": "ed25519", "public_key_hex": public_key_hex}],
    }


class TestVendoredVerifier:
    def test_package_exports(self):
        import pynukez

        assert pynukez.verify_offline is nukez_verify.verify_offline
        assert pynukez.verify_online is nukez_verify.verify_online
        assert pynukez.merkle_root_v1 is nukez_verify.merkle_root_v1

    def test_merkle_root_agrees_with_the_hand_computed_example(self):
        leaf_a = hashlib.sha256(f"a.txt:5:{_HASH_A}".encode("utf-8")).hexdigest()
        leaf_b = hashlib.sha256(f"b.txt:5:{_HASH_B}".encode("utf-8")).hexdigest()
        assert leaf_a == _LEAF_A
        assert leaf_b == _LEAF_B
        by_hand = hashlib.sha256((leaf_a + leaf_b).encode("utf-8")).hexdigest()
        assert by_hand == _TWO_FILE_ROOT

        assert nukez_verify.merkle_root_v1(_two_files()) == _TWO_FILE_ROOT

    def test_offline_verification_passes_for_a_signed_bundle(self):
        signing_key = SigningKey.generate()
        bundle = _build_v2_bundle(signing_key)

        facts = nukez_verify.verify_offline(bundle, pinned_keys=[signing_key.verify_key.encode().hex()])

        assert facts["merkle_root_matches"] == "passed"
        assert facts["statement_digest_matches"] == "passed"
        assert facts["envelope_binds_commitment"] == "passed"
        assert facts["signature_valid"] == "passed"
        assert facts["key_pinned"] == "passed"
        assert facts["files_match"] == "not_checked"
        assert "failed" not in facts.values()

    def test_offline_verification_without_a_pinned_key_says_so(self):
        bundle = _build_v2_bundle(SigningKey.generate())

        facts = nukez_verify.verify_offline(bundle)

        assert facts["signature_valid"] == "passed"
        assert facts["key_pinned"] == "not_checked"

    def test_a_tampered_file_entry_fails(self):
        signing_key = SigningKey.generate()
        bundle = _build_v2_bundle(signing_key)
        bundle["files"][0]["size_bytes"] = 6

        facts = nukez_verify.verify_offline(bundle, pinned_keys=[signing_key.verify_key.encode().hex()])

        assert facts["merkle_root_matches"] == "failed"

    def test_a_tampered_envelope_body_fails(self):
        signing_key = SigningKey.generate()
        bundle = _build_v2_bundle(signing_key)
        bundle["envelope"]["body"]["file_count"] = 3

        facts = nukez_verify.verify_offline(bundle, pinned_keys=[signing_key.verify_key.encode().hex()])

        assert facts["statement_digest_matches"] == "failed"
        assert facts["envelope_binds_commitment"] == "failed"
        assert facts["signature_valid"] == "failed"

    def test_a_signature_from_another_key_fails_against_the_pinned_key(self):
        bundle = _build_v2_bundle(SigningKey.generate())
        other_key = SigningKey.generate()

        facts = nukez_verify.verify_offline(bundle, pinned_keys=[other_key.verify_key.encode().hex()])

        assert facts["signature_valid"] == "failed"

    def test_a_historical_version_one_bundle_passes(self):
        """A Switchboard-era record carries a bare signature over the merkle root hex."""
        signing_key = SigningKey.generate()
        public_key_hex = signing_key.verify_key.encode().hex()
        bundle = {
            "schema": "nukez/evidence-bundle/v2",
            "bundle_version": 1,
            "commitment": {"merkle_root": "sha256:" + _TWO_FILE_ROOT, "file_count": 2},
            "files": _two_files(),
            "envelope": None,
            "v1_signature": {
                "manifest_signature": signing_key.sign(_TWO_FILE_ROOT.encode("utf-8")).signature.hex(),
            },
            "anchor": dict(_SWITCHBOARD_ANCHOR),
            "signing_keys": [{"key_id": "ed25519:test", "alg": "ed25519", "public_key_hex": public_key_hex}],
        }

        facts = nukez_verify.verify_offline(bundle, pinned_keys=[public_key_hex])

        assert facts["merkle_root_matches"] == "passed"
        assert facts["signature_valid"] == "passed"
        assert facts["statement_digest_matches"] == "not_checked"

    def test_local_files_are_checked_when_a_directory_is_given(self, tmp_path):
        signing_key = SigningKey.generate()
        bundle = _build_v2_bundle(signing_key)
        (tmp_path / "a.txt").write_bytes(b"hello")
        (tmp_path / "b.txt").write_bytes(b"world")

        assert nukez_verify.verify_offline(bundle, files_dir=str(tmp_path))["files_match"] == "passed"

        (tmp_path / "b.txt").write_bytes(b"w0rld")
        assert nukez_verify.verify_offline(bundle, files_dir=str(tmp_path))["files_match"] == "failed"

    def test_online_facts_are_not_checked_without_an_anchor(self):
        bundle = _build_v2_bundle(SigningKey.generate())

        facts = nukez_verify.verify_online(bundle, "http://127.0.0.1:1")

        assert set(facts.values()) == {"not_checked"}

    def test_command_line_exit_status(self, tmp_path, capsys):
        signing_key = SigningKey.generate()
        bundle = _build_v2_bundle(signing_key)
        good_path = tmp_path / "bundle.json"
        good_path.write_text(json.dumps(bundle))

        assert nukez_verify.main([str(good_path), "--pin", signing_key.verify_key.encode().hex()]) == 0
        printed = json.loads(capsys.readouterr().out)
        assert printed["facts"]["signature_valid"] == "passed"
        assert printed["facts"]["anchor_tx_succeeded"] == "not_checked"

        bundle["files"][0]["size_bytes"] = 6
        bad_path = tmp_path / "tampered.json"
        bad_path.write_text(json.dumps(bundle))
        assert nukez_verify.main([str(bad_path)]) == 1
