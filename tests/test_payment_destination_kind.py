"""
Tests for the destination_kind / spl_transfer envelope fields (4.0.18).

Covers the spec at nukez-mcp/docs/spec-pynukez-spl-destination-clarity.md
plus the nukez-mcp boundary lock: the raw `payment_options[i]["spl_transfer"]`
view MUST stay a plain dict so the MCP preflight's `.get()` chain keeps working.
"""
import copy

import pytest
from unittest.mock import Mock

from pynukez._http import handle_error_response
from pynukez.errors import PaymentRequiredError
from pynukez.types import SplTransfer, StorageRequest


# ── Fixtures (synthetic x402 v2 responses) ────────────────────────────────

SPL_ACCEPT = {
    "scheme": "exact",
    "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "amount": "1",
    "asset": "GBVdmQpooUmETgS8TiEqP9zuk3ajky2mabHrvSbYjR6s",
    "payTo": "7uuKkouh1PqEncfocPsbYVmW1arm2xk6sRmmdmBPa6uf",
    "maxTimeoutSeconds": 300,
    "extra": {
        "name": "BETA",
        "decimals": 0,
        "human_amount": "1",
        "pay_req_id": "test_req",
        "destination_kind": "spl_token_account",
        "spl_transfer": {
            "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "destination_token_account": "7uuKkouh1PqEncfocPsbYVmW1arm2xk6sRmmdmBPa6uf",
            "mint": "GBVdmQpooUmETgS8TiEqP9zuk3ajky2mabHrvSbYjR6s",
            "amount_raw": 1,
            "decimals": 0,
        },
    },
}

SOL_NATIVE_ACCEPT_OLD = {
    "scheme": "exact",
    "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "amount": "100000000",
    "asset": "So11111111111111111111111111111111111111112",
    "payTo": "WalletPubkey",
    "maxTimeoutSeconds": 300,
    "extra": {
        "name": "SOL",
        "decimals": 9,
        "human_amount": "0.1",
        "pay_req_id": "old_req",
    },
}


def _mock_402(accepts):
    body = {"x402Version": 2, "error": "payment_required", "accepts": accepts}
    resp = Mock()
    resp.status_code = 402
    resp.content = b"<placeholder>"   # truthy so parse_error_response calls .json()
    resp.json.return_value = body
    return resp


# ── Tests ──────────────────────────────────────────────────────────────────

class TestSplDestinationParsing:
    """Verifies _http.py's x402 v2 parser surfaces the new fields correctly."""

    def test_spl_end_to_end_typed_view(self):
        """SPL 402 -> PaymentRequiredError carries a typed SplTransfer."""
        with pytest.raises(PaymentRequiredError) as ei:
            handle_error_response(_mock_402([SPL_ACCEPT]))
        e = ei.value

        assert e.destination_kind == "spl_token_account"
        assert isinstance(e.spl_transfer, SplTransfer)
        assert e.spl_transfer.destination_token_account == SPL_ACCEPT["payTo"]
        assert e.spl_transfer.mint == "GBVdmQpooUmETgS8TiEqP9zuk3ajky2mabHrvSbYjR6s"
        assert e.spl_transfer.amount_raw == 1
        assert e.spl_transfer.decimals == 0
        assert e.spl_transfer.program_id == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

    def test_token_address_not_set_for_solana_spl(self):
        """token_address stays empty for Solana SPL — read spl_transfer.mint.

        Guards against a future "helpful" backfill that would silently
        change semantics for existing callers that treat token_address as EVM-only.
        """
        with pytest.raises(PaymentRequiredError) as ei:
            handle_error_response(_mock_402([SPL_ACCEPT]))
        assert ei.value.token_address == ""

    def test_raw_payment_options_dict_view(self):
        """nukez-mcp boundary lock: raw view stays plain dicts.

        nukez-mcp's preflight reads ``payment_options[i].get("spl_transfer").get(...)``
        — this only works if ``spl_transfer`` in the raw view is a plain dict,
        NOT an ``SplTransfer`` instance. The ``isinstance(..., dict)`` assertions
        below pin that contract so a future "let's make everything typed" refactor
        fails loudly here instead of silently breaking the MCP via
        ``AttributeError: 'SplTransfer' object has no attribute 'get'``.
        """
        with pytest.raises(PaymentRequiredError) as ei:
            handle_error_response(_mock_402([SPL_ACCEPT]))
        opt = ei.value.payment_options[0]

        # The lock:
        assert isinstance(opt, dict)
        assert isinstance(opt["spl_transfer"], dict)   # NOT an SplTransfer
        # And the values come through:
        assert opt["destination_kind"] == "spl_token_account"
        assert opt["spl_transfer"]["destination_token_account"] == SPL_ACCEPT["payTo"]
        assert opt["spl_transfer"]["mint"] == "GBVdmQpooUmETgS8TiEqP9zuk3ajky2mabHrvSbYjR6s"

    def test_older_gateway_fields_absent(self):
        """No-new-fields 402 -> destination_kind=None, spl_transfer=None, rest unchanged."""
        with pytest.raises(PaymentRequiredError) as ei:
            handle_error_response(_mock_402([SOL_NATIVE_ACCEPT_OLD]))
        e = ei.value

        assert e.destination_kind is None
        assert e.spl_transfer is None
        # Regression check: existing SOL parsing path unchanged.
        assert e.pay_to_address == "WalletPubkey"
        assert e.amount_sol == pytest.approx(0.1)
        # Raw view also yields None entries (not missing keys — explicit None).
        opt = e.payment_options[0]
        assert opt["destination_kind"] is None
        assert opt["spl_transfer"] is None

    def test_destination_kind_unknown(self):
        """destination_kind='unknown' is preserved verbatim; spl_transfer=None; no crash."""
        accept = copy.deepcopy(SOL_NATIVE_ACCEPT_OLD)
        accept["extra"]["destination_kind"] = "unknown"
        with pytest.raises(PaymentRequiredError) as ei:
            handle_error_response(_mock_402([accept]))
        e = ei.value
        assert e.destination_kind == "unknown"
        assert e.spl_transfer is None


class TestPaymentRequiredErrorDetails:
    """`.details` dict stays JSON-friendly (dict form), the attribute stays typed."""

    def test_spl_transfer_in_details_is_dict_not_dataclass(self):
        with pytest.raises(PaymentRequiredError) as ei:
            handle_error_response(_mock_402([SPL_ACCEPT]))
        e = ei.value

        assert isinstance(e.spl_transfer, SplTransfer)                   # attribute: typed
        assert isinstance(e.details["spl_transfer"], dict)               # details: dict
        assert e.details["destination_kind"] == "spl_token_account"
        assert e.details["spl_transfer"]["mint"] == e.spl_transfer.mint  # equal payloads

    def test_no_spl_keys_in_details_when_absent(self):
        """`details` only carries keys for fields that were actually present."""
        with pytest.raises(PaymentRequiredError) as ei:
            handle_error_response(_mock_402([SOL_NATIVE_ACCEPT_OLD]))
        e = ei.value
        assert "destination_kind" not in e.details
        assert "spl_transfer" not in e.details


class TestStorageRequestSplBranch:
    """SPL branch in StorageRequest.__post_init__ produces the 'do NOT' guidance."""

    def test_next_step_spl_canary(self):
        """If a future template edit silently regresses, this fires."""
        spl = SplTransfer(
            program_id="TokenkegQ...",
            destination_token_account="7uuKkouhDest",
            mint="MintAddr",
            amount_raw=1,
            decimals=0,
        )
        req = StorageRequest(
            pay_req_id="req_x",
            pay_to_address="7uuKkouhDest",
            amount_sol=0.0,
            amount_lamports=0,
            network="solana-mainnet",
            units=1,
            pay_asset="BETA",
            destination_kind="spl_token_account",
            spl_transfer=spl,
        )

        assert "do NOT" in req.next_step                  # explicit ATA-warning canary
        assert "transferChecked" in req.next_step
        assert "MintAddr" in req.next_step                # mint surfaced for the signer

    def test_native_sol_branch_unchanged(self):
        """Non-SPL native SOL still hits the existing branch (no regression)."""
        req = StorageRequest(
            pay_req_id="req_y",
            pay_to_address="WalletAddr",
            amount_sol=0.1,
            amount_lamports=100_000_000,
            network="solana-mainnet",
            units=1,
            pay_asset="SOL",
            destination_kind=None,
        )
        assert "0.1 SOL" in req.next_step
        assert "do NOT" not in req.next_step              # SPL canary stays in its lane
