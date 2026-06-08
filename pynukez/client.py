#pynukez/pynukez/client.py
"""
Nukez client - agent-native storage operations.

Every method is a tool that maps to one HTTP operation.
Explicit inputs/outputs - agents know exactly what to pass and what they get back.

FIXED: confirm_storage now has proper retry logic for tx_not_found,
matching the working nukez implementation.
"""

import base64
import binascii
import hashlib
import json
import logging
import mimetypes
import os
import threading
import time
import uuid

logger = logging.getLogger("pynukez.client")
import httpx as _httpx
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass
from urllib.parse import urlencode
from .types import (
    StorageRequest,
    SplTransfer,
    Receipt,
    NukezManifest,
    FileUrls,
    FileInfo,
    UploadResult,
    DeleteResult,
    VerificationResult,
    RecomputeVerifyResult,
    ReceiptHashVerification,
    PriceInfo,
    ConfirmResult,
    BatchConfirmResult,
    AttestResult,
    BatchUploadResult,
    DownloadedFile,
    BatchDownloadResult,
    ViewerLink,
    FileViewerInfo,
    ViewerFileList,
    ViewerContainer,
    OperatorResult,
    LockerRecord,
)

from .auth import (
    Keypair,
    build_signed_envelope,
    compute_locker_id,
    infer_sig_alg,
    _ReceiptState,
)
from .errors import (
    NukezError,
    PaymentRequiredError,
    ReceiptStateNotBoundError,
    TransactionNotFoundError,
)
from .hardening import sanitize_upload_data, validate_signed_url
from ._http import HTTPClient, caip2_to_friendly
from ._helpers import (
    UPLOAD_STRING_MAX_BYTES as UPLOAD_STRING_MAX_BYTES,
    _SANDBOX_PATH_BLOCKED_MARKERS as _SANDBOX_PATH_BLOCKED_MARKERS,
    _infer_content_type,
    _sanitize_filename,
    _normalize_expected_sha256,
    _is_sandbox_path_unavailable_error,
    _is_gateway_short_url,
    _normalize_viewer_base_url,
    _viewer_button_ui,
    _viewer_renderer_contract,
    _viewer_container_contract,
    make_text_renderable,
    make_json_renderable,
    make_pdf_renderable,
    make_image_renderable,
    make_binary_renderable,
    make_header_block,
    make_stats_block,
    make_links_block,
    make_table_block,
    make_kv_block,
    make_status_block,
    make_proofs_block,
    make_json_block,
    make_file_meta_block,
    make_file_preview_block,
)

VIEWER_RENDERER_CONTRACT_NAME = "nukez.mcp.viewer_link"
VIEWER_RENDERER_CONTRACT_VERSION = "1.0"
VIEWER_RENDERER_VARIANT = "nukez-neon"
VIEWER_CONTAINER_CONTRACT_NAME = "nukez.viewer_container"
VIEWER_CONTAINER_CONTRACT_VERSION = "1.0.0"
SANDBOX_INGEST_DEFAULT_PART_BYTES = int(os.getenv("PYNUKEZ_SANDBOX_INGEST_PART_BYTES", "196608"))
SANDBOX_INGEST_MAX_PART_BYTES = 512 * 1024
SANDBOX_INGEST_MIN_PART_BYTES = 4 * 1024
SANDBOX_INGEST_EXECUTION_MODE = os.getenv("PYNUKEZ_SANDBOX_EXECUTION_MODE", "sandbox")


class Nukez:
    """
    Agent-native Nukez client.
    
    Each method is a self-contained tool operation designed for LLM function calling.
    Methods use explicit parameters - agents always know what to pass.
    
    Basic Usage:
        client = Nukez(keypair_path="~/.config/solana/id.json")

        # Payment flow: PyNukez does not execute transfers. Use your wallet,
        # CLI, or signer, then pass the tx signature back to confirm.
        request = client.request_storage(units=1)
        # ... complete transfer via preferred method ...
        receipt = client.confirm_storage(request.pay_req_id, tx_sig=<your_tx_signature>)

        # File operations (require receipt_id)
        manifest = client.provision_locker(receipt.id)
        uploaded = client.upload_file_path(receipt.id, "~/Documents/report.pdf")
        file_urls = client.get_file_urls(receipt.id, uploaded["filename"])
        data = client.download_bytes(file_urls.download_url)
    
    Note:
        Most file operations require receipt_id (not locker_id) because the 
        signed envelope authentication uses receipt_id. Agents should track
        the receipt_id returned from confirm_storage().
    """
    
    def __init__(
        self,
        keypair_path: Optional[Union[str, Path]] = None,
        base_url: str = os.environ.get("NUKEZ_BASE_URL", "https://api.nukez.xyz"),
        network: str = "devnet",
        timeout: int = None,
        evm_private_key_path: Optional[Union[str, Path]] = None,
        evm_rpc_url: Optional[str] = None,
        auto_bind_operator: bool = True,
        signing_key: Optional[Any] = None,
    ):
        """
        Initialize Nukez client.

        Args:
            keypair_path: Path to Ed25519 keypair JSON file used to sign
                envelopes for Solana-paid lockers.
            base_url: Nukez API base URL
            network: Solana network identifier ("devnet" or "mainnet-beta")
                used for signed-envelope context.
            timeout: HTTP timeout in seconds
            evm_private_key_path: Path to EVM private key JSON file.
                The EVM key is used for secp256k1 envelope signing on
                EVM-paid lockers. It is not used to execute transfers.
            evm_rpc_url: Reserved; currently unused at the SDK layer.
            auto_bind_operator: When True (default), auto-bind Ed25519
                keypair as operator on EVM-paid lockers at confirm time.
                Deprecated — set False for EVM-native owners.
            signing_key: Explicit Signer instance for envelope signing.
                Takes priority over keypair_path and evm_private_key_path.

        Example:
            # Solana-paid locker (Ed25519 envelopes)
            client = Nukez(keypair_path="~/.config/solana/id.json")

            # EVM-paid locker, owner signs envelopes directly (secp256k1)
            client = Nukez(evm_private_key_path="~/.keys/evm_key.json",
                           auto_bind_operator=False)

            # Dual-key (Ed25519 envelope signing + EVM envelope signing
            # for EVM-paid lockers)
            client = Nukez(keypair_path="~/.keys/svm_key.json",
                           evm_private_key_path="~/.keys/evm_key.json")
        """

        self.base_url = base_url.rstrip('/')
        self.network = network
        self.timeout = timeout or 120
        self.http = HTTPClient(base_url, timeout=self.timeout)
        self._raw_client = _httpx.Client(timeout=60, follow_redirects=True)
        self._auto_bind_operator = auto_bind_operator

        # Signer resolution: signing_key > keypair_path > evm_private_key_path
        # Auto-detect: if keypair_path points to an EVM-format key file,
        # treat it as evm_private_key_path instead of failing.
        if keypair_path and not evm_private_key_path and not signing_key:
            try:
                kp = Path(keypair_path).expanduser()
                if kp.exists():
                    with open(kp, "r") as _f:
                        _data = json.load(_f)
                    if isinstance(_data, dict) and ("private_key" in _data or "address" in _data):
                        evm_private_key_path = keypair_path
                        keypair_path = None
            except Exception:
                pass  # Let Keypair() handle the error with its clear message

        self._signer = None
        self.keypair: Optional[Keypair] = None

        if signing_key is not None:
            self._signer = signing_key
            # Keep the Ed25519 Keypair around when the caller also supplied
            # keypair_path — it's still the default envelope signer for
            # Solana-paid lockers on dual-key clients.
            if keypair_path:
                self.keypair = Keypair(keypair_path)
        elif keypair_path:
            self.keypair = Keypair(keypair_path)
            self._signer = self.keypair
        elif evm_private_key_path:
            # EVM-only: use EVM key for envelope signing (secp256k1)
            from .signer import EVMSigner
            self._signer = EVMSigner.from_file(str(evm_private_key_path))
            # self.keypair stays None — no Ed25519 keypair

        # Per-receipt state: receipt_id → _ReceiptState(owner_identity, sig_alg).
        # Single source of truth for owner delegation detection (_is_delegating)
        # and dual-key signer auto-selection (_require_signer).
        # Written exclusively through bind_receipt() so every write goes through
        # the same validation path (conflict detection, sig_alg inference).
        self._receipt_state: Dict[str, _ReceiptState] = {}

        self._keypair_path = keypair_path
        self._evm_private_key_path = evm_private_key_path
        self._evm_rpc_url = evm_rpc_url

        # Store both signers for dual-key clients (EVM + Ed25519).
        # _signer is the default; _evm_signer is the EVM-specific one.
        self._evm_signer = None
        if keypair_path and evm_private_key_path and signing_key is None:
            from .signer import EVMSigner
            self._evm_signer = EVMSigner.from_file(str(evm_private_key_path))
        self._upload_jobs: Dict[str, Dict[str, Any]] = {}
        self._upload_jobs_lock = threading.Lock()

    def close(self):
        """Close underlying HTTP clients."""
        self.http.close()
        self._raw_client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _require_signer(self, operation: str, receipt_id: str = ""):
        """
        Ensure a signer is available and return the correct one for this receipt.

        For single-key clients: returns ``self._signer`` (unchanged behavior).

        For dual-key clients (both keypair_path and evm_private_key_path):
        looks up ``self._receipt_state`` for the receipt and returns either
        the EVM signer (``secp256k1``) or the Ed25519 signer (``ed25519``).
        If no state is bound, first tries to infer ``sig_alg`` from a cached
        owner identity; if that also fails, raises ``ReceiptStateNotBoundError``
        rather than silently guessing.  Callers recover by calling
        :meth:`bind_receipt` with the receipt (or its raw fields) and retrying.

        Raises:
            NukezError: No signer configured at all.
            ReceiptStateNotBoundError: Dual-key client, receipt state cold,
                and ``sig_alg`` cannot be inferred.
        """
        if self._signer is None:
            raise NukezError(
                f"{operation} requires a signing key. "
                "Provide keypair_path, evm_private_key_path, or signing_key."
            )
        # Single-key clients: no ambiguity, return the only signer we have.
        if not self._evm_signer:
            return self._signer
        # Dual-key: consult the per-receipt state, with a single inference pass.
        if not receipt_id:
            # No receipt context at all — fall back to default signer. Used by
            # operations that don't carry a receipt (e.g. get_price).
            return self._signer
        state = self._receipt_state.get(receipt_id)
        if state is None or not state.sig_alg:
            # Cold or incomplete — refuse to guess.
            raise ReceiptStateNotBoundError(receipt_id=receipt_id, operation=operation)
        if state.sig_alg == "secp256k1":
            return self._evm_signer
        if state.sig_alg == "ed25519":
            return self._signer
        raise ReceiptStateNotBoundError(receipt_id=receipt_id, operation=operation)

    def _is_delegating(self, receipt_id: str) -> bool:
        """
        Return True when the current signer is NOT the locker owner.

        Reads from ``self._receipt_state``.  Behavior on cold cache is
        narrower than the previous "default True" fallback:

          * No signer at all → ``False`` (nothing to delegate through).
          * Single-key client with cold state → ``True`` (preserved legacy
            default; a stray ``signer`` field is harmless when it matches
            the owner).
          * Dual-key client with cold state → raise
            ``ReceiptStateNotBoundError``.  Mixed bound/unbound receipts
            in a dual-key session are exactly the scenario where silent
            defaults cause identity confusion; force the caller to bind.

        Raises:
            ReceiptStateNotBoundError: Dual-key client, receipt state cold.
        """
        if self._signer is None:
            return False
        state = self._receipt_state.get(receipt_id)
        if state is None or not state.owner_identity:
            if self._evm_signer:
                raise ReceiptStateNotBoundError(
                    receipt_id=receipt_id, operation="_is_delegating"
                )
            # Single-key client: keep the legacy default.
            return True
        return self._signer.identity != state.owner_identity

    def bind_receipt(
        self,
        receipt: Optional[Receipt] = None,
        *,
        receipt_id: str = "",
        owner_identity: str = "",
        sig_alg: str = "",
    ) -> None:
        """Prime per-receipt state from a :class:`Receipt` or raw fields.

        This is the canonical entry point for cross-session workflows:
        load a receipt from disk, DB, or a gateway response, bind it, then
        operate.  Internal calls from :meth:`confirm_storage` and
        :meth:`provision_locker` also route through this method so every
        write to ``self._receipt_state`` goes through a single validator.

        The method accepts either a :class:`Receipt` dataclass or the raw
        fields.  When both are provided, the raw fields override the
        corresponding values on the dataclass.  ``sig_alg`` is inferred
        from ``owner_identity`` format when not supplied explicitly (see
        :func:`infer_sig_alg`).

        Args:
            receipt: Optional :class:`Receipt` supplying ``id``,
                ``payer_pubkey`` (as ``owner_identity``), and ``sig_alg``.
            receipt_id: Receipt ID.  Required if ``receipt`` is not given.
            owner_identity: Owner's public identifier (0x address or base58).
                Required to enable owner-op signing.
            sig_alg: Explicit signature algorithm.  Inferred from
                ``owner_identity`` format when omitted.

        Raises:
            NukezError: Not enough information to prime state, or sig_alg
                cannot be determined from the inputs provided.
            NukezError: An existing bind for this receipt_id conflicts with
                the new values (different owner_identity or sig_alg).
        """
        if receipt is not None:
            receipt_id = receipt_id or receipt.id
            owner_identity = owner_identity or receipt.payer_pubkey
            sig_alg = sig_alg or receipt.sig_alg

        if not receipt_id:
            raise NukezError(
                "bind_receipt requires receipt_id (pass receipt=... or receipt_id=...)."
            )
        if not owner_identity and not sig_alg:
            raise NukezError(
                f"bind_receipt for '{receipt_id}' requires owner_identity "
                f"or sig_alg — nothing to prime."
            )

        # Resolve sig_alg: explicit > inferred from owner_identity > error.
        if not sig_alg and owner_identity:
            inferred = infer_sig_alg(owner_identity)
            if inferred:
                sig_alg = inferred
        if not sig_alg:
            raise NukezError(
                f"bind_receipt cannot determine sig_alg for receipt "
                f"'{receipt_id}' from owner_identity '{owner_identity}'. "
                f"Call bind_receipt with explicit sig_alg='secp256k1' or "
                f"sig_alg='ed25519'."
            )
        if sig_alg not in ("secp256k1", "ed25519"):
            raise NukezError(
                f"bind_receipt: sig_alg must be 'secp256k1' or 'ed25519', "
                f"got '{sig_alg}'."
            )

        # Conflict detection: idempotent on same values, raise on mismatch.
        existing = self._receipt_state.get(receipt_id)
        if existing is not None:
            if (
                owner_identity
                and existing.owner_identity
                and existing.owner_identity != owner_identity
            ):
                raise NukezError(
                    f"bind_receipt: receipt '{receipt_id}' is already bound "
                    f"to owner '{existing.owner_identity}', refusing to "
                    f"overwrite with '{owner_identity}'."
                )
            if existing.sig_alg and existing.sig_alg != sig_alg:
                raise NukezError(
                    f"bind_receipt: receipt '{receipt_id}' is already bound "
                    f"with sig_alg '{existing.sig_alg}', refusing to "
                    f"overwrite with '{sig_alg}'."
                )
            # Idempotent re-bind, possibly filling in a previously-missing field.
            self._receipt_state[receipt_id] = _ReceiptState(
                owner_identity=owner_identity or existing.owner_identity,
                sig_alg=sig_alg,
            )
            return

        self._receipt_state[receipt_id] = _ReceiptState(
            owner_identity=owner_identity,
            sig_alg=sig_alg,
        )

    def set_owner(self, receipt_id: str, identity: Optional[str] = None) -> None:
        """Pre-seed the owner identity for a receipt.

        Thin compatibility shim over :meth:`bind_receipt`.  Prefer calling
        :meth:`bind_receipt` directly in new code — it accepts a full
        :class:`Receipt` and primes both owner identity and sig_alg in one
        call.

        Args:
            receipt_id: The receipt/locker identifier.
            identity: Owner identity string.  Defaults to the current
                signer's identity (i.e. "I am the owner").

        Raises:
            NukezError: If no signer is configured and identity is not provided,
                or if sig_alg cannot be inferred from the identity string.
        """
        if identity is None:
            if self._signer is None:
                raise NukezError(
                    "set_owner() requires either an explicit identity "
                    "or a configured signer."
                )
            identity = self._signer.identity
        self.bind_receipt(receipt_id=receipt_id, owner_identity=identity)

    # =========================================================================
    # DISCOVERY & PRICING (No auth required)
    # =========================================================================
    
    def get_price(self, units: int = 1) -> PriceInfo:
        """
        Get current storage pricing.

        Args:
            units: Number of storage units

        Returns:
            PriceInfo with pricing details
        """
        response = self.http.get("/v1/price", params={"units": units})
        meta = response.get("meta", {})
        sol = meta.get("sol", {})

        return PriceInfo(
            units=units,
            unit_price_usd=response.get("unit_price_usd", 0.0),
            total_usd=meta.get("total_usd", response.get("unit_price_usd", 0.0) * units),
            amount_sol=float(sol.get("amount_sol", 0) or 0),
            amount_lamports=int(sol.get("amount_lamports", 0) or 0),
            network=meta.get("network", self.network),
            pay_asset=meta.get("pay_asset", "SOL"),
            provider=meta.get("provider", ""),
            mode=meta.get("mode", "static"),
            cost_breakdown={
                "base_cost": meta.get("base_cost"),
                "attestation_fee": meta.get("attestation_fee"),
                "egress_allowance": meta.get("egress_allowance"),
                "margin": meta.get("margin"),
                "discount": meta.get("discount"),
            } if meta else None,
            payment_options=meta.get("payment_options"),
        )

    def get_provider_info(self, provider: str = "gcs"):
        """
        Get capabilities for a storage provider.

        Args:
            provider: Provider ID ("gcs", "mongodb", "firestore", "storj", "arweave", "filecoin")

        Returns:
            ProviderInfo with capabilities and limits.
        """
        from .types import PROVIDERS
        info = PROVIDERS.get(provider)
        if not info:
            raise NukezError(
                f"Unknown provider '{provider}'. "
                f"Available: {', '.join(PROVIDERS.keys())}"
            )
        return info

    # =========================================================================
    # PAYMENT FLOW (3 explicit steps)
    # =========================================================================
    
    def request_storage(
        self,
        units: int = 1,
        provider: str = None,
        pay_network: str = None,
        pay_asset: str = None,
    ) -> StorageRequest:
        """
        Step 1: Start the x402 payment flow and receive payment instructions.

        PyNukez does not execute blockchain payments. This call asks the
        gateway for a quote and returns a StorageRequest describing where to
        pay, how much, and on which chain. Use your own wallet, CLI, hardware
        signer, or custody workflow to complete the transfer, then submit the
        resulting tx signature to confirm_storage().

        Args:
            units: Number of storage units to purchase.
            provider: Storage backend. Default: gateway's default (currently "gcs").
                      Options:
                        "gcs"       — Google Cloud Storage, general-purpose.
                        "mongodb"   — Document/RAG store (16 MB per-doc limit).
                        "storj"     — Decentralized, S3-compatible storage.
                        "arweave"   — Permanent, immutable storage.
                        "filecoin"  — Content-addressed decentralized storage.
                        "firestore" — Firebase document store.
            pay_network: Payment chain identifier. Default: gateway picks a
                      chain based on the configured signer (Solana if only
                      a Solana keypair is provided; Monad if only an EVM
                      key is provided).

                      The SDK accepts EITHER the CAIP-2 identifier that the
                      gateway returns in the 402 response (preferred — matches
                      request.payment_options[].network entries 1:1) OR the
                      SDK's friendly alias. Both are forwarded to the gateway
                      verbatim and converted to CAIP-2 where needed for x402
                      headers.

                      CAIP-2                                              Friendly
                      -------------------------------------------------   ---------------
                      solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp             solana-mainnet
                      solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1             solana-devnet
                      solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z             solana-testnet
                      eip155:143                                          monad-mainnet
                      eip155:10143                                        monad-testnet
            pay_asset: Token symbol matching one of
                      `request.payment_options[].pay_asset`. Default: the
                      gateway picks ("SOL" for Solana, "MON" for Monad).

                      Asset availability is chain-dependent — the gateway's
                      402 response enumerates what's actually offered on
                      your selected chain in `payment_options`. Consult it
                      after your first call rather than guessing.

                      Symbols currently returned by the gateway:
                        Solana:          SOL, USDC, USDT
                        Monad (EVM):     MON, USDC, USDT0, WETH

                      Note: Monad returns `USDT0` (Tether USD₀), not `USDT`.

        Returns:
            StorageRequest with payment instructions:
            - pay_req_id: Save this for confirm_storage()
            - pay_to_address: Destination for the payment. Semantics depend
              on the asset — check `destination_kind`:
                * "wallet"            → native SOL / EVM wallet pubkey;
                  send value directly.
                * "spl_token_account" → Solana SPL (USDC/USDT/WETH/BETA):
                  this IS the treasury's SPL token account; pass it
                  directly as the transferChecked destination — do NOT
                  call get_associated_token_address. Read mint, amount_raw,
                  decimals from `spl_transfer`.
                * "evm_address"       → EVM rails: a wallet/EOA. ERC-20
                  transfers call `transfer(pay_to_address, amount)` on
                  `token_address`.
                * None / "unknown"    → older gateway / unspecified; the
                  SDK falls back to native-wallet interpretation.
              The field name is preserved for back-compat; `destination_kind`
              is the authoritative semantic.
            - destination_kind / spl_transfer: see above (additive,
              optional; None on older gateways).
            - amount_sol / amount_lamports: Populated for Solana quotes
            - amount / amount_raw / token_address / token_decimals:
              Populated for EVM quotes. `token_address` is NOT set for
              Solana SPL — read `spl_transfer.mint` instead.
            - pay_asset: Token symbol ("SOL", "USDC", "MON", "USDT0", etc.)
            - network: Payment network identifier (friendly form, converted
              from the 402 response's CAIP-2 string via caip2_to_friendly)
            - payment_options: Full list of chain/asset combinations the
              gateway offers for this quote (each entry's `network` field
              is CAIP-2)
            - next_step: Human-readable guidance for the agent, including
              the exact confirm_storage(...) call to make after the transfer
              lands

        Note:
            The gateway returns HTTP 402 Payment Required — this is expected
            behavior for the x402 protocol, not an error. The SDK catches
            the 402 and converts it to the StorageRequest return value.
        """
        # Auto-detect EVM defaults when client has an EVM key configured.
        # Infer mainnet vs testnet from client.network — don't hardcode testnet.
        if not pay_network and self._evm_private_key_path:
            if self.network in ("mainnet-beta", "mainnet", "solana-mainnet"):
                pay_network = "monad-mainnet"
            else:
                pay_network = "monad-testnet"
        if not pay_asset and pay_network and pay_network.lower() in (
            "monad-testnet", "monad-mainnet", "monad", "eip155:10143", "eip155:143",
        ):
            pay_asset = "MON"

        try:
            body = {"units": units}
            if provider:
                body["provider"] = provider
            if pay_network:
                body["pay_network"] = pay_network
            if pay_asset:
                body["pay_asset"] = pay_asset
            self.http.post("/v1/storage/request", json=body)
            # If we get here, something unexpected happened
            raise NukezError(
                "Expected HTTP 402 Payment Required, got success. "
                "This indicates an API change - please report this issue."
            )
        except PaymentRequiredError as e:
            # HTTP 402 is expected - contains payment instructions
            request = StorageRequest(
                pay_req_id=e.pay_req_id,
                pay_to_address=e.pay_to_address,
                amount_sol=e.amount_sol,
                amount_lamports=e.amount_lamports,
                network=e.network,
                units=units,
                provider=provider or "gcs",
                pay_asset=e.pay_asset,
                amount=e.amount or None,
                amount_raw=e.amount_raw or None,
                token_address=e.token_address or None,
                token_decimals=e.token_decimals or None,
                # Quote lifecycle fields
                payment_options=e.payment_options,
                quote_expires_at=e.quote_expires_at,
                quote_schema=e.details.get("quote_schema"),
                idempotency_key=e.details.get("idempotency_key"),
                terms=e.terms,
                price_breakdown=e.details.get("price_breakdown"),
                # Destination disambiguation (typed; None on older gateways).
                destination_kind=e.destination_kind,
                spl_transfer=e.spl_transfer,
            )

            # If the caller requested a specific chain/asset, override the
            # top-level fields with the matching payment option so that
            # the StorageRequest reflects the correct pay_to_address,
            # amount, etc.  The _http layer defaults to Solana, which
            # causes confirm_storage to verify against the wrong treasury.
            if pay_asset and request.payment_options:
                _net_hint = (pay_network or "").lower()
                for opt in request.payment_options:
                    if opt.get("pay_asset", "").upper() != pay_asset.upper():
                        continue
                    # If a network hint was given, also match on it.
                    # Normalize both sides through caip2_to_friendly so a
                    # friendly alias ("solana-mainnet") matches the CAIP-2
                    # form the gateway returns ("solana:5eykt4UsFv8...").
                    if _net_hint and caip2_to_friendly(opt.get("network", "")).lower() != \
                            caip2_to_friendly(pay_network or "").lower():
                        continue
                    # Found matching option — override top-level fields
                    request.pay_to_address = opt["pay_to_address"]
                    request.pay_asset = opt["pay_asset"]
                    raw_net = opt.get("network", "")
                    request.network = caip2_to_friendly(raw_net, pay_network)
                    request.amount = opt.get("human_amount") or opt.get("amount")
                    request.amount_raw = int(opt["amount"]) if opt.get("amount") else None
                    request.token_address = opt.get("asset_contract") if opt.get("asset_contract") not in (None, "native") else None
                    request.token_decimals = opt.get("decimals")
                    # Destination disambiguation — convert the raw-dict view to
                    # the typed SplTransfer so request.spl_transfer is type-correct.
                    request.destination_kind = opt.get("destination_kind")
                    request.spl_transfer = SplTransfer.from_dict(opt.get("spl_transfer"))
                    if opt.get("human_amount"):
                        try:
                            request.amount_sol = float(opt["human_amount"])
                        except (ValueError, TypeError):
                            pass
                    request.__post_init__()
                    break

            return request

    def confirm_storage(
        self,
        pay_req_id: str,
        tx_sig: str,
        max_retries: int = 5,
        initial_delay: float = 2.0,
        payment_chain: Optional[str] = None,
        payment_asset: Optional[str] = None,
        operator_pubkey: Optional[str] = None,
    ) -> Receipt:
        """
        Step 3: Confirm payment and receive storage receipt.

        FIXED: Now includes retry logic for transaction propagation delays,
        matching the working nukez implementation.

        Args:
            pay_req_id: Payment request ID from request_storage().
            tx_sig: On-chain transaction signature for the payment.
                You execute the transfer with your wallet, CLI, or signing
                workflow, then submit the resulting signature. PyNukez does
                not execute transfers.
            max_retries: Maximum retry attempts for tx_not_found / retryable
                402 responses (default: 5).
            initial_delay: Initial delay in seconds, doubles each retry (default: 2.0).
            payment_chain: Chain identifier for this payment. Required for
                EVM payments (ignored for Solana). Accepts either the CAIP-2
                form the gateway returns in its 402 response (preferred —
                matches request.payment_options[].network entries 1:1) or
                the SDK's friendly alias. The SDK converts friendly → CAIP-2
                for the X-Payment-Chain header at send time.

                CAIP-2                                              Friendly
                -------------------------------------------------   ---------------
                solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp             solana-mainnet
                solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1             solana-devnet
                eip155:143                                          monad-mainnet
                eip155:10143                                        monad-testnet
            payment_asset: Token symbol this payment settled in. Required
                for EVM payments (ignored for Solana). Must match one of
                request.payment_options[].pay_asset — e.g. "MON", "USDC",
                "USDT0", "WETH" on Monad.
            operator_pubkey: Ed25519 base58 pubkey to bind as operator at
                confirm time. If omitted and the tx_sig is EVM-shaped
                (0x-prefixed), the SDK auto-binds the current Ed25519
                keypair — this behavior is deprecated and will be removed
                in pynukez 5.0.

        Returns:
            Receipt with:
            - id: Receipt ID (SAVE THIS - needed for all file operations)
            - units: Storage units purchased
            - payer_pubkey: Your wallet address
            - network: Network used
            - provider: Storage backend
            - pay_asset: Token used for payment
            - tx_hash: Chain-agnostic transaction identifier
            - locker_id: Derived locker ID (convenience property)

        Next step:
            Call provision_locker(receipt_id=receipt.id) to create storage space

        Note:
            Transaction may take 10-30 seconds to confirm on-chain.
            This method automatically retries on tx_not_found errors.
        """
        url = f"{self.base_url}/v1/storage/confirm"
        payload = {"pay_req_id": pay_req_id}
        if payment_chain:
            payload["payment_chain"] = payment_chain
        if payment_asset:
            payload["payment_asset"] = payment_asset
        # Operator delegation: explicit param takes priority, then auto-infer
        # for EVM payments (0x-prefixed tx hash) where the Ed25519 keypair
        # must be bound as operator since the payer uses secp256k1.
        if operator_pubkey:
            payload["operator_pubkey"] = operator_pubkey
        elif (self._auto_bind_operator
              and self.keypair
              and isinstance(tx_sig, str)
              and tx_sig.startswith("0x")):
            import warnings
            warnings.warn(
                "Auto-binding Ed25519 operator for EVM payments is deprecated. "
                "EVM owners can now operate directly with secp256k1 envelopes. "
                "Pass operator_pubkey explicitly or set auto_bind_operator=False. "
                "This behavior will be removed in pynukez 5.0.",
                DeprecationWarning,
                stacklevel=2,
            )
            payload["operator_pubkey"] = self.keypair.pubkey_b58
        headers = {
            "Content-Type": "application/json",
            "X402-TX": tx_sig,
        }
        # Also send as x402 headers (belt-and-suspenders with body fields).
        # Map user-friendly chain names to x402 network identifiers.
        _chain_to_x402 = {
            "monad-testnet": "eip155:10143",
            "monad-mainnet": "eip155:143",
            "solana-devnet": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "solana-mainnet": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        }
        if payment_chain:
            headers["X-Payment-Chain"] = _chain_to_x402.get(payment_chain, payment_chain)
        if payment_asset:
            headers["X-Payment-Asset"] = payment_asset
        
        last_error: Optional[Exception] = None
        
        for attempt in range(max_retries):
            try:
                # Make raw request - don't use self.http which raises PaymentRequiredError
                resp = _httpx.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                    follow_redirects=True,
                )
                
                # Success!
                if resp.status_code == 200:
                    data = resp.json()
                    rcpt = data.get("receipt", {})
                    receipt = Receipt(
                        id=data["receipt_id"],
                        units=rcpt.get("units", data.get("units", 1)),
                        payer_pubkey=data.get("payer_pubkey", rcpt.get("payer_pubkey", "")),
                        network=rcpt.get("network", self.network),
                        created_at=rcpt.get("created_at"),
                        provider=rcpt.get("provider", ""),
                        pay_asset=rcpt.get("pay_asset", "SOL"),
                        tx_hash=rcpt.get("tx_hash", data.get("tx_sig", "")),
                        paid_amount=str(rcpt.get("paid_amount", "")) if rcpt.get("paid_amount") else None,
                        paid_raw=rcpt.get("paid_raw"),
                        block_number=rcpt.get("block_number"),
                        slot=rcpt.get("slot"),
                        sig_alg=data.get("sig_alg", rcpt.get("receipt_sig_alg", "")),
                        unit_price_usd=float(rcpt.get("unit_price_usd", 0)),
                        price_usd=float(rcpt.get("price_usd", 0)),
                        authorized_operator=rcpt.get("authorized_operator") or data.get("authorized_operator"),
                    )
                    # Prime per-receipt state. Gateway response is authoritative,
                    # so we bypass bind_receipt's conflict check by writing
                    # directly — this is the only write site outside bind_receipt
                    # and it never races with a prior bind for a fresh receipt.
                    alg = receipt.sig_alg or infer_sig_alg(receipt.payer_pubkey) or ""
                    if alg:
                        self._receipt_state[data["receipt_id"]] = _ReceiptState(
                            owner_identity=receipt.payer_pubkey,
                            sig_alg=alg,
                        )
                    return receipt
                
                # 402 from confirm endpoint - check if it's tx_not_found
                if resp.status_code == 402:
                    try:
                        body = resp.json()
                    except:
                        body = {"raw": resp.text}

                    # Check for tx_not_found in various response formats
                    # Format 1: details.verify.err
                    verify_info = (body.get("details") or {}).get("verify") or {}
                    err = verify_info.get("err", "")

                    # Format 2: error_code at top level
                    error_code = body.get("error_code", "")

                    # Format 3: message contains tx_not_found
                    message = body.get("message", "")
                    msg_lower = message.lower()

                    is_tx_not_found = (
                        err == "tx_not_found" or
                        error_code == "TX_NOT_FOUND" or
                        "tx_not_found" in msg_lower or
                        ("transaction" in msg_lower and "not found" in msg_lower)
                    )

                    # EVM chains may return generic failures while the tx
                    # is still propagating / finalising.  Treat these as
                    # retryable when there is no specific error code that
                    # indicates a permanent failure.
                    _permanent_codes = {
                        "AMOUNT_MISMATCH", "WRONG_RECIPIENT",
                        "QUOTE_EXPIRED", "DUPLICATE_CONFIRM",
                        "INVALID_PAY_REQ", "PAYMENT_VERIFICATION_FAILED",
                        "INSUFFICIENT_AMOUNT", "INSUFFICIENT_PAYMENT",
                        "TX_FAILED", "TX_REVERTED",
                    }
                    is_retryable_402 = (
                        is_tx_not_found
                        or (
                            error_code not in _permanent_codes
                            and msg_lower in ("", "request failed", "verification failed")
                        )
                    )

                    if is_retryable_402 and attempt < max_retries - 1:
                        delay = initial_delay * (2 ** attempt)
                        reason = "tx not found" if is_tx_not_found else f"retryable 402 ({message or error_code or 'no detail'})"
                        logger.debug("%s, retrying in %ss (attempt %d/%d)", reason, delay, attempt + 1, max_retries)
                        time.sleep(delay)
                        continue

                    # Out of retries or permanent failure
                    if is_tx_not_found:
                        last_error = TransactionNotFoundError(
                            tx_sig=tx_sig,
                            suggested_delay=int(initial_delay * (2 ** attempt))
                        )
                    else:
                        detail_str = json.dumps(body, indent=2) if body else resp.text
                        last_error = NukezError(
                            f"Payment confirmation failed: {message or resp.text}\n"
                            f"Server response: {detail_str}",
                            details=body
                        )
                    raise last_error
                
                # Other error status
                resp.raise_for_status()
                
            except _httpx.HTTPError as e:
                last_error = NukezError(f"Request failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(initial_delay * (2 ** attempt))
                    continue
                raise last_error
        
        # Exhausted retries
        if last_error:
            raise last_error
        raise NukezError(f"confirm_storage failed after {max_retries} attempts")

    # =========================================================================
    # LOCKER OPERATIONS (Require receipt_id and signed envelope)
    # =========================================================================
    
    def provision_locker(
        self,
        receipt_id: str,
        tags: Optional[List[str]] = None,
        operator_pubkey: Optional[str] = None,
    ) -> NukezManifest:
        """
        Create storage locker namespace for files.

        Args:
            receipt_id: Receipt ID from confirm_storage()
            tags: Optional tags for the locker
            operator_pubkey: Optional Ed25519 base58 pubkey to authorize as operator

        Returns:
            NukezManifest with locker details
        """
        signer = self._require_signer("provision_locker", receipt_id)

        locker_id = compute_locker_id(receipt_id)
        body = {"receipt_id": receipt_id, "tags": tags or []}
        if operator_pubkey:
            body["operator_pubkey"] = operator_pubkey
        
        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="POST",
            path="/v1/storage/signed_provision",
            ops=["locker:provision"],
            body=body
        )
        
        response = self.http.post(
            "/v1/storage/signed_provision",
            headers=envelope.headers,
            data=envelope.canonical_body.encode("utf-8"),
        )
        
        space = response.get("space", response)
        
        manifest = NukezManifest(
            locker_id=space.get("locker_id", locker_id),
            receipt_id=receipt_id,
            bucket=space.get("bucket", ""),
            path_prefix=space.get("path_prefix", ""),
            tags=space.get("tags", tags or []),
            cap_token=space.get("cap_token"),
            cap_expires_in_sec=space.get("cap_expires_in_sec"),
            created_at=space.get("created_at")
        )

        # Prime owner identity — provision is owner-only, so signer IS the owner.
        # Infer sig_alg from the signer's identity format; fall back to the
        # signer's class (EVMSigner → secp256k1, Keypair → ed25519) if inference
        # fails for any reason.
        alg = infer_sig_alg(signer.identity)
        if not alg:
            alg = "secp256k1" if signer is self._evm_signer else "ed25519"
        existing = self._receipt_state.get(receipt_id)
        if existing is None:
            self._receipt_state[receipt_id] = _ReceiptState(
                owner_identity=signer.identity,
                sig_alg=alg,
            )

        return manifest

    # =========================================================================
    # OPERATOR DELEGATION
    # =========================================================================

    def add_operator(self, receipt_id: str, operator_pubkey: str) -> OperatorResult:
        """
        Authorize an Ed25519 operator to perform file operations on this locker.

        Owner-only. Max 5 operators. Cannot add self.

        Args:
            receipt_id: Receipt ID from confirm_storage()
            operator_pubkey: Base58-encoded Ed25519 public key to authorize

        Returns:
            OperatorResult with ok=True and current operator_ids list

        Raises:
            InvalidOperatorPubkeyError: pubkey is not valid base58
            OperatorIsOwnerError: pubkey matches the locker owner
            OperatorConflictError: pubkey already added or max 5 reached
            OwnerOnlyError: caller is not the locker owner
        """
        signer = self._require_signer("add_operator", receipt_id)
        locker_id = compute_locker_id(receipt_id)
        body = {"pubkey": operator_pubkey}

        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="POST",
            path=f"/v1/lockers/{locker_id}/operators",
            ops=["locker:admin"],
            body=body,
        )

        response = self.http.post(
            f"/v1/lockers/{locker_id}/operators",
            headers=envelope.headers,
            data=envelope.canonical_body.encode("utf-8"),
        )

        return OperatorResult(
            ok=response.get("ok", True),
            operator_ids=response.get("operator_ids", []),
        )

    def remove_operator(self, receipt_id: str, operator_pubkey: str) -> OperatorResult:
        """
        Revoke an operator's access to this locker.

        Owner-only.

        Args:
            receipt_id: Receipt ID from confirm_storage()
            operator_pubkey: Base58-encoded Ed25519 public key to remove

        Returns:
            OperatorResult with ok=True and updated operator_ids list

        Raises:
            OperatorNotFoundError: pubkey is not in the operator list
            OwnerOnlyError: caller is not the locker owner
        """
        signer = self._require_signer("remove_operator", receipt_id)
        locker_id = compute_locker_id(receipt_id)

        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="DELETE",
            path=f"/v1/lockers/{locker_id}/operators/{operator_pubkey}",
            ops=["locker:admin"],
        )

        response = self.http.delete(
            f"/v1/lockers/{locker_id}/operators/{operator_pubkey}",
            headers=envelope.headers,
        )

        return OperatorResult(
            ok=response.get("ok", True),
            operator_ids=response.get("operator_ids", []),
        )

    def create_file(
        self, 
        receipt_id: str, 
        filename: str,
        content_type: str = "application/octet-stream",
        ttl_min: int = 30
    ) -> FileUrls:
        """
        Create a new file and get upload/download URLs.
        
        Args:
            receipt_id: Receipt ID from confirm_storage()
            filename: Name for the file
            content_type: MIME type (default: application/octet-stream)
            ttl_min: URL expiration time in minutes (default: 30)
            
        Returns:
            FileUrls with:
            - filename: The file name
            - upload_url: PUT data here
            - download_url: GET data from here
            - content_type: MIME type
            - expires_in_sec: URL validity duration
        """
        signer = self._require_signer("create_file", receipt_id)
        locker_id = compute_locker_id(receipt_id)
        
        body = {
            "filename": filename,
            "content_type": content_type,
            "ttl_min": ttl_min
        }
        
        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="POST",
            path=f"/v1/lockers/{locker_id}/files",
            ops=["locker:write"],
            body=body,
            delegating=self._is_delegating(receipt_id),
        )
        
        response = self.http.post(
            f"/v1/lockers/{locker_id}/files",
            headers=envelope.headers,
            data=envelope.canonical_body.encode("utf-8"),
        )
        
        urls = FileUrls(
            filename=response.get("filename", filename),
            upload_url=response["upload_url"],
            download_url=response["download_url"],
            content_type=response.get("content_type", content_type),
            expires_in_sec=response.get("urls_expire_in_sec", ttl_min * 60),
            confirm_url=response.get("confirm_url"),
        )
        return urls

    _infer_content_type = staticmethod(_infer_content_type)
    _sanitize_filename = staticmethod(_sanitize_filename)

    def create_files_batch(
        self,
        receipt_id: str,
        files: List[Dict[str, Any]],
        ttl_min: int = 30,
    ) -> Dict[str, Any]:
        """
        Create multiple file entries and mint upload/download URLs in one call.

        This maps to POST /v1/lockers/{locker_id}/files/batch and is the
        low-level primitive used by path-based bulk upload methods.
        """
        signer = self._require_signer("create_files_batch", receipt_id)
        locker_id = compute_locker_id(receipt_id)

        if not files:
            raise NukezError("create_files_batch requires at least one file")

        normalized_files: List[Dict[str, Any]] = []
        for file_spec in files:
            filename = (file_spec.get("filename") or "").strip()
            if not filename:
                raise NukezError("create_files_batch file spec missing filename")

            row: Dict[str, Any] = {
                "filename": filename,
                "content_type": self._infer_content_type(
                    filename,
                    file_spec.get("content_type"),
                ),
            }
            expected_hash = (file_spec.get("expected_hash") or "").strip()
            if expected_hash:
                row["expected_hash"] = expected_hash
            normalized_files.append(row)

        body = {
            "files": normalized_files,
            "ttl_min": ttl_min,
        }

        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="POST",
            path=f"/v1/lockers/{locker_id}/files/batch",
            ops=["locker:write"],
            body=body,
            delegating=self._is_delegating(receipt_id),
        )

        return self.http.post(
            f"/v1/lockers/{locker_id}/files/batch",
            headers=envelope.headers,
            data=envelope.canonical_body.encode("utf-8"),
        )

    def _normalize_path_sources(
        self,
        sources: List[Union[str, Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Normalize file path upload specs into a canonical internal format."""
        if not sources:
            raise NukezError("No file sources provided")

        normalized: List[Dict[str, Any]] = []
        for idx, raw in enumerate(sources):
            if isinstance(raw, str):
                spec: Dict[str, Any] = {"filepath": raw}
            elif isinstance(raw, dict):
                spec = dict(raw)
            else:
                raise NukezError(
                    f"Invalid source at index {idx}: expected str or dict, got {type(raw).__name__}"
                )

            filepath = str(spec.get("filepath") or spec.get("path") or "").strip()
            if not filepath:
                raise NukezError(f"Source {idx} missing filepath")

            p = Path(filepath).expanduser()
            if not p.exists():
                p_text = str(p)
                if "/mnt/data" in p_text or "/mnt/user-data/uploads" in p_text:
                    raise NukezError(
                        f"SANDBOX_PATH_UNAVAILABLE: {p_text}",
                        details={
                            "filepath": p_text,
                            "recovery_hint": (
                                "Path upload is blocked in this sandbox runtime. "
                                "Use sandbox_create_ingest_job -> sandbox_append_ingest_part -> sandbox_complete_ingest_job."
                            ),
                            "next_best_method": (
                                "sandbox_create_ingest_job -> sandbox_append_ingest_part -> sandbox_complete_ingest_job"
                            ),
                        },
                    )
                raise NukezError(f"File not found: {p}")
            if not p.is_file():
                raise NukezError(f"Expected file path, got non-file: {p}")

            filename = self._sanitize_filename(
                str(spec.get("filename") or p.name).strip()
            )
            if not filename:
                raise NukezError(f"Source {idx} produced empty filename")

            normalized.append(
                {
                    "filepath": str(p),
                    "filename": filename,
                    "content_type": self._infer_content_type(
                        filename,
                        spec.get("content_type"),
                    ),
                    "size_bytes": p.stat().st_size,
                    "expected_hash": spec.get("expected_hash"),
                }
            )

        return normalized

    def upload_file_path(
        self,
        receipt_id: str,
        filepath: str,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        ttl_min: int = 30,
        confirm: bool = True,
    ) -> Dict[str, Any]:
        """
        Upload one local file by path without passing file bytes through LLM context.
        """
        source: Dict[str, Any] = {"filepath": filepath}
        if filename:
            source["filename"] = filename
        if content_type:
            source["content_type"] = content_type

        result = self.bulk_upload_paths(
            receipt_id=receipt_id,
            sources=[source],
            workers=1,
            ttl_min=ttl_min,
            confirm=confirm,
            auto_attest=False,
        )
        if result["failed"] > 0:
            err = result.get("errors") or [{"error": "upload failed"}]
            first_error = err[0]
            first_message = str(first_error.get("error", "upload failed"))
            if self._is_sandbox_path_unavailable_error(
                NukezError(first_message, details=first_error)
            ):
                raise NukezError(
                    f"SANDBOX_PATH_UNAVAILABLE: {first_message}",
                    details={
                        "recovery_hint": (
                            "Path upload is blocked in this sandbox runtime. "
                            "Use sandbox_create_ingest_job -> sandbox_append_ingest_part -> sandbox_complete_ingest_job."
                        ),
                        "next_best_method": (
                            "sandbox_create_ingest_job -> sandbox_append_ingest_part -> sandbox_complete_ingest_job"
                        ),
                    },
                )
            raise NukezError(f"upload_file_path failed: {first_message}")
        return result["files"][0] if result.get("files") else result

    def bulk_upload_paths(
        self,
        receipt_id: str,
        sources: List[Union[str, Dict[str, Any]]],
        workers: int = 6,
        ttl_min: int = 30,
        confirm: bool = True,
        auto_attest: bool = False,
        attest_sync: bool = False,
        on_progress: Optional[Callable[[str, bool, int, int], None]] = None,
    ) -> Dict[str, Any]:
        """
        Upload multiple local files by path with optional confirm + attestation.

        This is context-safe for MCP/LLM flows because only file paths are passed
        through tool calls; file bytes are read directly from disk in the SDK.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        normalized = self._normalize_path_sources(sources)
        t0 = time.time()

        create_specs = [
            {
                "filename": s["filename"],
                "content_type": s["content_type"],
                "expected_hash": s.get("expected_hash"),
            }
            for s in normalized
        ]
        create_response = self.create_files_batch(
            receipt_id=receipt_id,
            files=create_specs,
            ttl_min=ttl_min,
        )

        url_by_filename = {
            row.get("filename"): row
            for row in (create_response.get("files") or [])
            if row.get("filename")
        }

        total = len(normalized)
        file_results: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        def _upload_one(spec: Dict[str, Any]) -> Dict[str, Any]:
            filename = spec["filename"]
            entry = url_by_filename.get(filename)
            if not entry:
                return {
                    "filename": filename,
                    "filepath": spec["filepath"],
                    "content_type": spec["content_type"],
                    "size_bytes": 0,
                    "success": False,
                    "error": "Missing upload URL for file from batch create response",
                }

            try:
                body = Path(spec["filepath"]).read_bytes()
                self.upload_bytes(
                    entry["upload_url"],
                    body,
                    content_type=spec["content_type"],
                )
                return {
                    "filename": filename,
                    "filepath": spec["filepath"],
                    "content_type": spec["content_type"],
                    "size_bytes": len(body),
                    "success": True,
                    "error": "",
                }
            except Exception as e:
                return {
                    "filename": filename,
                    "filepath": spec["filepath"],
                    "content_type": spec["content_type"],
                    "size_bytes": 0,
                    "success": False,
                    "error": str(e),
                }

        worker_count = max(1, int(workers or 1))
        uploaded_names: List[str] = []

        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = [pool.submit(_upload_one, spec) for spec in normalized]
            for idx, fut in enumerate(as_completed(futures), 1):
                row = fut.result()
                file_results.append(row)
                if row["success"]:
                    uploaded_names.append(row["filename"])
                else:
                    errors.append(
                        {
                            "filename": row["filename"],
                            "filepath": row["filepath"],
                            "error": row["error"],
                        }
                    )
                if on_progress:
                    try:
                        on_progress(row["filename"], row["success"], idx, total)
                    except Exception:
                        pass

        confirmed_map: Dict[str, ConfirmResult] = {}
        if confirm and uploaded_names:
            # Prefer gateway-provided confirm_batch_url when available.
            # Older gateways omit it — confirm_files() falls back to the
            # hardcoded path in that case.
            confirm_batch_url = create_response.get("confirm_batch_url")
            confirm_result = self.confirm_files(
                receipt_id, uploaded_names, confirm_batch_url=confirm_batch_url,
            )
            confirmed_map = {
                c.filename: c
                for c in confirm_result.results
                if c.confirmed
            }

        confirmed_count = 0
        for row in file_results:
            if row["success"] and row["filename"] in confirmed_map:
                c = confirmed_map[row["filename"]]
                row["content_hash"] = c.content_hash
                row["confirmed"] = True
                confirmed_count += 1
            elif row["success"]:
                row["content_hash"] = ""
                row["confirmed"] = False
            else:
                row["content_hash"] = ""
                row["confirmed"] = False

        attestation: Optional[Dict[str, Any]] = None
        if auto_attest and uploaded_names:
            try:
                att = self.attest(receipt_id, sync=attest_sync)
                attestation = {
                    "status": att.status,
                    "merkle_root": att.merkle_root,
                    "file_count": att.file_count,
                    "att_code": att.att_code,
                    "push_ok": att.push_ok,
                    "tx_signature": att.tx_signature,
                }
            except Exception as e:
                attestation = {
                    "status": "failed",
                    "error": str(e),
                }

        elapsed = round(time.time() - t0, 2)
        uploaded_count = len([r for r in file_results if r["success"]])

        return {
            "receipt_id": receipt_id,
            "uploaded": uploaded_count,
            "failed": len(file_results) - uploaded_count,
            "total": total,
            "confirmed": confirmed_count,
            "elapsed_sec": elapsed,
            "files": file_results,
            "errors": errors,
            "attestation": attestation,
        }

    def upload_directory(
        self,
        receipt_id: str,
        source_dir: str,
        pattern: str = "*",
        recursive: bool = False,
        exclude_pattern: Optional[str] = None,
        preserve_structure: bool = False,
        workers: int = 6,
        ttl_min: int = 30,
        confirm: bool = True,
        auto_attest: bool = False,
        attest_sync: bool = False,
    ) -> Dict[str, Any]:
        """
        Upload files from a directory using glob pattern filtering.
        """
        root = Path(source_dir).expanduser()
        if not root.exists():
            raise NukezError(f"Directory not found: {root}")
        if not root.is_dir():
            raise NukezError(f"Expected directory path, got: {root}")

        paths = root.rglob(pattern) if recursive else root.glob(pattern)
        sources: List[Dict[str, Any]] = []

        for p in paths:
            if not p.is_file():
                continue
            rel = str(p.relative_to(root))
            if exclude_pattern and (p.match(exclude_pattern) or Path(rel).match(exclude_pattern)):
                continue
            filename = rel if preserve_structure else p.name
            sources.append({"filepath": str(p), "filename": filename})

        if not sources:
            raise NukezError(
                f"No files matched pattern '{pattern}' in directory: {root}"
            )

        return self.bulk_upload_paths(
            receipt_id=receipt_id,
            sources=sources,
            workers=workers,
            ttl_min=ttl_min,
            confirm=confirm,
            auto_attest=auto_attest,
            attest_sync=attest_sync,
        )

    def _set_upload_job_state(self, job_id: str, **updates: Any) -> None:
        with self._upload_jobs_lock:
            job = self._upload_jobs.get(job_id)
            if not job:
                return
            job.update(updates)
            job["updated_at"] = int(time.time())

    def start_bulk_upload_job(
        self,
        receipt_id: str,
        sources: List[Union[str, Dict[str, Any]]],
        workers: int = 6,
        ttl_min: int = 30,
        confirm: bool = True,
        auto_attest: bool = False,
        attest_sync: bool = False,
    ) -> Dict[str, Any]:
        """
        Start a non-blocking background bulk upload job.

        Returns immediately with job_id. Poll with get_upload_job().
        """
        normalized = self._normalize_path_sources(sources)
        total = len(normalized)
        now = int(time.time())
        job_id = f"up_{uuid.uuid4().hex[:12]}"

        with self._upload_jobs_lock:
            self._upload_jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "created_at": now,
                "updated_at": now,
                "started_at": None,
                "finished_at": None,
                "receipt_id": receipt_id,
                "total": total,
                "uploaded": 0,
                "failed": 0,
                "confirmed": 0,
                "result": None,
                "error": None,
            }

        progress = {"uploaded": 0, "failed": 0}
        progress_lock = threading.Lock()

        def _progress_cb(_filename: str, success: bool, _index: int, _total: int) -> None:
            with progress_lock:
                if success:
                    progress["uploaded"] += 1
                else:
                    progress["failed"] += 1
                self._set_upload_job_state(
                    job_id,
                    status="running",
                    uploaded=progress["uploaded"],
                    failed=progress["failed"],
                )

        def _run_job() -> None:
            self._set_upload_job_state(job_id, status="running", started_at=int(time.time()))
            try:
                result = self.bulk_upload_paths(
                    receipt_id=receipt_id,
                    sources=normalized,
                    workers=workers,
                    ttl_min=ttl_min,
                    confirm=confirm,
                    auto_attest=auto_attest,
                    attest_sync=attest_sync,
                    on_progress=_progress_cb,
                )
                terminal = "complete" if result.get("failed", 0) == 0 else "partial"
                self._set_upload_job_state(
                    job_id,
                    status=terminal,
                    finished_at=int(time.time()),
                    uploaded=result.get("uploaded", 0),
                    failed=result.get("failed", 0),
                    confirmed=result.get("confirmed", 0),
                    result=result,
                )
            except Exception as e:
                self._set_upload_job_state(
                    job_id,
                    status="failed",
                    finished_at=int(time.time()),
                    error=str(e),
                )

        t = threading.Thread(
            target=_run_job,
            name=f"pynukez-upload-{job_id}",
            daemon=True,
        )
        t.start()

        return {
            "job_id": job_id,
            "status": "queued",
            "created_at": now,
            "total": total,
            "receipt_id": receipt_id,
        }

    def get_upload_job(self, job_id: str) -> Dict[str, Any]:
        """
        Return the current state of a previously started upload job.
        """
        with self._upload_jobs_lock:
            job = self._upload_jobs.get(job_id)
            if not job:
                raise NukezError(f"Upload job not found: {job_id}")
            return dict(job)

    def list_upload_jobs(self, limit: int = 20) -> Dict[str, Any]:
        """
        List recent upload jobs tracked in this SDK process.
        """
        with self._upload_jobs_lock:
            jobs = list(self._upload_jobs.values())
        jobs.sort(key=lambda j: j.get("created_at", 0), reverse=True)
        if limit > 0:
            jobs = jobs[:limit]
        return {
            "count": len(jobs),
            "jobs": [dict(j) for j in jobs],
        }

    _normalize_expected_sha256 = staticmethod(_normalize_expected_sha256)
    _is_sandbox_path_unavailable_error = staticmethod(_is_sandbox_path_unavailable_error)

    def sandbox_create_ingest_job(
        self,
        receipt_id: str,
        files: List[Dict[str, Any]],
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a sandbox-ingest job.

        This maps directly to:
            POST /v1/lockers/{locker_id}/ingest/jobs
        """
        signer = self._require_signer("sandbox_create_ingest_job", receipt_id)
        locker_id = compute_locker_id(receipt_id)

        if not files:
            raise NukezError("sandbox_create_ingest_job requires at least one file")

        normalized_files: List[Dict[str, Any]] = []
        for idx, spec in enumerate(files):
            filename = (spec.get("filename") or "").strip()
            if not filename:
                raise NukezError(f"sandbox_create_ingest_job file {idx} missing filename")

            row: Dict[str, Any] = {
                "filename": filename,
                "content_type": self._infer_content_type(
                    filename,
                    spec.get("content_type"),
                ),
            }

            if spec.get("expected_size_bytes") is not None:
                try:
                    row["expected_size_bytes"] = int(spec["expected_size_bytes"])
                except Exception as exc:
                    raise NukezError(
                        f"expected_size_bytes for '{filename}' must be an integer"
                    ) from exc

            normalized_sha = self._normalize_expected_sha256(
                spec.get("expected_sha256") or spec.get("expected_hash")
            )
            if normalized_sha:
                row["expected_sha256"] = normalized_sha

            normalized_files.append(row)

        body = {
            "receipt_id": receipt_id,
            "files": normalized_files,
            "execution_mode": (execution_mode or SANDBOX_INGEST_EXECUTION_MODE).strip().lower(),
        }
        path = f"/v1/lockers/{locker_id}/ingest/jobs"

        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="POST",
            path=path,
            ops=["locker:write"],
            body=body,
            delegating=self._is_delegating(receipt_id),
        )

        return self.http.post(path, headers=envelope.headers, data=envelope.canonical_body.encode("utf-8"))

    def sandbox_append_ingest_part(
        self,
        receipt_id: str,
        job_id: str,
        file_id: str,
        part_no: int,
        payload_b64: str,
        *,
        is_last: bool = False,
    ) -> Dict[str, Any]:
        """
        Append one base64 chunk into a sandbox-ingest job file.

        Maps to:
            POST /v1/ingest/jobs/{job_id}/files/{file_id}/parts
        """
        signer = self._require_signer("sandbox_append_ingest_part", receipt_id)

        raw_payload = (payload_b64 or "").strip()
        if not raw_payload:
            raise NukezError("sandbox_append_ingest_part requires non-empty payload_b64")
        if raw_payload.lower() in {"none", "null", "undefined"}:
            raise NukezError("payload_b64 sentinel values are rejected")

        try:
            base64.b64decode(raw_payload, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise NukezError("payload_b64 must be valid base64") from exc

        body = {
            "part_no": int(part_no),
            "payload_b64": raw_payload,
            "is_last": bool(is_last),
        }
        path = f"/v1/ingest/jobs/{job_id}/files/{file_id}/parts"

        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="POST",
            path=path,
            ops=["locker:write"],
            body=body,
            delegating=self._is_delegating(receipt_id),
        )
        return self.http.post(path, headers=envelope.headers, data=envelope.canonical_body.encode("utf-8"))

    def sandbox_complete_ingest_job(
        self,
        receipt_id: str,
        job_id: str,
        *,
        file_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Finalize a sandbox-ingest job.

        Maps to:
            POST /v1/ingest/jobs/{job_id}/complete
        """
        signer = self._require_signer("sandbox_complete_ingest_job", receipt_id)

        body: Dict[str, Any] = {}
        if file_ids:
            body["file_ids"] = list(file_ids)

        path = f"/v1/ingest/jobs/{job_id}/complete"
        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="POST",
            path=path,
            ops=["locker:write"],
            body=body,
            delegating=self._is_delegating(receipt_id),
        )
        return self.http.post(path, headers=envelope.headers, data=envelope.canonical_body.encode("utf-8"))

    def sandbox_upload_bytes(
        self,
        receipt_id: str,
        filename: str,
        data: bytes,
        *,
        content_type: Optional[str] = None,
        expected_sha256: Optional[str] = None,
        part_size_bytes: int = SANDBOX_INGEST_DEFAULT_PART_BYTES,
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Upload bytes through the sandbox-ingest job flow (chunked base64 parts).

        This is intended for sandboxed runtimes where local path uploads are blocked.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise NukezError("sandbox_upload_bytes expects bytes")
        data_bytes = bytes(data)
        if not data_bytes:
            raise NukezError("sandbox_upload_bytes requires non-empty data")

        try:
            part_size = int(part_size_bytes)
        except Exception as exc:
            raise NukezError("part_size_bytes must be an integer") from exc
        part_size = max(SANDBOX_INGEST_MIN_PART_BYTES, min(part_size, SANDBOX_INGEST_MAX_PART_BYTES))

        normalized_sha = self._normalize_expected_sha256(expected_sha256)
        if not normalized_sha:
            normalized_sha = f"sha256:{hashlib.sha256(data_bytes).hexdigest()}"

        created = self.sandbox_create_ingest_job(
            receipt_id=receipt_id,
            files=[
                {
                    "filename": filename,
                    "content_type": self._infer_content_type(filename, content_type),
                    "expected_size_bytes": len(data_bytes),
                    "expected_sha256": normalized_sha,
                }
            ],
            execution_mode=execution_mode,
        )

        job_id = str(created.get("job_id") or "")
        files = created.get("files") or []
        file_id = str((files[0] or {}).get("file_id") or "") if files else ""
        if not job_id or not file_id:
            raise NukezError(
                "sandbox_create_ingest_job response missing job_id or file_id",
                details={"response": created},
            )

        for idx, offset in enumerate(range(0, len(data_bytes), part_size)):
            chunk = data_bytes[offset : offset + part_size]
            payload_b64 = base64.b64encode(chunk).decode("ascii")
            is_last = offset + part_size >= len(data_bytes)
            self.sandbox_append_ingest_part(
                receipt_id=receipt_id,
                job_id=job_id,
                file_id=file_id,
                part_no=idx,
                payload_b64=payload_b64,
                is_last=is_last,
            )

        terminal = self.sandbox_complete_ingest_job(
            receipt_id=receipt_id,
            job_id=job_id,
            file_ids=[file_id],
        )

        result = terminal.get("result") or {}
        completed = result.get("completed") or []
        errors = result.get("errors") or []
        if completed:
            return {
                "job_id": job_id,
                "status": terminal.get("status"),
                "file": completed[0],
                "result": result,
            }
        if errors:
            raise NukezError(
                "sandbox_upload_bytes completed with errors",
                details={"job_id": job_id, "errors": errors},
            )
        raise NukezError(
            "sandbox_upload_bytes did not return any completed files",
            details={"job_id": job_id, "terminal": terminal},
        )

    def sandbox_upload_base64(
        self,
        receipt_id: str,
        filename: str,
        payload_b64: str,
        *,
        content_type: Optional[str] = None,
        expected_sha256: Optional[str] = None,
        part_size_bytes: int = SANDBOX_INGEST_DEFAULT_PART_BYTES,
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Decode base64 and upload via sandbox-ingest chunk flow.
        """
        raw = (payload_b64 or "").strip()
        if not raw:
            raise NukezError("sandbox_upload_base64 requires non-empty payload_b64")
        if raw.lower() in {"none", "null", "undefined"}:
            raise NukezError("payload_b64 sentinel values are rejected")
        try:
            data = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise NukezError("payload_b64 must be valid base64") from exc

        return self.sandbox_upload_bytes(
            receipt_id=receipt_id,
            filename=filename,
            data=data,
            content_type=content_type,
            expected_sha256=expected_sha256,
            part_size_bytes=part_size_bytes,
            execution_mode=execution_mode,
        )

    def sandbox_upload_file_path(
        self,
        receipt_id: str,
        filepath: str,
        *,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        expected_sha256: Optional[str] = None,
        part_size_bytes: int = SANDBOX_INGEST_DEFAULT_PART_BYTES,
        execution_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Read a local file and upload it through sandbox-ingest chunk flow.
        """
        p = Path(filepath).expanduser()
        if not p.exists():
            raise NukezError(f"File not found: {p}")
        if not p.is_file():
            raise NukezError(f"Expected file path, got non-file: {p}")
        remote_name = (filename or p.name).strip()
        if not remote_name:
            raise NukezError("sandbox_upload_file_path produced an empty filename")

        return self.sandbox_upload_bytes(
            receipt_id=receipt_id,
            filename=remote_name,
            data=p.read_bytes(),
            content_type=content_type or self._infer_content_type(remote_name),
            expected_sha256=expected_sha256,
            part_size_bytes=part_size_bytes,
            execution_mode=execution_mode,
        )
    
    def upload_bytes(self, upload_url: str, data: bytes, content_type: str = None) -> UploadResult:
        """
        Upload data to a signed URL.

        Args:
            upload_url: URL from create_file() or get_file_urls()
            data: Bytes to upload
            content_type: Optional content type override (default: application/octet-stream)

        Returns:
            UploadResult with upload confirmation

        Note:
            For agent/tool-calling use, prefer upload_string() which accepts
            a string and handles common formatting issues automatically.

        Cloud Run 32 MB limit handling:
            pynukez gateway short URLs (``https://.../f/{token}``) live behind
            Cloud Run, which enforces a 32 MB request body limit at the
            infrastructure layer. For files above that size, a one-shot PUT
            to the short URL is rejected with HTTP 413 before the gateway
            ever sees the body, so the 307 redirect to the underlying signed
            URL is never emitted.

            When the URL is a gateway short URL, this method first sends a
            bodyless preflight PUT to resolve the 307 Location, then PUTs
            the real body directly to the resolved signed URL, bypassing
            Cloud Run. This matches the proven two-step curl workflow in
            the test log and makes uploads of any size work uniformly. The
            extra preflight round trip is parallelizable with other uploads
            and adds ~50ms on a typical link.

            URLs that do not look like gateway short URLs fall straight
            through to a one-shot PUT — the escape hatch for callers who
            already have a resolved storage URL.
        """
        headers = {"Content-Type": content_type or "application/octet-stream"}

        target_url = upload_url
        if _is_gateway_short_url(upload_url):
            preflight = self._raw_client.put(
                upload_url,
                content=b"",
                headers=headers,
                follow_redirects=False,
            )
            if preflight.status_code in (307, 308):
                resolved = preflight.headers.get("Location")
                if not resolved:
                    raise NukezError(
                        f"Gateway returned {preflight.status_code} with no "
                        f"Location header for {upload_url}. Cannot resolve "
                        f"upload target."
                    )
                target_url = resolved
            elif preflight.status_code >= 400:
                # Real error from the gateway: expired URL, bad token,
                # signature mismatch, etc. Surface it instead of retrying.
                preflight.raise_for_status()
            # else: 200/204 — old gateway handled the empty PUT directly,
            # fall through to the single-shot PUT at the short URL.

        response = self._raw_client.put(target_url, content=data, headers=headers)
        response.raise_for_status()

        return UploadResult(
            upload_url=upload_url,
            size_bytes=len(data),
            content_type=content_type or "application/octet-stream",
            uploaded_at=int(time.time())
        )
    
    def upload_string(
        self,
        upload_url: str,
        data: str,
        content_type: str = None
    ) -> UploadResult:
        """
        Upload string data to signed URL (agent-native interface).
        
        Accepts a string, sanitizes common agent formatting issues
        (JSON wrappers, markdown fencing), encodes to bytes, and uploads.
        
        This is the recommended method for LLM tool-calling integrations
        where agents pass data as strings.

        Guardrail: this method rejects oversized payloads with
        PAYLOAD_TOO_LARGE_FOR_CONTEXT and a recovery hint to use
        upload_file_path/bulk_upload_paths/upload_directory/start_bulk_upload_job.
        
        Args:
            upload_url: Signed upload URL from create_file() or get_file_urls()
            data: Content string to store. Sent as raw bytes in the HTTP PUT body.
                  Common agent malformations are auto-corrected:
                  - JSON wrappers like {"content": "..."} are unwrapped
                  - Markdown code fencing is stripped
            content_type: Optional content type override
            
        Returns:
            UploadResult with upload confirmation and size_bytes
            
        Raises:
            NukezError: If upload_url is malformed or upload fails.
                Error message includes recovery steps.
        """
        # Validate URL before making the request
        url_err = validate_signed_url(upload_url, "upload_url")
        if url_err:
            raise NukezError(url_err)
        
        # Guardrail: prevent huge data-in-context payloads from blowing up LLM/MCP flows
        raw_bytes = len(data.encode("utf-8"))
        if raw_bytes > UPLOAD_STRING_MAX_BYTES:
            raise NukezError(
                "PAYLOAD_TOO_LARGE_FOR_CONTEXT: upload_string payload exceeds context-safe limit. "
                "Use upload_file_path, bulk_upload_paths, upload_directory, or start_bulk_upload_job."
            )

        # Sanitize common agent formatting issues
        cleaned, fix_applied = sanitize_upload_data(data)

        cleaned_bytes = len(cleaned.encode("utf-8"))
        if cleaned_bytes > UPLOAD_STRING_MAX_BYTES:
            raise NukezError(
                "PAYLOAD_TOO_LARGE_FOR_CONTEXT: cleaned upload payload exceeds context-safe limit. "
                "Use upload_file_path, bulk_upload_paths, upload_directory, or start_bulk_upload_job."
            )

        return self.upload_bytes(upload_url, cleaned.encode("utf-8"), content_type)
    
    def _resolve_gateway_download_url(self, download_url: str) -> str:
        """Resolve a gateway short URL (/f/{token}) to its underlying signed
        storage URL by preflighting a bodyless GET with follow_redirects=False.

        Returns the resolved URL when a 307/308 is received. For non-short URLs
        or responses that are not redirects, returns the original URL unchanged
        so the caller can fall through to its normal GET path.

        This exists because Cloud Run enforces a response streaming limit on
        the gateway's /f/{token} proxy path at the infrastructure layer. For
        files large enough to trip that limit, the proxy path either truncates
        or 500s. Resolving the redirect and GETting directly from the signed
        storage URL bypasses Cloud Run entirely — the same pattern used by
        upload_bytes for the parallel 32 MB request body limit.

        Raises:
            NukezError: Gateway returned a redirect with no Location header.
        """
        if not _is_gateway_short_url(download_url):
            return download_url

        preflight = self._raw_client.get(download_url, follow_redirects=False)
        if preflight.status_code in (307, 308):
            resolved = preflight.headers.get("Location")
            if not resolved:
                raise NukezError(
                    f"Gateway returned {preflight.status_code} with no "
                    f"Location header for {download_url}. Cannot resolve "
                    f"download target."
                )
            return resolved
        if preflight.status_code >= 400:
            # Don't raise here — let the existing GET path handle the error
            # with its structured 404 retry / CONTENT_PROPAGATION_PENDING
            # message. Fall through to the short URL.
            return download_url
        # 200/204 — old gateway or direct-serve path. Fall through.
        return download_url

    def download_bytes(
        self,
        download_url: str,
        max_retries: int = 3,
        initial_delay: float = 2.0,
    ) -> bytes:
        """
        Download data from signed URL into memory.

        Includes retry with exponential backoff on HTTP 404.  Content-addressed
        storage providers (Arweave, Filecoin) may return 404 for seconds after
        upload while data propagates through their indexing layers.  The gateway
        also retries server-side (P0), but this provides a defensive fallback
        when the SDK hits provider URLs directly.

        For files that may exceed available RAM, or when Cloud Run's response
        streaming limit on the /f/{token} proxy would truncate the download,
        use ``download_to_file`` instead — it streams chunk-by-chunk to disk
        and does not buffer the full body in memory.

        Args:
            download_url: URL from create_file() or get_file_urls()
            max_retries: Retry attempts on 404 (default: 3, set 0 to disable)
            initial_delay: Initial backoff in seconds, doubles each retry (default: 2.0)

        Returns:
            Downloaded bytes

        Raises:
            NukezError: If URL is malformed, download fails after retries, or
                a non-retryable HTTP error occurs.
                Error message includes recovery steps.

        Cloud Run proxy bypass:
            When download_url is a gateway short URL (/f/{token}), this method
            first resolves the 307 redirect to the underlying signed storage
            URL and GETs from there directly. This bypasses Cloud Run's
            response streaming limit on the gateway proxy path. Resolution
            happens once, before the retry loop — subsequent retries hit the
            resolved URL directly.
        """
        # Validate URL before making the request
        url_err = validate_signed_url(download_url, "download_url")
        if url_err:
            raise NukezError(url_err)

        # Resolve gateway short URL once. Retries hit the resolved URL
        # directly, within its signed URL TTL.
        target_url = self._resolve_gateway_download_url(download_url)

        max_attempts = 1 + max_retries
        for attempt in range(max_attempts):
            if attempt > 0:
                delay = initial_delay * (2 ** (attempt - 1))
                logger.debug(
                    "Download returned 404, retrying in %ss (attempt %d/%d)",
                    delay, attempt, max_retries,
                )
                time.sleep(delay)

            try:
                response = self._raw_client.get(target_url)
                if response.status_code == 404 and attempt < max_attempts - 1:
                    continue
                response.raise_for_status()
                return response.content
            except _httpx.HTTPStatusError as e:
                status = e.response.status_code if e.response is not None else None
                if status == 404:
                    # Extract structured error from gateway proxy responses.
                    # The gateway returns CONTENT_PROPAGATION_PENDING for
                    # content-addressed providers (Arweave/Filecoin) vs
                    # generic FILE_NOT_FOUND for key-addressed providers.
                    error_details = {"retryable": True, "status": 404}
                    message = (
                        "Download failed (HTTP 404). The file may still be propagating on a "
                        "content-addressed provider (Arweave/Filecoin). "
                        "Call confirm_file(receipt_id, filename) to verify availability, "
                        "then retry download_bytes(). If the file truly does not exist, "
                        "call list_files(receipt_id) to check."
                    )
                    try:
                        body = e.response.json()
                        if body.get("error_code") == "CONTENT_PROPAGATION_PENDING":
                            provider = body.get("details", {}).get("provider", "unknown")
                            suggested = body.get("details", {}).get("suggested_delay", 15)
                            message = (
                                f"Download failed: content-addressed storage ({provider}) "
                                f"has not finished propagating. The upload was confirmed but "
                                f"data is not yet downloadable. Wait {suggested}s and retry "
                                f"download_bytes(), or call confirm_file(receipt_id, filename) "
                                f"to verify availability."
                            )
                            error_details.update(body.get("details", {}))
                            error_details["error_code"] = "CONTENT_PROPAGATION_PENDING"
                    except Exception:
                        pass  # Non-JSON response (direct storage URL) — use generic message
                    raise NukezError(message, details=error_details) from e
                if status in (400, 403):
                    raise NukezError(
                        f"Download failed (HTTP {status}). The signed URL may be expired or malformed. "
                        f"Call get_file_urls(receipt_id=..., filename=...) or list_files(receipt_id=...) "
                        f"to get fresh download URLs."
                    ) from e
                raise

        # Should not reach here, but guard against it
        raise NukezError(
            "Download failed (HTTP 404) after retries. The file may still be propagating. "
            "Call confirm_file(receipt_id, filename) to verify availability, then retry.",
            details={"retryable": True, "status": 404},
        )

    def download_to_file(
        self,
        download_url: str,
        dest_path: Union[str, Path],
        chunk_size: int = 8 * 1024 * 1024,
        max_retries: int = 3,
        initial_delay: float = 2.0,
        verify_hash: bool = True,
    ) -> Dict[str, Any]:
        """
        Stream a signed download URL to disk chunk-by-chunk.

        Unlike ``download_bytes``, this method does not buffer the full
        response body in memory. Use it for files that may exceed available
        RAM, or whenever the gateway's Cloud Run proxy path would otherwise
        truncate the response due to its streaming limit.

        For gateway short URLs (``/f/{token}``) the method first resolves the
        307 redirect to the underlying signed storage URL and streams from
        there directly, bypassing Cloud Run entirely. Non-gateway URLs (a
        pre-resolved signed URL you already have in hand) skip the preflight
        and stream directly.

        Args:
            download_url: URL from create_file() / get_file_urls() / list_files()
            dest_path: Destination file path. Parent directory must exist.
            chunk_size: Number of bytes read per iteration (default: 8 MiB).
            max_retries: Retry attempts on HTTP 404 (default: 3). The retry
                re-issues the whole GET from scratch, since mid-stream errors
                cannot be resumed reliably.
            initial_delay: Initial backoff in seconds, doubles each retry.
            verify_hash: When True (default), compute SHA-256 of the streamed
                bytes alongside writing to disk, and return it as the
                ``content_hash`` field. Free to compute since the chunks are
                already in hand.

        Returns:
            Dict with:
              - download_url: The ORIGINAL URL passed in (not the resolved one)
              - dest_path:    The absolute path where the file was written
              - size_bytes:   Total bytes written
              - content_hash: ``sha256:...`` (when verify_hash=True) or empty
              - attempts:     Number of GET attempts consumed

        Raises:
            NukezError: URL validation failure, redirect without Location,
                or exhausted retries on 404.
            httpx.HTTPStatusError: Propagated for non-404 HTTP errors.
            OSError: File write failure (disk full, permission denied, etc.).
        """
        url_err = validate_signed_url(download_url, "download_url")
        if url_err:
            raise NukezError(url_err)

        dest = Path(dest_path).expanduser()
        if not dest.parent.exists():
            raise NukezError(
                f"Parent directory does not exist: {dest.parent}. "
                f"Create it before calling download_to_file()."
            )

        target_url = self._resolve_gateway_download_url(download_url)

        max_attempts = 1 + max_retries
        last_exc: Optional[Exception] = None

        for attempt in range(max_attempts):
            if attempt > 0:
                delay = initial_delay * (2 ** (attempt - 1))
                logger.debug(
                    "download_to_file returned 404, retrying in %ss (attempt %d/%d)",
                    delay, attempt, max_retries,
                )
                time.sleep(delay)

            try:
                bytes_written = 0
                hasher = hashlib.sha256() if verify_hash else None
                with self._raw_client.stream("GET", target_url) as response:
                    if response.status_code == 404 and attempt < max_attempts - 1:
                        # Swallow the body (httpx requires consuming or
                        # closing before the context exits) and retry.
                        response.read()
                        continue
                    if response.status_code >= 400:
                        response.read()  # load body so raise_for_status has it
                        response.raise_for_status()
                    with open(dest, "wb") as f:
                        for chunk in response.iter_bytes(chunk_size=chunk_size):
                            if not chunk:
                                continue
                            f.write(chunk)
                            if hasher is not None:
                                hasher.update(chunk)
                            bytes_written += len(chunk)

                return {
                    "download_url": download_url,
                    "dest_path": str(dest),
                    "size_bytes": bytes_written,
                    "content_hash": (
                        f"sha256:{hasher.hexdigest()}" if hasher is not None else ""
                    ),
                    "attempts": attempt + 1,
                }
            except _httpx.HTTPStatusError as e:
                last_exc = e
                status = e.response.status_code if e.response is not None else None
                if status == 404:
                    # Fall through to retry loop if attempts remain
                    continue
                if status in (400, 403):
                    raise NukezError(
                        f"download_to_file failed (HTTP {status}). The signed "
                        f"URL may be expired or malformed. Call get_file_urls"
                        f"(receipt_id=..., filename=...) for a fresh URL."
                    ) from e
                raise

        raise NukezError(
            "download_to_file failed (HTTP 404) after retries. The file may "
            "still be propagating on a content-addressed provider. Call "
            "confirm_file(receipt_id, filename) to verify availability, then "
            "retry.",
            details={"retryable": True, "status": 404},
        ) from last_exc

    def list_files(self, receipt_id: str) -> List[FileInfo]:
        """
        List all files in locker.
        
        Args:
            receipt_id: Receipt ID from confirm_storage()
            
        Returns:
            List of FileInfo objects
        """
        signer = self._require_signer("list_files", receipt_id)
        locker_id = compute_locker_id(receipt_id)
        
        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="GET",
            path=f"/v1/lockers/{locker_id}/files",
            ops=["locker:list"],
            delegating=self._is_delegating(receipt_id),
        )

        response = self.http.get(
            f"/v1/lockers/{locker_id}/files",
            headers=envelope.headers
        )
        
        files = response.get("files", [])
        return [
            FileInfo(
                filename=f["filename"],
                content_type=f.get("content_type", "application/octet-stream"),
                size_bytes=f.get("size_bytes", 0),
                content_hash=f.get("content_hash"),
                provider_ref=f.get("provider_ref"),
                created_at=f.get("created_at"),
                updated_at=f.get("updated_at"),
                object_key=f.get("object_key")
            )
            for f in files
        ]
    
    def get_file_urls(
        self, 
        receipt_id: str, 
        filename: str, 
        ttl_min: int = 30
    ) -> FileUrls:
        """
        Get fresh upload/download URLs for existing file.
        
        Args:
            receipt_id: Receipt ID from confirm_storage()
            filename: File name from list_files()
            ttl_min: URL expiration time in minutes
            
        Returns:
            FileUrls with refreshed signed URLs
        """
        signer = self._require_signer("get_file_urls", receipt_id)
        locker_id = compute_locker_id(receipt_id)
        
        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="GET",
            path=f"/v1/lockers/{locker_id}/files/{filename}",
            ops=["locker:read"],
            delegating=self._is_delegating(receipt_id),
        )
        
        response = self.http.get(
            f"/v1/lockers/{locker_id}/files/{filename}",
            headers=envelope.headers
        )
        
        return FileUrls(
            filename=response["filename"],
            upload_url=response["upload_url"],
            download_url=response["download_url"],
            content_type=response.get("content_type", "application/octet-stream"),
            expires_in_sec=response.get("expires_in_sec", ttl_min * 60),
            confirm_url=response.get("confirm_url"),
        )

    # =========================================================================
    # VIEWER PORTAL HANDOFF (Agent -> Human)
    # =========================================================================

    _normalize_viewer_base_url = staticmethod(_normalize_viewer_base_url)
    _viewer_button_ui = staticmethod(_viewer_button_ui)
    _viewer_renderer_contract = staticmethod(_viewer_renderer_contract)
    _viewer_container_contract = staticmethod(_viewer_container_contract)

    def get_viewer_container_url(
        self,
        viewer_base_url: str = "https://nukez.xyz",
        request_type: str = "container",
        receipt_id: Optional[str] = None,
        locker_id: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> str:
        """
        Build a generic viewer container URL.

        This URL is intentionally render-agnostic. The agent can hand it to a
        human as an empty container first, then later provide richer payloads.
        """
        base = self._normalize_viewer_base_url(viewer_base_url)
        resolved_locker_id = locker_id or (compute_locker_id(receipt_id) if receipt_id else None)

        params: Dict[str, str] = {}
        if request_type:
            params["request_type"] = request_type
        if receipt_id:
            params["receipt_id"] = receipt_id
        if resolved_locker_id:
            params["locker_id"] = resolved_locker_id
        if filename:
            params["filename"] = filename

        if not params:
            return f"{base}/viewer"
        return f"{base}/viewer?{urlencode(params)}"

    def get_viewer_container_handoff(
        self,
        viewer_base_url: str = "https://nukez.xyz",
        request_type: str = "container",
        view_kind: str = "custom",
        receipt_id: Optional[str] = None,
        locker_id: Optional[str] = None,
        filename: Optional[str] = None,
        blocks: Optional[List[Dict[str, Any]]] = None,
        renderables: Optional[List[Dict[str, Any]]] = None,
        embed_payload_in_url: bool = True,
        button_label: str = "Open Nukez Viewer",
    ) -> ViewerContainer:
        """
        Build a generic viewer-container handoff payload for MCP renderers.
        """
        resolved_locker_id = locker_id or (compute_locker_id(receipt_id) if receipt_id else None)
        base_viewer_url = self.get_viewer_container_url(
            viewer_base_url=viewer_base_url,
            request_type=request_type,
            receipt_id=receipt_id,
            locker_id=resolved_locker_id,
            filename=filename,
        )

        normalized_blocks = blocks or []
        normalized_renderables = renderables or []
        state = "ready" if (normalized_blocks or normalized_renderables) else "empty"
        errors: List[Dict[str, Any]] = []
        viewer_url = base_viewer_url

        if (normalized_blocks or normalized_renderables) and embed_payload_in_url:
            payload_obj = {
                "contract": VIEWER_CONTAINER_CONTRACT_NAME,
                "version": VIEWER_CONTAINER_CONTRACT_VERSION,
                "request_type": request_type,
                "view_kind": view_kind,
                "input": {
                    "receipt_id": receipt_id,
                    "locker_id": resolved_locker_id,
                    "filename": filename,
                },
                "result": {
                    "kind": "container",
                    "state": state,
                    "view_kind": view_kind,
                    "blocks": normalized_blocks,
                    "renderables": normalized_renderables,
                },
            }
            payload_param = urlencode(
                {"payload": json.dumps(payload_obj, separators=(",", ":"))}
            )
            candidate = f"{base_viewer_url}{'&' if '?' in base_viewer_url else '?'}{payload_param}"
            if len(candidate) <= 7800:
                viewer_url = candidate
            else:
                errors.append(
                    {
                        "code": "PAYLOAD_TOO_LARGE",
                        "message": "Renderable payload exceeded safe URL length; returning unembedded viewer URL.",
                    }
                )

        return ViewerContainer(
            contract=VIEWER_CONTAINER_CONTRACT_NAME,
            version=VIEWER_CONTAINER_CONTRACT_VERSION,
            request_type=request_type,
            viewer_url=viewer_url,
            input={
                "receipt_id": receipt_id,
                "locker_id": resolved_locker_id,
                "filename": filename,
            },
            result={
                "kind": "container",
                "state": state,
                "view_kind": view_kind,
                "viewer_url": base_viewer_url,
                "blocks": normalized_blocks,
                "renderables": normalized_renderables,
            },
            render_hints={
                "variant": VIEWER_RENDERER_VARIANT,
                "layout": "container",
                "primary_action_label": button_label,
                "target": "_blank",
            },
            auth_state={
                "mode": "keypair_signature",
            },
            errors=errors,
            meta={
                "generated_at": int(time.time()),
                "sdk_contract": self._viewer_container_contract(),
                "payload_embedded_in_url": viewer_url != base_viewer_url,
            },
            ui=self._viewer_button_ui(button_label, viewer_url),
        )

    make_text_renderable = staticmethod(make_text_renderable)
    make_json_renderable = staticmethod(make_json_renderable)
    make_pdf_renderable = staticmethod(make_pdf_renderable)
    make_image_renderable = staticmethod(make_image_renderable)
    make_binary_renderable = staticmethod(make_binary_renderable)
    make_header_block = staticmethod(make_header_block)
    make_stats_block = staticmethod(make_stats_block)
    make_links_block = staticmethod(make_links_block)
    make_table_block = staticmethod(make_table_block)
    make_kv_block = staticmethod(make_kv_block)
    make_status_block = staticmethod(make_status_block)
    make_proofs_block = staticmethod(make_proofs_block)
    make_json_block = staticmethod(make_json_block)
    make_file_meta_block = staticmethod(make_file_meta_block)
    make_file_preview_block = staticmethod(make_file_preview_block)

    def get_locker_view_container(
        self,
        receipt_id: str,
        viewer_base_url: str = "https://nukez.xyz",
        include_download_urls: bool = False,
        ttl_min: int = 30,
        embed_payload_in_url: bool = True,
        button_label: str = "Open Locker Viewer",
    ) -> ViewerContainer:
        """
        Build a locker view payload:
        table + stats + links.
        """
        bundle = self.list_files_with_viewer_urls(
            receipt_id=receipt_id,
            viewer_base_url=viewer_base_url,
            include_download_urls=include_download_urls,
            ttl_min=ttl_min,
        )
        rows: List[Dict[str, Any]] = []
        for f in bundle.files:
            row: Dict[str, Any] = {
                "filename": f.filename,
                "content_type": f.content_type,
                "updated_at": f.updated_at or f.created_at or "",
                "viewer_url": f.viewer_url,
            }
            if f.download_url:
                row["download_url"] = f.download_url
            rows.append(row)

        blocks: List[Dict[str, Any]] = [
            self.make_header_block(
                title="Locker Contents",
                subtitle=bundle.locker_id,
                description="Canonical manifest view of files stored through Nukez protocol flows.",
            ),
            self.make_stats_block(
                [
                    {"label": "Locker ID", "value": bundle.locker_id},
                    {"label": "Receipt ID", "value": bundle.receipt_id},
                    {"label": "File Count", "value": len(bundle.files)},
                ],
                title="Locker Stats",
            ),
            self.make_links_block(
                [{"label": "Open Owner Portal", "href": bundle.owner_viewer_url}],
                title="Locker Links",
            ),
            self.make_table_block(
                columns=[
                    {"key": "filename", "label": "Filename"},
                    {"key": "content_type", "label": "Type"},
                    {"key": "updated_at", "label": "Updated"},
                    {"key": "viewer_url", "label": "Viewer"},
                    {"key": "download_url", "label": "Download"},
                ],
                rows=rows,
                title="Files",
            ),
        ]

        return self.get_viewer_container_handoff(
            viewer_base_url=viewer_base_url,
            request_type="locker_view",
            view_kind="locker",
            receipt_id=receipt_id,
            locker_id=bundle.locker_id,
            blocks=blocks,
            embed_payload_in_url=embed_payload_in_url,
            button_label=button_label,
        )

    def get_attestation_view_container(
        self,
        receipt_id: str,
        viewer_base_url: str = "https://nukez.xyz",
        embed_payload_in_url: bool = True,
        button_label: str = "Open Attestation Viewer",
    ) -> ViewerContainer:
        """
        Build an attestation view payload:
        kv + status + proofs + json.
        """
        verification = self.verify_storage(receipt_id)
        locker_id = verification.locker_id or compute_locker_id(receipt_id)
        verified_status = "verified" if verification.verified else "unverified"
        status_detail = (
            "Attestation root is present."
            if verification.attested
            else "No attestation root found in verification response."
        )

        kv_items = [
            {"key": "Receipt ID", "value": verification.receipt_id},
            {"key": "Locker ID", "value": locker_id},
            {"key": "Verified", "value": verification.verified},
            {"key": "Attested", "value": verification.attested},
            {"key": "File Count", "value": verification.file_count},
            {"key": "Result Hash", "value": verification.result_hash},
            {"key": "Verified At", "value": verification.verified_at or "-"},
        ]

        proofs: List[Dict[str, Any]] = []
        if verification.att_code:
            proofs.append({"label": "Attestation Code", "value": verification.att_code})
        if verification.merkle_root:
            proofs.append({"label": "Merkle Root", "value": verification.merkle_root})
        if verification.manifest_signature:
            proofs.append({"label": "Manifest Signature", "value": verification.manifest_signature})
        if verification.verify_url:
            proofs.append({"label": "Verify URL", "href": verification.verify_url})

        raw_json = {
            "receipt_id": verification.receipt_id,
            "locker_id": locker_id,
            "verified": verification.verified,
            "attested": verification.attested,
            "result_hash": verification.result_hash,
            "att_code": verification.att_code,
            "verified_at": verification.verified_at,
            "merkle_root": verification.merkle_root,
            "manifest_signature": verification.manifest_signature,
            "file_count": verification.file_count,
            "files": verification.files or [],
            "verify_url": verification.verify_url,
        }

        blocks: List[Dict[str, Any]] = [
            self.make_header_block(
                title="Attestation View",
                subtitle=locker_id,
                description="Verification state and cryptographic proof data.",
            ),
            self.make_status_block(
                status=verified_status,
                label="Verification Status",
                detail=status_detail,
            ),
            self.make_kv_block(kv_items, title="Attestation Summary"),
        ]
        if proofs:
            blocks.append(self.make_proofs_block(proofs, title="Proof Material"))
        blocks.append(self.make_json_block(raw_json, title="Raw Verification JSON"))

        return self.get_viewer_container_handoff(
            viewer_base_url=viewer_base_url,
            request_type="attestation_view",
            view_kind="attestation",
            receipt_id=receipt_id,
            locker_id=locker_id,
            blocks=blocks,
            embed_payload_in_url=embed_payload_in_url,
            button_label=button_label,
        )

    def get_file_view_container(
        self,
        receipt_id: str,
        filename: str,
        viewer_base_url: str = "https://nukez.xyz",
        ttl_min: int = 30,
        include_download_url: bool = True,
        embed_payload_in_url: bool = True,
        button_label: str = "Open File Viewer",
    ) -> ViewerContainer:
        """
        Build a file view payload:
        file_meta + file_preview.
        """
        locker_id = compute_locker_id(receipt_id)
        owner_link = self.get_owner_viewer_url(receipt_id=receipt_id, viewer_base_url=viewer_base_url)
        file_link = self.get_file_viewer_url(
            receipt_id=receipt_id,
            filename=filename,
            viewer_base_url=viewer_base_url,
            ttl_min=ttl_min,
            include_download_url=include_download_url,
        )

        content_type = "application/octet-stream"
        updated_at: Optional[str] = None
        for f in self.list_files(receipt_id=receipt_id):
            if f.filename == filename:
                content_type = f.content_type or content_type
                updated_at = f.updated_at or f.created_at
                break

        links = [
            {"label": "Back to Locker", "href": owner_link.url},
            {"label": "File Route", "href": file_link.url},
        ]
        if file_link.download_url:
            links.append({"label": "Raw Download", "href": file_link.download_url})

        blocks: List[Dict[str, Any]] = [
            self.make_header_block(
                title="File View",
                subtitle=filename,
                description="Single-file viewer with automatic preview mode selection.",
            ),
            self.make_file_meta_block(
                filename=filename,
                content_type=content_type,
                updated_at=updated_at,
                extra={
                    "Locker ID": locker_id,
                    "Receipt ID": receipt_id,
                },
            ),
            self.make_links_block(links, title="File Links"),
            self.make_file_preview_block(
                filename=filename,
                content_type=content_type,
                url=file_link.download_url or "",
            ),
        ]

        return self.get_viewer_container_handoff(
            viewer_base_url=viewer_base_url,
            request_type="file_view",
            view_kind="file",
            receipt_id=receipt_id,
            locker_id=locker_id,
            filename=filename,
            blocks=blocks,
            embed_payload_in_url=embed_payload_in_url,
            button_label=button_label,
        )

    def get_owner_viewer_url(
        self,
        receipt_id: str,
        viewer_base_url: str = "https://nukez.xyz"
    ) -> ViewerLink:
        """
        Build a stable owner portal URL for a locker.

        This is the default agent handoff link for human-in-the-loop review.
        No network call is required.
        """
        locker_id = compute_locker_id(receipt_id)
        base = self._normalize_viewer_base_url(viewer_base_url)
        query = urlencode({
            "locker_id": locker_id,
            "receipt_id": receipt_id,
        })
        return ViewerLink(
            url=f"{base}/owner?{query}",
            kind="owner",
            locker_id=locker_id,
            receipt_id=receipt_id,
            includes_download_url=False,
        )

    def get_file_viewer_url(
        self,
        receipt_id: str,
        filename: str,
        viewer_base_url: str = "https://nukez.xyz",
        ttl_min: int = 30,
        include_download_url: bool = True,
    ) -> ViewerLink:
        """
        Build a file-scoped viewer URL with a stable download URL.

        Uses the receipt-based file proxy endpoint (/v1/r/{receipt_id}/f/{filename})
        which never expires, instead of time-limited short URL tokens.
        No network call is needed — the URL is computed locally.
        """
        locker_id = compute_locker_id(receipt_id)
        base = self._normalize_viewer_base_url(viewer_base_url)

        # Stable download URL: receipt-based proxy (never expires)
        api_base = self.base_url.rstrip("/")
        download_url = f"{api_base}/v1/r/{receipt_id}/f/{filename}"

        params: Dict[str, str] = {
            "locker_id": locker_id,
            "receipt_id": receipt_id,
            "filename": filename,
            "download_url": download_url,
        }

        return ViewerLink(
            url=f"{base}/view?{urlencode(params)}",
            kind="file",
            locker_id=locker_id,
            receipt_id=receipt_id,
            filename=filename,
            download_url=download_url,
            expires_in_sec=None,  # Never expires
            includes_download_url=True,
        )

    def list_files_with_viewer_urls(
        self,
        receipt_id: str,
        viewer_base_url: str = "https://nukez.xyz",
        include_download_urls: bool = False,
        ttl_min: int = 30,
    ) -> ViewerFileList:
        """
        List locker files and enrich each with a human viewer URL.

        Default behavior avoids minting per-file signed URLs
        (include_download_urls=False) so links are stable and cheap.
        Set include_download_urls=True for immediate one-click file previews.
        """
        owner_link = self.get_owner_viewer_url(
            receipt_id=receipt_id,
            viewer_base_url=viewer_base_url,
        )
        files = self.list_files(receipt_id=receipt_id)

        file_rows: List[FileViewerInfo] = []
        for f in files:
            link = self.get_file_viewer_url(
                receipt_id=receipt_id,
                filename=f.filename,
                viewer_base_url=viewer_base_url,
                ttl_min=ttl_min,
                include_download_url=include_download_urls,
            )
            file_rows.append(
                FileViewerInfo(
                    filename=f.filename,
                    content_type=f.content_type,
                    created_at=f.created_at,
                    updated_at=f.updated_at,
                    object_key=f.object_key,
                    viewer_url=link.url,
                    download_url=link.download_url,
                    expires_in_sec=link.expires_in_sec,
                )
            )

        return ViewerFileList(
            receipt_id=receipt_id,
            locker_id=owner_link.locker_id,
            owner_viewer_url=owner_link.url,
            files=file_rows,
        )

    def get_owner_viewer_handoff(
        self,
        receipt_id: str,
        viewer_base_url: str = "https://nukez.xyz",
        button_label: str = "Open Nukez Viewer",
    ) -> Dict[str, Any]:
        """
        Build MCP-friendly owner viewer payload with UI button metadata.
        """
        link = self.get_owner_viewer_url(
            receipt_id=receipt_id,
            viewer_base_url=viewer_base_url,
        )
        return {
            "renderer_contract": self._viewer_renderer_contract(),
            "kind": link.kind,
            "viewer_url": link.url,
            "locker_id": link.locker_id,
            "receipt_id": link.receipt_id,
            "ui": self._viewer_button_ui(button_label, link.url),
        }

    def get_viewer_renderer_contract(self) -> Dict[str, str]:
        """
        Return the stable MCP renderer contract descriptor used by viewer handoff payloads.
        """
        return self._viewer_renderer_contract()

    def get_viewer_container_contract(self) -> Dict[str, str]:
        """
        Return the stable viewer-container contract descriptor.
        """
        return self._viewer_container_contract()

    def get_file_viewer_handoff(
        self,
        receipt_id: str,
        filename: str,
        viewer_base_url: str = "https://nukez.xyz",
        ttl_min: int = 30,
        include_download_url: bool = True,
        button_label: str = "Open File Viewer",
    ) -> Dict[str, Any]:
        """
        Build MCP-friendly file viewer payload with UI button metadata.
        """
        link = self.get_file_viewer_url(
            receipt_id=receipt_id,
            filename=filename,
            viewer_base_url=viewer_base_url,
            ttl_min=ttl_min,
            include_download_url=include_download_url,
        )
        return {
            "renderer_contract": self._viewer_renderer_contract(),
            "kind": link.kind,
            "viewer_url": link.url,
            "locker_id": link.locker_id,
            "receipt_id": link.receipt_id,
            "filename": link.filename,
            "download_url": link.download_url,
            "expires_in_sec": link.expires_in_sec,
            "includes_download_url": link.includes_download_url,
            "ui": self._viewer_button_ui(button_label, link.url),
        }

    def list_files_with_viewer_handoffs(
        self,
        receipt_id: str,
        viewer_base_url: str = "https://nukez.xyz",
        include_download_urls: bool = False,
        ttl_min: int = 30,
    ) -> Dict[str, Any]:
        """
        Build MCP-friendly owner + file viewer payloads with UI metadata.
        """
        bundle = self.list_files_with_viewer_urls(
            receipt_id=receipt_id,
            viewer_base_url=viewer_base_url,
            include_download_urls=include_download_urls,
            ttl_min=ttl_min,
        )
        owner_ui = self._viewer_button_ui("Open Nukez Viewer", bundle.owner_viewer_url)
        file_rows = []
        for f in bundle.files:
            file_rows.append(
                {
                    "filename": f.filename,
                    "content_type": f.content_type,
                    "viewer_url": f.viewer_url,
                    "download_url": f.download_url,
                    "expires_in_sec": f.expires_in_sec,
                    "ui": self._viewer_button_ui(f"View {f.filename}", f.viewer_url),
                }
            )

        return {
            "renderer_contract": self._viewer_renderer_contract(),
            "kind": "owner_and_files",
            "receipt_id": bundle.receipt_id,
            "locker_id": bundle.locker_id,
            "owner_viewer_url": bundle.owner_viewer_url,
            "ui": owner_ui,
            "files": file_rows,
        }
    
    def delete_file(self, receipt_id: str, filename: str) -> DeleteResult:
        """
        Delete file from locker.
        
        Args:
            receipt_id: Receipt ID from confirm_storage()
            filename: File name to delete
            
        Returns:
            DeleteResult with deletion confirmation
        """
        signer = self._require_signer("delete_file", receipt_id)
        locker_id = compute_locker_id(receipt_id)
        
        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="DELETE",
            path=f"/v1/lockers/{locker_id}/files/{filename}",
            ops=["locker:write"],
            delegating=self._is_delegating(receipt_id),
        )
        
        response = self.http.delete(
            f"/v1/lockers/{locker_id}/files/{filename}",
            headers=envelope.headers
        )
        
        return DeleteResult(
            filename=filename,
            deleted=response.get("deleted", True),
            deleted_at=response.get("deleted_at")
        )
    
    def get_files_manifest(self, receipt_id: str) -> dict:
        """
        Read the files manifest for a locker (schema: locker_files_v1).

        Returns the hot-path document containing files[], timestamps, and
        aggregate stats (file_count, total_bytes, hashed_file_count).
        Does NOT contain ownership fields — use get_locker_record() for
        owner_id / operator_ids.
        """
        signer = self._require_signer("get_files_manifest", receipt_id)
        locker_id = compute_locker_id(receipt_id)

        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="GET",
            path=f"/v1/lockers/{locker_id}/manifest",
            ops=["locker:read"],
            delegating=self._is_delegating(receipt_id),
        )

        return self.http.get(
            f"/v1/lockers/{locker_id}/manifest",
            headers=envelope.headers,
        )

    def get_manifest(self, receipt_id: str) -> dict:
        """Deprecated: use get_files_manifest() instead."""
        import warnings
        warnings.warn(
            "get_manifest() is deprecated and will be removed in the next "
            "major release. Use get_files_manifest() for the files document, "
            "or get_locker_record() for ownership (owner_id, operator_ids).",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_files_manifest(receipt_id)

    def get_locker_record(self, receipt_id: str) -> LockerRecord:
        """
        Read the locker record (schema: lockers_v1).

        Returns ownership and identity fields — owner_id, operator_ids,
        receipt binding, provider. This is the cold-path document,
        distinct from get_files_manifest().

        Use this to verify the effect of add_operator() / remove_operator()
        against the gateway's authoritative state.
        """
        signer = self._require_signer("get_locker_record", receipt_id)
        locker_id = compute_locker_id(receipt_id)

        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="GET",
            path=f"/v1/lockers/{locker_id}/record",
            ops=["locker:read"],
            delegating=self._is_delegating(receipt_id),
        )

        response = self.http.get(
            f"/v1/lockers/{locker_id}/record",
            headers=envelope.headers,
        )

        return LockerRecord(
            locker_id=response.get("locker_id", locker_id),
            owner_id=response.get("owner_id", ""),
            operator_ids=list(response.get("operator_ids", []) or []),
            receipt_id=response.get("receipt_id", receipt_id),
            provider=response.get("provider", ""),
            created_at=response.get("created_at"),
            tags=response.get("tags"),
        )
    
    # =========================================================================
    # VERIFICATION
    # =========================================================================

    def get_receipt(self, receipt_id: str) -> dict:
        """
        Fetch the canonical gateway receipt document.

        This is the stored receipt object returned by the gateway after payment
        confirmation. Use verify_receipt_hash() when you want the gateway to
        recompute and compare the receipt's canonical hash.
        """
        return self.http.get(f"/v1/receipts/{receipt_id}")

    def verify_receipt_hash(self, receipt_id: str) -> ReceiptHashVerification:
        """
        Recompute and compare a receipt's canonical hash.

        This verifies the receipt object itself:
        - stored_hash comes from /v1/receipts/{receipt_id}
        - computed_hash comes from /v1/receipts/{receipt_id}/verify

        For storage/content attestation, use verify_storage().
        """
        receipt = self.get_receipt(receipt_id)
        verification = self.http.get(f"/v1/receipts/{receipt_id}/verify")

        stored_hash = str(
            receipt.get("receipt_hash")
            or verification.get("receipt_hash")
            or verification.get("stored_hash")
            or ""
        )
        computed_hash = str(verification.get("computed_hash") or "")

        return ReceiptHashVerification(
            receipt_id=receipt_id,
            stored_hash=stored_hash,
            computed_hash=computed_hash,
            matches=bool(stored_hash) and stored_hash == computed_hash,
            receipt=receipt,
            verification=verification,
        )

    def receipt_hash_matches(self, receipt_id: str) -> bool:
        """Return True when the stored and recomputed receipt hashes match."""
        return self.verify_receipt_hash(receipt_id).matches
    
    def verify_storage(self, receipt_id: str) -> VerificationResult:
        """
        Verify storage integrity and get cryptographic attestation.
        
        Returns the unified verification response including:
        - Receipt verification (payment confirmed on-chain)
        - Attestation data (merkle root, file hashes, gateway signature)
        - On-chain attestation code (if Switchboard push has occurred)
        
        Args:
            receipt_id: Receipt ID from confirm_storage()
            
        Returns:
            VerificationResult with:
            - verified: True if receipt + attestation are valid
            - merkle_root: SHA256 merkle root of all files in locker
            - manifest_signature: Gateway's Ed25519 signature over the merkle root
            - att_code: Numeric attestation code (from Switchboard on-chain push)
            - file_count: Number of files covered by attestation
            - files: List of {filename, content_hash, size_bytes} for each file
            - verify_url: Public verification page URL
        """
        response = self.http.get(
            "/v1/storage/verify", 
            params={"receipt_id": receipt_id}
        )
        
        # Extract attestation from nested object (verify endpoint returns unified response)
        attestation = response.get("attestation") or {}
        
        return VerificationResult(
            receipt_id=receipt_id,
            verified=response.get("verified", False),
            result_hash=attestation.get("result_hash", response.get("result_hash", "")),
            att_code=str(attestation.get("att_code", response.get("att_code", ""))),
            verified_at=attestation.get("attested_at", response.get("verified_at", "")),
            # Phase 5 attestation fields
            merkle_root=attestation.get("merkle_root", ""),
            manifest_signature=attestation.get("manifest_signature", ""),
            file_count=attestation.get("file_count", 0),
            files=attestation.get("files"),
            locker_id=response.get("locker_id", attestation.get("locker_id", "")),
            verify_url=response.get("verify_url", ""),
        )

    def recompute_verify(
        self,
        receipt_id: str,
        timeout: Optional[int] = None,
    ) -> RecomputeVerifyResult:
        """Re-download every file from storage and recompute hashes.

        Use when you need cryptographic proof that storage bytes still match
        the recorded hashes. Latency scales with total locker bytes. For a
        fast structural check, use ``verify_storage()`` or ``attest()``
        instead — those trust the manifest's recorded content_hash and run
        in seconds independent of locker size.

        Gateway endpoint: ``GET /v1/storage/recompute-verify?receipt_id=...``.
        Public-by-receipt_id — no signed envelope required.

        Args:
            receipt_id: Receipt ID from confirm_storage().
            timeout: Optional per-call timeout in seconds. Defaults to the
                client's effective timeout (120s) — recompute can be slow
                on large lockers, so consider raising this for sizeable
                content.

        Returns:
            RecomputeVerifyResult with ``match``, ``computed``, ``stored``,
            ``file_count``, ``recompute_ms``, and the full response under
            ``details``.
        """
        kwargs: Dict[str, Any] = {"params": {"receipt_id": receipt_id}}
        if timeout is not None:
            kwargs["timeout"] = timeout
        response = self.http.get("/v1/storage/recompute-verify", **kwargs)
        return RecomputeVerifyResult(
            receipt_id=receipt_id,
            match=bool(response.get("match", False)),
            computed=str(response.get("computed", "")),
            stored=str(response.get("stored", "")),
            file_count=int(response.get("file_count", 0) or 0),
            recompute_ms=int(response.get("recompute_ms", 0) or 0),
            details=response,
        )

    def get_merkle_proof(self, receipt_id: str, filename: str) -> dict:
        """
        Get a merkle inclusion proof for a specific file in an attested locker.

        The proof allows a verifier to confirm that a single file is included
        in the attested merkle tree without needing all other files.

        Verification algorithm:
          1. Compute leaf = SHA256("{filename}:{size_bytes}:{content_hash}")
          2. Walk proof: for each step, if position=='right' then
             current=SHA256(current+step.hash), else current=SHA256(step.hash+current)
          3. Assert final current == merkle_root

        Args:
            receipt_id: Receipt ID from confirm_storage()
            filename: Name of the file to prove inclusion for

        Returns:
            dict with:
            - receipt_id: The receipt ID
            - filename: The target filename
            - leaf_hash: SHA256 hash of the leaf node
            - leaf_index: Position in the sorted file list
            - merkle_root: The attested merkle root (sha256:...)
            - proof: List of {hash, position} steps from leaf to root
            - tree_depth: Number of levels in the merkle tree
            - file_count: Total files in the attestation
            - file_entry: {filename, size_bytes, content_hash} of the target file
            - schema_version: Attestation schema version
            - switchboard: {slot, tx} on-chain attestation data
            - verification_algorithm: Human-readable verification instructions
        """
        return self.http.get(
            "/v1/storage/merkle-proof",
            params={"receipt_id": receipt_id, "filename": filename},
        )

    def compute_hash(self, data: Union[str, bytes]) -> str:
        """
        Compute SHA256 hash of data for verification.

        Args:
            data: Data to hash (string or bytes)

        Returns:
            Hex-encoded SHA256 hash
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    # =========================================================================
    # CONFIRMATION & ATTESTATION (Trust boundary closure)
    # =========================================================================

    def _post_confirm(self, confirm_url: Optional[str], fallback_path: str,
                      fallback_params: Dict[str, Any],
                      timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        POST to a confirm endpoint. Prefers the absolute confirm_url returned
        by create_file/create_files_batch; falls back to the hardcoded path
        for backward compatibility with older gateways.

        Gateway confirm routes are public-by-receipt_id — no signed envelope
        required. receipt_id in the URL is the bearer credential.

        Args:
            confirm_url: Absolute confirm URL from create_file()/create_files_batch().
            fallback_path: Hardcoded path used when confirm_url is unset.
            fallback_params: Query params for the fallback path.
            timeout: Per-call timeout (seconds). Defaults to self.timeout.
        """
        eff_timeout = timeout if timeout is not None else self.timeout
        if confirm_url:
            try:
                resp = self._raw_client.post(confirm_url, timeout=eff_timeout)
                if resp.status_code >= 400:
                    # Route through normal error handling
                    from ._http import handle_error_response
                    handle_error_response(resp)
                return resp.json()
            except _httpx.TimeoutException:
                raise NukezError(f"Request timed out after {eff_timeout}s: POST confirm")
            except _httpx.HTTPError as e:
                raise NukezError(f"Request failed: POST confirm: {e}")
        post_kwargs: Dict[str, Any] = {"params": fallback_params}
        if timeout is not None:
            post_kwargs["timeout"] = timeout
        return self.http.post(fallback_path, **post_kwargs)

    def confirm_file(
        self,
        receipt_id: str,
        filename: str,
        confirm_url: Optional[str] = None,
    ) -> ConfirmResult:
        """
        Confirm a file upload by computing its content hash server-side.

        Call this AFTER uploading content to the signed URL returned by
        create_file(). The server downloads the content from storage,
        computes SHA256, and records it in the manifest.

        This closes the trust boundary at upload time — the server now
        has a verified hash of what was actually stored, not just what
        the client claimed to send.

        Args:
            receipt_id: Receipt ID from confirm_storage()
            filename: Name of the file to confirm
            confirm_url: Optional absolute confirm URL from create_file()
                response. If provided, POSTs to it directly. Otherwise
                falls back to the hardcoded path. New gateways return
                this URL; older gateways don't.

        Returns:
            ConfirmResult with:
            - filename: Confirmed filename
            - content_hash: Server-computed SHA256 hash (sha256:... prefixed)
            - size_bytes: Actual size of stored content
            - confirmed: True if hash was recorded successfully

        Note:
            If AUTO_REATTEST is enabled server-side, this also triggers
            re-attestation so the merkle root stays current.

            receipt_id is a bearer credential — anyone holding it can
            confirm files on this locker. Don't log or share confirm_url
            in error messages or third-party sinks.
        """
        response = self._post_confirm(
            confirm_url,
            "/v1/files/confirm",
            {"receipt_id": receipt_id, "filename": filename},
        )

        return ConfirmResult(
            filename=response.get("filename", filename),
            content_hash=response.get("content_hash", ""),
            size_bytes=response.get("size_bytes", 0),
            confirmed=True,
        )

    def confirm_files(
        self,
        receipt_id: str,
        filenames: List[str],
        confirm_batch_url: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> BatchConfirmResult:
        """
        Confirm multiple file uploads in a single operation.

        One manifest read-modify-write, one re-attestation (if AUTO_REATTEST
        is enabled). More efficient than calling confirm_file() in a loop —
        post-Patch-2, a batch confirm produces a single auto-reattest cycle
        rather than N independent on-chain pushes.

        Args:
            receipt_id: Receipt ID from confirm_storage()
            filenames: List of filenames to confirm
            confirm_batch_url: Optional absolute confirm URL from
                create_files_batch() response. If provided, POSTs to it
                directly. Otherwise falls back to the hardcoded path.
            timeout: Optional per-call timeout (seconds). Defaults to the
                client's effective timeout (120s). Raise for very large
                batches where the gateway needs more time to compute hashes.
        """
        response = self._post_confirm(
            confirm_batch_url,
            "/v1/files/confirm-batch",
            {"receipt_id": receipt_id, "filenames": filenames},
            timeout=timeout,
        )

        results = []
        for r in response.get("results", []):
            results.append(ConfirmResult(
                filename=r.get("filename", ""),
                content_hash=r.get("content_hash", ""),
                size_bytes=r.get("size_bytes", 0),
                confirmed=r.get("status") != "error",
            ))

        return BatchConfirmResult(
            results=results,
            confirmed_count=response.get("confirmed", len([r for r in results if r.confirmed])),
            failed_count=response.get("failed", len([r for r in results if not r.confirmed])),
        )

    def attest(
        self,
        receipt_id: str,
        sync: bool = True,
        timeout: Optional[int] = None,
    ) -> AttestResult:
        """
        Trigger attestation — compute merkle root and optionally push on-chain.

        The gateway no longer re-downloads file bytes on every attestation;
        it trusts the manifest's recorded content_hash. Latency is bounded by
        the on-chain Switchboard confirmation (~5-10s typical), not by locker
        size. For byte-level proof that the persisted hashes still match
        storage contents, call ``recompute_verify()`` instead — that path
        re-downloads everything and latency scales with locker bytes.

        Auth: signed envelope, ``ops=["locker:attest"]``. The SDK builds the
        envelope (with the query string bound) and adds the headers.

        Args:
            receipt_id: Receipt ID from confirm_storage().
            sync: If True (default), wait for attestation to complete and
                return the full result. If False, return immediately with
                status="accepted" — poll ``verify_storage()`` for a truthy
                ``merkle_root`` (or call ``attest_async()`` to do the polling
                for you).
            timeout: Optional per-call timeout (seconds). Defaults to the
                client's effective timeout (120s). Sync attest should
                complete well within that even on large lockers given the
                Patch-1 fast path.

        Returns:
            AttestResult with merkle_root, file_count, att_code, status,
            push_ok, tx_signature, switchboard_slot.

        Example:
            client.upload_bytes(urls.upload_url, data)
            client.confirm_file(receipt_id, "data.txt")
            proof = client.attest(receipt_id)
            print(proof.merkle_root)  # sha256:abc123...
        """
        params = {"receipt_id": receipt_id}
        if sync:
            params["sync"] = "true"

        # /v1/storage/attest is a signed endpoint (ops=["locker:attest"]). Its
        # arguments travel in the query string, so the envelope must bind that
        # query string — see build_signed_envelope's `query` parameter.
        signer = self._require_signer("attest", receipt_id)
        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="POST",
            path="/v1/storage/attest",
            query=urlencode(params),
            ops=["locker:attest"],
            body={},
            delegating=self._is_delegating(receipt_id),
        )

        post_kwargs: Dict[str, Any] = {
            "headers": envelope.headers,
            "params": params,
            "content": envelope.canonical_body.encode("utf-8"),
        }
        if timeout is not None:
            post_kwargs["timeout"] = timeout
        response = self.http.post("/v1/storage/attest", **post_kwargs)

        push_result = response.get("push_result") or {}

        return AttestResult(
            receipt_id=receipt_id,
            merkle_root=response.get("merkle_root", ""),
            file_count=response.get("file_count", 0),
            att_code=response.get("att_code"),
            status="complete" if response.get("merkle_root") else response.get("status", "accepted"),
            push_ok=push_result.get("ok", False),
            tx_signature=push_result.get("tx_signature"),
            switchboard_slot=push_result.get("slot"),
        )

    def attest_async(
        self,
        receipt_id: str,
        poll_interval: float = 1.0,
        max_wait: float = 60.0,
    ) -> AttestResult:
        """Trigger attestation asynchronously and poll until merkle_root appears.

        Calls ``attest(sync=False)`` (which enqueues a Cloud Tasks job and
        returns 202), then polls ``verify_storage()`` until a truthy
        ``merkle_root`` shows up — the authoritative completion signal. The
        status string transitions through pending → computed → pushing →
        complete and is informational only; do not gate completion on it.

        Cloud Tasks dedup window is 5 seconds: two ``attest_async()`` calls
        within 5 sec for the same receipt collapse to a single on-chain push,
        saving a Switchboard fee for back-to-back batch workflows.

        Args:
            receipt_id: Receipt ID from confirm_storage().
            poll_interval: Seconds between verify_storage() polls.
            max_wait: Total seconds to wait before raising
                ``NukezError("attest_timeout")``.

        Returns:
            AttestResult mirroring ``attest(sync=True)``'s shape. Note that
            ``tx_signature`` and ``switchboard_slot`` come from a separate
            push-confirmation stream and may be ``None`` here even when
            ``merkle_root`` is populated — call ``verify_storage()`` again
            (or ``get_merkle_proof()``) to pick them up after settlement.

        Raises:
            NukezError("attest_timeout: ..."): max_wait exceeded with no
                merkle_root.
        """
        self.attest(receipt_id, sync=False)

        deadline = time.time() + max_wait
        while time.time() < deadline:
            v = self.verify_storage(receipt_id)
            if v.merkle_root:
                att_code_int: Optional[int] = None
                if v.att_code and str(v.att_code).strip().lstrip("-").isdigit():
                    att_code_int = int(v.att_code)
                return AttestResult(
                    receipt_id=receipt_id,
                    merkle_root=v.merkle_root,
                    file_count=v.file_count,
                    att_code=att_code_int,
                    status="complete",
                    push_ok=bool(v.att_code),
                    tx_signature=None,
                    switchboard_slot=None,
                )
            time.sleep(poll_interval)

        raise NukezError(
            f"attest_timeout: receipt '{receipt_id}' did not produce a "
            f"merkle_root within {max_wait}s. Continue polling "
            f"verify_storage() manually, or retry attest_async() to "
            f"re-enqueue (within the 5s Cloud Tasks dedup window two "
            f"attempts collapse to one on-chain push)."
        )

    def upload_files(
        self,
        receipt_id: str,
        files: List[Dict[str, Any]],
        workers: int = 10,
        confirm: bool = True,
        on_progress: Optional[Any] = None,
    ) -> BatchUploadResult:
        """
        Upload multiple files concurrently with optional confirmation.

        Handles create_file → upload_bytes → confirm_file for each file
        using a thread pool. This is the production method for bulk uploads.

        Args:
            receipt_id: Receipt ID from confirm_storage()
            files: List of file dicts, each with:
                - filename (str): Name for the file
                - content (bytes): File content
                - content_type (str, optional): MIME type (default: application/octet-stream)
            workers: Number of concurrent upload threads (default: 10)
            confirm: If True (default), call confirm_file() after each upload
                     to close the trust boundary. If False, skip confirmation
                     (caller is responsible for confirming later).
            on_progress: Optional callback(filename, success, index, total)
                         called after each file completes.

        Returns:
            BatchUploadResult with:
            - uploaded: Number of files successfully uploaded
            - failed: Number of files that failed
            - total: Total files attempted
            - elapsed_sec: Wall-clock time for all uploads
            - errors: List of (filename, error_message) for failures
            - results: List of per-file UploadResult objects

        Example:
            files = [
                {"filename": "a.txt", "content": b"hello"},
                {"filename": "b.txt", "content": b"world"},
            ]
            result = client.upload_files(receipt_id, files, workers=5)
            print(f"Uploaded {result.uploaded}/{result.total} in {result.elapsed_sec:.1f}s")

            # Then attest once for the whole batch
            proof = client.attest(receipt_id)
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        t0 = time.time()
        uploaded_count = 0
        errors = []
        results = []

        def _do_one(sf: Dict[str, Any]) -> tuple:
            """Upload a single file. Returns (filename, success, error, upload_result)."""
            fname = sf["filename"]
            content = sf["content"]
            ctype = sf.get("content_type", "application/octet-stream")
            try:
                urls = self.create_file(receipt_id, fname, content_type=ctype)
                result = self.upload_bytes(urls.upload_url, content, content_type=ctype)

                if confirm:
                    try:
                        self.confirm_file(receipt_id, fname)
                    except Exception:
                        pass  # Non-fatal — attestation will still compute hashes

                return (fname, True, None, result)
            except Exception as e:
                return (fname, False, str(e), None)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_do_one, sf): sf
                for sf in files
            }
            for i, future in enumerate(as_completed(futures), 1):
                fname, success, error, result = future.result()
                if success:
                    uploaded_count += 1
                    if result:
                        results.append(result)
                else:
                    errors.append((fname, error))

                if on_progress:
                    try:
                        on_progress(fname, success, i, len(files))
                    except Exception:
                        pass

        elapsed = time.time() - t0

        return BatchUploadResult(
            uploaded=uploaded_count,
            failed=len(errors),
            total=len(files),
            elapsed_sec=round(elapsed, 2),
            errors=errors,
            results=results,
        )

    def get_batch_urls(
        self,
        receipt_id: str,
        filenames: list,
        ttl_min: int = 30,
    ) -> dict:
        """
        Get signed download URLs for multiple files in one API call.

        One envelope, one round-trip, N URLs back. Avoids rate limits
        that occur when calling get_file_urls() per file concurrently.

        Args:
            receipt_id: Receipt ID from confirm_storage()
            filenames: List of filenames to get URLs for
            ttl_min: URL lifetime in minutes (default: 30)

        Returns:
            Raw response dict with 'urls' list, 'found', 'not_found'.
        """
        signer = self._require_signer("get_batch_urls", receipt_id)
        locker_id = compute_locker_id(receipt_id)

        body = {
            "filenames": filenames,
            "ttl_min": ttl_min,
        }

        envelope = build_signed_envelope(
            signer=signer,
            receipt_id=receipt_id,
            method="POST",
            path=f"/v1/lockers/{locker_id}/files/urls",
            ops=["locker:read"],
            body=body,
            delegating=self._is_delegating(receipt_id),
        )

        return self.http.post(
            f"/v1/lockers/{locker_id}/files/urls",
            headers=envelope.headers,
            data=envelope.canonical_body.encode("utf-8"),
        )


    def download_files(
        self,
        receipt_id: str,
        filenames: list = None,
        workers: int = 5,
        verify: bool = True,
        on_progress=None,
    ) -> "BatchDownloadResult":
        """
        Download multiple files with full concurrency.

        Uses batch URL endpoint (one API call) then downloads all files
        from GCS concurrently. No rate limit risk.

        Args:
            receipt_id: Receipt ID from confirm_storage()
            filenames: Optional list of filenames. None = all files.
            workers: Concurrent download threads (default: 5)
            verify: Compare downloaded content SHA256 to manifest hash
            on_progress: Optional callback(filename, success, index, total)

        Returns:
            BatchDownloadResult with downloaded files and verification.
        """
        import hashlib as _hashlib
        from concurrent.futures import ThreadPoolExecutor, as_completed

        t0 = time.time()

        # Step 1: Get manifest for file list and hashes
        manifest = self.get_files_manifest(receipt_id)
        manifest_files = manifest.get("files", [])
        hash_lookup = {
            f.get("filename", ""): f.get("content_hash", "")
            for f in manifest_files
        }

        # Determine target filenames
        if filenames is None:
            filenames = list(hash_lookup.keys())

        # Step 2: Get all download URLs in ONE call
        batch_response = self.get_batch_urls(receipt_id, filenames)

        # Build filename → download_url map
        url_map = {}
        for entry in batch_response.get("urls", []):
            url_map[entry["filename"]] = entry["download_url"]

        errors = []
        # Track files not found on server
        for fn in batch_response.get("not_found", []):
            errors.append((fn, "File not found in locker"))

        # Step 3: Download from GCS at full concurrency
        # GCS signed URLs go to storage.googleapis.com — no rate limit
        downloaded_count = 0
        files_out = []

        def _download(fn: str):
            try:
                data = self.download_bytes(url_map[fn])
                local_hash = f"sha256:{_hashlib.sha256(data).hexdigest()}"
                verified_ok = True
                if verify:
                    expected = hash_lookup.get(fn, "")
                    verified_ok = (local_hash == expected) if expected else False

                return (fn, True, None, DownloadedFile(
                    filename=fn,
                    content=data,
                    content_hash=local_hash,
                    size_bytes=len(data),
                    verified=verified_ok,
                ))
            except Exception as e:
                return (fn, False, str(e), None)

        targets = [fn for fn in filenames if fn in url_map]

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_download, fn): fn for fn in targets}
            for i, future in enumerate(as_completed(futures), 1):
                fn, success, error, df = future.result()
                if success:
                    downloaded_count += 1
                    files_out.append(df)
                else:
                    errors.append((fn, error))

                if on_progress:
                    try:
                        on_progress(fn, success, i, len(targets))
                    except Exception:
                        pass

        elapsed = time.time() - t0

        return BatchDownloadResult(
            downloaded=downloaded_count,
            failed=len(errors),
            total=len(filenames),
            elapsed_sec=round(elapsed, 2),
            errors=errors,
            files=files_out,
        )












































































































































































