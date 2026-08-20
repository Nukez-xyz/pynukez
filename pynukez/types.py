"""
Data models for Nukez SDK.

All return types are dataclasses with explicit fields.
Agents can access fields predictably: result.field_name
"""

from dataclasses import dataclass
from decimal import Decimal
from typing import List, Optional, Dict, Any, Tuple
import hashlib


@dataclass(frozen=True)
class SplTransfer:
    """Self-contained Solana SPL transferChecked description.

    Present on payment options whose ``destination_kind == "spl_token_account"``.
    ``destination_token_account`` IS the treasury's SPL token account — pass it
    directly as the transferChecked destination; do NOT call
    ``get_associated_token_address`` on it.
    """
    program_id: str
    destination_token_account: str
    mint: str
    amount_raw: int
    decimals: int

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> Optional["SplTransfer"]:
        """Construct from a raw dict, or return None if ``d`` is None/empty.

        Tolerant of missing keys — defaults to empty/zero so a malformed
        gateway response doesn't blow up parsing of the surrounding payment.
        """
        if not d:
            return None
        return cls(
            program_id=d.get("program_id", ""),
            destination_token_account=d.get("destination_token_account", ""),
            mint=d.get("mint", ""),
            amount_raw=int(d.get("amount_raw", 0) or 0),
            decimals=int(d.get("decimals", 0) or 0),
        )


@dataclass
class StorageRequest:
    """Payment instructions from request_storage().

    Multi-chain support:
      - Solana SOL: amount_sol / amount_lamports are populated, pay_asset="SOL"
      - Solana SPL: amount / amount_raw / token_address / token_decimals populated
      - EVM/Monad: amount / amount_raw / token_address / token_decimals populated
    """
    pay_req_id: str
    pay_to_address: str
    amount_sol: float
    amount_lamports: int
    network: str
    units: int
    provider: str = "gcs"
    # EVM / multi-chain fields (Phase 2)
    pay_asset: str = "SOL"
    amount: Optional[str] = None          # human-readable amount (all chains)
    amount_raw: Optional[int] = None      # atomic units (lamports / wei / token units)
    token_address: Optional[str] = None   # ERC-20 contract address (EVM only — NOT set for Solana SPL; read spl_transfer.mint instead)
    token_decimals: Optional[int] = None  # token decimals (EVM only)

    # Destination disambiguation (additive, back-compat).
    # destination_kind tells the caller what pay_to_address means:
    #   "wallet"            — native SOL or EVM wallet: send value directly.
    #   "spl_token_account" — Solana SPL (USDC/USDT/WETH/BETA): pay_to_address
    #                         IS the treasury's SPL token account; pass it as the
    #                         transferChecked destination, do NOT derive an ATA.
    #                         The mint/amount_raw/decimals live on spl_transfer.
    #   "evm_address"       — EVM rails: a wallet/EOA. For ERC-20 the transfer
    #                         goes to the contract at token_address with
    #                         pay_to_address as the recipient argument.
    #   "unknown" / None    — older gateway or unspecified: treat as native wallet.
    destination_kind: Optional[str] = None
    spl_transfer: Optional[SplTransfer] = None

    # Quote lifecycle (from 402 response)
    payment_options: Optional[List[Dict[str, Any]]] = None   # all chain/asset combos as raw dicts (the dict view nukez-mcp's preflight reads); use parsed_options for typed access
    quote_expires_at: Optional[int] = None                    # unix timestamp
    quote_schema: Optional[str] = None                        # "dl_quote_v3"
    idempotency_key: Optional[str] = None
    terms: Optional[Dict[str, Any]] = None                    # storage limits, TTL, file limits
    price_breakdown: Optional[Dict[str, Any]] = None          # cost components from price object

    # Guide agent to next step. PyNukez does not execute transfers; the
    # agent should use the chosen wallet, CLI, signer, or custody workflow,
    # then submit the resulting tx signature to confirm_storage().
    next_step: str = ""

    @property
    def is_evm(self) -> bool:
        """True if this is an EVM payment (Monad, Ethereum, etc.)."""
        return any(tag in (self.network or "") for tag in ("monad", "ethereum", "evm", "arbitrum"))

    def __post_init__(self):
        if self.destination_kind == "spl_token_account":
            # Solana SPL — explicit instructions so the caller doesn't derive an ATA.
            sf = self.spl_transfer
            mint = sf.mint if sf else "?"
            amt = sf.amount_raw if sf else (self.amount_raw if self.amount_raw is not None else "?")
            dec = sf.decimals if sf else (self.token_decimals if self.token_decimals is not None else "?")
            self.next_step = (
                f"Solana SPL ({self.pay_asset}): pay_to_address ({self.pay_to_address}) "
                f"IS the treasury's SPL token account — pass it directly as the "
                f"transferChecked destination, do NOT call get_associated_token_address. "
                f"Use mint={mint}, amount_raw={amt}, decimals={dec}. Then call "
                f"confirm_storage(pay_req_id='{self.pay_req_id}', "
                f"tx_sig=<your_tx_signature>, payment_chain='{self.network}', "
                f"payment_asset='{self.pay_asset}')"
            )
        elif self.is_evm:
            self.next_step = (
                f"Transfer {self.amount or '?'} {self.pay_asset} "
                f"to {self.pay_to_address} on {self.network}, then call "
                f"confirm_storage(pay_req_id='{self.pay_req_id}', "
                f"tx_sig=<your_tx_signature>)"
            )
        elif (self.pay_asset or "").upper() == "SOL":
            self.next_step = (
                f"Transfer {self.amount_sol} SOL "
                f"to {self.pay_to_address} on {self.network}, then call "
                f"confirm_storage(pay_req_id='{self.pay_req_id}', "
                f"tx_sig=<your_tx_signature>)"
            )
        else:
            display_amount = self.amount or self.amount_raw or "?"
            if self.amount_raw is not None and self.token_decimals is not None:
                try:
                    q = Decimal(int(self.amount_raw)) / (Decimal(10) ** int(self.token_decimals))
                    display_amount = format(q, "f")
                    if "." in display_amount:
                        display_amount = display_amount.rstrip("0").rstrip(".") or "0"
                except Exception:
                    pass
            self.next_step = (
                f"Transfer {display_amount} {self.pay_asset} "
                f"to {self.pay_to_address} on {self.network}, then call "
                f"confirm_storage(pay_req_id='{self.pay_req_id}', "
                f"tx_sig=<your_tx_signature>, payment_chain='{self.network}', "
                f"payment_asset='{self.pay_asset}')"
            )
        if self.payment_options:
            self.next_step += (
                f" ({len(self.payment_options)} payment option(s) available — "
                f"check payment_options for alternatives.)"
            )

    @property
    def parsed_options(self) -> List["PaymentOption"]:
        """Parse raw payment_options dicts into typed PaymentOption objects."""
        if not self.payment_options:
            return []
        return [PaymentOption.from_dict(d) for d in self.payment_options]

@dataclass
class Receipt:
    """Storage receipt from confirmed payment."""
    id: str  # receipt_id
    units: int
    payer_pubkey: str
    network: str
    created_at: Optional[str] = None

    # Multi-chain & provider fields (from confirm response)
    provider: str = ""                          # storage backend used
    pay_asset: str = "SOL"                      # token used for payment
    tx_hash: str = ""                           # chain-agnostic tx identifier
    paid_amount: Optional[str] = None           # human-readable amount paid
    paid_raw: Optional[int] = None              # atomic units paid
    block_number: Optional[int] = None          # EVM only
    slot: Optional[int] = None                  # Solana only
    sig_alg: str = ""                           # "ed25519" or "secp256k1"
    unit_price_usd: float = 0.0
    price_usd: float = 0.0
    authorized_operator: Optional[str] = None  # operator bound at confirm time

    def __post_init__(self):
        self.receipt_id = self.id #agent-visible alias

    @property
    def locker_id(self) -> str:
        """Compute locker_id from receipt_id."""
        return "locker_" + hashlib.sha256(self.id.encode()).hexdigest()[:12]

@dataclass
class SignedEnvelope:
    """Result from build_signed_envelope()."""
    headers: Dict[str, str]  # X-Nukez-Envelope, X-Nukez-Signature
    canonical_body: Optional[str]
    locker_id: str
    
    # Include what agent needs to know
    usage: str = "Add headers to your HTTP request"

@dataclass
class FileUrls:
    """URLs for file operations."""
    filename: str
    upload_url: str
    download_url: str
    content_type: str
    expires_in_sec: int
    # Absolute confirm URL from the gateway (new in gateway Phase N-4).
    # POST to this after upload to populate content_hash in the manifest.
    # The confirm endpoint requires a payer-signed locker:write envelope
    # bound to this URL's exact path and query — holding the receipt_id in
    # the URL is not authorization by itself. confirm_file()/confirm_files()
    # build and sign that envelope automatically.
    # None when talking to older gateways that don't return this field.
    confirm_url: Optional[str] = None

    # Large-blob resumable uploads (gateway 2026-08 design). upload_mode is
    # "put" or "resumable" as echoed by the gateway; resumable_upload is the
    # session-opener block ({url, method, headers, chunk_alignment_bytes,
    # session_ttl_sec, protocol, instructions}) present only when the file
    # was created with upload_mode="resumable" on a provider that supports
    # it. expected_hash / expected_size_bytes echo the client's
    # pre-commitment; confirm refuses to record the manifest hash unless the
    # stored bytes agree with both. All None on older gateways.
    upload_mode: Optional[str] = None
    resumable_upload: Optional[Dict[str, Any]] = None
    expected_hash: Optional[str] = None
    expected_size_bytes: Optional[int] = None

    # Agent guidance
    next_steps: str = (
        "PUT your raw bytes to upload_url via upload_bytes(upload_url=<the upload_url above>, "
        "data='your content here'). The data string is sent as raw bytes in the HTTP PUT body. "
        "Then GET via download_bytes(download_url=<the download_url above>)."
    )

@dataclass  
class VerificationResult:
    """Storage verification result with attestation data."""
    receipt_id: str
    verified: bool
    result_hash: str
    att_code: str = ""
    verified_at: str = ""
    # Phase 5 attestation fields
    merkle_root: str = ""
    manifest_signature: str = ""
    file_count: int = 0
    files: Optional[List[Dict[str, Any]]] = None  # [{filename, content_hash, size_bytes}, ...]
    locker_id: str = ""
    verify_url: str = ""
    
    @property
    def status(self) -> str:
        return "verified" if self.verified else "verification_failed"
    
    @property
    def attested(self) -> bool:
        """True if an on-chain attestation exists (merkle_root computed)."""
        return bool(self.merkle_root)

@dataclass
class ReceiptHashVerification:
    """Receipt hash verification result."""
    receipt_id: str
    stored_hash: str
    computed_hash: str
    matches: bool
    receipt: Dict[str, Any]
    verification: Dict[str, Any]

    @property
    def ok(self) -> bool:
        return self.matches

    @property
    def status(self) -> str:
        return "verified" if self.matches else "hash_mismatch"

@dataclass
class PriceInfo:
    """Pricing information from get_price()."""
    units: int
    unit_price_usd: float
    total_usd: float
    amount_sol: float
    amount_lamports: int
    network: str
    # Multi-chain pricing (Phase 2) — populated when pay_asset != SOL
    pay_asset: str = "SOL"
    amount: Optional[str] = None          # human-readable for any chain
    amount_raw: Optional[int] = None      # atomic units for any chain
    # Extended pricing fields
    provider: str = ""                                  # which provider was priced
    mode: str = "static"                                # "static" or "override"
    cost_breakdown: Optional[Dict[str, Any]] = None     # base, attestation, egress, margin
    payment_options: Optional[List[Dict[str, Any]]] = None  # use parsed_options for typed access

    @property
    def parsed_options(self) -> List["PaymentOption"]:
        """Parse raw payment_options dicts into typed PaymentOption objects."""
        if not self.payment_options:
            return []
        return [PaymentOption.from_dict(d) for d in self.payment_options]

@dataclass
class PaymentOption:
    """One chain/asset payment path from the 402 response."""
    chain: str              # "solana-devnet", "monad-mainnet"
    asset: str              # "SOL", "USDC", "USDT", "MON", "WETH"
    amount: str             # human-readable
    amount_raw: int         # atomic units
    treasury: str           # destination address
    decimals: int           # token decimals
    token_contract: Optional[str] = None   # ERC-20 address (EVM only)
    oracle_rate: Optional[Dict[str, Any]] = None  # e.g. {"mon_usd": 0.42, "source": "coingecko"}
    # See StorageRequest.destination_kind for the full vocabulary.
    destination_kind: Optional[str] = None
    spl_transfer: Optional[SplTransfer] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PaymentOption":
        """Construct from a gateway payment_options dict, ignoring unknown keys."""
        return cls(
            chain=d["chain"],
            asset=d["asset"],
            amount=d["amount"],
            amount_raw=d["amount_raw"],
            treasury=d["treasury"],
            decimals=d["decimals"],
            token_contract=d.get("token_contract"),
            oracle_rate=d.get("oracle_rate"),
            destination_kind=d.get("destination_kind"),
            spl_transfer=SplTransfer.from_dict(d.get("spl_transfer")),
        )

@dataclass
class NukezManifest:
    """Locker provisioning result from provision_locker()."""
    locker_id: str
    receipt_id: str
    bucket: str
    path_prefix: str
    tags: List[str]
    cap_token: Optional[str] = None  # Capability token for file operations
    cap_expires_in_sec: Optional[int] = None  # Token expiration
    created_at: Optional[str] = None

@dataclass
class FileInfo:
    """File information from list_files()."""
    filename: str
    content_type: str
    size_bytes: int = 0
    content_hash: Optional[str] = None
    provider_ref: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    object_key: Optional[str] = None

@dataclass
class ViewerLink:
    """Portal link that can be returned by an autonomous agent."""
    url: str
    kind: str                    # "owner" or "file"
    locker_id: str
    receipt_id: str
    filename: Optional[str] = None
    download_url: Optional[str] = None
    expires_in_sec: Optional[int] = None
    includes_download_url: bool = False

@dataclass
class FileViewerInfo:
    """File metadata enriched with a viewer portal URL."""
    filename: str
    content_type: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    object_key: Optional[str] = None
    viewer_url: str = ""
    download_url: Optional[str] = None
    expires_in_sec: Optional[int] = None

@dataclass
class ViewerFileList:
    """Owner portal + file list suitable for agent handoff."""
    receipt_id: str
    locker_id: str
    owner_viewer_url: str
    files: List[FileViewerInfo]

@dataclass
class ViewerContainer:
    """Generic viewer container payload for MCP/agent handoff."""
    contract: str
    version: str
    request_type: str
    viewer_url: str
    input: Dict[str, Any]
    result: Dict[str, Any]
    render_hints: Dict[str, Any]
    auth_state: Dict[str, Any]
    errors: List[Dict[str, Any]]
    meta: Dict[str, Any]
    ui: Dict[str, Any]

@dataclass
class UploadResult:
    """Result from upload_bytes()."""
    upload_url: str
    size_bytes: int
    content_type: Optional[str] = None
    uploaded_at: int = 0

@dataclass
class DeleteResult:
    """Result from delete_file()."""
    filename: str
    deleted: bool
    deleted_at: Optional[str] = None

@dataclass
class DiscoveryDoc:
    """Discovery document from discover()."""
    api_version: str
    service: str
    description: str
    auth_modes: List[str]
    endpoints: Dict[str, str]
    features: List[str]
    status: str

@dataclass(frozen=True)
class ProviderInfo:
    """Storage provider metadata and capabilities.

    Accepted provider arg names: "gcs", "mongodb", "filecoin",
    "arweave", "firestore", "storj".  See PROVIDERS for the full registry.
    """
    id: str                                     # "gcs", "mongodb", etc.
    supports_signed_urls: bool = True
    supports_streaming: bool = True
    max_object_size: Optional[int] = None       # bytes, None = no limit
    immutable: bool = False                     # True for arweave
    content_addressed: bool = False             # True for arweave, filecoin


# Static registry mirroring gateway/app/core/storage_providers/
#
# Accepted provider arg names (pass as the ``provider`` kwarg to
# ``request_storage()``, ``get_provider_info()``, etc.):
#
#   "gcs"        — Google Cloud Storage
#   "mongodb"    — MongoDB
#   "filecoin"   — Filecoin
#   "arweave"    — Arweave
#   "firestore"  — Firestore
#   "storj"      — Storj
PROVIDERS: Dict[str, ProviderInfo] = {
    "gcs":       ProviderInfo("gcs"),
    "mongodb":   ProviderInfo("mongodb", supports_signed_urls=False, supports_streaming=False, max_object_size=16_777_216),
    "firestore": ProviderInfo("firestore", supports_signed_urls=False, supports_streaming=False, max_object_size=1_048_576),
    "storj":     ProviderInfo("storj"),
    "arweave":   ProviderInfo("arweave", immutable=True, content_addressed=True),
    "filecoin":  ProviderInfo("filecoin", content_addressed=True),
}


@dataclass
class ConfirmResult:
    """Result of confirming a file upload (server-side hash computation)."""
    filename: str
    content_hash: str          # sha256:... prefixed
    size_bytes: int
    confirmed: bool


@dataclass
class BatchConfirmResult:
    """Result of confirming multiple file uploads.

    Mirrors the gateway's confirm-batch response shape: ``results`` carries
    the successfully confirmed files only, while failures are reported
    separately. ``errors`` is the gateway's failure count and
    ``error_details`` carries the gateway's per-file error records verbatim
    (``None`` when every file confirmed). ``failed_count`` reports the same
    failure count as ``errors`` and is retained for backward compatibility.
    """
    results: List[ConfirmResult]
    confirmed_count: int
    failed_count: int
    errors: int = 0
    error_details: Optional[List[Dict[str, Any]]] = None


@dataclass
class AttestResult:
    """Result of triggering attestation on a locker."""
    receipt_id: str
    merkle_root: str           # sha256:... prefixed
    file_count: int
    att_code: Optional[int] = None
    status: str = "accepted"   # "complete" or "accepted"
    push_ok: bool = False      # True if Switchboard push succeeded
    tx_signature: Optional[str] = None
    switchboard_slot: Optional[int] = None


@dataclass
class BatchUploadResult:
    """Result of uploading multiple files concurrently."""
    uploaded: int
    failed: int
    total: int
    elapsed_sec: float
    errors: List[Tuple[str, str]]    # (filename, error_message)
    results: List[UploadResult]

@dataclass
class DownloadedFile:
    """ Result of downloading a single file. """
    filename: str
    content: bytes
    content_hash: str
    size_bytes: int
    verified: bool

@dataclass
class BatchDownloadResult:
    """Result of a batch download operation."""
    downloaded: int
    failed: int
    total: int
    elapsed_sec: float
    errors: List[Tuple[str, str]]    # (filename, error_message)
    files: List[DownloadedFile]


@dataclass
class OperatorResult:
    """Result from add_operator() / remove_operator()."""
    ok: bool
    operator_ids: List[str]  # current list of operator pubkeys


@dataclass
class LockerRecord:
    """
    Locker record from get_locker_record().

    Maps to the gateway's `locker_index` document (schema: lockers_v1).
    This is the cold-path ownership/identity record — distinct from
    get_files_manifest(), which returns the hot-path files document
    (schema: locker_files_v1).

    Use this to read owner_id / operator_ids and to verify the result
    of add_operator() / remove_operator() mutations.
    """
    locker_id: str
    owner_id: str
    operator_ids: List[str]
    receipt_id: str
    provider: str
    created_at: Optional[str] = None
    tags: Optional[List[str]] = None


@dataclass
class RecomputeVerifyResult:
    """Byte-level recompute-verify result from recompute_verify().

    This is the "expensive proof" path — the gateway re-downloads every file
    from storage and recomputes hashes, returning whether the freshly-computed
    digest matches the stored merkle root.

    Use when you need cryptographic proof that storage bytes still match the
    recorded hashes. For a fast structural check (no re-download), use
    verify_storage() or attest() instead — those trust the manifest's
    recorded content_hash. recompute_verify is the honest "prove the bytes
    still match" path; its latency scales with total locker bytes.

    The call is authenticated by the payer keypair: the SDK sends a signed
    envelope with ops=["locker:read"], so the client must be configured with
    a signing key (or an authorized operator key). The gateway performs the
    recompute entirely in memory and never modifies the stored attestation.

    Attributes:
        receipt_id: Receipt the verification was scoped to.
        match: True iff the recomputed digest matches the stored merkle root.
        computed: SHA256 the gateway recomputed by re-downloading files.
        stored: SHA256 the gateway had on record before the recompute.
        file_count: Number of files re-downloaded and hashed.
        recompute_ms: Wall-clock milliseconds the gateway spent on the recompute.
        details: Full response dict for any fields not surfaced as attributes.
    """
    receipt_id: str
    match: bool
    computed: str = ""
    stored: str = ""
    file_count: int = 0
    recompute_ms: int = 0
    details: Optional[Dict[str, Any]] = None
