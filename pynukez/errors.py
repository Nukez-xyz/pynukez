"""
Agent-friendly error classes for Nukez SDK.

Every error includes actionable guidance for autonomous agents.
Error messages tell agents exactly how to fix problems.

Design Philosophy:
- Errors are part of the API, not just failure modes
- Each error tells the agent what to do next
- The `retryable` flag indicates if retry might help
- Details dict provides structured error information
"""

from dataclasses import asdict
from typing import Optional

from .types import SplTransfer


class NukezError(Exception):
    """
    Base exception for Nukez SDK operations.

    All Nukez exceptions inherit from this class.

    Attributes:
        message: Human-readable error message
        details: Structured error information dict
        retryable: Whether retrying might succeed
    """
    
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.retryable = False
    
    def __str__(self):
        return self.message


class PaymentRequiredError(NukezError):
    """
    HTTP 402 Payment Required - contains payment instructions.

    This is NOT an error in the traditional sense - it's the expected response
    from request_storage(). The SDK converts this to a StorageRequest object.

    Multi-chain support (Phase 2):
      - Solana: amount_sol / amount_lamports populated, pay_asset="SOL"
      - EVM/Monad: amount / amount_raw / token_address / token_decimals populated

    If you see this error directly, use the payment fields to execute the transfer:

        try:
            client.http.post("/v1/storage/request", ...)
        except PaymentRequiredError as e:
            # e.pay_to_address - where to send payment
            # e.amount_sol - how much SOL to send (Solana)
            # e.amount - human-readable amount (EVM)
            # e.pay_req_id - save for confirm_storage()

    Attributes:
        pay_req_id: Payment request ID (save for confirm_storage)
        pay_to_address: Destination for the payment. Semantics depend on the
            asset — check ``destination_kind`` to be sure:
              * ``"wallet"``            — native SOL or EVM wallet pubkey.
                Send value directly.
              * ``"spl_token_account"`` — Solana SPL (USDC/USDT/WETH/BETA):
                this IS the treasury's SPL token account. Use it directly
                as the transferChecked destination; do NOT call
                ``get_associated_token_address`` on it. The mint, raw amount,
                and decimals live on ``spl_transfer``.
              * ``"evm_address"``       — EVM rails: a wallet/EOA. For ERC-20
                the transfer goes to the contract at ``token_address`` with
                ``pay_to_address`` as the recipient argument.
              * ``"unknown"`` / ``None`` — older gateway or unspecified;
                the SDK treats it as if absent (fall back to native wallet
                interpretation).
            The field name is preserved for backward compatibility —
            ``destination_kind`` is the authoritative semantic.
        amount_sol: Amount in SOL (Solana payments)
        amount_lamports: Amount in lamports (Solana payments)
        network: Payment network identifier
        pay_asset: Token symbol ("SOL", "USDC", "USDT", "MON", "WETH", "BETA")
        amount: Human-readable amount string (EVM payments)
        amount_raw: Atomic units as integer (EVM payments)
        token_address: ERC-20 contract address (EVM payments). NOT set for
            Solana SPL — read ``spl_transfer.mint`` instead.
        token_decimals: Token decimal places (EVM payments)
        destination_kind: See ``pay_to_address`` above. Optional / additive.
        spl_transfer: Self-contained SPL transferChecked description
            (``SplTransfer``: ``program_id``, ``destination_token_account``,
            ``mint``, ``amount_raw``, ``decimals``). Present only when
            ``destination_kind == "spl_token_account"``.
    """

    def __init__(
        self,
        pay_req_id: str,
        pay_to_address: str,
        amount_sol: float,
        amount_lamports: int,
        network: str,
        # EVM / multi-chain fields (Phase 2) — all optional for backward compat
        pay_asset: str = "SOL",
        amount: str = "",
        amount_raw: int = 0,
        token_address: str = "",
        token_decimals: int = 0,
        # Quote lifecycle fields
        payment_options: list = None,
        quote_expires_at: int = None,
        terms: dict = None,
        # Destination disambiguation — additive, back-compat (None defaults).
        destination_kind: Optional[str] = None,
        spl_transfer: Optional[SplTransfer] = None,
    ):
        is_evm = any(tag in (network or "") for tag in ("monad", "ethereum", "evm", "arbitrum"))
        if is_evm and amount:
            message = (
                f"Payment required: {amount} {pay_asset} to {pay_to_address} on {network}. "
                f"Use pay_req_id '{pay_req_id}' in confirm_storage() after payment."
            )
        else:
            message = (
                f"Payment required: {amount_sol} SOL to {pay_to_address}. "
                f"Use pay_req_id '{pay_req_id}' in confirm_storage() after payment."
            )
        details = {
            "pay_req_id": pay_req_id,
            "pay_to_address": pay_to_address,
            "amount_sol": amount_sol,
            "amount_lamports": amount_lamports,
            "network": network,
            "pay_asset": pay_asset,
        }
        if amount:
            details["amount"] = amount
        if amount_raw:
            details["amount_raw"] = amount_raw
        if token_address:
            details["token_address"] = token_address
        if token_decimals:
            details["token_decimals"] = token_decimals
        if payment_options:
            details["payment_options"] = payment_options
        if quote_expires_at is not None:
            details["quote_expires_at"] = quote_expires_at
        if terms:
            details["terms"] = terms
        # Destination disambiguation — store the dict form in `details` for
        # JSON-friendliness (matches the rest of the dict), and the typed
        # dataclass on the attribute for ergonomic access.
        if destination_kind:
            details["destination_kind"] = destination_kind
        if spl_transfer is not None:
            details["spl_transfer"] = asdict(spl_transfer)
        super().__init__(message, details=details)
        self.pay_req_id = pay_req_id
        self.pay_to_address = pay_to_address
        self.amount_sol = amount_sol
        self.amount_lamports = amount_lamports
        self.network = network
        self.pay_asset = pay_asset
        self.amount = amount
        self.amount_raw = amount_raw
        self.token_address = token_address
        self.token_decimals = token_decimals
        self.payment_options = payment_options
        self.quote_expires_at = quote_expires_at
        self.terms = terms
        self.destination_kind = destination_kind
        self.spl_transfer = spl_transfer
        self.retryable = False  # Need to pay first


class TransactionNotFoundError(NukezError):
    """
    Solana transaction not yet visible on-chain.
    
    The payment was sent but hasn't propagated to all RPC nodes yet.
    This is a transient condition - wait and retry.
    
    Recovery:
        1. Wait for suggested_delay seconds
        2. Retry confirm_storage() with the same parameters
        3. If still failing after 60 seconds, check transaction on Solana explorer
    
    Attributes:
        tx_sig: Transaction signature that wasn't found
        suggested_delay: Recommended wait time in seconds
    """
    
    def __init__(self, tx_sig: str, suggested_delay: int = 2):
        message = (
            f"Transaction {tx_sig[:16]}... not found on chain (may still be propagating). "
            f"Wait {suggested_delay} seconds and retry confirm_storage()."
        )
        super().__init__(
            message,
            details={"tx_sig": tx_sig, "suggested_delay": suggested_delay}
        )
        self.tx_sig = tx_sig
        self.suggested_delay = suggested_delay
        self.retryable = True


class AuthenticationError(NukezError):
    """
    Authentication failed - signed envelope rejected by server.
    
    Common causes:
    - Wrong keypair (must match the one used for payment)
    - Envelope expired (valid for 5 minutes after creation)
    - Invalid signature or envelope format
    - Mismatched receipt_id
    
    Recovery:
        1. Verify you're using the same keypair used for payment
        2. Try generating a fresh envelope (they expire after 5 minutes)
        3. Check that receipt_id matches a valid receipt
    
    Attributes:
        missing_headers: List of required headers that were missing (if any)
    """
    
    def __init__(self, message: str = None, missing_headers: list = None):
        default_message = (
            "Authentication failed. Verify you're using the correct keypair "
            "and that the signed envelope hasn't expired."
        )
        super().__init__(
            message or default_message,
            details={"missing_headers": missing_headers or []}
        )
        self.missing_headers = missing_headers or []
        self.retryable = False


class NukezFileNotFoundError(NukezError):
    """
    File doesn't exist in locker.
    
    The requested file was not found. This could mean:
    - File was never created
    - File was deleted
    - Filename is misspelled
    
    Recovery:
        1. Use list_files(receipt_id) to see what files exist
        2. Use create_file(receipt_id, filename) to create new files
        3. Check filename spelling matches exactly
    
    Attributes:
        filename: The file that wasn't found
        locker_id: The locker that was searched (if available)
    """
    
    def __init__(self, filename: str, locker_id: str = ""):
        message = (
            f"File not found: '{filename}'. "
            "Use list_files() to see existing files, or create_file() to create new ones."
        )
        super().__init__(
            message,
            details={"filename": filename, "locker_id": locker_id}
        )
        self.filename = filename
        self.locker_id = locker_id
        self.retryable = False


FileNotFound = NukezFileNotFoundError


class URLExpiredError(NukezError):
    """
    Signed URL has expired.
    
    Upload/download URLs have a TTL (default 30 minutes).
    After expiration, the URL returns HTTP 403 Forbidden.
    
    Recovery:
        1. Call get_file_urls(receipt_id, filename) to get fresh URLs
        2. Use the new URLs immediately
        3. Consider requesting longer TTL if operations take time
    
    Attributes:
        operation: What operation was attempted ("upload" or "download")
    """
    
    def __init__(self, operation: str = "upload"):
        message = (
            f"Signed {operation} URL has expired. "
            f"Call get_file_urls() to get a fresh {operation} URL."
        )
        super().__init__(
            message,
            details={"operation": operation}
        )
        self.operation = operation
        self.retryable = True  # Get fresh URL and retry


class NukezNotProvisionedError(NukezError):
    """
    Storage locker has not been provisioned yet.
    
    File operations require a provisioned locker. The receipt exists
    but provision_locker() hasn't been called yet.
    
    Recovery:
        1. Call provision_locker(receipt_id) to create the locker
        2. Then proceed with file operations
    
    Attributes:
        receipt_id: The receipt that needs provisioning
    """
    
    def __init__(self, receipt_id: str):
        message = (
            f"Locker not provisioned for receipt '{receipt_id}'. "
            "Call provision_locker(receipt_id) first."
        )
        super().__init__(
            message,
            details={"receipt_id": receipt_id}
        )
        self.receipt_id = receipt_id
        self.retryable = False


class RateLimitError(NukezError):
    """
    API rate limit exceeded.
    
    Too many requests in a short time period.
    
    Recovery:
        1. Wait for retry_after seconds
        2. Implement exponential backoff for subsequent requests
    
    Attributes:
        retry_after: Seconds to wait before retrying
    """
    
    def __init__(self, retry_after: int = 60):
        message = (
            f"Rate limit exceeded. Wait {retry_after} seconds before retrying."
        )
        super().__init__(
            message,
            details={"retry_after": retry_after}
        )
        self.retry_after = retry_after
        self.retryable = True


# ---------------------------------------------------------------------------
# Operator delegation errors
# ---------------------------------------------------------------------------

class OperatorError(NukezError):
    """
    Base for operator delegation errors.

    All operator-related failures inherit from this class,
    so callers can ``except OperatorError`` to catch any delegation issue.

    Attributes:
        error_code: Gateway error code (e.g. "OPERATOR_IS_OWNER")
        pubkey: Operator pubkey involved (if applicable)
        locker_id: Locker ID involved (if applicable)
    """

    def __init__(self, message: str, error_code: str, pubkey: str = "", locker_id: str = ""):
        super().__init__(message, details={
            "error_code": error_code,
            "pubkey": pubkey,
            "locker_id": locker_id,
        })
        self.error_code = error_code
        self.pubkey = pubkey
        self.locker_id = locker_id


class InvalidOperatorPubkeyError(OperatorError):
    """
    400 INVALID_OPERATOR_PUBKEY — pubkey is not valid base58 or wrong length.

    Recovery:
        Provide a valid Ed25519 public key encoded as base58 (32-44 chars).
    """

    def __init__(self, pubkey: str = "", locker_id: str = ""):
        super().__init__(
            f"Invalid operator pubkey: '{pubkey}'. Must be a valid base58 key (32-44 chars) or 0x EVM address (42 chars).",
            error_code="INVALID_OPERATOR_PUBKEY",
            pubkey=pubkey,
            locker_id=locker_id,
        )


class OperatorIsOwnerError(OperatorError):
    """
    400 OPERATOR_IS_OWNER / OPERATOR_IS_PAYER — cannot delegate to yourself.

    Recovery:
        Use a different keypair as the operator (Ed25519 or EVM).
    """

    def __init__(self, pubkey: str = "", locker_id: str = "", error_code: str = "OPERATOR_IS_OWNER"):
        super().__init__(
            f"Operator pubkey cannot be the same as the owner/payer: '{pubkey}'.",
            error_code=error_code,
            pubkey=pubkey,
            locker_id=locker_id,
        )


class OperatorNotAuthorizedError(OperatorError):
    """
    403 NOT_AUTHORIZED_OPERATOR — signer is not in the locker's operator list.

    Recovery:
        The locker owner must call add_operator() to authorize this key first.
    """

    def __init__(self, pubkey: str = "", locker_id: str = ""):
        super().__init__(
            f"Operator '{pubkey}' is not authorized for this locker. "
            "The owner must call add_operator() first.",
            error_code="NOT_AUTHORIZED_OPERATOR",
            pubkey=pubkey,
            locker_id=locker_id,
        )


class OwnerOnlyError(OperatorError):
    """
    403 OWNER_ONLY — only the locker owner can perform this action.

    Recovery:
        Use the owner keypair (the one that paid for the locker) to sign.
    """

    def __init__(self, locker_id: str = ""):
        super().__init__(
            "This action is restricted to the locker owner.",
            error_code="OWNER_ONLY",
            locker_id=locker_id,
        )


class OperatorNotFoundError(OperatorError):
    """
    404 OPERATOR_NOT_FOUND — trying to remove a pubkey that isn't an operator.

    Recovery:
        Check operator_ids returned by add_operator() or remove_operator().
    """

    def __init__(self, pubkey: str = "", locker_id: str = ""):
        super().__init__(
            f"Operator '{pubkey}' not found in this locker's operator list.",
            error_code="OPERATOR_NOT_FOUND",
            pubkey=pubkey,
            locker_id=locker_id,
        )


class ReceiptStateNotBoundError(NukezError):
    """
    Raised when a client needs per-receipt state (owner identity or sig_alg)
    that has not been primed.

    This is the cold-cache signal — the client has enough information to know
    that it doesn't have enough information.  Instead of silently guessing a
    signer or a delegation flag, the SDK raises this so callers can recover
    explicitly.

    Recovery:
        Call ``client.bind_receipt(receipt=...)`` (or
        ``client.bind_receipt(receipt_id=..., owner_identity=..., sig_alg=...)``)
        before retrying the operation.

    Attributes:
        receipt_id: The receipt whose state is missing.
        operation: The SDK method that triggered the lookup (for diagnostics).
    """

    def __init__(self, receipt_id: str, operation: str = ""):
        prefix = f"{operation}: " if operation else ""
        super().__init__(
            f"{prefix}no bound state for receipt '{receipt_id}'. "
            f"Call client.bind_receipt(receipt=...) or "
            f"client.bind_receipt(receipt_id='{receipt_id}', "
            f"owner_identity=..., sig_alg=...) to prime the caches.",
            details={"receipt_id": receipt_id, "operation": operation},
        )
        self.receipt_id = receipt_id
        self.operation = operation


class OperatorConflictError(OperatorError):
    """
    409 OPERATOR_ALREADY_EXISTS or MAX_OPERATORS_REACHED.

    Recovery:
        - OPERATOR_ALREADY_EXISTS: The pubkey is already an operator (no action needed).
        - MAX_OPERATORS_REACHED: Remove an existing operator before adding a new one (max 5).
    """

    def __init__(self, error_code: str, pubkey: str = "", locker_id: str = ""):
        if error_code == "MAX_OPERATORS_REACHED":
            message = "Maximum operators reached (5). Remove an existing operator first."
        else:
            message = f"Operator '{pubkey}' already exists on this locker."
        super().__init__(
            message,
            error_code=error_code,
            pubkey=pubkey,
            locker_id=locker_id,
        )
