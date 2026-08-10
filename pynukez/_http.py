"""
Internal HTTP client for Nukez SDK.

Handles:
- Request execution with timeouts
- Error response parsing
- Conversion to agent-friendly exceptions

Provides both sync (HTTPClient) and shared error-handling functions
used by AsyncHTTPClient in _async_http.py.
"""

import logging
import httpx
from typing import Dict, Any, Optional

logger = logging.getLogger("pynukez.http")

from .errors import (
    NukezError,
    PaymentRequiredError,
    TransactionNotFoundError,
    AuthenticationError,
    NukezFileNotFoundError,
    URLExpiredError,
    RateLimitError,
    InvalidOperatorPubkeyError,
    OperatorIsOwnerError,
    OperatorNotAuthorizedError,
    OwnerOnlyError,
    OperatorNotFoundError,
    OperatorConflictError,
)
from .types import SplTransfer
from ._version import __version__

# Standard headers shared by sync and async clients. The User-Agent string
# derives from the package version so the two can never drift apart again.
STANDARD_HEADERS = {
    "User-Agent": f"nukez-sdk/{__version__}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}


# CAIP-2 network identifier to SDK-friendly name mapping.
# Used by the 402 parser and re-selection logic in both sync/async clients.
CAIP2_TO_FRIENDLY = {
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "solana-mainnet",
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": "solana-devnet",
    "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z": "solana-testnet",
    "eip155:143": "monad-mainnet",
    "eip155:10143": "monad-testnet",
}


def caip2_to_friendly(raw_network: str, fallback_hint: str = "") -> str:
    """Resolve a CAIP-2 network identifier to a friendly name.

    Args:
        raw_network: CAIP-2 string (e.g. "solana:5eykt4UsFv..." or "eip155:143")
                     or already-friendly name (e.g. "solana-mainnet").
        fallback_hint: Preferred friendly name if CAIP-2 is unknown (e.g. from
                       the caller's pay_network parameter).

    Returns:
        Friendly network string (e.g. "solana-mainnet", "monad-testnet").
    """
    known = CAIP2_TO_FRIENDLY.get(raw_network)
    if known:
        return known
    if raw_network.startswith("solana:"):
        return fallback_hint or "solana-mainnet"
    if raw_network.startswith("eip155:"):
        chain_id = raw_network.split(":")[-1]
        return "monad-mainnet" if chain_id == "143" else (fallback_hint or "monad-testnet")
    return raw_network


# ---------------------------------------------------------------------------
# Shared error-handling functions (duck-typed: works with both
# httpx.Response and requests.Response)
# ---------------------------------------------------------------------------

def parse_json_response(response, method: str, path: str) -> Dict[str, Any]:
    """
    Safely parse JSON response body with clear error messages.

    Args:
        response: HTTP response object (httpx.Response or requests.Response)
        method: HTTP method (for error messages)
        path: Request path (for error messages)

    Returns:
        Parsed JSON as dict, or empty dict if no content

    Raises:
        NukezError: If JSON parsing fails
    """
    if not response.content:
        return {}

    try:
        return response.json()
    except (ValueError, TypeError) as e:
        content_preview = response.content[:200].decode('utf-8', errors='replace')
        raise NukezError(
            f"Invalid JSON response from {method} {path}: {e}. "
            f"Response content: {content_preview}..."
        )


def parse_error_response(response) -> dict:
    """
    Safely parse error response body.

    Args:
        response: HTTP response object (httpx.Response or requests.Response)

    Returns:
        Parsed error dict, or empty dict on failure
    """
    try:
        if response.content:
            data = response.json()
            return data if isinstance(data, dict) else {}
    except (ValueError, TypeError) as e:
        logger.warning("Failed to parse response JSON: %s", e)
        logger.debug("Response content: %s", response.content[:500])
    return {}


def handle_error_response(response) -> None:
    """
    Convert HTTP error responses to appropriate Nukez exceptions.

    Maps HTTP status codes to Nukez exception types with
    all relevant details extracted from the response.

    Args:
        response: HTTP response object (httpx.Response or requests.Response)

    Raises:
        PaymentRequiredError, AuthenticationError, NukezFileNotFoundError,
        TransactionNotFoundError, URLExpiredError, RateLimitError, NukezError
    """
    error_details = parse_error_response(response)
    error_code = error_details.get("error_code", "")
    message = error_details.get("message", "")
    pubkey = error_details.get("pubkey", "")
    locker_id = error_details.get("locker_id", "")

    # --- Operator delegation errors (checked before generic handlers) ---

    # 400 operator errors
    if response.status_code == 400 and error_code == "INVALID_OPERATOR_PUBKEY":
        raise InvalidOperatorPubkeyError(pubkey=pubkey, locker_id=locker_id)
    if response.status_code == 400 and error_code in ("OPERATOR_IS_OWNER", "OPERATOR_IS_PAYER"):
        raise OperatorIsOwnerError(pubkey=pubkey, locker_id=locker_id, error_code=error_code)

    # 403 operator errors
    if response.status_code == 403 and error_code == "NOT_AUTHORIZED_OPERATOR":
        raise OperatorNotAuthorizedError(pubkey=pubkey, locker_id=locker_id)
    if response.status_code == 403 and error_code == "OWNER_ONLY":
        raise OwnerOnlyError(locker_id=locker_id)

    # 404 operator errors
    if response.status_code == 404 and error_code == "OPERATOR_NOT_FOUND":
        raise OperatorNotFoundError(pubkey=pubkey, locker_id=locker_id)

    # 409 operator errors
    if response.status_code == 409 and error_code in ("OPERATOR_ALREADY_EXISTS", "MAX_OPERATORS_REACHED"):
        raise OperatorConflictError(error_code=error_code, pubkey=pubkey, locker_id=locker_id)

    # 402 Payment Required - contains payment instructions (multi-chain)
    if response.status_code == 402:
        # ── x402 v2 format: accepts[] array with structured payment options ──
        accepts = error_details.get("accepts")
        if isinstance(accepts, list) and accepts:
            pay_req_id, pay_to_address, amount_sol, amount_lamports = "", "", 0.0, 0
            network, pay_asset = "devnet", "SOL"
            amount, amount_raw, token_address, token_decimals = "", 0, "", 0
            payment_options, quote_expires_at, terms = [], None, None
            quote_schema, idempotency_key, price_breakdown = None, None, None

            # Build payment_options from all accepts entries.
            #
            # CONTRACT: `entry` stays a plain dict of primitives (incl.
            # nested raw-dict spl_transfer). This is the "dict view" that
            # external consumers — notably nukez-mcp's preflight at
            # nukez_mcp/tools/_preflight.py — read via .get(). Do NOT
            # convert spl_transfer to an SplTransfer instance here; the
            # typed view lives on PaymentOption.spl_transfer (via
            # parsed_options) and StorageRequest.spl_transfer. Test
            # `test_payment_destination_kind.py::test_raw_payment_options_*`
            # pins this with an explicit isinstance(..., dict) assertion.
            for opt in accepts:
                extra = opt.get("extra", {})
                entry = {
                    "network": opt.get("network", ""),
                    "pay_to_address": opt.get("payTo", ""),
                    "pay_asset": extra.get("name", ""),
                    "amount": opt.get("amount", ""),
                    "decimals": extra.get("decimals", 0),
                    "human_amount": extra.get("human_amount", ""),
                    "asset_contract": opt.get("asset", ""),
                    # Destination disambiguation — additive, back-compat.
                    # Older gateways omit these fields; .get() yields None.
                    "destination_kind": extra.get("destination_kind"),
                    "spl_transfer": extra.get("spl_transfer"),  # raw dict, see CONTRACT above
                }
                payment_options.append(entry)

            # Select default payment option — prefer Solana, fall back to first
            selected = accepts[0]
            for opt in accepts:
                net = opt.get("network", "")
                if "solana" in net.lower():
                    selected = opt
                    break

            extra = selected.get("extra", {})
            raw_network = selected.get("network", "")

            # Parse network: x402 uses CAIP-2 identifiers like
            # "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" or "eip155:10143".
            # Must resolve to the correct friendly name — hardcoding devnet
            # breaks mainnet confirm_storage (gateway validates CAIP-2 match).
            network = caip2_to_friendly(raw_network)

            pay_to_address = selected.get("payTo", "")
            pay_asset = extra.get("name", "SOL")
            pay_req_id = extra.get("pay_req_id", "")
            amount = selected.get("amount", "")
            token_decimals = int(extra.get("decimals", 0) or 0)
            quote_expires_at = extra.get("quote_expires_at")
            idempotency_key = extra.get("idempotency_key")
            quote_schema = extra.get("quote_schema")
            terms = extra.get("terms")
            price_breakdown = extra.get("price_summary")

            asset_contract = selected.get("asset", "")
            is_native = asset_contract in ("native", "So11111111111111111111111111111111111111112")

            # Destination disambiguation from the selected option.
            destination_kind = extra.get("destination_kind")
            spl_transfer = SplTransfer.from_dict(extra.get("spl_transfer"))

            if "solana" in network:
                if token_decimals:
                    amount_sol = float(int(amount)) / (10 ** token_decimals)
                else:
                    amount_sol = float(int(amount)) / 1_000_000_000
                amount_lamports = int(amount)
                amount_raw = int(amount)
                # NOTE: token_address is intentionally NOT set for Solana SPL.
                # For SPL the mint lives on `spl_transfer.mint`. Backfilling
                # token_address from asset_contract here would silently change
                # semantics for existing callers that treat token_address as
                # EVM-only. If you need the mint, read spl_transfer.mint.
            else:
                amount_raw = int(amount)
                if not is_native:
                    token_address = asset_contract

            err = PaymentRequiredError(
                pay_req_id=pay_req_id,
                pay_to_address=pay_to_address,
                amount_sol=amount_sol,
                amount_lamports=amount_lamports,
                network=network,
                pay_asset=pay_asset,
                amount=str(amount),
                amount_raw=amount_raw,
                token_address=token_address,
                token_decimals=token_decimals,
                payment_options=payment_options,
                quote_expires_at=quote_expires_at,
                terms=terms,
                destination_kind=destination_kind,
                spl_transfer=spl_transfer,
            )
            if price_breakdown:
                err.details["price_breakdown"] = price_breakdown
            if quote_schema:
                err.details["quote_schema"] = quote_schema
            if idempotency_key:
                err.details["idempotency_key"] = idempotency_key
            raise err

        # ── Legacy flat format (pre-x402) ──
        pay_req_id = error_details.get("pay_req_id", "")
        pay_to_address = error_details.get("pay_to_address", "")
        amount_sol = error_details.get("amount_sol", 0)
        amount_lamports = error_details.get("amount_lamports", 0)
        network = error_details.get("network", "devnet")

        # EVM / multi-chain fields
        pay_asset = error_details.get("pay_asset", "SOL")
        amount = str(error_details.get("amount", ""))
        amount_raw = int(error_details.get("amount_raw", 0) or 0)
        token_address = str(error_details.get("token_address", ""))
        token_decimals = int(error_details.get("token_decimals", 0) or 0)

        # Fallback: check nested 'price' object
        if not pay_req_id or not pay_to_address:
            price = error_details.get("price", {})
            if not amount_sol and price:
                amount_sol = price.get("amount_sol", 0)
            if not amount_lamports and price:
                amount_lamports = price.get("amount_lamports", 0)

        # Fallback: check 'details' wrapper (some API versions)
        if not pay_req_id:
            details = error_details.get("details", {})
            pay_req_id = details.get("pay_req_id", pay_req_id)
            pay_to_address = details.get("pay_to_address", pay_to_address)
            amount_sol = details.get("amount_sol", amount_sol)

        # Calculate lamports from SOL if not provided (Solana only)
        if amount_sol and not amount_lamports:
            amount_lamports = int(float(amount_sol) * 1_000_000_000)

        # Quote lifecycle fields
        payment_options = error_details.get("payment_options")
        quote_expires_at = error_details.get("quote_expires_at")
        terms = error_details.get("terms")
        quote_schema = error_details.get("quote_schema")
        idempotency_key = error_details.get("idempotency_key")
        price_breakdown = error_details.get("price")

        # Debug logging if fields are missing
        if not pay_req_id or not pay_to_address:
            logger.warning("402 response missing expected fields")
            logger.debug("Response keys: %s", list(error_details.keys()))
            logger.debug("pay_req_id=%r, pay_to_address=%r", pay_req_id, pay_to_address)

        err = PaymentRequiredError(
            pay_req_id=str(pay_req_id) if pay_req_id else "",
            pay_to_address=str(pay_to_address) if pay_to_address else "",
            amount_sol=float(amount_sol) if amount_sol else 0.0,
            amount_lamports=int(amount_lamports) if amount_lamports else 0,
            network=str(network) if network else "devnet",
            pay_asset=str(pay_asset) if pay_asset else "SOL",
            amount=amount,
            amount_raw=amount_raw,
            token_address=token_address,
            token_decimals=token_decimals,
            payment_options=payment_options,
            quote_expires_at=quote_expires_at,
            terms=terms,
        )
        if price_breakdown:
            err.details["price_breakdown"] = price_breakdown
        if quote_schema:
            err.details["quote_schema"] = quote_schema
        if idempotency_key:
            err.details["idempotency_key"] = idempotency_key
        raise err

    # 401/403 Authentication errors
    if response.status_code in (401, 403):
        message = error_details.get("message", "Authentication failed")
        missing_headers = error_details.get("missing_headers", [])

        if "expired" in message.lower() or "url" in message.lower():
            raise URLExpiredError(operation="access")

        raise AuthenticationError(message=message, missing_headers=missing_headers)

    # 404 Not Found
    if response.status_code == 404:
        error_code = error_details.get("error_code", "").lower()
        message = error_details.get("message", "")

        if "file" in error_code or "file" in message.lower():
            filename = error_details.get("filename", "unknown")
            locker_id = error_details.get("locker_id", "")
            raise NukezFileNotFoundError(filename=filename, locker_id=locker_id)

        # Use response.url.path (not full URL) to avoid leaking query-string
        # credentials like receipt_id from confirm_url.
        fallback = getattr(response.url, "path", "resource")
        raise NukezError(
            f"Resource not found: {error_details.get('message', fallback)}",
            details=error_details
        )

    # 409 Conflict
    if response.status_code == 409:
        tx_sig = error_details.get("tx_sig", "")
        if tx_sig:
            raise TransactionNotFoundError(tx_sig=tx_sig)

        raise NukezError(
            f"Conflict: {error_details.get('message', 'Resource conflict')}",
            details=error_details
        )

    # 429 Rate Limited
    if response.status_code == 429:
        retry_after = int(response.headers.get("Retry-After", 60))
        raise RateLimitError(retry_after=retry_after)

    # 5xx Server Errors
    if response.status_code >= 500:
        error = NukezError(
            f"Server error ({response.status_code}). "
            "This may be temporary - try again in a few seconds.",
            details=error_details
        )
        error.retryable = True
        raise error

    # Generic error for other status codes
    message = error_details.get("message", f"HTTP {response.status_code}")
    raise NukezError(message, details=error_details)


# ---------------------------------------------------------------------------
# Sync HTTP client (httpx.Client backend)
# ---------------------------------------------------------------------------

class HTTPClient:
    """
    Internal sync HTTP client with Nukez-specific error handling.

    Converts HTTP error responses into appropriate Nukez exceptions
    with actionable error messages for agents.

    The default timeout (120s) matches Nukez's effective default — see
    Nukez.__init__'s ``self.timeout = timeout or 120``. Per-call overrides
    are supported by passing ``timeout=`` through ``post()`` / ``get()`` /
    ``put()`` / ``delete()`` (httpx honors per-request timeout overrides).
    """

    def __init__(self, base_url: str, timeout: int = 120):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=timeout,
            headers=STANDARD_HEADERS.copy(),
            follow_redirects=True,
        )

    def close(self):
        """Close the underlying HTTP client."""
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def get(
        self,
        path: str,
        params: dict = None,
        headers: dict = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Execute GET request. Extra kwargs (e.g. ``timeout=``) flow to httpx."""
        url = f"{self.base_url}{path}"

        try:
            response = self.client.get(
                url,
                params=params,
                headers=headers or {},
                **kwargs,
            )
        except httpx.TimeoutException:
            raise NukezError(f"Request timed out after {self.timeout}s: GET {path}")
        except httpx.HTTPError as e:
            raise NukezError(f"Request failed: GET {path}: {e}")

        if response.status_code >= 400:
            handle_error_response(response)

        return parse_json_response(response, "GET", path)

    def post(
        self,
        path: str,
        json: dict = None,
        headers: dict = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute POST request."""
        url = f"{self.base_url}{path}"

        try:
            response = self.client.post(
                url,
                json=json,
                headers=headers or {},
                **kwargs
            )
        except httpx.TimeoutException:
            raise NukezError(f"Request timed out after {self.timeout}s: POST {path}")
        except httpx.HTTPError as e:
            raise NukezError(f"Request failed: POST {path}: {e}")

        if response.status_code >= 400:
            handle_error_response(response)

        return parse_json_response(response, "POST", path)

    def delete(
        self,
        path: str,
        headers: dict = None
    ) -> Dict[str, Any]:
        """Execute DELETE request."""
        url = f"{self.base_url}{path}"

        try:
            response = self.client.delete(
                url,
                headers=headers or {},
            )
        except httpx.TimeoutException:
            raise NukezError(f"Request timed out after {self.timeout}s: DELETE {path}")
        except httpx.HTTPError as e:
            raise NukezError(f"Request failed: DELETE {path}: {e}")

        if response.status_code >= 400:
            handle_error_response(response)

        return parse_json_response(response, "DELETE", path)

    def put(
        self,
        path: str,
        json: dict = None,
        content: bytes = None,
        headers: dict = None
    ) -> Dict[str, Any]:
        """Execute PUT request."""
        url = f"{self.base_url}{path}"

        try:
            response = self.client.put(
                url,
                json=json,
                content=content,
                headers=headers or {},
            )
        except httpx.TimeoutException:
            raise NukezError(f"Request timed out after {self.timeout}s: PUT {path}")
        except httpx.HTTPError as e:
            raise NukezError(f"Request failed: PUT {path}: {e}")

        if response.status_code >= 400:
            handle_error_response(response)

        return parse_json_response(response, "PUT", path)
