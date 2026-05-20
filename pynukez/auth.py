"""
Authentication utilities for Nukez SDK.

Extracted from nukez GenericAgentTools - proven patterns.
Critical implementation details preserved exactly as tested.

CRITICAL: The signed envelope structure MUST match server expectations exactly.
Any deviation will cause authentication failures.
"""

import hashlib
import json
import os
import time
import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union

try:
    from nacl.signing import SigningKey
    HAS_NACL = True
except ImportError:
    HAS_NACL = False
    SigningKey = None

try:
    import base58
    HAS_BASE58 = True
except ImportError:
    HAS_BASE58 = False
    base58 = None

from .errors import NukezError
from .signer import _EVM_ADDR_RE


@dataclass
class _ReceiptState:
    """Per-receipt signer/owner state primed by confirm_storage/provision_locker/bind_receipt.

    Collapses the old ``_owner_cache`` and ``_sig_alg_cache`` dicts into a single
    record so partial-state bugs become impossible by construction.

    Attributes:
        owner_identity: Public identifier of the locker owner (0x EVM or base58 Ed25519).
        sig_alg: Signature algorithm of the owner — ``"secp256k1"`` or ``"ed25519"``.
    """
    owner_identity: str
    sig_alg: str


def infer_sig_alg(identity: str) -> Optional[str]:
    """Infer the signature algorithm from a public identity string.

    Mirrors the gateway's own inference in ``identity.py`` so the SDK and
    server always agree on the mapping:

      * ``0x`` + 40 hex chars → ``"secp256k1"``
      * base58 that decodes to exactly 32 bytes → ``"ed25519"``
      * anything else → ``None`` (caller must raise or prompt for explicit value)

    This helper is deliberately pure: it takes a string, returns a string
    (or ``None``), touches no network, and holds no state.  Use it as the
    cold-start fallback when a receipt's ``sig_alg`` was not supplied.
    """
    if not identity:
        return None
    # 0x-prefix check is anchored first — adversarial 42-char no-prefix strings
    # that happen to decode as 32-byte base58 must not be mis-classified.
    if _EVM_ADDR_RE.match(identity):
        return "secp256k1"
    if HAS_BASE58:
        try:
            decoded = base58.b58decode(identity)
            if len(decoded) == 32:
                return "ed25519"
        except Exception:
            pass
    return None


@dataclass
class UnsignedEnvelope:
    """Result from build_unsigned_envelope().

    Contains everything needed for an external signer (relay, HSM, etc.)
    to produce a signature and complete the envelope.
    """
    envelope: Dict[str, Union[str, int, List[str]]]  # raw envelope dict
    envelope_json: str        # canonical JSON (what must be signed)
    envelope_b64: str         # base64url-encoded envelope (for X-Nukez-Envelope header)
    canonical_body: Optional[str]
    locker_id: str


@dataclass
class SignedEnvelope:
    """Result from build_signed_envelope()."""
    headers: Dict[str, str]  # X-Nukez-Envelope, X-Nukez-Signature
    canonical_body: Optional[str]
    locker_id: str

    # Include what agent needs to know
    usage: str = "Add headers to your HTTP request"


class Keypair:
    """Ed25519 keypair management for Solana-compatible signing."""
    
    def __init__(self, keypair_path: Union[str, Path]):
        """
        Load keypair from Solana CLI format JSON file.
        
        Args:
            keypair_path: Path to keypair JSON file (e.g., ~/.config/solana/id.json)
            
        Raises:
            ImportError: If pynacl or base58 not installed
            NukezError: If keypair file not found or invalid
        """
        if not HAS_NACL:
            raise ImportError(
                "PyNaCl required for signing. "
                "Install with: pip install pynacl"
            )
        if not HAS_BASE58:
            raise ImportError(
                "base58 required for Solana address encoding. "
                "Install with: pip install base58"
            )
        
        self.keypair_path = Path(keypair_path).expanduser()
        
        if not self.keypair_path.exists():
            raise NukezError(
                f"Keypair file not found: {self.keypair_path}. "
                f"Create one with: solana-keygen new --outfile {self.keypair_path}"
            )
        
        # Load Solana keypair format (JSON array of 64 bytes)
        try:
            with open(self.keypair_path, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, dict) and ("private_key" in data or "address" in data):
                raise NukezError(
                    f"EVM key file detected at {self.keypair_path}. "
                    f"Keypair() is for Ed25519 (Solana) keys only. "
                    f"For EVM/Monad keys, use evm_private_key_path= instead of keypair_path= "
                    f"when initializing Nukez/AsyncNukez, or use EVMSigner.from_file() directly."
                )
            elif isinstance(data, list) and len(data) >= 32:
                # Take first 32 bytes as seed (standard Solana format)
                seed = bytes(data[:32])
                self.signing_key = SigningKey(seed)
            else:
                raise ValueError("Invalid keypair format - expected JSON array of 64 bytes")
                
        except json.JSONDecodeError as e:
            raise NukezError(f"Invalid JSON in keypair file {self.keypair_path}: {e}")
        except Exception as e:
            raise NukezError(f"Failed to load keypair from {self.keypair_path}: {e}")
    
    @property
    def pubkey_b58(self) -> str:
        """Get public key as Base58 string (Solana address format)."""
        return base58.b58encode(self.signing_key.verify_key.encode()).decode()
    
    @property
    def identity(self) -> str:
        """Canonical public identifier (base58 for Ed25519).

        Satisfies the Signer protocol.
        """
        return self.pubkey_b58

    @property
    def sig_alg(self) -> str:
        """Signature algorithm. Satisfies the Signer protocol."""
        return "ed25519"

    def sign(self, message: bytes) -> str:
        """Sign and return base58-encoded signature. Satisfies the Signer protocol."""
        return self.sign_message(message)

    def sign_message(self, message: bytes) -> str:
        """
        Sign message bytes and return Base58-encoded signature.

        Args:
            message: Bytes to sign

        Returns:
            Base58-encoded signature string
        """
        signature = self.signing_key.sign(message).signature
        return base58.b58encode(signature).decode()


def compute_locker_id(receipt_id: str) -> str:
    """
    Compute locker_id from receipt_id using the canonical pattern.
    
    This is the EXACT formula used by the Nukez backend.
    DO NOT MODIFY without matching server-side changes.
    
    Args:
        receipt_id: Receipt ID from confirm_storage()
        
    Returns:
        Locker ID string in format "locker_" + 12 hex chars
        
    Example:
        >>> compute_locker_id("receipt_abc123")
        'locker_7f3d2a1b9c8e'
        
    Note:
        This is deterministic - same receipt_id always produces same locker_id.
        The mapping is ONE-WAY (cannot reverse locker_id back to receipt_id).
    """
    return "locker_" + hashlib.sha256(receipt_id.encode()).hexdigest()[:12]


def build_signed_envelope(
    signer: "Signer" = None,
    receipt_id: str = "",
    method: str = "",
    path: str = "",
    query: str = "",
    ops: List[str] = None,
    body: Optional[Union[Dict, str]] = None,
    ttl_seconds: int = 300,
    delegating: bool = False,
    # Deprecated — use signer
    keypair: "Keypair" = None,
) -> SignedEnvelope:
    """
    Build signed envelope for Nukez API authentication.

    CRITICAL: This implementation MUST match the server's expectations exactly.
    The envelope structure, field names, and canonicalization are all verified
    server-side. Any deviation causes authentication failure.

    Args:
        signer: Signer instance (Keypair or EVMSigner) for signing.
        receipt_id: Receipt ID from confirm_storage()
        method: HTTP method (GET, POST, PUT, DELETE)
        path: API path (e.g., "/v1/lockers/{id}/files")
        query: Raw request query string (e.g. "receipt_id=abc&sync=true").
            Required for endpoints whose arguments live in the query string
            (e.g. POST /v1/storage/attest) — the gateway binds the envelope
            to it. Omit (default "") for body-only endpoints.
        ops: Required operations (e.g., ["locker:write"])
        body: Request body dict for POST/PUT (will be canonicalized)
        ttl_seconds: Envelope validity duration (default 5 minutes)
        delegating: If True, include signer identity in the envelope
            (operator acting on behalf of owner). If False (default),
            omit signer field (owner-direct operation).
        keypair: DEPRECATED — use signer parameter instead.

    Returns:
        SignedEnvelope with headers and canonical body

    Raises:
        NukezError: If no signer provided, or body missing for POST/PUT

    Critical implementation notes (DO NOT CHANGE):
        1. Envelope MUST include "v": 1 version field
        2. Field name is "receipt_id" not "sub"
        3. Field name is "body_sha256" not "body_hash"
        4. Nonce uses os.urandom(16).hex() for cryptographic randomness
        5. JSON canonicalization: separators=(',', ':'), sort_keys=True
        6. Envelope is Base64URL-encoded with padding stripped
    """
    # Backward compat: accept keypair as positional or keyword
    if signer is None and keypair is not None:
        signer = keypair
    if signer is None:
        raise NukezError("build_signed_envelope requires a signer (or keypair)")

    if ops is None:
        ops = []

    # Compute locker_id from receipt_id
    locker_id = compute_locker_id(receipt_id)

    # Handle body - CRITICAL for signature verification
    canonical_body = None
    body_sha256 = None

    if body is not None:
        # Support both dict and string inputs (fallback tolerance for agents)
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                raise NukezError(
                    "build_signed_envelope: 'body' must be valid JSON if provided as string. "
                    f"Received: {body[:100]}..."
                )

        # Canonical JSON - EXACT pattern from proven nukez implementation
        # This MUST match: json.dumps(body, separators=(',', ':'), sort_keys=True)
        canonical_body = json.dumps(body, separators=(',', ':'), sort_keys=True)
        body_sha256 = hashlib.sha256(canonical_body.encode('utf-8')).hexdigest()

    # POST/PUT MUST have body for signature verification
    if method.upper() in ('POST', 'PUT') and canonical_body is None:
        raise NukezError(
            f"build_signed_envelope: 'body' parameter is REQUIRED for {method} requests. "
            "The server verifies the signature covers the request body. "
            "Pass body={} for empty body if needed."
        )

    # For GET/DELETE, compute hash of empty string
    if method.upper() in ('GET', 'DELETE'):
        body_sha256 = hashlib.sha256(b'').hexdigest()

    # Current timestamp
    now = int(time.time())

    # Build envelope - EXACT structure from proven implementation
    # WARNING: Field names and structure are verified server-side
    envelope = {
        "v": 1,                              # Version field - REQUIRED
        "locker_id": locker_id,
        "receipt_id": receipt_id,            # NOT "sub"
        "nonce": os.urandom(16).hex(),       # Cryptographic randomness
        "iat": now,                          # Issued at
        "exp": now + ttl_seconds,            # Expiration
        "ops": ops,                          # Required operations
        "method": method.upper(),
        "path": path,
        "body_sha256": body_sha256,          # NOT "body_hash"
        # Always set sig_alg. Gateway falls back to signature format inference
        # for old SDKs, but we always emit it explicitly for clarity.
        "sig_alg": signer.sig_alg,
    }

    # Only include signer field when delegating (operator != owner).
    # The presence of "signer" is a semantic signal — it means delegation.
    # Omitting it for owner-direct envelopes avoids a needless OwnerIdentity
    # comparison on every request in the gateway.
    if delegating:
        envelope["signer"] = signer.identity

    # Bind the envelope to the request query string when present. The gateway
    # canonicalizes (parse_qsl -> sort -> urlencode) both sides and rejects a
    # mismatch (ENVELOPE_QUERY_MISMATCH). Endpoints that carry their arguments
    # in the query string -- notably POST /v1/storage/attest -- require this;
    # body-only endpoints omit it (the gateway reads an absent query as "").
    if query:
        envelope["query"] = query

    # Canonicalize envelope for signing - MUST use exact same pattern
    envelope_json = json.dumps(envelope, separators=(',', ':'), sort_keys=True)

    # Sign the canonical envelope bytes
    signature = signer.sign(envelope_json.encode('utf-8'))

    # Encode envelope for header - Base64URL without padding
    envelope_b64 = base64.urlsafe_b64encode(
        envelope_json.encode('utf-8')
    ).decode().rstrip('=')

    # Build headers
    headers = {
        "X-Nukez-Envelope": envelope_b64,
        "X-Nukez-Signature": signature
    }

    return SignedEnvelope(
        headers=headers,
        canonical_body=canonical_body,
        locker_id=locker_id
    )


def build_unsigned_envelope(
    signer_identity: str,
    sig_alg: str,
    receipt_id: str = "",
    method: str = "",
    path: str = "",
    query: str = "",
    ops: List[str] = None,
    body: Optional[Union[Dict, str]] = None,
    ttl_seconds: int = 300,
    delegating: bool = False,
) -> UnsignedEnvelope:
    """
    Build an unsigned envelope for external/relay signing.

    Constructs the same canonical envelope as build_signed_envelope but
    does NOT sign it.  The caller is responsible for obtaining a signature
    (via a relay, HSM, or multi-party protocol) and attaching it with
    attach_signature().

    Args:
        signer_identity: Public identifier of the signer (base58 pubkey
            or 0x address).
        sig_alg: Signature algorithm ("ed25519" or "secp256k1").
        receipt_id: Receipt ID from confirm_storage().
        method: HTTP method (GET, POST, PUT, DELETE).
        path: API path (e.g., "/v1/lockers/{id}/files").
        query: Raw request query string (e.g. "receipt_id=abc&sync=true").
            Bound by the gateway for query-arg endpoints; omit for
            body-only endpoints.
        ops: Required operations (e.g., ["locker:write"]).
        body: Request body dict for POST/PUT (will be canonicalized).
        ttl_seconds: Envelope validity duration (default 5 minutes).
        delegating: If True, include signer identity in the envelope
            (operator acting on behalf of owner).

    Returns:
        UnsignedEnvelope with envelope dict, canonical JSON, base64url
        encoding, canonical body, and locker_id.

    Raises:
        NukezError: If body missing for POST/PUT
    """
    if ops is None:
        ops = []

    locker_id = compute_locker_id(receipt_id)

    # Handle body — same canonicalization as build_signed_envelope
    canonical_body = None
    body_sha256 = None

    if body is not None:
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                raise NukezError(
                    "build_unsigned_envelope: 'body' must be valid JSON if provided as string. "
                    f"Received: {body[:100]}..."
                )
        canonical_body = json.dumps(body, separators=(',', ':'), sort_keys=True)
        body_sha256 = hashlib.sha256(canonical_body.encode('utf-8')).hexdigest()

    if method.upper() in ('POST', 'PUT') and canonical_body is None:
        raise NukezError(
            f"build_unsigned_envelope: 'body' parameter is REQUIRED for {method} requests. "
            "The server verifies the signature covers the request body. "
            "Pass body={} for empty body if needed."
        )

    if method.upper() in ('GET', 'DELETE'):
        body_sha256 = hashlib.sha256(b'').hexdigest()

    now = int(time.time())

    envelope = {
        "v": 1,
        "locker_id": locker_id,
        "receipt_id": receipt_id,
        "nonce": os.urandom(16).hex(),
        "iat": now,
        "exp": now + ttl_seconds,
        "ops": ops,
        "method": method.upper(),
        "path": path,
        "body_sha256": body_sha256,
        "sig_alg": sig_alg,
    }

    if delegating:
        envelope["signer"] = signer_identity

    # See build_signed_envelope: bind the query string when present.
    if query:
        envelope["query"] = query

    envelope_json = json.dumps(envelope, separators=(',', ':'), sort_keys=True)
    envelope_b64 = base64.urlsafe_b64encode(
        envelope_json.encode('utf-8')
    ).decode().rstrip('=')

    return UnsignedEnvelope(
        envelope=envelope,
        envelope_json=envelope_json,
        envelope_b64=envelope_b64,
        canonical_body=canonical_body,
        locker_id=locker_id,
    )


def attach_signature(unsigned: UnsignedEnvelope, signature: str) -> SignedEnvelope:
    """
    Attach a signature to an unsigned envelope, producing a SignedEnvelope.

    Args:
        unsigned: UnsignedEnvelope from build_unsigned_envelope().
        signature: Transport-ready encoded signature (base58 for ed25519,
            0x-hex for secp256k1).

    Returns:
        SignedEnvelope with headers ready for HTTP request.
    """
    headers = {
        "X-Nukez-Envelope": unsigned.envelope_b64,
        "X-Nukez-Signature": signature,
    }

    return SignedEnvelope(
        headers=headers,
        canonical_body=unsigned.canonical_body,
        locker_id=unsigned.locker_id,
    )
