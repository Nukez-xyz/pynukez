# pynukez/pynukez/_helpers.py
"""
Pure-computation helpers shared by sync ``Nukez`` and (upcoming) ``AsyncNukez``.

Every function here is stateless and has no dependency on ``Nukez`` instance state
so that both client flavours can call them without duplication.
"""

import json
import mimetypes
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlsplit

from .errors import AuthenticationError, NukezError


def _is_gateway_short_url(url: str) -> bool:
    """Return True if ``url`` looks like a pynukez gateway short URL.

    Gateway short URLs have the shape ``https://<gateway>/f/{token}``. They
    live behind the gateway's Cloud Run endpoint, which enforces a 32 MB
    request body limit at the infrastructure layer — so uploads for files
    larger than that must first resolve the 307 redirect to the underlying
    storage signed URL and PUT the body there directly, bypassing Cloud Run.

    The caller is ``upload_bytes`` / its async equivalent, which preflights
    a bodyless PUT when this returns True to extract the redirect target.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.path.startswith("/f/")


def _validated_confirm_url(
    confirm_url: str, expected_path: str, base_url: str
) -> Optional[str]:
    """Validate a server-supplied confirm URL before an envelope binds to it.

    The confirm URL arrives inside a create_file/create_files_batch response,
    and the confirm step signs a payer envelope over whatever path and query
    the URL carries. Trusting the URL blindly would let a poisoned create
    response obtain a payer-signed ``locker:write`` envelope for an arbitrary
    gateway path, so this helper only accepts a URL whose path is exactly
    ``expected_path`` and whose host is either empty (a relative URL) or
    exactly the host of the client's configured ``base_url``. For absolute
    URLs the scheme must match the base URL's scheme as well, so a matching
    host cannot be combined with a downgraded transport.

    Returns the URL unchanged when it passes every check, and ``None`` on any
    mismatch so the caller falls back to the client-constructed request — the
    client must never sign a path it did not choose.
    """
    try:
        parts = urlsplit(confirm_url)
    except Exception:
        return None
    if parts.path != expected_path:
        return None
    if not parts.netloc and not parts.scheme:
        # A relative URL cannot redirect the request to another host, and its
        # path has already been checked, so it is safe to sign.
        return confirm_url
    base = urlsplit(base_url)
    if parts.netloc.lower() != base.netloc.lower():
        return None
    if parts.scheme.lower() != base.scheme.lower():
        return None
    return confirm_url

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UPLOAD_STRING_MAX_BYTES = int(os.getenv("PYNUKEZ_UPLOAD_STRING_MAX_BYTES", "262144"))

_SANDBOX_PATH_BLOCKED_MARKERS = (
    "file arg rewrite paths are required",
    "proxied mounts are present",
    "proxied mount",
    "path rewrite",
    "sandbox_path_unavailable",
    "/mnt/data",
    "/mnt/user-data/uploads",
)

# ---------------------------------------------------------------------------
# Filename / content-type helpers
# ---------------------------------------------------------------------------

def _infer_content_type(filename: str, explicit: Optional[str] = None) -> str:
    """Infer MIME type from filename when explicit value is not provided."""
    if explicit:
        return explicit
    guessed = mimetypes.guess_type(filename)[0]
    return guessed or "application/octet-stream"


def _sanitize_filename(name: str) -> str:
    """Sanitize filename for gateway: replace spaces and disallowed chars."""
    s = name.replace(" ", "_")
    s = s.lstrip(".")
    s = re.sub(r"[^a-zA-Z0-9._/\-]", "_", s)
    if s and not re.match(r"[a-zA-Z0-9_]", s[0]):
        s = "_" + s
    return s or "file"


def _normalize_expected_sha256(value: Optional[str]) -> Optional[str]:
    raw = (value or "").strip().lower()
    if not raw:
        return None
    if raw.startswith("sha256:"):
        raw = raw[7:]
    if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
        raise NukezError(
            "expected_sha256 must be 64 hex chars (optionally prefixed with sha256:)"
        )
    return f"sha256:{raw}"


def _is_sandbox_path_unavailable_error(exc: Exception) -> bool:
    message = str(exc).lower()
    details_text = ""
    details = getattr(exc, "details", None)
    if details:
        try:
            details_text = json.dumps(details, sort_keys=True).lower()
        except Exception:
            details_text = str(details).lower()
    return any(
        marker in message or marker in details_text
        for marker in _SANDBOX_PATH_BLOCKED_MARKERS
    )

# ---------------------------------------------------------------------------
# Viewer helpers
# ---------------------------------------------------------------------------

def _normalize_viewer_base_url(viewer_base_url: str) -> str:
    """Normalize viewer host for URL construction."""
    base = (viewer_base_url or "https://nukez.xyz").strip()
    if not base:
        base = "https://nukez.xyz"
    return base.rstrip("/")


def _viewer_button_ui(
    label: str,
    url: str,
    variant: str = "nukez-neon",
) -> Dict[str, str]:
    """UI metadata for MCP/tool renderers."""
    return {
        "kind": "button",
        "label": label,
        "href": url,
        "variant": variant,
        "target": "_blank",
    }


def _viewer_renderer_contract() -> Dict[str, str]:
    """Stable renderer contract descriptor for MCP/frontends."""
    # Import constants lazily to avoid circular imports; they live in client.py
    # for now but we reference them by value to stay self-contained.
    return {
        "name": "nukez.mcp.viewer_link",
        "version": "1.0",
    }


def _viewer_container_contract() -> Dict[str, str]:
    """Stable container contract descriptor for generic viewer payloads."""
    return {
        "name": "nukez.viewer_container",
        "version": "1.0.0",
    }

# ---------------------------------------------------------------------------
# Block / renderable builders
# ---------------------------------------------------------------------------

def make_text_renderable(
    content: str,
    title: str = "Text",
    description: str = "",
    content_type: str = "text/plain",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a text renderable object for viewer_container payloads."""
    payload: Dict[str, Any] = {
        "type": "text",
        "title": title,
        "content": content,
        "content_type": content_type,
    }
    if description:
        payload["description"] = description
    if meta:
        payload["meta"] = meta
    return payload


def make_json_renderable(
    data: Any,
    title: str = "JSON",
    description: str = "",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a JSON renderable object for viewer_container payloads."""
    payload: Dict[str, Any] = {
        "type": "json",
        "title": title,
        "data": data,
        "content_type": "application/json",
    }
    if description:
        payload["description"] = description
    if meta:
        payload["meta"] = meta
    return payload


def make_pdf_renderable(
    url: str,
    title: str = "PDF",
    description: str = "",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a PDF renderable object for viewer_container payloads."""
    payload: Dict[str, Any] = {
        "type": "pdf",
        "title": title,
        "url": url,
        "content_type": "application/pdf",
    }
    if description:
        payload["description"] = description
    if meta:
        payload["meta"] = meta
    return payload


def make_image_renderable(
    url: str,
    title: str = "Image",
    description: str = "",
    alt: str = "",
    content_type: str = "image/*",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build an image renderable object for viewer_container payloads."""
    payload: Dict[str, Any] = {
        "type": "image",
        "title": title,
        "url": url,
        "content_type": content_type,
    }
    if description:
        payload["description"] = description
    if alt:
        payload["alt"] = alt
    if meta:
        payload["meta"] = meta
    return payload


def make_binary_renderable(
    hex_preview: str = "",
    title: str = "Binary",
    description: str = "",
    size_bytes: Optional[int] = None,
    content_type: str = "application/octet-stream",
    base64_data: str = "",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a binary renderable object for viewer_container payloads."""
    payload: Dict[str, Any] = {
        "type": "binary",
        "title": title,
        "content_type": content_type,
    }
    if description:
        payload["description"] = description
    if hex_preview:
        payload["hex_preview"] = hex_preview
    if base64_data:
        payload["base64"] = base64_data
    if size_bytes is not None:
        payload["size_bytes"] = size_bytes
    if meta:
        payload["meta"] = meta
    return payload


def make_header_block(
    title: str,
    subtitle: str = "",
    description: str = "",
    badge: str = "",
) -> Dict[str, Any]:
    """Build a generic header block for viewer_container blocks."""
    block: Dict[str, Any] = {"type": "header", "title": title}
    if subtitle:
        block["subtitle"] = subtitle
    if description:
        block["description"] = description
    if badge:
        block["badge"] = badge
    return block


def make_stats_block(items: List[Dict[str, Any]], title: str = "Stats") -> Dict[str, Any]:
    """Build a stats block."""
    return {"type": "stats", "title": title, "items": items}


def make_links_block(items: List[Dict[str, Any]], title: str = "Links") -> Dict[str, Any]:
    """Build a links block."""
    return {"type": "links", "title": title, "items": items}


def make_table_block(
    columns: List[Dict[str, Any]],
    rows: List[Dict[str, Any]],
    title: str = "Table",
) -> Dict[str, Any]:
    """Build a table block."""
    return {
        "type": "table",
        "title": title,
        "columns": columns,
        "rows": rows,
    }


def make_kv_block(items: List[Dict[str, Any]], title: str = "Details") -> Dict[str, Any]:
    """Build a key-value block."""
    return {"type": "kv", "title": title, "items": items}


def make_status_block(status: str, label: str = "Status", detail: str = "") -> Dict[str, Any]:
    """Build a status block."""
    block: Dict[str, Any] = {"type": "status", "status": status, "label": label}
    if detail:
        block["detail"] = detail
    return block


def make_proofs_block(items: List[Dict[str, Any]], title: str = "Proofs") -> Dict[str, Any]:
    """Build a proofs block."""
    return {"type": "proofs", "title": title, "items": items}


def make_json_block(data: Any, title: str = "Raw JSON") -> Dict[str, Any]:
    """Build a JSON block."""
    return {"type": "json", "title": title, "data": data}


def make_file_meta_block(
    filename: str,
    content_type: str = "",
    size_bytes: Optional[int] = None,
    updated_at: Optional[str] = None,
    sha256: str = "",
    extra: Optional[Dict[str, Any]] = None,
    title: str = "File Metadata",
) -> Dict[str, Any]:
    """Build a file metadata block."""
    items: List[Dict[str, Any]] = [{"key": "Filename", "value": filename}]
    if content_type:
        items.append({"key": "Content-Type", "value": content_type})
    if size_bytes is not None:
        items.append({"key": "Size Bytes", "value": size_bytes})
    if updated_at:
        items.append({"key": "Updated At", "value": updated_at})
    if sha256:
        items.append({"key": "SHA-256", "value": sha256})
    if extra:
        for key, value in extra.items():
            items.append({"key": str(key), "value": value})
    return {"type": "file_meta", "title": title, "items": items}


def make_file_preview_block(
    filename: str,
    content_type: str = "",
    url: str = "",
    text_content: str = "",
    json_data: Any = None,
    hex_preview: str = "",
    base64_data: str = "",
    size_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a file preview block.

    The frontend resolves rendering mode from filename/content_type and
    available fields so callers do not manage mime-specific rendering logic.
    """
    block: Dict[str, Any] = {
        "type": "file_preview",
        "filename": filename,
    }
    if content_type:
        block["content_type"] = content_type
    if url:
        block["url"] = url
    if text_content:
        block["text_content"] = text_content
    if json_data is not None:
        block["data"] = json_data
    if hex_preview:
        block["hex_preview"] = hex_preview
    if base64_data:
        block["base64"] = base64_data
    if size_bytes is not None:
        block["size_bytes"] = size_bytes
    return block


# ---------------------------------------------------------------------------
# Provider-neutral proof readers
# ---------------------------------------------------------------------------
#
# Newer gateways describe the on-chain anchor of a record with an "anchor"
# object and report separate "verification" facts. Older gateways send
# neither. Every reader below tolerates their absence, so that a response
# from an older gateway is read exactly as it was read before.

ANCHOR_CONFIRMED_FACT = "anchor_confirmed"
FACT_PASSED = "passed"
ANCHOR_TYPE_SWITCHBOARD = "switchboard_v2"


def _dict_or_none(value: Any) -> Optional[Dict[str, Any]]:
    """Return the value when it is a non-empty dict, and None otherwise."""
    return value if isinstance(value, dict) and value else None


def _verification_extras(response: Dict[str, Any], attestation: Dict[str, Any]) -> Dict[str, Any]:
    """Read the provider-neutral proof fields from a verify response.

    The gateway sends "anchor" and "verification" at the top level of the
    response, and it stores "proof_id" inside the attestation object. New
    records also carry the anchor inside the attestation object, so that copy
    is used when the top level has none. The historical "switchboard_tx" is
    read from the attestation object so that the result can fall back to it
    when the gateway sends no anchor object.

    The returned dict holds keyword arguments for ``VerificationResult``.
    Every value is None when the gateway is older and does not send the field.
    """
    response = response if isinstance(response, dict) else {}
    attestation = attestation if isinstance(attestation, dict) else {}
    anchor = _dict_or_none(response.get("anchor")) or _dict_or_none(attestation.get("anchor"))
    proof_id = attestation.get("proof_id")
    switchboard_tx = attestation.get("switchboard_tx")
    return {
        "anchor": anchor,
        "verification": _dict_or_none(response.get("verification")),
        "proof_id": str(proof_id) if proof_id else None,
        "switchboard_tx": str(switchboard_tx) if switchboard_tx else None,
    }


def _attest_anchor_fields(response: Dict[str, Any]) -> Dict[str, Any]:
    """Read the provider-neutral anchor fields from an attest response.

    The anchor object is taken from ``push_result.anchor``. Some gateway
    paths report a successful push without repeating the anchor object inside
    ``push_result``. In that case the anchor object at the top level of the
    response is used, but only when the push succeeded and that object names
    the same transaction as ``push_result.tx_signature``.

    The returned dict holds keyword arguments for ``AttestResult``. Every
    value except ``anchor_slot`` is None when the gateway is older and does
    not send the field. The slot falls back to ``push_result.slot``, because
    that value is the slot of the anchor transaction for every anchor type.
    """
    response = response if isinstance(response, dict) else {}
    push_result = response.get("push_result")
    push_result = push_result if isinstance(push_result, dict) else {}

    anchor = _dict_or_none(push_result.get("anchor"))
    if anchor is None and push_result.get("ok"):
        top_level = _dict_or_none(response.get("anchor"))
        if (
            top_level is not None
            and top_level.get("tx")
            and top_level.get("tx") == push_result.get("tx_signature")
        ):
            anchor = top_level

    anchor_type = push_result.get("anchor_type") or (anchor or {}).get("type")
    anchor_slot = (anchor or {}).get("slot")
    if anchor_slot is None:
        anchor_slot = push_result.get("slot")

    return {
        "anchor": anchor,
        "anchor_type": str(anchor_type) if anchor_type else None,
        "anchor_slot": anchor_slot,
        "verification": _dict_or_none(response.get("verification")),
    }


def _attest_outcome_from_verification(verification_result: Any) -> Dict[str, Any]:
    """Describe the anchor outcome for ``attest_async`` from a verify result.

    When the verify result carries the verification facts, ``push_ok`` is
    True only when the fact "anchor_confirmed" has the value "passed". A
    record whose merkle root was computed but not anchored therefore reports
    ``push_ok=False``. When the verify result carries an anchor object, the
    transaction, the anchor type, and the slot are taken from it. The
    historical ``switchboard_slot`` is filled only for a historical
    Switchboard anchor.

    When the verify result carries neither field, the gateway is older, and
    the returned values are exactly the ones that ``attest_async`` has always
    reported: ``push_ok`` follows the attestation code, and the transaction
    and the slot are None.

    The returned dict holds keyword arguments for ``AttestResult``.
    """
    facts = _dict_or_none(getattr(verification_result, "verification", None))
    anchor = _dict_or_none(getattr(verification_result, "anchor", None))
    legacy_push_ok = bool(getattr(verification_result, "att_code", ""))

    if facts is not None and ANCHOR_CONFIRMED_FACT in facts:
        push_ok = facts.get(ANCHOR_CONFIRMED_FACT) == FACT_PASSED
    else:
        push_ok = legacy_push_ok

    anchor_type = (anchor or {}).get("type")
    anchor_slot = (anchor or {}).get("slot")
    return {
        "push_ok": push_ok,
        "tx_signature": (anchor or {}).get("tx") or None,
        "switchboard_slot": anchor_slot if anchor_type == ANCHOR_TYPE_SWITCHBOARD else None,
        "anchor": anchor,
        "anchor_type": str(anchor_type) if anchor_type else None,
        "anchor_slot": anchor_slot,
        "verification": facts,
    }


# ---------------------------------------------------------------------------
# Payer-signed confirm intent
# ---------------------------------------------------------------------------

CONFIRM_INTENT_PREFIX = "nukez/confirm/v1"


def confirm_intent_message(pay_req_id: str, tx: str, operator_pubkey: Optional[str] = None) -> bytes:
    """Return the exact bytes that a payer signs to authorize a confirm.

    The message is the UTF-8 encoding of four parts joined by the vertical
    bar character: the text "nukez/confirm/v1", the pay request id, the
    transaction signature or hash, and the operator public key. A single
    hyphen stands in for the operator when no operator is being bound.

    A Solana payer signs these bytes with Ed25519 and sends the signature in
    base58. An EVM payer signs these bytes with EIP-191 personal_sign and
    sends the signature as hex with the "0x" prefix.
    """
    operator = (operator_pubkey or "").strip() or "-"
    return f"{CONFIRM_INTENT_PREFIX}|{pay_req_id}|{str(tx).strip()}|{operator}".encode("utf-8")


def _sign_confirm_intent(
    *,
    pay_req_id: str,
    tx_sig: Any,
    operator_pubkey: Optional[str],
    signers: List[Any],
) -> Optional[str]:
    """Sign the confirm intent with a key that could belong to the payer.

    The client does not know for certain who paid, so this function applies
    two rules. The key must use the signature algorithm of the payment chain,
    which is secp256k1 for an EVM transaction hash that starts with "0x" and
    Ed25519 otherwise. The key must not be the operator that is being bound,
    because the gateway refuses an operator that is also the payer.

    The function returns None when no operator is being bound, when no
    suitable key is held, or when signing fails for any reason. It never
    raises, so a confirm is never refused because signing was unavailable.
    """
    try:
        operator = (operator_pubkey or "").strip()
        tx = str(tx_sig or "").strip()
        if not operator or not tx or not pay_req_id:
            return None
        is_evm = tx.startswith("0x")
        wanted_alg = "secp256k1" if is_evm else "ed25519"
        message = confirm_intent_message(pay_req_id, tx, operator)
        seen: List[int] = []
        for signer in signers:
            if signer is None or id(signer) in seen:
                continue
            seen.append(id(signer))
            if getattr(signer, "sig_alg", None) != wanted_alg:
                continue
            identity = getattr(signer, "identity", None)
            if not isinstance(identity, str) or not identity:
                continue
            same_key = identity.lower() == operator.lower() if is_evm else identity == operator
            if same_key:
                continue
            signature = signer.sign(message)
            if isinstance(signature, str) and signature:
                return signature
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Newer error codes from POST /v1/storage/confirm
# ---------------------------------------------------------------------------

# A 402 response with one of these codes is permanent, so confirm_storage()
# must not retry it.
CONFIRM_PERMANENT_402_CODES = ("PAYMENT_OUTSIDE_QUOTE_WINDOW",)

_CONFIRM_GUIDANCE = {
    "PAYMENT_ALREADY_ALLOCATED": (
        "This transaction has already paid for a different pay request. Each "
        "payment buys one request, so make a new payment for this request. "
        "Retrying the same pay request with its own transaction is still safe."
    ),
    "PAYMENT_OPTION_NOT_IN_QUOTE": (
        "The quote did not offer this asset on this chain. Request a new "
        "quote, or pay with one of the options that the quote lists."
    ),
    "CONFIRM_INTENT_REQUIRED": (
        "Binding an operator requires the payer's signature over the confirm "
        "intent. Sign the exact text in details['sign_this'] with the payer "
        "key and pass the result as payer_signature."
    ),
    "CONFIRM_INTENT_INVALID": (
        "The payer_signature did not verify against the payer of this "
        "transaction. Sign the exact text in details['sign_this'] with the "
        "payer key and pass the result as payer_signature."
    ),
}


def _confirm_error_from_response(status_code: int, body: Any) -> Optional[NukezError]:
    """Return the SDK error for one of the newer confirm error codes.

    The function returns None for every other response, so that the caller
    keeps its existing handling. The two confirm intent codes arrive with
    HTTP 401 and map to ``AuthenticationError``, which is the class the SDK
    already uses for a rejected signature. The other codes have no dedicated
    class and map to ``NukezError``. Every returned error is marked as not
    retryable and carries the full response body in ``details``.
    """
    if not isinstance(body, dict):
        return None
    nested = body.get("detail") if isinstance(body.get("detail"), dict) else {}
    raw_code = (
        body.get("error_code")
        or nested.get("error_code")
        or body.get("error")
        or nested.get("error")
        or ""
    )
    error_code = str(raw_code).strip().upper()
    guidance = _CONFIRM_GUIDANCE.get(error_code)
    if guidance is None:
        return None

    gateway_message = str(body.get("message") or nested.get("message") or "").strip()
    message = f"Payment confirmation failed ({error_code}): {gateway_message} {guidance}".replace("  ", " ")

    details: Dict[str, Any] = dict(body)
    details["error_code"] = error_code
    details["status_code"] = status_code
    inner = body.get("details") if isinstance(body.get("details"), dict) else {}
    sign_this = inner.get("sign_this") or nested.get("sign_this") or body.get("sign_this")
    if sign_this:
        details["sign_this"] = sign_this

    if error_code in ("CONFIRM_INTENT_REQUIRED", "CONFIRM_INTENT_INVALID"):
        error: NukezError = AuthenticationError(message=message)
        error.details.update(details)
    else:
        error = NukezError(message, details=details)
    error.retryable = False
    return error
