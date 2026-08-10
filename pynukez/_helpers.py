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

from .errors import NukezError


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
