"""
Nukez - Agent-native Python SDK for Nukez storage.

Autonomous AI storage with cryptographic verification.

This SDK is designed for autonomous AI agents that need persistent storage
with cryptographic receipts. Every function is tool-shaped and stateless —
perfect for LLM tool-calling patterns.

PyNukez does not execute blockchain payments. request_storage() returns
payment instructions (address, amount, chain, asset). You complete the
transfer with your own wallet, CLI, signer, or custody workflow, then submit
the resulting transaction signature to confirm_storage().

Quick Start (sync):
    from pynukez import Nukez

    client = Nukez(keypair_path=KEYPAIR_PATH)
    request = client.request_storage(units=1)
    # ... complete transfer via preferred method ...
    receipt = client.confirm_storage(request.pay_req_id, tx_sig=<your_tx_signature>)

Quick Start (async):
    from pynukez import AsyncNukez

    async with AsyncNukez(keypair_path=KEYPAIR_PATH) as client:
        request = await client.request_storage(units=1)
        # ... complete transfer via preferred method ...
        receipt = await client.confirm_storage(request.pay_req_id, tx_sig=<your_tx_signature>)
"""

# Client classes
from .client import Nukez
from ._async_client import AsyncNukez

# Signer protocol and implementations
from .signer import Signer, EVMSigner

# Data models and types
from .types import (
    # Payment flow types
    StorageRequest,
    Receipt,
    PaymentOption,

    # File operation types
    NukezManifest,
    FileUrls,
    FileInfo,
    ViewerLink,
    FileViewerInfo,
    ViewerFileList,
    ViewerContainer,
    UploadResult,
    DeleteResult,

    # Utility types
    VerificationResult,
    RecomputeVerifyResult,
    ReceiptHashVerification,
    PriceInfo,
    DiscoveryDoc,

    # Provider awareness
    ProviderInfo,
    PROVIDERS,

    # Batch and Attest types
    ConfirmResult,
    BatchConfirmResult,
    AttestResult,
    BatchUploadResult,

    # Operator delegation
    OperatorResult,

    # Locker record (ownership / operator_ids)
    LockerRecord,
)

# Error classes with agent-friendly messages
from .errors import (
    NukezError,                   # Base exception
    PaymentRequiredError,         # HTTP 402 - contains payment instructions
    TransactionNotFoundError,     # tx not yet confirmed (retryable)
    AuthenticationError,          # Signature verification failed
    NukezFileNotFoundError,       # File doesn't exist
    FileNotFound,                 # Alias for NukezFileNotFoundError
    URLExpiredError,              # Signed URL has expired (retryable)
    NukezNotProvisionedError,     # Locker needs provisioning
    RateLimitError,               # API rate limit hit
    # Operator delegation errors
    OperatorError,                # Base for all operator errors
    InvalidOperatorPubkeyError,   # 400 bad pubkey format
    OperatorIsOwnerError,         # 400 cannot delegate to self
    OperatorNotAuthorizedError,   # 403 signer not in operator list
    OwnerOnlyError,               # 403 owner-only action
    OperatorNotFoundError,        # 404 removing non-existent operator
    OperatorConflictError,        # 409 duplicate or max reached
    ReceiptStateNotBoundError,    # bind_receipt required before op
)

# Authentication utilities
from .auth import (
    Keypair,
    build_signed_envelope,
    build_unsigned_envelope,
    attach_signature,
    compute_locker_id,
    infer_sig_alg,
    SignedEnvelope,
    UnsignedEnvelope,
)

# Discovery utilities
from .discovery import (
    discover,
    health_check,
    get_current_price,
)

__version__ = "4.0.19"

__all__ = [
    # Main client
    "Nukez",

    # Data types - Payment Flow
    "StorageRequest",
    "Receipt",
    "PaymentOption",

    # Data types - File Operations
    "SignedEnvelope",
    "NukezManifest",
    "FileUrls",
    "FileInfo",
    "ViewerLink",
    "FileViewerInfo",
    "ViewerFileList",
    "ViewerContainer",
    "UploadResult",
    "DeleteResult",

    # Data types - Utilities
    "VerificationResult",
    "RecomputeVerifyResult",
    "ReceiptHashVerification",
    "PriceInfo",
    "DiscoveryDoc",

    # Provider awareness
    "ProviderInfo",
    "PROVIDERS",

    # Error classes
    "NukezError",
    "PaymentRequiredError",
    "TransactionNotFoundError",
    "AuthenticationError",
    "NukezFileNotFoundError",
    "FileNotFound",
    "URLExpiredError",
    "NukezNotProvisionedError",
    "RateLimitError",
    "ReceiptStateNotBoundError",

    # Operator delegation errors
    "OperatorError",
    "InvalidOperatorPubkeyError",
    "OperatorIsOwnerError",
    "OperatorNotAuthorizedError",
    "OwnerOnlyError",
    "OperatorNotFoundError",
    "OperatorConflictError",

    # Authentication utilities
    "Keypair",
    "build_signed_envelope",
    "build_unsigned_envelope",
    "attach_signature",
    "compute_locker_id",
    "infer_sig_alg",
    "SignedEnvelope",
    "UnsignedEnvelope",
    
    # Discovery utilities
    "discover",
    "health_check",
    "get_current_price",
    
    # Agent integration functions
    "get_agent_instructions",
    "get_tool_definitions",
]


def get_agent_instructions() -> dict:
    """
    Get structured instructions for autonomous agents.
    
    An agent that has installed this SDK can call this function
    to understand how to use it without reading external documentation.
    
    Returns:
        dict: Structured instructions including quickstart, methods, and examples
        
    Example:
        >>> import pynukez
        >>> instructions = pynukez.get_agent_instructions()
        >>> print(instructions['quickstart_flow'])
    """
    return {
        "package": "pynukez",
        "version": __version__,
        "description": "Agent-native storage with cryptographic verification",

        "installation": {
            "basic": "pip install pynukez",
            "development": "pip install pynukez[dev]"
        },

        "quickstart_flow": [
            "1. client = Nukez(keypair_path='~/.config/solana/id.json')",
            "2. request = client.request_storage(units=1)",
            "3. # Complete the transfer with your own wallet, CLI, signer, or custody workflow.",
            "   # Send request.amount",
            "   # request.pay_asset to request.pay_to_address on request.network.",
            "4. receipt = client.confirm_storage(request.pay_req_id, tx_sig=<your_tx_signature>)",
            "5. manifest = client.provision_locker(receipt.id)",
            "6. uploaded = client.upload_file_path(receipt.id, '~/Documents/report.pdf')",
            "7. file_urls = client.get_file_urls(receipt.id, uploaded['filename'])",
            "8. data = client.download_bytes(file_urls.download_url)"
        ],

        "payment_flow": {
            "description": (
                "pynukez does not execute crypto transfers. request_storage() returns "
                "payment instructions (address, amount, asset, chain). You execute the "
                "transfer externally — wallet, CLI, another tool — and hand the "
                "resulting transaction signature to confirm_storage() to close the loop. "
                "The response includes payment_options listing ALL available "
                "chain/asset combinations."
            ),
            "confirm": (
                "After you obtain a tx signature, call "
                "confirm_storage(request.pay_req_id, tx_sig=<your_tx_signature>). "
                "For EVM payments, also pass payment_chain=request.network, "
                "payment_asset=request.pay_asset."
            ),
        },

        "storage_providers": {
            "note": "Available providers are determined by the gateway configuration. "
                    "Default is gcs. Use get_provider_info(provider) for capability details. "
                    "The gateway will reject providers that are not enabled.",
        },
        
        "important_note": (
            "Most file operations require receipt_id (not locker_id) because "
            "signed envelope authentication uses the receipt. Keep the "
            "receipt_id returned from confirm_storage() as the primary SDK "
            "handle; if a local copy is lost, the on-chain transaction trail "
            "for the relevant keypair provides a recovery path."
        ),
        "sandbox_note": (
            "In MCP/provider-hosted app sandboxes where local path handling or "
            "direct signed-URL uploads are restricted, prefer "
            "sandbox_upload_file_path(), sandbox_upload_bytes(), or "
            "sandbox_upload_base64(). The create/append/complete job methods "
            "are low-level manual chunk controls. Reuse existing receipt_id; "
            "do not purchase new storage unless explicitly requested."
        ),
        
        "core_operations": {
            "discovery": {
                "discover": "Get API capabilities and endpoints",
                "get_current_price": "Check current storage pricing",
                "health_check": "Verify API availability"
            },
            "payment": {
                "request_storage": "Start x402 payment flow — returns payment instructions with payment_options. PyNukez does not execute transfers; use your own wallet, CLI, or signer.",
                "confirm_storage": "Confirm payment and get receipt. Keep receipt.id as the primary SDK handle; takes the tx_sig from the transfer you completed with your own payment tool.",
                "get_provider_info": "Check provider capabilities and limits before selecting",
            },
            "storage": {
                "provision_locker": "Create storage namespace (one-time per receipt)",
                "create_file": "Get upload/download URLs for new file",
                "create_files_batch": "Create multiple file URL pairs in one signed request",
                "upload_bytes": "Upload data to signed URL (raw bytes interface)",
                "upload_string": "Upload data to signed URL (agent-native, auto-sanitizes formatting; small payloads only)",
                "upload_file_path": "Upload one local file by filesystem path (preferred for large files; no content in context)",
                "bulk_upload_paths": "Upload many local files by path with parallelism and batch confirm (preferred for multi-file runs)",
                "upload_directory": "Upload an entire directory (pattern/recursive aware)",
                "start_bulk_upload_job": "Start non-blocking background bulk upload; returns job_id immediately (best for long-running uploads)",
                "get_upload_job": "Poll background upload job state by job_id",
                "sandbox_upload_file_path": "Advanced fallback: read local file then upload through sandbox ingest flow",
                "sandbox_upload_bytes": "Advanced fallback: chunked bytes uploader for constrained runtimes",
                "sandbox_upload_base64": "Advanced fallback: decode base64 then chunk-upload through sandbox ingest",
                "sandbox_create_ingest_job": "Low-level manual chunk control: create sandbox chunk-ingest job",
                "sandbox_append_ingest_part": "Low-level manual chunk control: append one base64 chunk",
                "sandbox_complete_ingest_job": "Low-level manual chunk control: finalize sandbox ingest job",
                "download_bytes": "Download data from signed URL",
                "list_files": "List all files in locker",
                "get_file_urls": "Get fresh URLs for existing file",
                "delete_file": "Remove file from locker"
            },
            "viewer_portal": {
                "get_viewer_container_handoff": "Build generic viewer_container payload (empty container by default)",
                "make_*_renderable": "Build typed renderable objects (text/json/pdf/image/binary) for container payloads",
                "get_locker_view_container": "Build locker view blocks (table + stats + links)",
                "get_attestation_view_container": "Build attestation view blocks (kv + status + proofs + json)",
                "get_file_view_container": "Build file view blocks (file_meta + file_preview)",
                "get_owner_viewer_url": "Build stable portal URL for a locker (agent -> human handoff)",
                "get_file_viewer_url": "Build file-scoped viewer URL (optionally embeds fresh download URL)",
                "list_files_with_viewer_urls": "List files enriched with viewer URLs for human review",
                "viewer_container_contract": "nukez.viewer_container@1.0.0 (container-first handoff)",
                "renderer_contract": "nukez.mcp.viewer_link@1.0 with ui.variant='nukez-neon'"
            },
            "verification": {
                "get_receipt": "Fetch the canonical stored receipt document",
                "verify_receipt_hash": "Recompute and compare the receipt object's canonical hash",
                "receipt_hash_matches": "Boolean convenience helper for receipt hash checks",
                "verify_storage": "Get cryptographic attestation — returns merkle_root, manifest_signature, att_code, per-file hashes",
                "compute_hash": "Calculate SHA256 for local verification"
            },
            "utilities": {
                "compute_locker_id": "Derive locker ID from receipt ID",
                "build_signed_envelope": "Create authentication headers",
            }
        },

        "error_handling": {
            "PaymentRequiredError": "Expected from request_storage() - contains payment instructions",
            "TransactionNotFoundError": "tx not visible yet - wait and retry confirm_storage()",
            "AuthenticationError": "Check keypair and that envelope hasn't expired (5 min TTL)",
            "NukezFileNotFoundError": "Use create_file() first or check list_files()",
            "URLExpiredError": "Call get_file_urls() to get fresh URLs (30 min default TTL)"
        },

        "authentication_modes": [
            "signed_envelope: Ed25519 or secp256k1 signatures for API requests (automatic)",
            "Solana-paid lockers: keypair_path (Ed25519)",
            "EVM-paid lockers: evm_private_key_path (secp256k1)",
        ],

        "networks": {
            "solana": ["solana-devnet", "solana-mainnet-beta"],
            "evm": ["monad-testnet", "monad-mainnet"],
        },

        "requirements": {
            "python": ">=3.9",
            "ed25519_keypair": "Required to sign envelopes for Solana-paid lockers",
            "evm_private_key": "Required to sign envelopes for EVM-paid lockers",
            "dependencies": {
                "core": ["httpx", "pynacl", "base58", "eth-account"],
            }
        }
    }


def get_tool_definitions() -> list:
    """
    Get OpenAI-compatible tool definitions for LLM function calling.
    
    These definitions can be used directly with:
    - OpenAI API (tools parameter)
    - LangChain
    - Any framework supporting OpenAI tool format
    
    Returns:
        list: Tool definitions ready for use with OpenAI, LangChain, etc.
        
    Example:
        >>> tools = pynukez.get_tool_definitions()
        >>> # Use with OpenAI client
        >>> response = openai.chat.completions.create(
        ...     model="gpt-4",
        ...     tools=tools,
        ...     messages=[...]
        ... )
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "nukez_request_storage",
                "description": "Start x402 payment flow to purchase Nukez storage. Returns payment instructions including pay_req_id, pay_to_address, amount_sol, and payment_options listing all available chain/asset combinations.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "units": {
                            "type": "integer",
                            "description": "Number of storage units to purchase",
                            "default": 1,
                            "minimum": 1
                        },
                        "provider": {
                            "type": "string",
                            "default": "gcs",
                            "description": "Storage backend (default: gcs). Available providers are "
                                           "determined by the gateway. Common options: gcs, mongodb."
                        },
                        "pay_network": {
                            "type": "string",
                            "description": "Payment chain. Examples: solana-devnet, monad-testnet, monad-mainnet"
                        },
                        "pay_asset": {
                            "type": "string",
                            "description": "Token to pay with. SOL (Solana), USDC/USDT/MON/WETH (Monad)"
                        }
                    },
                    "required": []
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_provider_info",
                "description": "Get capabilities and limits for a storage provider. Use before selecting a provider for request_storage().",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "provider": {
                            "type": "string",
                            "description": "Provider ID to look up (e.g. gcs, mongodb). "
                                           "See PROVIDERS dict for known provider capabilities."
                        }
                    },
                    "required": ["provider"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_confirm_storage",
                "description": "Confirm payment and receive storage receipt. CRITICAL: The response contains receipt_id (aliased as 'id') — save it. Every subsequent operation (provision_locker, create_file, list_files, verify_storage) requires this receipt_id.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pay_req_id": {
                            "type": "string",
                            "description": "Payment request ID from request_storage()"
                        },
                        "tx_sig": {
                            "type": "string",
                            "description": "On-chain transaction signature from the payment you completed with your own wallet, CLI, or signer"
                        }
                    },
                    "required": ["pay_req_id", "tx_sig"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_provision_locker",
                "description": "Create storage locker namespace. Call once per receipt before creating files.", 
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional tags for the locker",
                            "default": []
                        }
                    },
                    "required": ["receipt_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_create_file",
                "description": "Create file entry and get signed upload/download URLs. Requires receipt_id, not locker_id.",
                "parameters": {
                    "type": "object", 
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "filename": {
                            "type": "string",
                            "description": "File name (auto-generated if not provided)"
                        },
                        "content_type": {
                            "type": "string", 
                            "description": "MIME type",
                            "default": "application/octet-stream"
                        },
                        "ttl_min": {
                            "type": "integer",
                            "description": "URL expiration time in minutes",
                            "default": 30
                        }
                    },
                    "required": ["receipt_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_upload_bytes",
                "description": "PUT raw bytes to the signed upload URL returned by create_file(). This executes an HTTP PUT directly to the signed URL — no additional auth headers needed. The SDK sanitizes the data parameter automatically (unwraps accidental JSON wrappers, strips markdown fencing).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "upload_url": {
                            "type": "string",
                            "description": "The upload_url returned by create_file() — pass exactly as received"
                        },
                        "data": {
                            "type": "string",
                            "description": "The exact content to store as a plain string (e.g. 'Hello world'). This string becomes the raw HTTP PUT body. Do NOT wrap in JSON — pass the content directly."
                        },
                        "content_type": {
                            "type": "string",
                            "description": "Must match the content_type used in create_file() if one was specified"
                        }
                    },
                    "required": ["upload_url", "data"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_upload_file_path",
                "description": "Upload one local file by filesystem path. The SDK reads file bytes directly from disk (no data-in-context), creates URLs, uploads, and optionally confirms.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "filepath": {
                            "type": "string",
                            "description": "Absolute or relative filesystem path to a local file"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Optional remote filename override (defaults to basename)"
                        },
                        "content_type": {
                            "type": "string",
                            "description": "Optional MIME type override"
                        },
                        "ttl_min": {
                            "type": "integer",
                            "description": "Signed URL lifetime in minutes",
                            "default": 30
                        },
                        "confirm": {
                            "type": "boolean",
                            "description": "If true, call server-side confirm after upload",
                            "default": True
                        }
                    },
                    "required": ["receipt_id", "filepath"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_bulk_upload_paths",
                "description": "Upload multiple local files by path with batch URL creation, parallel uploads, optional batch confirm, and optional attestation.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "sources": {
                            "type": "array",
                            "description": "List of file sources. Each item can be a string filepath or an object with filepath, filename, content_type.",
                            "items": {
                                "anyOf": [
                                    {"type": "string"},
                                    {"type": "object"}
                                ]
                            }
                        },
                        "workers": {
                            "type": "integer",
                            "description": "Concurrent upload workers",
                            "default": 6
                        },
                        "ttl_min": {
                            "type": "integer",
                            "description": "Signed URL lifetime in minutes",
                            "default": 30
                        },
                        "confirm": {
                            "type": "boolean",
                            "description": "If true, batch confirm uploaded files",
                            "default": True
                        },
                        "auto_attest": {
                            "type": "boolean",
                            "description": "If true, trigger attestation after upload batch",
                            "default": False
                        },
                        "attest_sync": {
                            "type": "boolean",
                            "description": "If auto_attest=true, wait for attest completion when true",
                            "default": False
                        }
                    },
                    "required": ["receipt_id", "sources"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_upload_directory",
                "description": "Upload matching files from a directory with optional recursion/pattern filtering.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "source_dir": {
                            "type": "string",
                            "description": "Directory path to scan for files"
                        },
                        "pattern": {
                            "type": "string",
                            "description": "Glob pattern (e.g. *.png, *.md)",
                            "default": "*"
                        },
                        "recursive": {
                            "type": "boolean",
                            "description": "If true, recurse into subdirectories",
                            "default": False
                        },
                        "exclude_pattern": {
                            "type": "string",
                            "description": "Optional glob exclusion pattern"
                        },
                        "preserve_structure": {
                            "type": "boolean",
                            "description": "If true, keep relative subpaths in remote filenames",
                            "default": False
                        },
                        "workers": {
                            "type": "integer",
                            "description": "Concurrent upload workers",
                            "default": 6
                        },
                        "confirm": {
                            "type": "boolean",
                            "description": "If true, batch confirm uploaded files",
                            "default": True
                        },
                        "auto_attest": {
                            "type": "boolean",
                            "description": "If true, trigger attestation after upload batch",
                            "default": False
                        }
                    },
                    "required": ["receipt_id", "source_dir"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_start_bulk_upload_job",
                "description": "Start a non-blocking background bulk upload job. Returns immediately with job_id.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "sources": {
                            "type": "array",
                            "description": "List of file sources (filepath strings or source objects).",
                            "items": {
                                "anyOf": [
                                    {"type": "string"},
                                    {"type": "object"}
                                ]
                            }
                        },
                        "workers": {
                            "type": "integer",
                            "description": "Concurrent upload workers",
                            "default": 6
                        },
                        "confirm": {
                            "type": "boolean",
                            "description": "If true, batch confirm uploaded files",
                            "default": True
                        },
                        "auto_attest": {
                            "type": "boolean",
                            "description": "If true, trigger attestation when uploads finish",
                            "default": False
                        }
                    },
                    "required": ["receipt_id", "sources"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_upload_job",
                "description": "Get status/result for a previously started background upload job.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "job_id": {
                            "type": "string",
                            "description": "Job identifier returned by nukez_start_bulk_upload_job"
                        }
                    },
                    "required": ["job_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_download_bytes",
                "description": "GET data from the signed download URL returned by create_file() or get_file_urls(). If the URL has expired or fails, call list_files() or get_file_urls() for fresh URLs.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "download_url": {
                            "type": "string",
                            "description": "The download_url returned by create_file() or get_file_urls() — pass exactly as received"
                        }
                    },
                    "required": ["download_url"]
                }
            }
        },
        {
            "type": "function", 
            "function": {
                "name": "nukez_list_files",
                "description": "List all files in a locker",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        }
                    },
                    "required": ["receipt_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_file_urls",
                "description": "Get fresh upload/download URLs for an existing file (use if URLs expired)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Name of existing file"
                        },
                        "ttl_min": {
                            "type": "integer",
                            "description": "URL expiration time in minutes",
                            "default": 30
                        }
                    },
                    "required": ["receipt_id", "filename"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_viewer_container_contract",
                "description": "Return the stable viewer-container contract descriptor used by generic container payloads.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_viewer_container",
                "description": "Build a generic viewer_container payload for agent -> human handoff. This is container-first and render-agnostic.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "viewer_base_url": {
                            "type": "string",
                            "description": "Viewer frontend origin",
                            "default": "https://nukez.xyz"
                        },
                        "request_type": {
                            "type": "string",
                            "description": "Container request mode",
                            "default": "container"
                        },
                        "view_kind": {
                            "type": "string",
                            "description": "High-level viewer mode: locker | attestation | file | custom",
                            "default": "custom"
                        },
                        "receipt_id": {
                            "type": "string",
                            "description": "Optional receipt ID if the container is locker-scoped"
                        },
                        "locker_id": {
                            "type": "string",
                            "description": "Optional locker ID override"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Optional filename if this container is file-focused"
                        },
                        "renderables": {
                            "type": "array",
                            "description": "Optional renderable objects (text/json/pdf/image/binary) for in-container rendering",
                            "items": {
                                "type": "object"
                            }
                        },
                        "blocks": {
                            "type": "array",
                            "description": "Optional view blocks for structured container rendering (header/stats/links/table/kv/status/proofs/json/file_meta/file_preview)",
                            "items": {
                                "type": "object"
                            }
                        },
                        "embed_payload_in_url": {
                            "type": "boolean",
                            "description": "If true, embed container payload into viewer URL query for immediate rendering",
                            "default": True
                        },
                        "button_label": {
                            "type": "string",
                            "description": "Optional button label for UI renderers",
                            "default": "Open Nukez Viewer"
                        }
                    },
                    "required": []
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_locker_view",
                "description": "Build a locker-focused viewer payload: table + stats + links.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "viewer_base_url": {
                            "type": "string",
                            "description": "Viewer frontend origin",
                            "default": "https://nukez.xyz"
                        },
                        "include_download_urls": {
                            "type": "boolean",
                            "description": "If true, include per-file download links in table rows",
                            "default": False
                        },
                        "ttl_min": {
                            "type": "integer",
                            "description": "Download URL TTL when include_download_urls=true",
                            "default": 30
                        },
                        "embed_payload_in_url": {
                            "type": "boolean",
                            "description": "If true, embed block payload in viewer URL query",
                            "default": True
                        },
                        "button_label": {
                            "type": "string",
                            "description": "Optional button label for UI renderers",
                            "default": "Open Locker Viewer"
                        }
                    },
                    "required": ["receipt_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_attestation_view",
                "description": "Build an attestation-focused viewer payload: kv + status + proofs + json.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "viewer_base_url": {
                            "type": "string",
                            "description": "Viewer frontend origin",
                            "default": "https://nukez.xyz"
                        },
                        "embed_payload_in_url": {
                            "type": "boolean",
                            "description": "If true, embed block payload in viewer URL query",
                            "default": True
                        },
                        "button_label": {
                            "type": "string",
                            "description": "Optional button label for UI renderers",
                            "default": "Open Attestation Viewer"
                        }
                    },
                    "required": ["receipt_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_file_view",
                "description": "Build a file-focused viewer payload: file_meta + file_preview (mime handling hidden in viewer).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Target file name"
                        },
                        "viewer_base_url": {
                            "type": "string",
                            "description": "Viewer frontend origin",
                            "default": "https://nukez.xyz"
                        },
                        "ttl_min": {
                            "type": "integer",
                            "description": "Download URL TTL in minutes",
                            "default": 30
                        },
                        "include_download_url": {
                            "type": "boolean",
                            "description": "If true, include a signed download URL for preview fetching",
                            "default": True
                        },
                        "embed_payload_in_url": {
                            "type": "boolean",
                            "description": "If true, embed block payload in viewer URL query",
                            "default": True
                        },
                        "button_label": {
                            "type": "string",
                            "description": "Optional button label for UI renderers",
                            "default": "Open File Viewer"
                        }
                    },
                    "required": ["receipt_id", "filename"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_viewer_renderer_contract",
                "description": "Return the stable renderer contract descriptor for viewer-link UI payloads.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_owner_viewer_url",
                "description": "Build stable owner portal URL for human-in-the-loop review of a locker. Returns ui button metadata for Nukez-themed rendering.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "viewer_base_url": {
                            "type": "string",
                            "description": "Viewer frontend origin",
                            "default": "https://nukez.xyz"
                        },
                        "button_label": {
                            "type": "string",
                            "description": "Optional button label for UI renderers",
                            "default": "Open Nukez Viewer"
                        }
                    },
                    "required": ["receipt_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_file_viewer_url",
                "description": "Build file-scoped viewer URL for a specific file. Optionally mints and embeds a fresh download_url for immediate viewing. Returns ui button metadata for Nukez-themed rendering.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Target file name"
                        },
                        "viewer_base_url": {
                            "type": "string",
                            "description": "Viewer frontend origin",
                            "default": "https://nukez.xyz"
                        },
                        "ttl_min": {
                            "type": "integer",
                            "description": "Download URL TTL in minutes if include_download_url=true",
                            "default": 30
                        },
                        "include_download_url": {
                            "type": "boolean",
                            "description": "If true, include a fresh signed download_url in the returned viewer link",
                            "default": True
                        },
                        "button_label": {
                            "type": "string",
                            "description": "Optional button label for UI renderers",
                            "default": "Open File Viewer"
                        }
                    },
                    "required": ["receipt_id", "filename"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_list_files_with_viewer_urls",
                "description": "List files and return portal viewer links per file plus owner portal URL. Includes ui button metadata for Nukez-themed rendering.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "viewer_base_url": {
                            "type": "string",
                            "description": "Viewer frontend origin",
                            "default": "https://nukez.xyz"
                        },
                        "include_download_urls": {
                            "type": "boolean",
                            "description": "If true, mint and embed download URLs per file (more expensive, expires)",
                            "default": False
                        },
                        "ttl_min": {
                            "type": "integer",
                            "description": "Download URL TTL in minutes when include_download_urls=true",
                            "default": 30
                        }
                    },
                    "required": ["receipt_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_delete_file",
                "description": "Delete a file from locker (permanent, cannot be undone)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Name of file to delete"
                        }
                    },
                    "required": ["receipt_id", "filename"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_verify_storage",
                "description": "Verify storage integrity and get cryptographic attestation. Returns merkle_root (hash of all files), manifest_signature (gateway's Ed25519 signature), att_code (on-chain attestation badge), file_count, and per-file content hashes. Call after uploading data to confirm integrity.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        }
                    },
                    "required": ["receipt_id"]
                }
            }
        },
        # ── Attestation & Proof tools ────────────────────────────────
        {
            "type": "function",
            "function": {
                "name": "nukez_confirm_file",
                "description": "Confirm a file's content hash with the server. The server computes the SHA-256 hash of the uploaded file and stores it. This is step 1 of the attestation trust chain: confirm_file → attest → verify_storage → get_merkle_proof.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Name of the file to confirm"
                        }
                    },
                    "required": ["receipt_id", "filename"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_confirm_files",
                "description": "Confirm content hashes for multiple files in one call. Batch version of confirm_file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "filenames": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of filenames to confirm"
                        }
                    },
                    "required": ["receipt_id", "filenames"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_attest",
                "description": "Build a Merkle tree from confirmed file hashes and optionally push the root on-chain. This is step 2 of the attestation trust chain. Must call confirm_file for each file first. Returns tx_signature (on-chain attestation tx) and push_ok status.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "sync": {
                            "type": "boolean",
                            "description": "If true (default), wait for attestation to complete. If false, return 202 and poll verify_storage for result.",
                            "default": True
                        }
                    },
                    "required": ["receipt_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_get_merkle_proof",
                "description": "Get a per-file Merkle inclusion proof. Returns leaf_hash, proof path (sibling hashes), and merkle_root. This is step 4 of the trust chain: confirm_file → attest → verify_storage → get_merkle_proof. Must call attest first.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Name of the file to get proof for"
                        }
                    },
                    "required": ["receipt_id", "filename"]
                }
            }
        },
        # ── Operator delegation tools ─────────────────────────────────
        {
            "type": "function",
            "function": {
                "name": "nukez_add_operator",
                "description": "Authorize an Ed25519 operator to perform file operations on this locker. Owner-only. Max 5 operators. The operator_pubkey must differ from your own wallet pubkey. Returns ok and updated operator_ids list.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "operator_pubkey": {
                            "type": "string",
                            "description": "Base58-encoded Ed25519 public key to authorize (32-44 chars, must differ from your own wallet pubkey)"
                        }
                    },
                    "required": ["receipt_id", "operator_pubkey"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "nukez_remove_operator",
                "description": "Revoke an operator's access to this locker. Owner-only. Returns ok and updated operator_ids list.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "receipt_id": {
                            "type": "string",
                            "description": "Receipt ID from confirm_storage()"
                        },
                        "operator_pubkey": {
                            "type": "string",
                            "description": "Base58-encoded Ed25519 public key to remove"
                        }
                    },
                    "required": ["receipt_id", "operator_pubkey"]
                }
            }
        },
    ]
