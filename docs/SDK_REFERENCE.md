# PyNukez SDK Reference

**Agent-native storage with cryptographic verification.**

Pay with SOL or MON. Store anything. Get a cryptographic receipt. Verify independently.

- **Version:** 3.2.0
- **License:** MIT
- **Python:** >= 3.9
- **PyPI:** `pip install pynukez`

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Async Client](#async-client)
- [Client Initialization](#client-initialization)
- [Payment Flow (x402 Protocol)](#payment-flow-x402-protocol)
- [Storage & File Operations](#storage--file-operations)
- [Verification & Attestation](#verification--attestation)
- [Operator Delegation](#operator-delegation)
- [Viewer Portal](#viewer-portal)
- [Authentication & Signing](#authentication--signing)
- [Discovery & Utilities](#discovery--utilities)
- [Error Handling](#error-handling)
- [Data Types Reference](#data-types-reference)
- [Storage Providers](#storage-providers)
- [Agent Integration](#agent-integration)
- [Environment Variables](#environment-variables)

---

## Installation

```bash
pip install pynukez
```

One command, one install target. Envelope signing for both Solana-paid (Ed25519) and EVM-paid (secp256k1) lockers is in the base install.

Requires Python 3.9+. Supported on macOS, Linux, and Windows.

### Dependencies

| Group | Packages |
|-------|----------|
| **Core (runtime)** | `httpx>=0.24.0`, `pynacl>=1.5.0`, `base58>=2.1.0`, `eth-account>=0.10.0`, `google-crc32c>=1.5.0` |
| **[dev]** | `pytest`, `pytest-asyncio`, `pytest-mock`, `black`, `isort`, `mypy`, `python-dotenv` |
| **dev** | `pytest`, `pytest-asyncio`, `pytest-mock`, `black`, `isort`, `mypy` |

---

## Quick Start

```python
import webbrowser
from pathlib import Path
from pynukez import Nukez

client = Nukez(
    keypair_path="~/.config/solana/id.json",  # local Ed25519 envelope signer
)

# 1. Check pricing
price = client.get_price()

# 2. Request storage (returns payment instructions)
request = client.request_storage(units=1)
print(request.next_step)
# -> "Transfer 0.001 SOL to <addr> on solana-devnet, then call
#     confirm_storage(pay_req_id='...', tx_sig=<your_tx_signature>)"

# Using the x402 payment details assigned to the request variable
# Complete transfer via preferred method
# Assign transaction signature from above transfer to variable like so:
tx_sig = "..."

# Issue receipt object by confirming payment with the Nukez Gateway
receipt = client.confirm_storage(request.pay_req_id, tx_sig=tx_sig)
# Keep receipt.id as the primary SDK handle for this locker.

# Provision storage locker instance via the receipt
manifest = client.provision_locker(receipt.id)

# Upload file. File contents do not pass through agent context window.
# Tremendous advantage over ordinary flows.
local_file = Path("~/Documents/report.pdf").expanduser()
uploaded = client.upload_file_path(
    receipt.id,
    str(local_file),
    content_type="application/pdf",
)

# Large or long-running upload option:
# job = client.start_bulk_upload_job(
#     receipt.id,
#     sources=[{"filepath": str(local_file), "content_type": "application/pdf"}],
#     workers=1,
# )
# status = client.get_upload_job(job["job_id"])

# How to read stored content back
file_urls = client.get_file_urls(receipt.id, uploaded["filename"])

# 8. Download data
data = client.download_bytes(file_urls.download_url)

# How to view/render retrieved object
downloaded_file = Path("~/Downloads/nukez_report.pdf").expanduser()
downloaded_file.parent.mkdir(parents=True, exist_ok=True)
downloaded_file.write_bytes(data)
webbrowser.open(downloaded_file.as_uri())
```

---

## Async Client

`AsyncNukez` provides full method parity with `Nukez`. Same method names, same parameters, same return types. The only difference is `async/await` and `httpx.AsyncClient` under the hood.

```python
from pynukez import AsyncNukez

async with AsyncNukez(
    keypair_path="~/.config/solana/id.json",  # local Ed25519 envelope signer
) as client:
    price = await client.get_price()
    request = await client.request_storage(units=1)
    # ... execute the transfer externally, capture tx_sig ...
    receipt = await client.confirm_storage(request.pay_req_id, tx_sig=tx_sig)
    files = await client.list_files(receipt.id)
```

Use `AsyncNukez` for FastAPI, MCP servers, and event-loop contexts.

---

## Client Initialization

```python
from pynukez import Nukez

# Solana-paid lockers (Ed25519 envelope signing)
client = Nukez(
    keypair_path="~/.config/solana/id.json",
    network="devnet",                           # or "mainnet-beta"
    base_url="https://api.nukez.xyz",           # default
)

# EVM-paid lockers (secp256k1 envelope signing)
client = Nukez(
    evm_private_key_path="~/.keys/evm_key.json",
    network="devnet",
)

# Dual-key (Ed25519 for Solana-paid, secp256k1 for EVM-paid)
client = Nukez(
    keypair_path="~/.config/solana/id.json",
    evm_private_key_path="~/.keys/evm_key.json",
)

# Custom signer (relay, HSM, etc.)
client = Nukez(signing_key=my_custom_signer)
```

### Constructor Parameters

`keypair_path` is one supported signer source. Use it when local scripts or
agents should sign protected gateway envelopes from a Solana CLI keypair file.
For protected locker/file operations, PyNukez still needs a signer source:
`keypair_path`, `evm_private_key_path`, or an explicit `signing_key`. Nukez
does not custody, receive, or store client keypair material.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `keypair_path` | `str \| Path` | `None` | Optional path to a local Ed25519 keypair JSON used to sign envelopes |
| `base_url` | `str` | `NUKEZ_BASE_URL` env or `https://api.nukez.xyz` | Gateway API URL |
| `network` | `str` | `"devnet"` | Network target |
| `timeout` | `int` | `None` | HTTP request timeout (seconds) |
| `evm_private_key_path` | `str \| Path` | `None` | Optional path to a local EVM private key used for secp256k1 envelope signing |
| `evm_rpc_url` | `str` | `None` | Reserved; currently unused at the SDK layer |
| `signing_key` | `Signer` | `None` | Explicit Signer instance (overrides keypair) |

Both clients support context managers:

```python
with Nukez(keypair_path="~/.config/solana/id.json") as client:  # local Ed25519 envelope signer
    ...

# or
client = Nukez(keypair_path="~/.config/solana/id.json")  # local Ed25519 envelope signer
try:
    ...
finally:
    client.close()
```

---

## Payment Flow (x402 Protocol)

Nukez uses the x402 HTTP 402 Payment Required protocol. **PyNukez does not execute blockchain payments** — the SDK tells you what to pay and confirms the transaction signature you provide. Complete the transfer with your own wallet, CLI, hardware signer, or custody workflow.

The flow is always three explicit steps:

1. **Request** -- `request_storage()` returns payment instructions (address, amount, asset, chain, `pay_req_id`)
2. **Pay** -- Complete the transfer with your own payment tool and capture the tx signature
3. **Confirm** -- `confirm_storage()` presents `pay_req_id` + your tx signature, gateway verifies on-chain, returns receipt

The receipt ID is the primary SDK handle for follow-on operations. Persist it
for ergonomic lookups and deterministic workflows. It is not a custody secret:
because payment and attestation state are anchored to the payer/signing context,
a lost local receipt handle can be recovered from the on-chain transaction trail
for the relevant keypair.

### Methods

#### `request_storage(units=1, provider=None, pay_network=None, pay_asset=None)` -> `StorageRequest`

Start the payment flow. Returns payment instructions including all available chain/asset options.

```python
request = client.request_storage(units=1, provider="gcs")

request.pay_req_id       # Save for confirm_storage()
request.pay_to_address   # Send payment here
request.amount_sol       # SOL amount (Solana)
request.amount_raw       # Atomic units (any chain)
request.payment_options  # All available chain/asset combos
request.is_evm           # True if default option is EVM
request.next_step        # Human-readable guidance for the agent
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `units` | `int` | `1` | Number of storage units |
| `provider` | `str` | `None` | Storage backend: `"gcs"`, `"mongodb"`, `"filecoin"`, `"arweave"`, `"firestore"`, `"storj"` |
| `pay_network` | `str` | `None` | Payment chain: friendly names such as `"solana-mainnet"` / `"monad-mainnet"` or CAIP-2 values such as `"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"` / `"eip155:143"` |
| `pay_asset` | `str` | `None` | Payment token: `"SOL"`, `"MON"`, `"USDC"`, `"USDT"`, `"WETH"` |

#### Executing the payment

PyNukez 4.0.0 removed `solana_transfer()` and `evm_transfer()`. The SDK intentionally leaves transfer execution to your own wallet, CLI, hardware signer, or custody workflow:

- **Solana**: `solana transfer`, a wallet (Phantom, Backpack, Solflare), or a signing relay
- **EVM (Monad, etc.)**: MetaMask, `cast send`, `web3.py`, a wallet/relay, or a hardware signer

When the transfer lands and you have a signature, pass it to `confirm_storage`.

#### `confirm_storage(pay_req_id, tx_sig, ...)` -> `Receipt`

Confirm payment and get your receipt.

```python
receipt = client.confirm_storage(request.pay_req_id, tx_sig=<your_tx_signature>)
receipt.id          # Primary SDK handle for this locker
receipt.locker_id   # Derived automatically
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pay_req_id` | `str` | required | Payment request ID from `request_storage()` |
| `tx_sig` | `str` | required | On-chain transaction signature for the payment you executed externally |
| `max_retries` | `int` | `5` | Retry count for blockchain confirmation |
| `initial_delay` | `float` | `2.0` | Initial retry delay in seconds |
| `payment_chain` | `str` | `None` | Chain ID (required for EVM) |
| `payment_asset` | `str` | `None` | Asset symbol (required for EVM) |
| `operator_pubkey` | `str` | `None` | Authorize operator at purchase time |

### Multi-Chain Payment Options

| Chain | Token | Envelope Signature Algorithm |
|-------|-------|------------------------------|
| Solana | SOL | Ed25519 |
| Solana | USDC | Ed25519 |
| Solana | USDT | Ed25519 |
| Solana | WETH | Ed25519 |
| Monad (EVM) | USDC | secp256k1 |
| Monad (EVM) | USDT0 | secp256k1 |
| Monad (EVM) | MON | secp256k1 |
| Monad (EVM) | WETH | secp256k1 |

### Choosing a Payment Path

```python
request = client.request_storage(units=1)

if request.is_evm:
    # You execute the EVM transfer externally; capture the tx hash
    tx_sig = "..."
    receipt = client.confirm_storage(
        request.pay_req_id, tx_sig=tx_sig,
        payment_chain=request.network,
        payment_asset=request.pay_asset,
    )
else:
    # You execute the Solana transfer externally; capture the tx signature
    tx_sig = "..."
    receipt = client.confirm_storage(request.pay_req_id, tx_sig=tx_sig)
```

---

## Storage & File Operations

All file operations require a `receipt_id` from the payment flow.

### Locker Management

| Method | Returns | Description |
|--------|---------|-------------|
| `provision_locker(receipt_id, tags=None, operator_pubkey=None)` | `NukezManifest` | Create storage namespace (one-time per receipt) |
| `get_files_manifest(receipt_id)` | `dict` | Raw files document (`locker_files_v1`): `files[]`, counts, timestamps. No ownership fields. |
| `get_locker_record(receipt_id)` | `LockerRecord` | Locker identity document (`lockers_v1`): `owner_id`, `operator_ids`, receipt binding, provider. |
| `list_files(receipt_id)` | `List[FileInfo]` | Typed file list (sugar over `get_files_manifest` + `FileInfo`) |

`get_manifest()` is retained as a deprecated alias for `get_files_manifest()` and will be removed in the next major release.

The gateway stores two independent documents per locker. `get_files_manifest()` is the hot-path read (changes on every upload); `get_locker_record()` is the cold-path read for ownership. Use `get_locker_record()` to verify the result of `add_operator()` / `remove_operator()` against the gateway's authoritative state.

```python
manifest = client.provision_locker(receipt.id, tags=["myapp"])

# Files
files = client.list_files(receipt.id)
for f in files:
    print(f.filename, f.size_bytes, f.content_hash)

# Ownership
record = client.get_locker_record(receipt.id)
print(record.owner_id, record.operator_ids)
```

### File URL Management

| Method | Returns | Description |
|--------|---------|-------------|
| `create_file(receipt_id, filename, content_type="application/octet-stream", ttl_min=30)` | `FileUrls` | Create file entry and get signed upload/download URLs |
| `create_files_batch(receipt_id, files, ttl_min=30)` | `dict` | Create multiple file URL pairs in one signed request |
| `get_file_urls(receipt_id, filename, ttl_min=30)` | `FileUrls` | Refresh expired signed URLs for existing file |
| `get_batch_urls(receipt_id, filenames, ttl_min=30)` | `dict` | Refresh URLs for multiple files |
| `delete_file(receipt_id, filename)` | `DeleteResult` | Delete a file permanently |

```python
urls = client.create_file(receipt.id, "data.json", content_type="application/json")
urls.upload_url     # PUT your data here
urls.download_url   # GET your data here
urls.expires_in_sec # URL lifetime
```

### Upload Methods

| Method | Best For | Description |
|--------|----------|-------------|
| `upload_bytes(upload_url, data, content_type=None)` | Small in-memory data | Upload raw bytes to signed URL |
| `upload_string(upload_url, content, content_type="text/plain")` | Agent-generated text | Upload string with auto-sanitization |
| `upload_file_path(receipt_id, filepath, filename=None, content_type=None, ttl_min=30, confirm=True)` | Single local file | Upload by filesystem path (avoids context bloat) |
| `bulk_upload_paths(receipt_id, sources, workers=6, ttl_min=30, confirm=True, auto_attest=False, attest_sync=False, on_progress=None)` | Multiple local files | Parallel upload with batch confirm |
| `upload_directory(receipt_id, source_dir, pattern="*", recursive=False, exclude_pattern=None, preserve_structure=False, workers=6, ...)` | Directories | Glob-filtered directory upload |
| `upload_files(receipt_id, sources, workers=6, ttl_min=30, confirm=True)` | General batch | Concurrent upload from source list |
| `upload_large_file(receipt_id, filepath, filename=None, content_type=None, ttl_min=30, chunk_bytes=8 MiB, confirm=True, auto_attest=False, push_attestation=False, threshold_bytes=256 MiB, on_progress=None, ...)` | Large files (any size) | Resumable direct-to-provider upload with streaming digests |

```python
# Direct bytes
client.upload_bytes(urls.upload_url, b"Hello!")

# From filesystem (preferred for large files)
result = client.upload_file_path(receipt.id, "/path/to/report.pdf")

# Batch upload
result = client.bulk_upload_paths(
    receipt.id,
    sources=[
        {"filepath": "/path/to/doc.html"},
        {"filepath": "/path/to/data.json"},
    ],
    workers=6,
    confirm=True,
)
print(result["uploaded"], result["failed"])

# Upload a whole directory
result = client.upload_directory(
    receipt.id,
    source_dir="/path/to/reports",
    pattern="*.pdf",
    recursive=True,
)
```

### Large Files: Resumable Direct-to-Provider Uploads

For large objects, `upload_large_file()` moves the bytes straight from disk
to the storage provider in a resumable session — they never pass through the
gateway, the model's context, or client memory as a whole. The flow: one
streaming pass computes the file's SHA-256 and CRC32C; the create call
pre-commits both hash and size; the file is uploaded in aligned chunks
(default 8 MiB) that resume from the provider's committed offset after any
interruption; the final chunk carries the whole-object CRC32C so the
provider itself refuses a corrupted transfer; and confirmation makes the
gateway stream the stored object and record the verified hash.

Confirmation routes by size: below `threshold_bytes` (default 256 MiB) the
ordinary synchronous confirm runs; at or above it — or whenever
`auto_attest`/`push_attestation` is requested — the gateway's asynchronous
finalize-upload job runs the confirm (and optional attestation) off the
request path, and the method polls the job to completion. Practical
ceilings: the synchronous path is comfortable to roughly 10 GB and a single
job dispatch to roughly 50-100 GB; beyond that is deliberately unsupported
for now.

`upload_file_path()` and `bulk_upload_paths()` route files at or above the
threshold through this path automatically, so existing callers gain
streaming and resumability with no API change.

```python
result = client.upload_large_file(
    receipt.id,
    "/path/to/dataset.bin",
    on_progress=lambda done, total: print(f"{done}/{total} bytes committed"),
)
print(result["sha256"], result["confirm_path"], result["resume_count"])
```

The two job primitives are also available directly when you manage the
confirm step yourself:

| Method | Description |
|--------|-------------|
| `finalize_upload_job(receipt_id, filenames, auto_attest=False, attest_sync=False, push_attestation=False, run_inline=False)` | Create the gateway's asynchronous confirm-and-attest job for already-uploaded files |
| `get_job(job_id, receipt_id)` | Poll a job to its terminal state (`complete`, `partial`, or `failed`) |

### Background Upload Jobs

For long-running uploads that shouldn't block chat turns:

| Method | Returns | Description |
|--------|---------|-------------|
| `start_bulk_upload_job(receipt_id, sources, workers=6, ...)` | `dict` | Start non-blocking background upload; returns `job_id` |
| `get_upload_job(job_id)` | `dict` | Poll job status |
| `list_upload_jobs(limit=20)` | `dict` | List all upload jobs |

```python
job = client.start_bulk_upload_job(receipt.id, sources=[...])
print(job["job_id"], job["status"])  # queued

# Later...
status = client.get_upload_job(job["job_id"])
print(status["status"], status.get("uploaded"))
```

### Download Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `download_bytes(download_url, max_retries=3, initial_delay=2.0)` | `bytes` | Download file content (retries on 404 for propagation) |
| `download_files(receipt_id, filenames, workers=6)` | `BatchDownloadResult` | Concurrent download of multiple files |

```python
data = client.download_bytes(urls.download_url)

batch = client.download_files(receipt.id, ["a.txt", "b.txt"])
for f in batch.files:
    print(f.filename, f.size_bytes, f.verified)
```

### Sandbox Ingest

Sandbox helpers are advanced fallback methods for MCP/provider-hosted runtimes
where local path handling or direct signed-URL uploads are restricted. Most
Python users should use `upload_file_path()`, `bulk_upload_paths()`, or
`upload_directory()` first.

| Method | Returns | Description |
|--------|---------|-------------|
| `sandbox_upload_bytes(receipt_id, filename, data, ...)` | `dict` | Convenience: bytes -> chunked ingest |
| `sandbox_upload_base64(receipt_id, filename, base64_data, ...)` | `dict` | Convenience: base64 -> chunked ingest |
| `sandbox_upload_file_path(receipt_id, filepath, filename=None, ...)` | `dict` | Convenience: local file -> chunked ingest |
| `sandbox_create_ingest_job(receipt_id, files, execution_mode=None)` | `dict` | Low-level: create manual chunked ingest job |
| `sandbox_append_ingest_part(receipt_id, job_id, file_id, part_no, payload_b64, is_last=False)` | `dict` | Low-level: append one base64 chunk |
| `sandbox_complete_ingest_job(receipt_id, job_id, file_ids=None)` | `dict` | Low-level: finalize and commit files |

```python
# Recommended constrained-runtime helper
result = client.sandbox_upload_file_path(
    receipt.id,
    "/Users/alice/Downloads/image.png",
    filename="image.png",
    content_type="image/png",
)

# Notebook-safe readback: write bytes to disk instead of printing them
file_urls = client.get_file_urls(receipt.id, "image.png")
client.download_to_file(file_urls.download_url, "~/Downloads/image_roundtrip.png")

# Manual chunk control
job = client.sandbox_create_ingest_job(
    receipt_id=receipt.id,
    files=[{"filename": "image.png", "content_type": "image/png"}],
)
client.sandbox_append_ingest_part(
    receipt_id=receipt.id,
    job_id=job["job_id"],
    file_id=job["files"][0]["file_id"],
    part_no=0,
    payload_b64="<chunk-0-base64>",
    is_last=True,
)
result = client.sandbox_complete_ingest_job(receipt.id, job["job_id"])
```

---

## Verification & Attestation

After uploading, confirm file hashes and generate a merkle attestation.

| Method | Returns | Description |
|--------|---------|-------------|
| `confirm_file(receipt_id, filename)` | `ConfirmResult` | Compute and record content hash for one file |
| `confirm_files(receipt_id, filenames)` | `BatchConfirmResult` | Batch hash confirmation |
| `attest(receipt_id, sync=True)` | `AttestResult` | Compute merkle root and trigger attestation |
| `get_receipt(receipt_id)` | `dict` | Fetch the canonical stored receipt document |
| `verify_receipt_hash(receipt_id)` | `ReceiptHashVerification` | Recompute and compare the receipt object's canonical hash |
| `receipt_hash_matches(receipt_id)` | `bool` | Convenience boolean for receipt hash checks |
| `verify_storage(receipt_id)` | `VerificationResult` | Full verification: merkle root, manifest signature, per-file hashes |
| `get_merkle_proof(receipt_id, filename)` | `dict` | Get inclusion proof for a specific file |
| `compute_hash(data)` | `str` | SHA-256 hash for local verification |

```python
# Confirm individual file hashes
result = client.confirm_file(receipt.id, "notes.txt")
print(result.content_hash)  # "sha256:..."

# Batch confirm
batch = client.confirm_files(receipt.id, ["a.txt", "b.txt"])
print(batch.confirmed_count)

# Generate merkle attestation
att = client.attest(receipt.id, sync=True)
print(att.merkle_root, att.file_count)

# Full verification
v = client.verify_storage(receipt.id)
print(v.verified, v.merkle_root, v.file_count)

# Receipt object hash verification
check = client.verify_receipt_hash(receipt.id)
print(check.stored_hash)
print(check.computed_hash)
print(check.matches)

# Per-file merkle proof
proof = client.get_merkle_proof(receipt.id, "notes.txt")
```

### `verify_receipt_hash(receipt_id)`

Recompute and compare the canonical receipt hash.

This verifies the receipt object itself. Use `verify_storage()` for
storage/content attestation, merkle roots, file hashes, and on-chain proof.

```python
check = client.verify_receipt_hash(receipt.id)

print(f"stored:   {check.stored_hash}")
print(f"computed: {check.computed_hash}")
print(f"RECEIPT_HASH_MATCH: {'yes' if check.matches else 'no'}")
```

### Agent-to-Agent Verification

Agent A stores data and shares the `receipt_id` with Agent B. Agent B verifies independently:

```python
# Agent B verifies Agent A's work
verification = client.verify_storage(agent_a_receipt_id)
assert verification.verified == True
```

No shared keys, no shared accounts. The receipt ID is the trust bridge.

---

## Operator Delegation

Owners can delegate file operations to other signers (operators) without sharing keys.

| Method | Returns | Description |
|--------|---------|-------------|
| `add_operator(receipt_id, operator_pubkey)` | `OperatorResult` | Authorize an operator (owner-only) |
| `remove_operator(receipt_id, operator_pubkey)` | `OperatorResult` | Revoke an operator (owner-only) |
| `bind_receipt(receipt=None, *, receipt_id, owner_identity, sig_alg)` | `None` | Prime per-receipt signer/owner state for cross-session flows |
| `set_owner(receipt_id, identity=None)` | `None` | Compatibility shim over `bind_receipt` (prefer `bind_receipt` in new code) |

```python
# Owner authorizes an operator
result = client.add_operator(receipt.id, "operator_pubkey_base58")
print(result.ok, result.operator_ids)

# Operator performs file ops with their own signer
operator_client = Nukez(keypair_path="/path/to/operator_key.json")
urls = operator_client.create_file(receipt.id, "delegated.txt")

# Owner revokes
client.remove_operator(receipt.id, "operator_pubkey_base58")

# Verify the mutation landed on the gateway's authoritative record
record = client.get_locker_record(receipt.id)
assert "operator_pubkey_base58" not in record.operator_ids
```

### Cross-Session Workflows: `bind_receipt`

`confirm_storage()` primes per-receipt state (owner identity + signature
algorithm) on the client in the same process.  If you load a receipt from
disk, a database, or a gateway response in a fresh client — or re-run a
notebook cell that rebuilt the client — the state is cold.  On dual-key
clients (both `keypair_path` and `evm_private_key_path`), owner-only ops
like `add_operator`/`remove_operator` will raise `ReceiptStateNotBoundError`
instead of silently picking the wrong signer.

Recovery is one call:

```python
# Option A — pass the Receipt dataclass (primes both owner and sig_alg)
client.bind_receipt(receipt)

# Option B — raw kwargs (loaded from JSON, DB, etc.)
client.bind_receipt(
    receipt_id="8573c83375ebf3ac",
    owner_identity="0xc12e3657ce2ede7fae1d6f5a83b386f6a630fd18",
    # sig_alg is inferred from owner_identity format (0x → secp256k1)
)
```

`bind_receipt` is purely local state priming — no network I/O, safe to
call from any context.  Idempotent on identical values; raises
`NukezError` on conflicting re-bind (different `owner_identity` or
`sig_alg` for the same `receipt_id`).

### Operator Error Classes

| Error | HTTP | Description |
|-------|------|-------------|
| `OperatorError` | -- | Base class for all operator errors |
| `InvalidOperatorPubkeyError` | 400 | Bad pubkey format |
| `OperatorIsOwnerError` | 400 | Cannot delegate to self |
| `OperatorNotAuthorizedError` | 403 | Signer not in operator list |
| `OwnerOnlyError` | 403 | Action requires owner (not operator) |
| `OperatorNotFoundError` | 404 | Removing non-existent operator |
| `OperatorConflictError` | 409 | Duplicate add or max operators reached |
| `ReceiptStateNotBoundError` | -- | Dual-key client needs `bind_receipt()` before op |

---

## Viewer Portal

The viewer portal provides agent-to-human handoff via structured container payloads. Agents build typed view payloads that render in the Nukez viewer UI.

### Container System

| Method | Returns | Description |
|--------|---------|-------------|
| `get_viewer_container_handoff(viewer_base_url, request_type, view_kind, receipt_id, locker_id, filename, blocks, renderables, embed_payload_in_url, button_label)` | `ViewerContainer` | Build generic viewer container payload |
| `get_locker_view_container(receipt_id, viewer_base_url, include_download_urls, ttl_min, embed_payload_in_url, button_label)` | `ViewerContainer` | Locker view: table + stats + links |
| `get_attestation_view_container(receipt_id, viewer_base_url, embed_payload_in_url, button_label)` | `ViewerContainer` | Attestation view: kv + status + proofs + json |
| `get_file_view_container(receipt_id, filename, viewer_base_url, ttl_min, include_download_url, embed_payload_in_url, button_label)` | `ViewerContainer` | File view: file_meta + file_preview |
| `get_viewer_container_url(viewer_base_url, request_type, receipt_id, locker_id, filename)` | `str` | Raw container URL builder |

```python
# Locker overview
container = client.get_locker_view_container(receipt.id)
print(container.viewer_url)

# Attestation proof viewer
container = client.get_attestation_view_container(receipt.id)

# Single file viewer
container = client.get_file_view_container(receipt.id, "report.pdf")
```

### URL Builders

| Method | Returns | Description |
|--------|---------|-------------|
| `get_owner_viewer_url(receipt_id, viewer_base_url)` | `ViewerLink` | Stable locker portal URL |
| `get_file_viewer_url(receipt_id, filename, viewer_base_url, ttl_min, include_download_url)` | `ViewerLink` | File-scoped viewer URL (optionally embeds download URL) |
| `list_files_with_viewer_urls(receipt_id, viewer_base_url, include_download_urls, ttl_min)` | `ViewerFileList` | Files enriched with viewer URLs |

```python
# Owner portal link
link = client.get_owner_viewer_url(receipt.id)
print(link.url)

# File viewer with embedded download
link = client.get_file_viewer_url(receipt.id, "data.json")

# All files with viewer URLs
bundle = client.list_files_with_viewer_urls(receipt.id)
for f in bundle.files:
    print(f.filename, f.viewer_url)
```

### MCP Handoff Helpers

For MCP renderers and UI button integration:

| Method | Returns | Description |
|--------|---------|-------------|
| `get_owner_viewer_handoff(receipt_id)` | `dict` | Owner portal with `ui` button payload |
| `get_file_viewer_handoff(receipt_id, filename)` | `dict` | File viewer with `ui` button payload |
| `list_files_with_viewer_handoffs(receipt_id)` | `dict` | All files with `ui` button payloads |
| `get_viewer_renderer_contract()` | `dict` | Renderer contract: `nukez.mcp.viewer_link@1.0` |
| `get_viewer_container_contract()` | `dict` | Container contract: `nukez.viewer_container@1.0.0` |

```python
payload = client.get_owner_viewer_handoff(receipt.id)
print(payload["ui"])  # {"kind": "button", "label": "Open Nukez Viewer", ...}

contract = client.get_viewer_renderer_contract()
# {"name": "nukez.mcp.viewer_link", "version": "1.0"}
```

### Renderable Helpers

Build typed content objects for container payloads:

| Method | Description |
|--------|-------------|
| `make_text_renderable(text, title)` | Plain text content card |
| `make_json_renderable(data, title)` | JSON content card |
| `make_pdf_renderable(url, title)` | PDF embed card |
| `make_image_renderable(url, title)` | Image embed card |
| `make_binary_renderable(hex_preview, size_bytes, title)` | Binary preview card |

### Block Builders

Build structured view blocks:

| Method | Description |
|--------|-------------|
| `make_header_block(title, subtitle, description)` | Section header |
| `make_stats_block(items, title)` | Key-value statistics |
| `make_links_block(links, title)` | Link list |
| `make_table_block(columns, rows, title)` | Data table |
| `make_kv_block(items, title)` | Key-value pairs |
| `make_status_block(status, label, detail)` | Status indicator |
| `make_proofs_block(proofs, title)` | Cryptographic proof material |
| `make_json_block(data, title)` | Raw JSON display |
| `make_file_meta_block(...)` | File metadata summary |
| `make_file_preview_block(...)` | Automatic file preview |

```python
# Custom container with renderables
container = client.get_viewer_container_handoff(
    request_type="file_view",
    renderables=[
        client.make_text_renderable("Analysis complete", title="Agent Note"),
        client.make_json_renderable({"score": 0.98}, title="Results"),
    ],
)

# Structured container with blocks
container = client.get_viewer_container_handoff(
    view_kind="locker",
    request_type="locker_view",
    blocks=[
        client.make_header_block("Locker Contents", subtitle="locker_abc"),
        client.make_stats_block([{"label": "Files", "value": 12}]),
        client.make_table_block(
            columns=[{"key": "filename", "label": "Filename"}],
            rows=[{"filename": "report.pdf"}],
        ),
    ],
)
```

---

## Authentication & Signing

Every mutating request to the gateway requires a signed envelope. PyNukez handles this automatically -- you do not construct envelopes manually unless building a custom integration.

### Signer Protocol

```python
from pynukez import Signer

class Signer(Protocol):
    @property
    def identity(self) -> str:    # Base58 (Ed25519) or 0x address (EVM)
        ...
    @property
    def sig_alg(self) -> str:     # "ed25519" or "secp256k1"
        ...
    def sign(self, message: bytes) -> str:  # Must be synchronous
        ...
```

### Built-in Signers

| Class | Algorithm | Identity Format | Use Case |
|-------|-----------|-----------------|----------|
| `Keypair` | Ed25519 | Base58 pubkey | Solana wallets |
| `EVMSigner` | secp256k1 | 0x address | EVM/Monad wallets |

```python
from pynukez import Keypair, EVMSigner

# Solana keypair from CLI format JSON
kp = Keypair("~/.config/solana/id.json")
print(kp.pubkey_b58, kp.sig_alg)  # "ABC..." "ed25519"

# EVM signer from private key file
signer = EVMSigner.from_file("~/.keys/evm_key.json")
print(signer.identity, signer.sig_alg)  # "0xabc..." "secp256k1"
```

### Envelope Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `build_signed_envelope(signer, receipt_id, method, path, query="", ops, body, ttl_seconds=300, delegating=False)` | `SignedEnvelope` | Create signed auth headers |
| `build_unsigned_envelope(signer_identity, sig_alg, receipt_id, method, path, query="", ops, body, ttl_seconds=300, delegating=False)` | `UnsignedEnvelope` | For relay/external signing |
| `attach_signature(unsigned, signature)` | `SignedEnvelope` | Attach signature to unsigned envelope |
| `compute_locker_id(receipt_id)` | `str` | Deterministic locker ID: `"locker_" + sha256(receipt_id)[:12]` |

```python
from pynukez import build_unsigned_envelope, attach_signature

# Relay signing flow
unsigned = build_unsigned_envelope(
    signer_identity="ABC...",
    sig_alg="ed25519",
    receipt_id="rec_123",
    method="POST",
    path="/v1/files",
)

# Sign externally (HSM, remote signer, etc.)
signature = external_signer.sign(unsigned.envelope_json.encode())

# Attach and use
signed = attach_signature(unsigned, signature)
# signed.headers -> {"X-Nukez-Envelope": "...", "X-Nukez-Signature": "..."}
```

### Envelope Contents

The signed envelope includes:
- Request method and path
- `query` — the request query string, bound by the gateway when the
  endpoint carries its arguments there (e.g. `POST /v1/storage/attest`).
  Optional; omitted for body-only endpoints.
- `body_sha256` hash for POST requests
- Timestamp with TTL (default 5 minutes, prevents replay)
- Signer's public key and algorithm
- Nonce for uniqueness
- Locker ID (derived from receipt ID)

---

## Discovery & Utilities

### Module-Level Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `discover(base_url, timeout=10.0)` | `DiscoveryDoc` | Get API capabilities from `/.well-known/nukez.json` |
| `health_check(base_url, timeout=5.0)` | `dict` | Verify API availability |
| `get_current_price(base_url, units=1)` | `PriceInfo` | Check current storage pricing |

```python
from pynukez import discover, health_check, get_current_price

doc = discover()
print(doc.api_version, doc.features)

health = health_check()
price = get_current_price(units=5)
```

### Client Utility Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_price(units=1)` | `PriceInfo` | Current storage pricing |
| `get_provider_info(provider="gcs")` | `ProviderInfo` | Provider capabilities and limits |

```python
price = client.get_price(units=1)
print(f"Cost: {price.amount_sol} SOL (${price.total_usd})")

info = client.get_provider_info("mongodb")
print(info.supports_signed_urls, info.max_object_size)
```

---

## Error Handling

All errors inherit from `NukezError`. Each has a `retryable` attribute indicating whether the operation can be retried.

| Error Class | HTTP | Retryable | Recovery |
|-------------|------|-----------|----------|
| `NukezError` | -- | No | Base class |
| `PaymentRequiredError` | 402 | No | Contains payment instructions -- this is expected from `request_storage()` |
| `TransactionNotFoundError` | -- | Yes | Wait `e.suggested_delay` seconds and retry `confirm_storage()` |
| `AuthenticationError` | 401/403 | No | Check keypair matches the one used to pay |
| `NukezFileNotFoundError` | 404 | No | Check `list_files()` or `create_file()` first |
| `URLExpiredError` | 403/410 | Yes | Call `get_file_urls()` to refresh signed URLs |
| `NukezNotProvisionedError` | 412 | No | Call `provision_locker()` first |
| `RateLimitError` | 429 | Yes | Wait `e.retry_after` seconds |

```python
from pynukez.errors import NukezError, URLExpiredError, TransactionNotFoundError

try:
    data = client.download_bytes(urls.download_url)
except URLExpiredError:
    urls = client.get_file_urls(receipt_id, filename)
    data = client.download_bytes(urls.download_url)
except NukezError as e:
    if e.retryable:
        time.sleep(2)
        # retry...
    else:
        raise
```

### PaymentRequiredError Fields

`PaymentRequiredError` is not a failure -- it's the expected response from `request_storage()` containing:

| Field | Type | Description |
|-------|------|-------------|
| `pay_req_id` | `str` | Payment request ID |
| `pay_to_address` | `str` | Destination address |
| `amount_sol` | `float` | SOL amount |
| `amount_lamports` | `int` | Lamports (Solana atomic) |
| `amount_raw` | `int` | Atomic units (any chain) |
| `pay_asset` | `str` | Token symbol |
| `network` | `str` | Chain network |
| `payment_options` | `list` | All available chain/asset options |
| `quote_expires_at` | `int` | Unix timestamp |
| `terms` | `dict` | Storage limits, TTL, file limits |

---

## Data Types Reference

All types are plain Python `@dataclass` objects.

### Payment Types

**`StorageRequest`**
| Field | Type | Description |
|-------|------|-------------|
| `pay_req_id` | `str` | Payment request ID |
| `pay_to_address` | `str` | Destination address |
| `amount_sol` | `float` | SOL amount |
| `amount_lamports` | `int` | Lamports |
| `network` | `str` | Network |
| `units` | `int` | Storage units |
| `provider` | `str` | Storage backend (default `"gcs"`) |
| `pay_asset` | `str` | Token symbol (default `"SOL"`) |
| `amount` | `str?` | Human-readable amount |
| `amount_raw` | `int?` | Atomic units |
| `token_address` | `str?` | ERC-20 contract (EVM) |
| `payment_options` | `list?` | All chain/asset combos |
| `quote_expires_at` | `int?` | Quote expiry timestamp |
| `terms` | `dict?` | Storage terms |
| `is_evm` | property | `True` if EVM payment |
| `parsed_options` | property | List of `PaymentOption` |

**`Receipt`**
| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Receipt ID (primary key for all operations) |
| `units` | `int` | Storage units purchased |
| `payer_pubkey` | `str` | Payer's public key |
| `network` | `str` | Network |
| `provider` | `str` | Storage backend |
| `pay_asset` | `str` | Payment token |
| `tx_hash` | `str` | Transaction hash |
| `sig_alg` | `str` | Signature algorithm used |
| `locker_id` | property | Derived locker ID |

**`PriceInfo`**
| Field | Type | Description |
|-------|------|-------------|
| `units` | `int` | Units priced |
| `unit_price_usd` | `float` | Per-unit USD price |
| `total_usd` | `float` | Total USD |
| `amount_sol` | `float` | SOL equivalent |
| `amount_lamports` | `int` | Lamports |
| `network` | `str` | Network |
| `payment_options` | `list?` | Chain/asset options |

**`PaymentOption`**
| Field | Type | Description |
|-------|------|-------------|
| `chain` | `str` | Chain ID (`"solana-devnet"`, `"monad-mainnet"`) |
| `asset` | `str` | Token symbol |
| `amount` | `str` | Human-readable amount |
| `amount_raw` | `int` | Atomic units |
| `treasury` | `str` | Destination address |
| `decimals` | `int` | Token decimals |
| `token_contract` | `str?` | ERC-20 address |

### File Types

**`NukezManifest`**
| Field | Type | Description |
|-------|------|-------------|
| `locker_id` | `str` | Storage namespace ID |
| `receipt_id` | `str` | Associated receipt |
| `bucket` | `str` | Storage bucket |
| `path_prefix` | `str` | Object path prefix |
| `tags` | `list` | User tags |
| `cap_token` | `str?` | Capability token |

**`FileUrls`**
| Field | Type | Description |
|-------|------|-------------|
| `filename` | `str` | File name |
| `upload_url` | `str` | Signed upload URL (PUT) |
| `download_url` | `str` | Signed download URL (GET) |
| `content_type` | `str` | MIME type |
| `expires_in_sec` | `int` | URL lifetime |

**`FileInfo`**
| Field | Type | Description |
|-------|------|-------------|
| `filename` | `str` | File name |
| `content_type` | `str` | MIME type |
| `size_bytes` | `int` | File size |
| `content_hash` | `str?` | SHA-256 hash |
| `provider_ref` | `str?` | Provider object reference |
| `created_at` | `str?` | Creation timestamp |
| `updated_at` | `str?` | Update timestamp |

**`UploadResult`** -- `upload_url`, `size_bytes`, `content_type`, `uploaded_at`

**`DeleteResult`** -- `filename`, `deleted`, `deleted_at`

### Verification Types

**`VerificationResult`**
| Field | Type | Description |
|-------|------|-------------|
| `receipt_id` | `str` | Receipt ID |
| `verified` | `bool` | Verification passed |
| `result_hash` | `str` | Verification hash |
| `merkle_root` | `str` | Merkle tree root |
| `manifest_signature` | `str` | Signed manifest |
| `file_count` | `int` | Number of files |
| `files` | `list?` | Per-file hashes and sizes |
| `verify_url` | `str` | Public verification URL |
| `status` | property | `"verified"` or `"unverified"` |
| `attested` | property | True if merkle root present |

**`ReceiptHashVerification`**
| Field | Type | Description |
|-------|------|-------------|
| `receipt_id` | `str` | Receipt ID |
| `stored_hash` | `str` | Receipt hash stored with the receipt |
| `computed_hash` | `str` | Hash recomputed by the gateway |
| `matches` | `bool` | True when stored and computed hashes match |
| `receipt` | `dict` | Raw receipt document |
| `verification` | `dict` | Raw verification response |
| `ok` | property | Alias for `matches` |
| `status` | property | `"verified"` or `"hash_mismatch"` |

**`ConfirmResult`** -- `filename`, `content_hash` (`"sha256:..."`), `size_bytes`, `confirmed`

**`BatchConfirmResult`** -- `results` (list), `confirmed_count`, `failed_count`

**`AttestResult`** -- `receipt_id`, `merkle_root`, `file_count`, `att_code`, `status`, `push_ok`, `tx_signature`

### Batch Types

**`BatchUploadResult`** -- `uploaded`, `failed`, `total`, `elapsed_sec`, `errors`, `results`

**`BatchDownloadResult`** -- `downloaded`, `failed`, `total`, `elapsed_sec`, `errors`, `files`

**`DownloadedFile`** -- `filename`, `content`, `content_hash`, `size_bytes`, `verified`

### Auth Types

**`SignedEnvelope`** -- `headers` (dict with X-Nukez-Envelope, X-Nukez-Signature), `canonical_body`, `locker_id`

**`UnsignedEnvelope`** -- `envelope` (dict), `envelope_json`, `envelope_b64`, `canonical_body`, `locker_id`

### Viewer Types

**`ViewerContainer`** -- `viewer_url`, `result`, `meta`, `contract`, `ui`

**`ViewerLink`** -- `url`, `download_url`

**`ViewerFileList`** -- `receipt_id`, `locker_id`, `owner_viewer_url`, `files`

**`FileViewerInfo`** -- `filename`, `content_type`, `viewer_url`, `download_url`, `created_at`, `updated_at`

### Operator Types

**`OperatorResult`** -- `ok`, `operator_ids`

### Discovery Types

**`DiscoveryDoc`** -- `api_version`, `service`, `description`, `auth_modes`, `endpoints`, `features`, `status`

**`ProviderInfo`** -- `id`, `supports_signed_urls`, `supports_streaming`, `max_object_size`, `immutable`, `content_addressed`

---

## Storage Providers

Pass the **Arg Name** as the `provider` kwarg to `request_storage()`, `get_provider_info()`, and other methods that accept a provider.

| Provider | Arg Name | Best For |
|----------|----------|----------|
| **Google Cloud Storage** | `"gcs"` | General-purpose, large files, proof-of-storage |
| **MongoDB** | `"mongodb"` | Fast read/write, small context/state data (16 MB per-doc limit) |
| **Filecoin** | `"filecoin"` | Content-addressed decentralized storage |
| **Arweave** | `"arweave"` | Permanent, immutable storage |
| **Firestore** | `"firestore"` | Firebase document store (1 MB per-doc limit) |
| **Storj** | `"storj"` | S3-compatible, decentralized storage |

Select a provider at storage request time:

```python
request = client.request_storage(units=1, provider="mongodb")
```

Check provider capabilities:

```python
from pynukez import PROVIDERS

for name, info in PROVIDERS.items():
    print(f"{name}: signed_urls={info.supports_signed_urls}, immutable={info.immutable}")
```

---

## Agent Integration

PyNukez is designed for LLM tool-calling patterns. Every method is stateless and returns structured data.

### Tool Definitions

```python
import pynukez

# Get LLM-compatible tool schemas
tools = pynukez.get_tool_definitions()

# Get structured guidance for autonomous agents
instructions = pynukez.get_agent_instructions()
print(instructions["quickstart_flow"])
```

### Design Principles

1. **Explicit parameters** -- No hidden state. Every method gets everything it needs as arguments.
2. **Atomic operations** -- Clear success/failure boundaries. No multi-step operations that can half-succeed.
3. **Dataclass returns** -- Predictable `.field` access. No custom objects.
4. **Agent-friendly errors** -- Error messages tell agents how to fix problems. `retryable` flag enables automated recovery.
5. **Receipt ID as primary key** -- All operations use `receipt_id` for consistent auth.

### Quick Reference (Cheat Sheet)

| What you want | Code |
|---------------|------|
| Buy storage | `request = client.request_storage()` |
| Pay | Complete the transfer with your own wallet, CLI, hardware signer, or custody workflow |
| Get receipt | `receipt = client.confirm_storage(request.pay_req_id, tx_sig=<your_tx_sig>)` |
| Setup locker | `client.provision_locker(receipt.id)` |
| Store bytes | `urls = client.create_file(receipt.id, "f.txt")` then `client.upload_bytes(urls.upload_url, data)` |
| Store file | `client.upload_file_path(receipt.id, "/path/to/file.pdf")` |
| Batch upload | `client.bulk_upload_paths(receipt.id, [{"filepath": "..."}])` |
| Get data | `data = client.download_bytes(urls.download_url)` |
| List files | `files = client.list_files(receipt.id)` |
| Delete file | `client.delete_file(receipt.id, "old.txt")` |
| Receipt hash | `check = client.verify_receipt_hash(receipt.id)` |
| Verify | `v = client.verify_storage(receipt.id)` |
| Attest | `att = client.attest(receipt.id)` |
| Delegate | `client.add_operator(receipt.id, "pubkey")` |
| Viewer link | `client.get_owner_viewer_url(receipt.id)` |

---

## Environment Variables

These are the environment variables the library actually reads. (Earlier
revisions of this document also listed `NUKEZ_NETWORK`, `NUKEZ_KEYPAIR_PATH`,
and `NUKEZ_WALLET_PATH`; the code has never read any of them — the network
and keypair path are constructor arguments, not environment variables.)

| Variable | Default | Description |
|----------|---------|-------------|
| `NUKEZ_BASE_URL` | `https://api.nukez.xyz` | Gateway API URL |
| `PYNUKEZ_UPLOAD_STRING_MAX_BYTES` | `262144` (256 KB) | Max upload_string size |
| `PYNUKEZ_SANDBOX_INGEST_PART_BYTES` | `196608` (192 KB) | Sandbox-ingest part size for chunked uploads |
| `PYNUKEZ_SANDBOX_EXECUTION_MODE` | `sandbox` | Execution mode sent with sandbox-ingest sessions |

A note on the async client: twelve public methods on `AsyncNukez` are
deliberately synchronous because they perform no I/O — `bind_receipt`,
`set_owner`, `compute_hash`, `get_provider_info`, and the viewer URL,
handoff, and contract builders. Call them without `await`; awaiting them
raises `TypeError`. Every other public method on the async client is
awaitable.

---

## Selecting Devnet Or Mainnet

```python
# Devnet (testing)
client = Nukez(keypair_path="~/.config/solana/id.json", network="devnet")

# Mainnet (production)
client = Nukez(keypair_path="~/.config/solana/id.json", network="mainnet-beta")
```

---

## Common Issues

| Problem | Fix |
|---------|-----|
| "Transaction not found" | The tx hasn't propagated yet. Wait a few seconds, retry `confirm_storage()` (auto-retries 5 times) |
| "URL expired" | `client.get_file_urls(receipt_id, filename)` for fresh URLs |
| "File not found" | Check `client.list_files(receipt_id)` |
| "Locker not provisioned" | Call `client.provision_locker(receipt_id)` first |
| "Authentication error" | Check keypair matches payer. Envelope TTL is 5 minutes. |

---

## License

MIT
