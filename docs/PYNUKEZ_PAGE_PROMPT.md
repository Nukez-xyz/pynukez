# Frontend Builder Prompt: PyNukez SDK Page for nukez.xyz

## Context

You are building a new page for the Nukez website (nukez.xyz) that presents the **PyNukez Python SDK**. This page will live at `nukez.xyz/sdk/python` (or `nukez.xyz/pynukez`) and be linked from the main navigation.

The existing site uses:
- **Fonts**: "Press Start 2P" (headings/accents), "JetBrains Mono" (code/body)
- **Accent color**: `#02fffd` (neon cyan)
- **Stack**: Next.js with React Server Components
- **Tone**: Technical, retro-futuristic, crypto-native, developer-focused
- **Existing nav**: BLOG, DEMOS, DECLARATION, TRY IT, DOCS
- **Landing hero**: "On-Demand Storage for Autonomous Agents"
- **Tagline**: "Agent-native, trustless storage infrastructure. Independently verifiable -- without trusting anyone, including us."

The page should match the existing design language while serving as both a marketing page (convince developers to use PyNukez) and a functional reference (help them get started immediately).

---

## Page Structure & Component Layout

### 1. Hero Section

**Headline**: `PyNukez`
**Subhead**: `The Python SDK for agent-native storage with cryptographic verification.`
**One-liner**: `Pay with SOL or MON. Store anything. Get a cryptographic receipt. Verify independently.`

**Key stats row** (pill/badge components):
- `v4.0.13`
- `Python 3.9+`
- `MIT License`
- `pip install pynukez`

**Primary CTA**: "Get Started" (scrolls to Quick Start)
**Secondary CTA**: "GitHub" (links to https://github.com/Nukez-xyz/pynukez)

---

### 2. Install Strip

A horizontal bar or card with install variants. Use a tab/toggle component:

| Tab Label | Command |
|-----------|---------|
| Install | `pip install pynukez` |
| Dev tools | `pip install pynukez[dev]` |

Each install command should be in a styled code block with a copy button.

Core dependencies: `httpx`, `pynacl`, `base58` (no pydantic, no python-dotenv).

---

### 3. Quick Start Code Block

A full-width, syntax-highlighted code card showing the 8-step flow. This is the most important content on the page -- it should be immediately visible and copy-pasteable.

```python
import webbrowser
from pathlib import Path
from pynukez import Nukez

client = Nukez(
    keypair_path="~/.config/solana/id.json",  # local Ed25519 envelope signer
)

# 1. Check pricing
price = client.get_price()

# 2. Request storage (returns x402 payment instructions).
#    Complete payment with your own wallet, CLI, signer, or custody workflow.
request = client.request_storage(units=1)

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

Below the code block, a callout:
> **That's it.** Your agent now has permanent storage with a cryptographic receipt.

---

### 4. How It Works -- Visual Flow

A horizontal pipeline/flowchart component with 4 stages. Use the neon cyan accent for connectors/arrows.

```
[Request Storage] --> [Pay Externally] --> [Confirm & Receipt] --> [Store / Verify]
```

**Stage 1: Request**
- `client.request_storage(units=1)`
- Gateway returns payment instructions via x402 protocol
- Multi-chain: choose SOL, MON, USDC, USDT, or WETH

**Stage 2: Pay (externally)**
- pynukez does NOT execute on-chain transfers
- Use your wallet, CLI, or any other signer to send the amount
- Capture the resulting tx signature for the next step

**Stage 3: Confirm**
- `client.confirm_storage(pay_req_id, tx_sig=<your_tx_signature>)`
- Gateway verifies on-chain, returns cryptographic receipt
- Receipt ID is the primary SDK handle. It should be persisted for ergonomic lookups, while on-chain payment history gives a recovery path if a local copy is lost.

**Stage 4: Store & Verify**
- `create_file`, `upload_bytes`, `download_bytes`
- `verify_receipt_hash` recomputes and compares the receipt object's canonical hash
- `verify_storage` returns merkle root and attestation
- Independent verification -- no trust required

---

### 5. Multi-Chain Payment Support

A table or card grid showing supported payment options:

| Chain | Tokens | Signature |
|-------|--------|-----------|
| Solana | SOL, USDC, USDT | Ed25519 |
| Monad (EVM) | MON, WETH | secp256k1 |

Note: "The gateway returns all available payment options in the 402 response. The SDK auto-selects based on your configured signer, or you can specify `pay_network` and `pay_asset` explicitly."

---

### 6. Feature Cards Grid

A 2x3 or 3x2 grid of feature cards. Each card has an icon, title, and 1-2 line description.

**Card 1: Agent-Native Design**
Every method is a self-contained tool. Explicit parameters, predictable dataclass returns, no hidden state. Built for LLM tool-calling patterns.

**Card 2: Multi-Chain Payment Boundary**
Pay with SOL on Solana or MON/WETH on Monad. PyNukez provides the quote and confirms the transaction signature; your wallet, CLI, signer, or custody workflow executes the transfer. Ed25519 + secp256k1 envelope signing.

**Card 3: Cryptographic Verification**
SHA-256 content hashes, merkle tree attestation, and an on-chain anchor. Independently verifiable without trusting anyone.

**Card 4: Operator Delegation**
Delegate file operations to other signers without sharing keys. Owner adds/removes operators. Operators sign with their own identity.

**Card 5: Multiple Storage Backends**
GCS (archival), MongoDB (fast small data), Storj (decentralized), Arweave (permanent), Filecoin (content-addressed). Select per-locker.

**Card 6: Sync + Async**
`Nukez` (sync) and `AsyncNukez` (async) with full method parity. Same signatures, same return types. Use async for FastAPI, MCP servers, event loops.

---

### 7. API Quick Reference

A compact, scannable table showing the most common operations. Use a monospace code font for the "Code" column.

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

### 8. Upload Methods Comparison

Developers need to quickly understand which upload method to use. A comparison card or decision-tree component:

| Method | Best For | Context Bloat? |
|--------|----------|----------------|
| `upload_bytes()` | Small in-memory data | Yes -- data passes through LLM context |
| `upload_string()` | Agent-generated text | Yes -- auto-sanitizes formatting artifacts |
| `upload_file_path()` | Single local file | No -- reads from disk directly |
| `bulk_upload_paths()` | Multiple local files | No -- parallel, batch confirm |
| `upload_directory()` | Whole directories | No -- glob filtering, recursive |

Callout: "For LLM/agent workflows, prefer path-based uploads (`upload_file_path`, `bulk_upload_paths`) to avoid sending file content through the context window."

Secondary callout: "Advanced constrained-runtime fallback: PyNukez also exposes `sandbox_upload_*` helpers for MCP/provider-hosted runtimes where local path handling or direct signed-URL uploads are restricted. Most Python users should start with the methods above."

---

### 9. Async Usage Section

Side-by-side code comparison (two-column layout or toggle):

**Sync:**
```python
from pynukez import Nukez

with Nukez(keypair_path="key.json") as client:  # local Ed25519 envelope signer
    files = client.list_files(receipt_id)
```

**Async:**
```python
from pynukez import AsyncNukez

async with AsyncNukez(keypair_path="key.json") as client:  # local Ed25519 envelope signer
    files = await client.list_files(receipt_id)
```

Note: "Same method names. Same parameters. Same return types. The only difference is `async/await`."

---

### 10. Error Handling Section

A styled table showing errors, whether they're retryable, and how to recover:

| Error | Retryable | What To Do |
|-------|-----------|------------|
| `TransactionNotFoundError` | Yes | Wait `e.suggested_delay` seconds, retry `confirm_storage()` |
| `URLExpiredError` | Yes | Call `get_file_urls()` for fresh URLs |
| `RateLimitError` | Yes | Wait `e.retry_after` seconds |
| `NukezFileNotFoundError` | No | Check `list_files()` -- file may not exist yet |
| `NukezNotProvisionedError` | No | Call `provision_locker()` first |
| `AuthenticationError` | No | Check keypair matches payer. Envelope TTL is 5 min. |

Code example showing the retry pattern:

```python
from pynukez.errors import NukezError, URLExpiredError

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

---

### 11. Storage Providers

A card grid or icon row showing the 5 supported backends:

| Provider | Best For | Immutable |
|----------|----------|-----------|
| **GCS** | Archival, large files, proof-of-storage | No |
| **MongoDB** | Fast read/write, small context/state data | No |
| **Storj** | S3-compatible, decentralized | No |
| **Arweave** | Permanent storage | Yes |
| **Filecoin** | Content-addressed storage | Yes |

"Select a provider when requesting storage: `client.request_storage(units=1, provider='mongodb')`"

---

### 12. Verification & Attestation

This is a differentiator -- emphasize it visually. A step-flow or diagram:

```
Upload Files --> Confirm Hashes --> Attest (Merkle Root) --> Verify On-Chain
```

```python
# 1. Confirm file hashes
client.confirm_file(receipt.id, "report.pdf")

# 2. Generate merkle attestation
att = client.attest(receipt.id)
print(att.merkle_root)  # "sha256:..."

# 3. Verify the receipt object's canonical hash
check = client.verify_receipt_hash(receipt.id)
assert check.matches == True

# 4. Verify independently (anyone can do this)
v = client.verify_storage(receipt.id)
assert v.verified == True
```

Callout: "Verification is public. Agent B can verify Agent A's data using only the receipt ID. No shared keys, no shared accounts."

---

### 13. Operator Delegation

A brief explanation with a visual showing Owner -> Operator relationship:

```
[Owner] --add_operator()--> [Operator]
                             |
                             v
                        [File Operations]
                        create_file, upload, download
```

```python
# Owner authorizes an operator
client.add_operator(receipt.id, operator_pubkey)

# Operator uses their own signer
operator_client = Nukez(keypair_path="operator_key.json")
urls = operator_client.create_file(receipt.id, "delegated.txt")

# Owner revokes when done
client.remove_operator(receipt.id, operator_pubkey)
```

---

### 14. Agent Integration Section

Emphasize the LLM tool-calling angle -- this is the primary audience.

```python
import pynukez

# Get LLM-compatible tool schemas (OpenAI function calling format)
tools = pynukez.get_tool_definitions()

# Get structured instructions for autonomous agents
instructions = pynukez.get_agent_instructions()
```

Design principles (as a bulleted list or icon row):
- **Explicit parameters** -- no hidden state, every method gets everything it needs
- **Atomic operations** -- clear success/failure, no half-succeeded multi-step ops
- **Dataclass returns** -- predictable `.field` access, no custom objects
- **Agent-friendly errors** -- messages tell agents how to fix problems, `retryable` flag for auto-recovery
- **Receipt ID as primary key** -- one handle for all operations

---

### 15. Client Initialization Options

A tabbed component showing different setup patterns:

**Tab: Solana**
```python
client = Nukez(
    keypair_path="~/.config/solana/id.json",
    network="devnet",
)
```

**Tab: EVM/Monad**
```python
client = Nukez(
    evm_private_key_path="~/.keys/evm_key.json",
    network="devnet",
)
```

**Tab: Dual-Key**
```python
client = Nukez(
    keypair_path="~/.config/solana/id.json",
    evm_private_key_path="~/.keys/evm_key.json",
)
```

**Tab: Custom Signer**
```python
client = Nukez(signing_key=my_custom_signer)
```

Constructor parameter table:

Make the signer boundary explicit near this table: `keypair_path` is one
supported signer source, not a requirement and not magic signing. Protected
locker/file operations still require a signer source: `keypair_path`,
`evm_private_key_path`, or an explicit `signing_key`.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `keypair_path` | -- | Local Ed25519 keypair JSON for envelope signing |
| `base_url` | `https://api.nukez.xyz` | Gateway API URL |
| `network` | `"devnet"` | `"devnet"` or `"mainnet-beta"` |
| `evm_private_key_path` | -- | EVM private key for secp256k1 envelope signing |
| `evm_rpc_url` | -- | Reserved; currently unused at the SDK layer |
| `signing_key` | -- | Explicit `Signer` instance |

---

### 16. Selecting Devnet Or Mainnet

Choose the target network explicitly when constructing the client:

```python
# Devnet (testing)
client = Nukez(keypair_path="key.json", network="devnet")

# Mainnet (production)
client = Nukez(keypair_path="key.json", network="mainnet-beta")
```

---

### 17. Common Issues (Troubleshooting)

A compact FAQ/accordion component:

| Problem | Fix |
|---------|-----|
| "Transaction not found" | Wait 3 seconds, retry `confirm_storage()` (auto-retries 5x) |
| Transfer tooling | Use your own wallet, CLI, preferred signer, or custody workflow |
| "URL expired" | `client.get_file_urls(receipt_id, filename)` for fresh URLs |
| "File not found" | Check `client.list_files(receipt_id)` |
| "Locker not provisioned" | Call `client.provision_locker(receipt_id)` first |
| "Authentication error" | Check keypair matches payer. Envelope TTL is 5 minutes. |

---

### 18. Footer CTA

**Headline**: "Start building in 30 seconds"
**Command**: `pip install pynukez` (with copy button)
**Links row**: [PyNukez Docs](https://nukez.xyz/docs/pynukez) | [Full SDK Reference](https://nukez.xyz/docs/pynukez/reference) | [Examples](https://nukez.xyz/docs/pynukez/examples) | [Python Helpers](https://nukez.xyz/docs/pynukez/helpers) | [GitHub](https://github.com/Nukez-xyz/pynukez)

---

## Content Accuracy Notes

These facts are verified against the source code (pynukez v4.0.13) and must be presented accurately:

1. **Python >= 3.9** (not 3.11+)
2. **Core deps**: `httpx`, `pynacl`, `base58` (NOT pydantic, NOT python-dotenv, NOT requests)
3. **Install extras**: only `[dev]` exists. Envelope signing for both Solana-paid (Ed25519) and EVM-paid (secp256k1) lockers ships in the base install — no separate `[solana]` or `[evm]` target.
4. **Two clients**: `Nukez` (sync) and `AsyncNukez` (async) with full parity
5. **Errors**: `NukezFileNotFoundError` (NOT `LockerFileNotFoundError`)
6. **Default workers**: 6 for `bulk_upload_paths` and `upload_files`
7. **Data types**: plain Python `@dataclass` (NOT pydantic models)
8. **No config file system** -- only env vars and constructor params
9. **`request_storage(provider=...)`** works -- provider selection is functional
10. **`attest(receipt_id, sync=True)`** exists and works
11. **Multi-chain**: Solana (Ed25519) + EVM/Monad (secp256k1)
12. **Payment assets**: SOL, USDC, USDT on Solana; MON, WETH on Monad
13. **Signer protocol**: `Keypair` (Ed25519), `EVMSigner` (secp256k1), custom `Signer`
14. **60+ public methods** on the client
15. **25+ dataclass types**
16. **15 error classes** with `retryable` flag
17. **Viewer portal**: ~15 methods for agent-to-human handoff
18. **Sandbox ingest**: 6 methods for restricted runtimes

---

## Design Guidance

- **Code is king**: This audience (AI/agent developers) wants to see working code immediately. The quick start block should be above the fold.
- **Scannable tables**: Use tables for the API reference, error handling, and constructor params. Developers skim, they don't read paragraphs.
- **Copy buttons**: Every code block needs a copy-to-clipboard button.
- **Syntax highlighting**: Python syntax highlighting with the JetBrains Mono font. Use the neon cyan accent for keywords or method names if possible.
- **Don't bury the install command**: `pip install pynukez` should be visible within 2 seconds of page load.
- **Mobile responsive**: Tables should scroll horizontally on mobile rather than wrapping.
- **Dark theme**: Match the existing site's dark aesthetic. Code blocks should use a dark syntax theme.
- **Navigation**: Consider a sticky sidebar TOC for the reference sections (like modern docs sites) -- the page has 17+ sections.
- **No fluff**: This audience hates marketing speak. Let the code and capabilities sell themselves. Short sentences, direct language.
