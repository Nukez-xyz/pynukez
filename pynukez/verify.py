"""
pynukez.verify: check a Nukez evidence bundle without trusting Nukez.

This module is a vendored copy of the standalone Nukez verifier. It uses only
the Python standard library, plus PyNaCl or the cryptography package for the
Ed25519 check when one of them is installed. Fetch a bundle with
``Nukez.get_evidence_bundle(receipt_id)`` and pass it to ``verify_offline()``
and ``verify_online()``.

It answers separate questions and never folds them into one "verified"
flag. Every fact is one of: passed, failed, not_checked, unavailable.

  Offline (needs only the saved bundle, plus your files if you have them):
    merkle_root_matches     the file list in the bundle hashes to the committed root
    files_match             your local copies hash to the listed content hashes
    statement_digest_matches  the envelope body hashes to its statement digest
    signature_valid         the envelope (or version-one root) signature verifies
    key_pinned              the key used was one YOU supplied, not one the bundle supplied

  Online (needs a Solana RPC endpoint that YOU choose; it trusts that RPC):
    anchor_tx_succeeded     the anchor transaction exists and did not fail
    anchor_signer_matches   it was signed by the key the bundle names
    anchor_payload_matches  its memo carries this statement digest and this Merkle root
    anchor_slot_matches     the recorded slot is the transaction's own slot
    anchor_finalized        the cluster reports it finalized
    registry_matches        the Solana Attestation Service account holds the same statement

A saved transaction is not an offline proof of finality, so the online facts
are reported as not_checked unless an RPC endpoint is given.

Usage:
  nukez-verify bundle.json [--pin <ed25519 pubkey hex>]... [--rpc URL] [--files DIR]
  python -m pynukez.verify bundle.json [--pin <ed25519 pubkey hex>]... [--rpc URL] [--files DIR]
Exit status is 0 only when nothing failed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import urllib.request
from typing import Any, Dict, List, Optional

__all__ = ["verify_offline", "verify_online", "merkle_root_v1", "canonicalize", "main"]

PASSED, FAILED, NOT_CHECKED, UNAVAILABLE = "passed", "failed", "not_checked", "unavailable"
SIGN_DOMAIN = b"NUKEZ_CONTENT_ENVELOPE_V2\x00"
MEMO_PROGRAMS = {"MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"}
SAS_PROGRAM = "22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _strip(h: Optional[str]) -> str:
    h = (h or "").strip()
    return h[7:] if h.startswith("sha256:") else h


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


# Canonical JSON. This is a strict subset of RFC 8785, and it is written
# independently of the gateway's code.

def canonicalize(v: Any) -> bytes:
    def enc(x: Any) -> str:
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, int):
            if abs(x) > 2**53 - 1:
                raise ValueError("integer outside the interoperable range")
            return str(x)
        if isinstance(x, float):
            raise ValueError("floats are not permitted")
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, list):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            items = sorted(x.items(), key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(val) for k, val in items) + "}"
        raise ValueError(f"unsupported type {type(x).__name__}")
    return enc(v).encode("utf-8")


# The nukez-merkle-v1 algorithm. This is an independent implementation of the
# published algorithm.

def merkle_root_v1(files: List[Dict[str, Any]]) -> str:
    rows = sorted(files, key=lambda f: f["filename"])
    level = [hashlib.sha256(f"{f['filename']}:{int(f['size_bytes'])}:{_strip(f['content_hash'])}".encode("utf-8")).hexdigest()
             for f in rows]
    if not level:
        return hashlib.sha256(b"").hexdigest()
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256((level[i] + level[i + 1]).encode("utf-8")).hexdigest() for i in range(0, len(level), 2)]
    return level[0]


def _ed25519_verify(pub_hex: str, message: bytes, sig_hex: str) -> Optional[bool]:
    try:
        pub, sig = bytes.fromhex(pub_hex), bytes.fromhex(sig_hex)
    except ValueError:
        return False
    try:
        from nacl.signing import VerifyKey
        try:
            VerifyKey(pub).verify(message, sig)
            return True
        except Exception:
            return False
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
            return True
        except Exception:
            return False
    except ImportError:
        # No Ed25519 implementation is installed, so the check is unavailable.
        return None


def verify_offline(bundle: Dict[str, Any], *, pinned_keys: Optional[List[str]] = None,
                   files_dir: Optional[str] = None) -> Dict[str, str]:
    facts: Dict[str, str] = {}
    files = bundle.get("files") or []
    committed = _strip((bundle.get("commitment") or {}).get("merkle_root"))
    try:
        facts["merkle_root_matches"] = PASSED if files and merkle_root_v1(files) == committed else FAILED
    except Exception:
        facts["merkle_root_matches"] = FAILED

    if files_dir:
        ok, missing = True, False
        for f in files:
            path = os.path.join(files_dir, f["filename"])
            if not os.path.isfile(path):
                missing = True
                continue
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            if h.hexdigest() != _strip(f["content_hash"]) or os.path.getsize(path) != int(f["size_bytes"]):
                ok = False
        facts["files_match"] = FAILED if not ok else (UNAVAILABLE if missing else PASSED)
    else:
        facts["files_match"] = NOT_CHECKED

    env = bundle.get("envelope")
    pins = [k.lower() for k in (pinned_keys or [])]
    if isinstance(env, dict):
        body = env.get("body") or {}
        try:
            digest = hashlib.sha256(canonicalize(body)).digest()
            facts["statement_digest_matches"] = PASSED if digest.hex() == env.get("statement_digest") else FAILED
        except Exception:
            digest, facts["statement_digest_matches"] = b"", FAILED
        facts["envelope_binds_commitment"] = PASSED if (
            _strip(body.get("merkle_root")) == committed and int(body.get("file_count", -1)) == len(files)) else FAILED
        key = (env.get("issuer_pubkey") or "").lower()
        message, sig = SIGN_DOMAIN + digest, env.get("signature") or ""
    else:
        v1 = bundle.get("v1_signature") or {}
        facts["statement_digest_matches"] = NOT_CHECKED
        facts["envelope_binds_commitment"] = NOT_CHECKED
        keys = bundle.get("signing_keys") or []
        key = (keys[0].get("public_key_hex") if keys else "").lower()
        message, sig = committed.encode("utf-8"), v1.get("manifest_signature") or ""

    if pins:
        candidates, facts["key_pinned"] = pins, PASSED
    else:
        candidates, facts["key_pinned"] = ([key] if key else []), NOT_CHECKED
    if not sig or sig.startswith("unsigned") or not candidates:
        facts["signature_valid"] = NOT_CHECKED
    else:
        results = [_ed25519_verify(k, message, sig) for k in candidates]
        facts["signature_valid"] = UNAVAILABLE if all(r is None for r in results) else (PASSED if any(results) else FAILED)
    return facts


def _rpc(url: str, method: str, params: list) -> Any:
    req = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = json.loads(resp.read())
    if "error" in body:
        raise RuntimeError(str(body["error"])[:200])
    return body.get("result")


def verify_online(bundle: Dict[str, Any], rpc_url: str) -> Dict[str, str]:
    names = ("anchor_tx_succeeded", "anchor_signer_matches", "anchor_payload_matches", "anchor_slot_matches",
             "anchor_finalized", "registry_matches")
    anchor = bundle.get("anchor") or {}
    if not anchor.get("tx"):
        return {n: NOT_CHECKED for n in names}
    facts = {n: UNAVAILABLE for n in names}
    try:
        tx = _rpc(rpc_url, "getTransaction", [anchor["tx"], {"encoding": "json", "commitment": "confirmed",
                                                             "maxSupportedTransactionVersion": 0}])
    except Exception:
        return facts
    if not tx:
        return facts
    meta, msg = tx.get("meta") or {}, (tx.get("transaction") or {}).get("message") or {}
    keys = list(msg.get("accountKeys") or [])
    facts["anchor_tx_succeeded"] = PASSED if meta.get("err") is None else FAILED
    n_signers = int((msg.get("header") or {}).get("numRequiredSignatures") or 0)
    signer = anchor.get("signer")
    facts["anchor_signer_matches"] = (PASSED if signer in keys[:n_signers] else FAILED) if signer else NOT_CHECKED
    facts["anchor_slot_matches"] = (PASSED if tx.get("slot") == anchor.get("slot") else FAILED) if anchor.get("slot") else NOT_CHECKED

    env = bundle.get("envelope") or {}
    want_digest = env.get("statement_digest")
    want_root = _strip((bundle.get("commitment") or {}).get("merkle_root"))
    memo_ok: Optional[bool] = None
    for ix in msg.get("instructions") or []:
        if keys[ix["programIdIndex"]] in MEMO_PROGRAMS:
            try:
                memo = json.loads(b58decode(ix["data"]).decode("utf-8"))
            except Exception:
                memo_ok = False
                continue
            if want_digest:
                # This is a version two payload.
                memo_ok = memo.get("dg") == want_digest and memo.get("root") == want_root
            else:
                # This is a version one payload from the Switchboard era.
                memo_ok = _strip(memo.get("merkle_root")) == want_root
    facts["anchor_payload_matches"] = NOT_CHECKED if memo_ok is None else (PASSED if memo_ok else FAILED)

    try:
        st = (_rpc(rpc_url, "getSignatureStatuses", [[anchor["tx"]], {"searchTransactionHistory": True}]) or {}).get("value", [None])[0]
        facts["anchor_finalized"] = PASSED if (st or {}).get("confirmationStatus") == "finalized" else NOT_CHECKED
    except Exception:
        pass

    sas_meta = anchor.get("sas") or {}
    if sas_meta.get("attestation") and want_digest:
        try:
            acct = (_rpc(rpc_url, "getAccountInfo", [sas_meta["attestation"], {"encoding": "base64", "commitment": "confirmed"}]) or {}).get("value")
            if not acct:
                # The account was closed or was replaced by a later snapshot.
                # The memo transaction remains the permanent record.
                facts["registry_matches"] = UNAVAILABLE
            elif acct.get("owner") != SAS_PROGRAM:
                facts["registry_matches"] = FAILED
            else:
                raw = base64.b64decode(acct["data"][0])
                (dlen,) = struct.unpack_from("<I", raw, 97)
                data = raw[101:101 + dlen]
                fields, o = [], 0
                for _ in range(4):
                    (n,) = struct.unpack_from("<I", data, o)
                    fields.append(data[o + 4:o + 4 + n])
                    o += 4 + n
                same = fields[2].hex() == want_digest and fields[3].hex() == want_root and \
                    fields[0].hex() == (env.get("body") or {}).get("proof_id")
                # A newer snapshot legitimately replaces the account in
                # latest-state mode, so a different statement under the same
                # proof id is reported as unavailable and not as failed.
                facts["registry_matches"] = PASSED if same else (UNAVAILABLE if fields[0].hex() == (env.get("body") or {}).get("proof_id") else FAILED)
        except Exception:
            facts["registry_matches"] = UNAVAILABLE
    else:
        facts["registry_matches"] = NOT_CHECKED
    return facts


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle")
    ap.add_argument("--pin", action="append", default=[], help="a Nukez Ed25519 public key (hex) that you trust")
    ap.add_argument("--rpc", help="a Solana RPC endpoint you choose, for the online facts")
    ap.add_argument("--files", help="a directory holding your copies of the files")
    args = ap.parse_args(argv)
    with open(args.bundle, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    facts = verify_offline(bundle, pinned_keys=args.pin, files_dir=args.files)
    facts.update(verify_online(bundle, args.rpc) if args.rpc else
                 {k: NOT_CHECKED for k in ("anchor_tx_succeeded", "anchor_signer_matches", "anchor_payload_matches",
                                           "anchor_slot_matches", "anchor_finalized", "registry_matches")})
    print(json.dumps({"bundle_version": bundle.get("bundle_version"), "anchor_type": (bundle.get("anchor") or {}).get("type"),
                      "facts": facts}, indent=2))
    if not args.pin:
        print("note: no --pin given; the signature was checked against the key inside the bundle, "
              "which proves self-consistency only.", file=sys.stderr)
    return 1 if FAILED in facts.values() else 0


if __name__ == "__main__":
    raise SystemExit(main())
