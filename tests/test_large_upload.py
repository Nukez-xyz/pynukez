# tests/test_large_upload.py
"""
Tests for the large-blob resumable upload surface (SDK steps 6-10 of the
2026-08 large-blob design).

What is pinned:
  6.  create_file forwards expected_hash / expected_size_bytes / upload_mode
      only when set (so wire bodies to older gateways stay byte-identical)
      and surfaces the gateway's resumable_upload block on FileUrls.
  7.  upload_large_file streams digests, opens the session, uploads in
      aligned chunks, recovers from a mid-transfer failure by querying the
      provider's committed offset, sends the whole-object CRC32C on the
      final chunk, cross-checks the provider's committed resource, and
      routes confirm to sync below the threshold and to the finalize job at
      or above it.
  8.  finalize_upload_job and get_job sign the correct envelopes (ops,
      method, path, body).
  9.  bulk_upload_paths routes oversized files through upload_large_file,
      keeps them out of the batch create and batch confirm, and still
      counts them for the auto-attest gate.

The HTTP layers are mocked; no network access happens here.
"""
import base64
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pynukez.client import (
    Nukez,
    LARGE_UPLOAD_THRESHOLD_BYTES,
    RESUMABLE_CHUNK_ALIGN_BYTES,
)
from pynukez.errors import NukezError
from pynukez.types import FileUrls


def _decode_envelope(headers):
    raw = headers["X-Nukez-Envelope"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def _resumable_block(url="https://storage.googleapis.com/nukez/lockers/l/x.bin?sig=1"):
    return {
        "url": url,
        "method": "POST",
        "headers": {"x-goog-resumable": "start", "Content-Type": "application/octet-stream"},
        "chunk_alignment_bytes": 262144,
        "session_ttl_sec": 604800,
        "protocol": "gcs-resumable-v1",
    }


class _Resp:
    def __init__(self, status_code, headers=None, body=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


# ── 6. create_file field forwarding ───────────────────────────────────


class TestCreateFileFields:
    def test_optional_fields_absent_by_default(self, sync_client):
        sync_client.http.post.return_value = {
            "filename": "a.bin", "upload_url": "u", "download_url": "d",
        }
        with patch("pynukez.client.build_signed_envelope") as mock_env:
            mock_env.return_value = MagicMock(
                headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"},
                canonical_body="{}",
            )
            sync_client.create_file("rcpt_1", "a.bin")
        body = mock_env.call_args.kwargs["body"]
        assert "expected_hash" not in body
        assert "expected_size_bytes" not in body
        assert "upload_mode" not in body

    def test_fields_forwarded_when_set(self, sync_client):
        sync_client.http.post.return_value = {
            "filename": "a.bin", "upload_url": "u", "download_url": "d",
            "upload_mode": "resumable",
            "resumable_upload": _resumable_block(),
            "expected_hash": "sha256:" + "ab" * 32,
            "expected_size_bytes": 123,
        }
        with patch("pynukez.client.build_signed_envelope") as mock_env:
            mock_env.return_value = MagicMock(
                headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"},
                canonical_body="{}",
            )
            urls = sync_client.create_file(
                "rcpt_1", "a.bin",
                expected_hash="sha256:" + "ab" * 32,
                expected_size_bytes=123,
                upload_mode="resumable",
            )
        body = mock_env.call_args.kwargs["body"]
        assert body["expected_hash"] == "sha256:" + "ab" * 32
        assert body["expected_size_bytes"] == 123
        assert body["upload_mode"] == "resumable"
        assert isinstance(urls, FileUrls)
        assert urls.upload_mode == "resumable"
        assert urls.resumable_upload["protocol"] == "gcs-resumable-v1"
        assert urls.expected_size_bytes == 123


# ── 7. upload_large_file ──────────────────────────────────────────────


@pytest.fixture
def big_file(tmp_path):
    """A 1 MiB deterministic file (small enough for fast tests; the chunk
    size is shrunk to the 256 KiB alignment so multiple chunks happen)."""
    import random
    data = random.Random(7).randbytes(1024 * 1024)
    p = tmp_path / "big.bin"
    p.write_bytes(data)
    return p, data


class TestUploadLargeFile:
    def _client_with_resumable_create(self, sync_client, tmp_size):
        sync_client.create_file = MagicMock(return_value=FileUrls(
            filename="big.bin", upload_url="u", download_url="d",
            content_type="application/octet-stream", expires_in_sec=1800,
            upload_mode="resumable", resumable_upload=_resumable_block(),
        ))
        return sync_client

    def test_happy_path_with_interruption_and_resume(self, sync_client, big_file):
        path, data = big_file
        total = len(data)
        chunk = RESUMABLE_CHUNK_ALIGN_BYTES  # 256 KiB -> 4 chunks
        client = self._client_with_resumable_create(sync_client, total)
        client.confirm_file = MagicMock(return_value={"content_hash": "sha256:" + hashlib.sha256(data).hexdigest(), "size_bytes": total})

        session_uri = "https://storage.googleapis.com/upload/session/abc"
        calls = {"puts": []}

        def raw_request(method, url, headers=None, content=b""):
            # session opener
            assert url == _resumable_block()["url"]
            return _Resp(201, headers={"Location": session_uri})

        def raw_put(url, content=b"", headers=None):
            headers = headers or {}
            cr = headers.get("Content-Range", "")
            calls["puts"].append((cr, len(content), headers.get("x-goog-hash")))
            if cr == f"bytes */{total}":
                # status query after the injected failure: 256 KiB committed
                return _Resp(308, headers={"Range": f"bytes=0-{chunk - 1}"})
            start = int(cr.split(" ")[1].split("-")[0])
            end = int(cr.split("-")[1].split("/")[0])
            # Inject one transport failure on the SECOND data chunk
            if start == chunk and not calls.get("failed"):
                calls["failed"] = True
                import httpx
                raise httpx.ConnectError("reset")
            if end == total - 1:
                return _Resp(200, body={"size": str(total), "crc32c": calls.get("crc") or ""})
            return _Resp(308, headers={"Range": f"bytes=0-{end}"})

        client._raw_client = MagicMock()
        client._raw_client.request.side_effect = raw_request
        client._raw_client.put.side_effect = raw_put

        with patch("pynukez.client.time.sleep"):
            result = client.upload_large_file(
                "rcpt_1", str(path), chunk_bytes=chunk,
            )

        assert result["size_bytes"] == total
        assert result["sha256"] == hashlib.sha256(data).hexdigest()
        assert result["resume_count"] == 1
        assert result["confirm_path"] == "sync"
        client.confirm_file.assert_called_once_with("rcpt_1", "big.bin")
        # The final data chunk carried the whole-object checksum header
        # when CRC32C was computable in this environment.
        final_puts = [c for c in calls["puts"] if c[0].endswith(f"{total - 1}/{total}")]
        if result["crc32c_base64"]:
            assert any(h == f"crc32c={result['crc32c_base64']}" for _, _, h in final_puts)

    def test_routes_to_job_at_threshold(self, sync_client, big_file):
        path, data = big_file
        total = len(data)
        client = self._client_with_resumable_create(sync_client, total)
        client._raw_client = MagicMock()
        client._raw_client.request.return_value = _Resp(201, headers={"Location": "s"})
        client._raw_client.put.return_value = _Resp(200, body={"size": str(total)})
        client.finalize_upload_job = MagicMock(return_value={"job_id": "job_1"})
        client.get_job = MagicMock(return_value={
            "job_id": "job_1", "status": "complete", "terminal": True,
        })

        result = client.upload_large_file(
            "rcpt_1", str(path),
            chunk_bytes=1024 * 1024,
            threshold_bytes=total,  # equal -> job path
        )
        assert result["confirm_path"] == "job"
        client.finalize_upload_job.assert_called_once()
        client.get_job.assert_called_with("job_1", "rcpt_1")

    def test_job_failure_raises(self, sync_client, big_file):
        path, data = big_file
        total = len(data)
        client = self._client_with_resumable_create(sync_client, total)
        client._raw_client = MagicMock()
        client._raw_client.request.return_value = _Resp(201, headers={"Location": "s"})
        client._raw_client.put.return_value = _Resp(200, body={"size": str(total)})
        client.finalize_upload_job = MagicMock(return_value={"job_id": "job_1"})
        client.get_job = MagicMock(return_value={
            "job_id": "job_1", "status": "failed", "terminal": True,
            "error": {"message": "boom"},
        })
        with pytest.raises(NukezError, match="did not complete"):
            client.upload_large_file(
                "rcpt_1", str(path), chunk_bytes=1024 * 1024,
                threshold_bytes=total,
            )

    def test_missing_resumable_block_raises_clear_error(self, sync_client, big_file):
        path, _ = big_file
        sync_client.create_file = MagicMock(return_value=FileUrls(
            filename="big.bin", upload_url="u", download_url="d",
            content_type="application/octet-stream", expires_in_sec=1800,
        ))
        with pytest.raises(NukezError, match="resumable_upload block"):
            sync_client.upload_large_file("rcpt_1", str(path), chunk_bytes=262144)

    def test_misaligned_chunk_rejected(self, sync_client, big_file):
        path, _ = big_file
        with pytest.raises(NukezError, match="multiple"):
            sync_client.upload_large_file("rcpt_1", str(path), chunk_bytes=1000)

    def test_provider_size_disagreement_raises(self, sync_client, big_file):
        path, data = big_file
        total = len(data)
        client = self._client_with_resumable_create(sync_client, total)
        client._raw_client = MagicMock()
        client._raw_client.request.return_value = _Resp(201, headers={"Location": "s"})
        client._raw_client.put.return_value = _Resp(200, body={"size": str(total - 1)})
        with pytest.raises(NukezError, match="committed"):
            client.upload_large_file("rcpt_1", str(path), chunk_bytes=1024 * 1024)


# ── 8. finalize_upload_job / get_job envelopes ────────────────────────


class TestJobEnvelopes:
    def test_finalize_job_envelope(self, sync_client):
        sync_client.http.post.return_value = {"job_id": "job_9"}
        with patch("pynukez.client.build_signed_envelope") as mock_env:
            mock_env.return_value = MagicMock(
                headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"},
                canonical_body="{}",
            )
            out = sync_client.finalize_upload_job(
                "rcpt_1", ["big.bin"], auto_attest=True,
            )
        kw = mock_env.call_args.kwargs
        assert kw["method"] == "POST"
        assert kw["path"].endswith("/jobs/finalize-upload")
        assert kw["ops"] == ["locker:write"]
        assert kw["body"]["filenames"] == ["big.bin"]
        assert kw["body"]["auto_attest"] is True
        assert kw["body"]["receipt_id"] == "rcpt_1"
        assert out["job_id"] == "job_9"

    def test_get_job_envelope(self, sync_client):
        sync_client.http.get.return_value = {"job_id": "job_9", "status": "running"}
        with patch("pynukez.client.build_signed_envelope") as mock_env:
            mock_env.return_value = MagicMock(
                headers={"X-Nukez-Envelope": "e", "X-Nukez-Signature": "s"},
                canonical_body=None,
            )
            sync_client.get_job("job_9", "rcpt_1")
        kw = mock_env.call_args.kwargs
        assert kw["method"] == "GET"
        assert kw["path"] == "/v1/jobs/job_9"
        assert kw["ops"] == ["locker:read"]


# ── 9. bulk routing ───────────────────────────────────────────────────


class TestBulkLargeRouting:
    def test_large_file_routed_and_excluded_from_batch(self, sync_client, tmp_path, monkeypatch):
        small = tmp_path / "small.bin"; small.write_bytes(b"s" * 100)
        big = tmp_path / "big.bin"; big.write_bytes(b"b" * 2048)
        # Shrink the threshold so "big" qualifies as large.
        monkeypatch.setattr("pynukez.client.LARGE_UPLOAD_THRESHOLD_BYTES", 1024)

        sync_client.create_files_batch = MagicMock(return_value={
            "files": [{"filename": "small.bin", "upload_url": "u", "download_url": "d"}],
        })
        sync_client.upload_bytes = MagicMock()
        sync_client.confirm_files = MagicMock(return_value=MagicMock(results=[
            MagicMock(filename="small.bin", confirmed=True, content_hash="sha256:aa"),
        ]))
        sync_client.upload_large_file = MagicMock(return_value={
            "filename": "big.bin", "size_bytes": 2048,
            "sha256": "bb" * 32, "confirm_path": "job",
            "resume_count": 0,
        })
        sync_client.attest = MagicMock(return_value=MagicMock(
            status="complete", merkle_root="sha256:mm", file_count=2,
            att_code=1, push_ok=True, tx_signature="t", switchboard_slot=1,
        ))

        result = sync_client.bulk_upload_paths(
            "rcpt_1",
            [str(small), str(big)],
            confirm=True,
            auto_attest=True,
        )

        # The large file went through upload_large_file with confirm...
        sync_client.upload_large_file.assert_called_once()
        assert sync_client.upload_large_file.call_args.kwargs["confirm"] is True
        # ...and was excluded from the batch create and batch confirm.
        batch_specs = sync_client.create_files_batch.call_args.kwargs["files"]
        assert [s["filename"] for s in batch_specs] == ["small.bin"]
        confirm_names = sync_client.confirm_files.call_args.args[1]
        assert confirm_names == ["small.bin"]
        # Both rows report confirmed with hashes; attest ran (large counts).
        rows = {r["filename"]: r for r in result["files"]}
        assert rows["big.bin"]["confirmed"] is True
        assert rows["big.bin"]["content_hash"] == "sha256:" + "bb" * 32
        assert rows["small.bin"]["confirmed"] is True
        assert result["attestation"] is not None

    def test_all_large_still_attests(self, sync_client, tmp_path, monkeypatch):
        big = tmp_path / "only.bin"; big.write_bytes(b"b" * 2048)
        monkeypatch.setattr("pynukez.client.LARGE_UPLOAD_THRESHOLD_BYTES", 1024)
        sync_client.create_files_batch = MagicMock()
        sync_client.upload_large_file = MagicMock(return_value={
            "filename": "only.bin", "size_bytes": 2048,
            "sha256": "cc" * 32, "confirm_path": "job", "resume_count": 0,
        })
        sync_client.attest = MagicMock(return_value=MagicMock(
            status="complete", merkle_root="sha256:mm", file_count=1,
            att_code=1, push_ok=True, tx_signature="t", switchboard_slot=1,
        ))
        result = sync_client.bulk_upload_paths(
            "rcpt_1", [str(big)], confirm=True, auto_attest=True,
        )
        # No batch create for an all-large source list, and attest still ran.
        sync_client.create_files_batch.assert_not_called()
        assert result["attestation"] is not None
