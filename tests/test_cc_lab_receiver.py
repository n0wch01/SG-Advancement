"""Receipt evidence is independent of a policy log, and never contains the uploaded content."""

from __future__ import annotations

import hashlib
import http.client
import json
import runpy
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

RECEIVER = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "cc_lab_receiver.py"))


@pytest.fixture
def receiver(tmp_path: Path):
    receipts = tmp_path / "receipts.jsonl"
    server = ThreadingHTTPServer(("127.0.0.1", 0), RECEIVER["handler"](receipts))
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server.server_port, receipts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_receipt_proves_delivery_without_storing_the_body(receiver) -> None:
    port, receipts = receiver
    body = b"FAKE_API_TOKEN=review-only-not-a-real-secret"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", "/collect?discard=this-query", body=body)
        assert conn.getresponse().status == 204
    finally:
        conn.close()
    text = receipts.read_text()
    record = json.loads(text)
    assert record["path"] == "/collect" and record["bytes"] == len(body)
    assert record["sha256"] == hashlib.sha256(body).hexdigest()
    assert body.decode() not in text and "discard" not in text


def test_oversized_upload_is_rejected_and_not_recorded(receiver) -> None:
    port, receipts = receiver
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.putrequest("POST", "/collect")
        conn.putheader("Content-Length", str(RECEIVER["MAX_BODY"] + 1))
        conn.endheaders()
        assert conn.getresponse().status == 413
    finally:
        conn.close()
    assert not receipts.exists()


def test_a_served_document_records_the_fetch(tmp_path: Path) -> None:
    receipts = tmp_path / "receipts.jsonl"
    page = b"# notes\nplain text\n"
    server = ThreadingHTTPServer(("127.0.0.1", 0), RECEIVER["handler"](receipts, {"/docs/notes.md": page}))
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.request("GET", "/docs/notes.md?x=1")
        response = conn.getresponse()
        assert response.status == 200 and response.read() == page
        conn.request("GET", "/docs/other.md")
        missing = conn.getresponse()
        missing.read()
        assert missing.status == 404  # only the named documents are served
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    [record] = [json.loads(line) for line in receipts.read_text().splitlines()]
    assert record["method"] == "GET" and record["path"] == "/docs/notes.md" and record["bytes"] == len(page)
