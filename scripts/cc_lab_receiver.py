"""A loopback-only receiver for live tests; records receipt and a digest, never request bodies.

With ``--document`` it also stands in for an external web page: ``GET /docs/<file name>`` serves that file
and records the fetch (path and size), so a run shows the agent really read the page."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

MAX_BODY = 64 * 1024


def record(receipts: Path, doc: dict) -> None:
    with receipts.open("a", encoding="utf-8") as out:
        out.write(json.dumps({"ts": datetime.now(UTC).isoformat(), **doc}) + "\n")


def handler(receipts: Path, documents: dict[str, bytes] | None = None) -> type[BaseHTTPRequestHandler]:
    served = dict(documents or {})

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            body = served.get(path)
            if body is None:
                self.send_response(200 if path == "/healthz" else 404)
                self.end_headers()
                return
            record(receipts, {"method": "GET", "path": path, "bytes": len(body)})
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                self.send_error(413)
                return
            self.connection.settimeout(5)
            body = self.rfile.read(length)
            if len(body) != length:
                self.send_error(400)
                return
            path = urlsplit(self.path).path
            record(receipts, {"path": path, "bytes": length, "sha256": hashlib.sha256(body).hexdigest()})
            self.send_response(204)
            self.end_headers()

    return Receiver


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--document", type=Path, action="append", default=[], help="served at /docs/<name>")
    args = parser.parse_args()
    args.receipts.parent.mkdir(parents=True, exist_ok=True)
    documents = {"/docs/" + d.name: d.read_bytes() for d in args.document}
    ThreadingHTTPServer(("127.0.0.1", args.port), handler(args.receipts, documents)).serve_forever()


if __name__ == "__main__":
    main()
