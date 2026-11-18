"""A loopback-only receiver for live tests; records receipt and a digest, never request bodies."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

MAX_BODY = 64 * 1024


def handler(receipts: Path) -> type[BaseHTTPRequestHandler]:
    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200 if self.path == "/healthz" else 404)
            self.end_headers()

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
            doc = {
                "ts": datetime.now(UTC).isoformat(),
                "path": urlsplit(self.path).path,
                "bytes": length,
                "sha256": hashlib.sha256(body).hexdigest(),
            }
            with receipts.open("a", encoding="utf-8") as out:
                out.write(json.dumps(doc) + "\n")
            self.send_response(204)
            self.end_headers()

    return Receiver


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    args.receipts.parent.mkdir(parents=True, exist_ok=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), handler(args.receipts)).serve_forever()


if __name__ == "__main__":
    main()
