"""The control plane's device CA on disk (M12): created on first start, key kept 0600."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote

from cryptography import x509

from ..pki import CertificateAuthority, cert_pem, fingerprint, key_pem, load_cert, load_key

KEY_FILE = "ca-key.pem"
CERT_FILE = "ca.pem"


def _write(path: Path, data: str, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)


def load_or_create(directory: Path) -> CertificateAuthority:
    key_path, cert_path = directory / KEY_FILE, directory / CERT_FILE
    if key_path.exists() and cert_path.exists():
        return CertificateAuthority(load_key(key_path.read_bytes()), load_cert(cert_path.read_bytes()))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    ca = CertificateAuthority.create()
    _write(key_path, key_pem(ca.key), 0o600)
    _write(cert_path, cert_pem(ca.cert), 0o644)
    return ca


def presented_certificate(header: str | None, ca: CertificateAuthority) -> x509.Certificate | None:
    """The client certificate the LAN gateway verified (nginx ``$ssl_client_escaped_cert``)."""
    if not header:
        return None
    try:
        cert = load_cert(unquote(header))
    except ValueError:
        return None
    return cert if ca.issued(cert) else None  # the gateway checked the chain; check it again here


__all__ = ["fingerprint", "load_or_create", "presented_certificate"]
