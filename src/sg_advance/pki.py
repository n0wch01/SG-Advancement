"""Device certificates (M12): the X.509 pieces both sides need.

Sensors on other PCs reach the control plane over the LAN through a TLS gateway that demands a
client certificate (mTLS). At enrollment the sensor makes a key that never leaves the endpoint and
sends a CSR; the control plane's device CA signs it with the device id as the subject. The
control plane also issues the gateway's server certificate from the same CA, so a sensor trusts
exactly one root: the CA certificate it pinned at install time (by SHA-256 fingerprint).

ECDSA P-256 throughout: small, fast, supported by nginx, OpenSSL, Windows and Python's ``ssl``.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PrivateKey = ec.EllipticCurvePrivateKey


def new_key() -> PrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_pem(key: PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def load_key(pem: str | bytes) -> PrivateKey:
    key = serialization.load_pem_private_key(pem if isinstance(pem, bytes) else pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("expected an EC private key")
    return key


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def load_cert(pem: str | bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem if isinstance(pem, bytes) else pem.encode())


def fingerprint(cert: x509.Certificate | str | bytes) -> str:
    """SHA-256 of the DER certificate, lower-case hex (what the install command pins)."""
    if not isinstance(cert, x509.Certificate):
        cert = load_cert(cert)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def make_csr(key: PrivateKey, device_id: str | None) -> str:
    """The subject is only a hint: the CA sets the device id it actually enrolled."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id or "sg-advance-sensor")])
    csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _builder(subject: str, issuer: x509.Name, public_key, days: int) -> x509.CertificateBuilder:  # noqa: ANN001
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))  # tolerate small clock skew
        .not_valid_after(now + timedelta(days=days))
    )


class CertificateAuthority:
    """The control plane's device CA. Signs device (client) and gateway (server) certificates."""

    def __init__(self, key: PrivateKey, cert: x509.Certificate) -> None:
        self.key = key
        self.cert = cert

    @classmethod
    def create(cls, name: str = "SG-Advance Device CA", days: int = 3650) -> CertificateAuthority:
        key = new_key()
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (
            _builder(name, issuer, key.public_key(), days)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return cls(key, cert)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.cert)

    def sign_device(self, csr_pem: str, device_id: str, days: int) -> x509.Certificate:
        """A client certificate for ``device_id`` (the CSR's subject is ignored)."""
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except ValueError as e:
            raise ValueError(f"not a PEM certificate request: {e}") from e
        if not csr.is_signature_valid:
            raise ValueError("certificate request signature is invalid")
        pub = csr.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
            raise ValueError("device keys must be EC P-256")
        return (
            _builder(device_id, self.cert.subject, pub, days)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(self.key, hashes.SHA256())
        )

    def sign_server(self, hosts: list[str], days: int) -> tuple[x509.Certificate, PrivateKey]:
        """Certificate + key for the LAN gateway, valid for these IPs / DNS names."""
        if not hosts:
            raise ValueError("give at least one IP address or host name")
        names: list[x509.GeneralName] = []
        for h in hosts:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(h)))
            except ValueError:
                names.append(x509.DNSName(h))
        key = new_key()
        cert = (
            _builder(hosts[0], self.cert.subject, key.public_key(), days)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        return cert, key

    def issued(self, cert: x509.Certificate) -> bool:
        """Signed by this CA (checks the signature, not the dates)."""
        try:
            cert.verify_directly_issued_by(self.cert)
        except Exception:  # noqa: BLE001 - InvalidSignature, wrong key type, …
            return False
        return True
