"""TLS certificate inspection (PRD §7 A13).

``default_tls_fetch`` performs the handshake and parses the presented
certificate. It is injectable (via ``ProviderServices.tls_fetcher``) so tests
supply a fake and never open a socket. It never raises: failures come back as a
:class:`TlsInfo` with an ``error``.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TlsInfo:
    host: str
    port: int
    ok: bool
    version: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    sans: tuple[str, ...] = field(default_factory=tuple)
    validation_ok: bool | None = None
    validation_error: str | None = None
    error: str | None = None


def _parse_cert(der: bytes) -> dict:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    cert = x509.load_der_x509_certificate(der)

    def iso(attr: str) -> str | None:
        value = getattr(cert, f"{attr}_utc", None) or getattr(cert, attr, None)
        return value.isoformat() if value is not None else None

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": iso("not_valid_before"),
        "not_after": iso("not_valid_after"),
        "sans": tuple(sans),
    }


def default_tls_fetch(host: str, port: int = 443, timeout: float = 10.0) -> TlsInfo:
    """Handshake with ``host:port`` and return certificate/protocol details."""
    # Unverified handshake so we can inspect even mismatched/expired certs.
    ctx = ssl._create_unverified_context()  # noqa: S323 (inspection, not trust)
    try:
        with socket.create_connection((host, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                version = ssock.version()
                cipher = ssock.cipher()
    except (OSError, ssl.SSLError) as exc:
        return TlsInfo(host=host, port=port, ok=False, error=str(exc))

    parsed = _parse_cert(der) if der else {}

    # Separate best-effort validation (hostname + trust store).
    validation_ok: bool | None
    validation_error: str | None = None
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                validation_ok = True
    except ssl.SSLCertVerificationError as exc:
        validation_ok = False
        validation_error = str(exc)
    except (OSError, ssl.SSLError) as exc:
        validation_ok = None
        validation_error = str(exc)

    return TlsInfo(
        host=host,
        port=port,
        ok=True,
        version=version,
        cipher=cipher[0] if cipher else None,
        subject=parsed.get("subject"),
        issuer=parsed.get("issuer"),
        not_before=parsed.get("not_before"),
        not_after=parsed.get("not_after"),
        sans=parsed.get("sans", ()),
        validation_ok=validation_ok,
        validation_error=validation_error,
    )
