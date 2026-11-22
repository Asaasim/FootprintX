"""TLS certificate inspection (spec §5.4) using only the standard library."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any


def fetch_certificate(host: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    """Validate the certificate chain like a browser would and summarise it.

    ``valid`` is True (trusted), False (served but failed validation — e.g. expired,
    self-signed, wrong name) or None (no TLS handshake possible).
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
            version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": exc.verify_message or str(exc)}
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"valid": None, "error": str(exc)}
    return {"valid": True, "protocol": version, **summarise(cert)}


def summarise(cert: dict[str, Any]) -> dict[str, Any]:
    def name(field: str) -> dict[str, str]:
        return {k: v for rdn in cert.get(field, ()) for k, v in rdn}

    info: dict[str, Any] = {
        "subject": name("subject").get("commonName", ""),
        "issuer": name("issuer").get("organizationName") or name("issuer").get("commonName", ""),
        "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
    }
    if "notAfter" in cert:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), UTC)
        info["not_after"] = expires.isoformat()
        info["days_left"] = (expires - datetime.now(UTC)).days
    return info
