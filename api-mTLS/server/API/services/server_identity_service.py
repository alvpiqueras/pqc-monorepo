from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict

from core.config import settings
from models.server_models import ConfigureServerIdentityRequest


SERVER_IDENTITY_STATE: Dict[str, Any] = {
    "configured": False,
    "service_id": settings.SERVICE_ID,
    "service_role": settings.SERVICE_ROLE,
    "ca_certificate_pem": None,
    "own_certificate_pem": None,
    "expected_client_subject": None,
    "certificate_metadata": {},
}


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_temp_pem(directory: Path, filename: str, content: str) -> Path:
    path = directory / filename
    path.write_text(content, encoding="utf-8")
    return path


def _extract_certificate_field(cert_path: Path, field: str) -> str:
    result = _run_command(
        [
            "openssl",
            "x509",
            "-in",
            str(cert_path),
            "-noout",
            field,
        ]
    )

    if result.returncode != 0:
        return result.stderr.strip()

    return result.stdout.strip()


def _extract_certificate_metadata(
    certificate_pem: str,
) -> tuple[Dict[str, str], Dict[str, float]]:
    """
    Extract basic X.509 metadata from the server certificate.

    This only parses the certificate. Trust verification happens later when the
    server receives a secure call from the client.
    """

    total_start = time.perf_counter()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        cert_path = _write_temp_pem(
            temp_path,
            "server_service.cert.pem",
            certificate_pem,
        )

        parse_start = time.perf_counter()

        subject = _extract_certificate_field(cert_path, "-subject")
        issuer = _extract_certificate_field(cert_path, "-issuer")
        dates = _extract_certificate_field(cert_path, "-dates")

        parse_end = time.perf_counter()

    metadata = {
        "certificate_subject": subject,
        "certificate_issuer": issuer,
        "certificate_dates": dates,
    }

    measurements = {
        "certificate_metadata_parse_ms": round(
            (parse_end - parse_start) * 1000,
            3,
        ),
        "identity_metadata_total_ms": round(
            (time.perf_counter() - total_start) * 1000,
            3,
        ),
    }

    return metadata, measurements


def configure_server_identity(
    request: ConfigureServerIdentityRequest,
) -> dict:
    """
    Configure this service as the mTLS server.

    The gateway provides:
    - the internal CA certificate;
    - the server service certificate;
    - the expected client identity.

    The material is stored in memory because this is an academic distributed
    proof of concept.
    """

    total_start = time.perf_counter()

    if "-----BEGIN CERTIFICATE-----" not in request.ca_certificate_pem:
        raise ValueError("CA certificate does not look like a PEM certificate.")

    if "-----BEGIN CERTIFICATE-----" not in request.own_certificate_pem:
        raise ValueError("Server certificate does not look like a PEM certificate.")

    metadata, measurements = _extract_certificate_metadata(
        request.own_certificate_pem
    )

    SERVER_IDENTITY_STATE["configured"] = True
    SERVER_IDENTITY_STATE["service_id"] = request.service_id
    SERVER_IDENTITY_STATE["service_role"] = settings.SERVICE_ROLE
    SERVER_IDENTITY_STATE["ca_certificate_pem"] = request.ca_certificate_pem
    SERVER_IDENTITY_STATE["own_certificate_pem"] = request.own_certificate_pem
    SERVER_IDENTITY_STATE["expected_client_subject"] = request.expected_client_subject
    SERVER_IDENTITY_STATE["certificate_metadata"] = metadata

    measurements["server_identity_configuration_total_ms"] = round(
        (time.perf_counter() - total_start) * 1000,
        3,
    )

    return {
        "configured": True,
        "reason": "Server service identity configured successfully.",
        "service_id": request.service_id,
        "service_role": settings.SERVICE_ROLE,
        "expected_client_subject": request.expected_client_subject,
        "certificate_subject": metadata.get("certificate_subject"),
        "certificate_issuer": metadata.get("certificate_issuer"),
        "certificate_dates": metadata.get("certificate_dates"),
        "measurements": measurements,
    }


def get_server_identity_status() -> dict:
    """
    Return the current in-memory identity configuration status.
    """

    metadata = SERVER_IDENTITY_STATE.get("certificate_metadata", {})

    return {
        "configured": bool(SERVER_IDENTITY_STATE.get("configured")),
        "service_id": SERVER_IDENTITY_STATE.get("service_id", settings.SERVICE_ID),
        "service_role": SERVER_IDENTITY_STATE.get("service_role", settings.SERVICE_ROLE),
        "expected_client_subject": SERVER_IDENTITY_STATE.get("expected_client_subject"),
        "certificate_subject": metadata.get("certificate_subject"),
        "certificate_issuer": metadata.get("certificate_issuer"),
        "certificate_dates": metadata.get("certificate_dates"),
        "ca_certificate_loaded": SERVER_IDENTITY_STATE.get("ca_certificate_pem") is not None,
        "own_certificate_loaded": SERVER_IDENTITY_STATE.get("own_certificate_pem") is not None,
        "measurements": {},
        "metadata": {
            "storage": "in-memory",
            "scope": "academic distributed mTLS proof of concept",
        },
    }


def require_configured_server_identity() -> dict:
    """
    Return the configured identity or fail if the service has not been bootstrapped.

    This will be used later in Phase C when the server receives the secure call.
    """

    if not SERVER_IDENTITY_STATE.get("configured"):
        raise RuntimeError(
            "Server service identity is not configured. Run gateway bootstrap first."
        )

    return SERVER_IDENTITY_STATE