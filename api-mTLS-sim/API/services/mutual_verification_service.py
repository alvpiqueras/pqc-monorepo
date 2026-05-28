from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict

from models.handshake_models import MutualIdentityVerificationRequest
from services.artifact_store_service import require_artifact


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


def _verify_certificate_against_ca(
    ca_certificate_pem: str,
    certificate_pem: str,
    expected_subject: str,
    certificate_filename: str,
    role_description: str,
) -> dict:
    """
    Verify a certificate against the internal CA and check its expected subject.

    This helper is used twice in mTLS:
    - client verifies the server certificate;
    - server verifies the client certificate.
    """

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        ca_path = _write_temp_pem(
            temp_path,
            "internal_ca.cert.pem",
            ca_certificate_pem,
        )

        cert_path = _write_temp_pem(
            temp_path,
            certificate_filename,
            certificate_pem,
        )

        verify_result = _run_command(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(ca_path),
                str(cert_path),
            ]
        )

        openssl_valid = verify_result.returncode == 0

        subject = _extract_certificate_field(cert_path, "-subject")
        issuer = _extract_certificate_field(cert_path, "-issuer")
        dates = _extract_certificate_field(cert_path, "-dates")

        subject_matches = expected_subject in subject

        valid = openssl_valid and subject_matches

        if not openssl_valid:
            reason = (
                f"{role_description} certificate could not be verified against "
                "the provided internal CA."
            )
        elif not subject_matches:
            reason = (
                f"{role_description} certificate chains to the internal CA, "
                "but its subject does not match the expected identity."
            )
        else:
            reason = (
                f"{role_description} certificate is valid and matches the "
                "expected identity."
            )

        return {
            "valid": valid,
            "reason": reason,
            "expected_subject": expected_subject,
            "subject_matches": subject_matches,
            "openssl_verify_output": verify_result.stdout or verify_result.stderr,
            "certificate_subject": subject,
            "certificate_issuer": issuer,
            "certificate_dates": dates,
        }


def verify_mutual_identity(
    request: MutualIdentityVerificationRequest,
) -> dict:
    """
    Verify mutual identity for the mTLS simulation.

    This models the core trust decision in an mTLS-like flow:

    1. The client service verifies the server certificate.
    2. The server service verifies the client certificate.
    3. Mutual trust is established only if both checks succeed.
    """

    total_start = time.perf_counter()

    load_start = time.perf_counter()

    ca_artifact = require_artifact(
        request.ca_artifact_id,
        expected_type="ca_certificate",
    )

    client_artifact = require_artifact(
        request.client_certificate_id,
        expected_type="client_certificate",
    )

    server_artifact = require_artifact(
        request.server_certificate_id,
        expected_type="server_certificate",
    )

    ca_pem = ca_artifact["pem"]
    client_pem = client_artifact["pem"]
    server_pem = server_artifact["pem"]

    load_end = time.perf_counter()

    client_verification_start = time.perf_counter()

    client_verifies_server = _verify_certificate_against_ca(
        ca_certificate_pem=ca_pem,
        certificate_pem=server_pem,
        expected_subject=request.expected_server_subject,
        certificate_filename="server_service.cert.pem",
        role_description="Server service",
    )

    client_verification_end = time.perf_counter()

    server_verification_start = time.perf_counter()

    server_verifies_client = _verify_certificate_against_ca(
        ca_certificate_pem=ca_pem,
        certificate_pem=client_pem,
        expected_subject=request.expected_client_subject,
        certificate_filename="client_service.cert.pem",
        role_description="Client service",
    )

    server_verification_end = time.perf_counter()

    mutual_trust_established = bool(
        client_verifies_server["valid"]
        and server_verifies_client["valid"]
    )

    if mutual_trust_established:
        reason = (
            "Mutual trust established. The client service trusts the server "
            "certificate and the server service trusts the client certificate."
        )
    elif not client_verifies_server["valid"] and not server_verifies_client["valid"]:
        reason = (
            "Mutual trust rejected. Both server and client certificate "
            "verification failed."
        )
    elif not client_verifies_server["valid"]:
        reason = (
            "Mutual trust rejected. The client service could not trust the "
            "server service identity."
        )
    else:
        reason = (
            "Mutual trust rejected. The server service could not trust the "
            "client service identity."
        )

    total_end = time.perf_counter()

    steps = [
        f"Client service '{request.client_service_id}' initiates a connection to server service '{request.server_service_id}'.",
        "The server service presents its X.509 PQC certificate.",
        "The client service verifies the server certificate against the internal CA artifact.",
        f"The client service checks that the server certificate subject matches '{request.expected_server_subject}'.",
        "The client service presents its own X.509 PQC certificate.",
        "The server service verifies the client certificate against the same internal CA artifact.",
        f"The server service checks that the client certificate subject matches '{request.expected_client_subject}'.",
    ]

    if mutual_trust_established:
        steps.append("Mutual identity verification succeeds. The mTLS-like trust decision is accepted.")
    else:
        steps.append("Mutual identity verification fails. The mTLS-like trust decision is rejected.")

    measurements: Dict[str, float] = {
        "artifact_loading_ms": round((load_end - load_start) * 1000, 3),
        "client_side_server_verification_ms": round(
            (client_verification_end - client_verification_start) * 1000,
            3,
        ),
        "server_side_client_verification_ms": round(
            (server_verification_end - server_verification_start) * 1000,
            3,
        ),
        "total_mutual_identity_verification_ms": round(
            (total_end - total_start) * 1000,
            3,
        ),
    }

    return {
        "mutual_trust_established": mutual_trust_established,
        "reason": reason,
        "client_service": {
            "service_id": request.client_service_id,
            "role": "mtls-client-service",
            "certificate_id": request.client_certificate_id,
            "expected_subject": request.expected_client_subject,
            "certificate_subject": server_verifies_client.get("certificate_subject"),
            "certificate_issuer": server_verifies_client.get("certificate_issuer"),
        },
        "server_service": {
            "service_id": request.server_service_id,
            "role": "mtls-server-service",
            "certificate_id": request.server_certificate_id,
            "expected_subject": request.expected_server_subject,
            "certificate_subject": client_verifies_server.get("certificate_subject"),
            "certificate_issuer": client_verifies_server.get("certificate_issuer"),
        },
        "client_verifies_server": client_verifies_server,
        "server_verifies_client": server_verifies_client,
        "steps": steps,
        "measurements": measurements,
    }