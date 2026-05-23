import subprocess
import tempfile
from pathlib import Path

from models.intranet_models import (
    IntranetConnectRequest,
    VerifyIntranetCertificateRequest,
)


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


def verify_intranet_certificate(
    request: VerifyIntranetCertificateRequest,
) -> dict:
    """
    Verify an intranet server certificate against the provided internal CA.

    This simulates what an internal client would do when connecting to an
    HTTPS intranet service: validate the presented server certificate against
    a private trust anchor and check the expected server identity.
    """

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        ca_path = _write_temp_pem(
            temp_path,
            "internal_ca.cert.pem",
            request.ca_certificate_pem,
        )
        server_path = _write_temp_pem(
            temp_path,
            "intranet_server.cert.pem",
            request.server_certificate_pem,
        )

        verify_result = _run_command(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(ca_path),
                str(server_path),
            ]
        )

        openssl_valid = verify_result.returncode == 0

        subject = _extract_certificate_field(server_path, "-subject")
        issuer = _extract_certificate_field(server_path, "-issuer")
        dates = _extract_certificate_field(server_path, "-dates")

        subject_matches = request.expected_subject in subject

        valid = openssl_valid and subject_matches

        if not openssl_valid:
            reason = "Server certificate could not be verified against the provided internal CA."
        elif not subject_matches:
            reason = "Server certificate is valid, but its subject does not match the expected intranet identity."
        else:
            reason = "Server certificate is valid for the expected intranet identity."

        return {
            "valid": valid,
            "reason": reason,
            "expected_subject": request.expected_subject,
            "subject_matches": subject_matches,
            "openssl_verify_output": verify_result.stdout or verify_result.stderr,
            "certificate_subject": subject,
            "certificate_issuer": issuer,
            "certificate_dates": dates,
        }


def simulate_intranet_connection(request: IntranetConnectRequest) -> dict:
    """
    Simulate an internal client connecting to a private intranet service.

    The connection is allowed only if the intranet server certificate is valid
    and matches the expected intranet identity.
    """

    verification = verify_intranet_certificate(
        VerifyIntranetCertificateRequest(
            ca_certificate_pem=request.ca_certificate_pem,
            server_certificate_pem=request.server_certificate_pem,
            expected_subject=request.expected_subject,
        )
    )

    connection_allowed = bool(verification["valid"])

    steps = [
        f"Client '{request.client_id}' requests access to '{request.requested_resource}'.",
        "The intranet server presents an X.509 PQC certificate.",
        "The client verifies the certificate against the internal CA certificate.",
        "The client checks that the certificate subject matches the expected intranet identity.",
    ]

    if connection_allowed:
        steps.append("Certificate validation succeeded. Access to the private intranet resource is granted.")
        resource_response = {
            "resource": request.requested_resource,
            "message": "Private intranet resource accessed successfully.",
            "classification": "internal-only",
        }
        reason = "Connection allowed."
    else:
        steps.append("Certificate validation failed. Access to the private intranet resource is denied.")
        resource_response = None
        reason = "Connection denied."

    return {
        "connection_allowed": connection_allowed,
        "client_id": request.client_id,
        "requested_resource": request.requested_resource,
        "reason": reason,
        "verification": verification,
        "steps": steps,
        "resource_response": resource_response,
    }

def verify_intranet_certificate_from_files(
    ca_certificate_pem: str,
    server_certificate_pem: str,
    expected_subject: str,
) -> dict:
    """
    Verify an intranet server certificate using uploaded PEM file contents.
    """

    return verify_intranet_certificate(
        VerifyIntranetCertificateRequest(
            ca_certificate_pem=ca_certificate_pem,
            server_certificate_pem=server_certificate_pem,
            expected_subject=expected_subject,
        )
    )


def simulate_intranet_connection_from_files(
    client_id: str,
    requested_resource: str,
    ca_certificate_pem: str,
    server_certificate_pem: str,
    expected_subject: str,
) -> dict:
    """
    Simulate an intranet connection using uploaded CA/server certificate files.
    """

    return simulate_intranet_connection(
        IntranetConnectRequest(
            client_id=client_id,
            requested_resource=requested_resource,
            ca_certificate_pem=ca_certificate_pem,
            server_certificate_pem=server_certificate_pem,
            expected_subject=expected_subject,
        )
    )