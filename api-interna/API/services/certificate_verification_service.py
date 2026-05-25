import subprocess
import tempfile
from pathlib import Path

from models.internal_api_models import (
    ServiceCallRequest,
    VerifyServiceCertificateRequest,
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


def verify_service_certificate(
    request: VerifyServiceCertificateRequest,
) -> dict:
    """
    Verify a calling microservice certificate against the provided internal CA.

    This simulates what an internal API would do before accepting a request
    from another internal service.
    """

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        ca_path = _write_temp_pem(
            temp_path,
            "internal_ca.cert.pem",
            request.ca_certificate_pem,
        )
        service_cert_path = _write_temp_pem(
            temp_path,
            "calling_service.cert.pem",
            request.service_certificate_pem,
        )

        verify_result = _run_command(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(ca_path),
                str(service_cert_path),
            ]
        )

        openssl_valid = verify_result.returncode == 0

        subject = _extract_certificate_field(service_cert_path, "-subject")
        issuer = _extract_certificate_field(service_cert_path, "-issuer")
        dates = _extract_certificate_field(service_cert_path, "-dates")

        subject_matches = request.expected_service_subject in subject
        valid = openssl_valid and subject_matches

        if not openssl_valid:
            reason = (
                "Calling service certificate could not be verified against "
                "the provided internal CA."
            )
        elif not subject_matches:
            reason = (
                "Calling service certificate is valid, but its subject does "
                "not match the expected service identity."
            )
        else:
            reason = (
                "Calling service certificate is valid for the expected "
                "internal service identity."
            )

        return {
            "valid": valid,
            "reason": reason,
            "expected_service_subject": request.expected_service_subject,
            "subject_matches": subject_matches,
            "openssl_verify_output": verify_result.stdout or verify_result.stderr,
            "certificate_subject": subject,
            "certificate_issuer": issuer,
            "certificate_dates": dates,
        }


def simulate_internal_service_call(
    request: ServiceCallRequest,
) -> dict:
    """
    Simulate an internal API-to-API call.

    The target API accepts the request only if:
    - the calling service certificate chains to the internal CA;
    - the certificate subject matches the expected service identity;
    - the requested action is allowed.
    """

    certificate_verification = verify_service_certificate(
        VerifyServiceCertificateRequest(
            ca_certificate_pem=request.ca_certificate_pem,
            service_certificate_pem=request.service_certificate_pem,
            expected_service_subject=request.expected_service_subject,
        )
    )

    action_allowed = request.action in request.allowed_actions
    certificate_valid = bool(certificate_verification["valid"])

    call_allowed = certificate_valid and action_allowed

    steps = [
        (
            f"Service '{request.calling_service}' attempts to call "
            f"'{request.target_api}'."
        ),
        "The calling service presents an X.509 PQC certificate.",
        "The target API verifies the certificate against the internal CA.",
        "The target API checks that the certificate subject matches the expected service identity.",
        "The target API checks whether the requested action is allowed.",
    ]

    authorization_result = {
        "requested_action": request.action,
        "allowed_actions": request.allowed_actions,
        "action_allowed": action_allowed,
    }

    if call_allowed:
        steps.append("Certificate and authorization checks succeeded. Internal API call is accepted.")
        reason = "Internal service call allowed."
        api_response = {
            "target_api": request.target_api,
            "resource": request.resource,
            "message": "Internal API request processed successfully.",
            "classification": "internal-service-data",
            "demo_payload": {
                "customer_id": "123",
                "profile_status": "active",
                "served_to": request.calling_service,
            },
        }
    else:
        steps.append("One or more checks failed. Internal API call is denied.")
        reason = "Internal service call denied."
        api_response = None

    return {
        "call_allowed": call_allowed,
        "calling_service": request.calling_service,
        "target_api": request.target_api,
        "action": request.action,
        "resource": request.resource,
        "reason": reason,
        "certificate_verification": certificate_verification,
        "authorization_result": authorization_result,
        "steps": steps,
        "api_response": api_response,
    }


def verify_service_certificate_from_files(
    ca_certificate_pem: str,
    service_certificate_pem: str,
    expected_service_subject: str,
) -> dict:
    return verify_service_certificate(
        VerifyServiceCertificateRequest(
            ca_certificate_pem=ca_certificate_pem,
            service_certificate_pem=service_certificate_pem,
            expected_service_subject=expected_service_subject,
        )
    )


def simulate_internal_service_call_from_files(
    calling_service: str,
    target_api: str,
    action: str,
    resource: str,
    allowed_actions: list[str],
    ca_certificate_pem: str,
    service_certificate_pem: str,
    expected_service_subject: str,
) -> dict:
    return simulate_internal_service_call(
        ServiceCallRequest(
            calling_service=calling_service,
            target_api=target_api,
            action=action,
            resource=resource,
            allowed_actions=allowed_actions,
            ca_certificate_pem=ca_certificate_pem,
            service_certificate_pem=service_certificate_pem,
            expected_service_subject=expected_service_subject,
        )
    )