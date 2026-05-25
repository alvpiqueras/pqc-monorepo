import subprocess
import tempfile
import json
from typing import Any, Dict
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

def _load_authorization_policy(policy_json: str) -> Dict[str, Any]:
    """
    Load an authorization policy from a JSON string.
    """

    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid authorization policy JSON: {exc}") from exc

    if not isinstance(policy, dict):
        raise ValueError("Authorization policy must be a JSON object.")

    return policy


def _is_action_authorized(
    policy: Dict[str, Any],
    calling_service: str,
    target_api: str,
    action: str,
) -> Dict[str, Any]:
    """
    Check whether a calling service is authorized to perform an action
    against a target internal API.

    Expected policy format:

    {
      "billing-service": {
        "customer-api": [
          "read_customer_profile",
          "read_invoice_status"
        ]
      }
    }
    """

    service_policy = policy.get(calling_service, {})
    target_permissions = service_policy.get(target_api, [])

    if not isinstance(target_permissions, list):
        target_permissions = []

    action_allowed = action in target_permissions

    return {
        "calling_service": calling_service,
        "target_api": target_api,
        "requested_action": action,
        "allowed_actions": target_permissions,
        "action_allowed": action_allowed,
    }


def _execute_internal_action(
    target_api: str,
    action: str,
    resource: str,
    calling_service: str,
) -> Dict[str, Any]:
    """
    Execute a simulated internal API action.

    This is intentionally not a real backend. It demonstrates that successful
    authentication and authorization allow access to a protected internal
    operation.
    """

    if target_api == "customer-api" and action == "read_customer_profile":
        customer_id = resource.rstrip("/").split("/")[-1]

        return {
            "target_api": target_api,
            "resource": resource,
            "action": action,
            "message": "Customer profile retrieved successfully.",
            "classification": "internal-service-data",
            "data": {
                "customer_id": customer_id,
                "profile_status": "active",
                "billing_visibility": "enabled",
                "served_to": calling_service,
            },
        }

    if target_api == "customer-api" and action == "read_invoice_status":
        return {
            "target_api": target_api,
            "resource": resource,
            "action": action,
            "message": "Invoice status retrieved successfully.",
            "classification": "internal-service-data",
            "data": {
                "invoice_id": resource.rstrip("/").split("/")[-1],
                "status": "pending",
                "served_to": calling_service,
            },
        }

    return {
        "target_api": target_api,
        "resource": resource,
        "action": action,
        "message": "Generic internal action executed successfully.",
        "classification": "internal-service-data",
        "data": {
            "served_to": calling_service,
        },
    }


def simulate_internal_service_call_with_policy_from_files(
    calling_service: str,
    target_api: str,
    action: str,
    resource: str,
    ca_certificate_pem: str,
    service_certificate_pem: str,
    expected_service_subject: str,
    authorization_policy_json: str,
) -> dict:
    """
    Simulate an internal API-to-API call using:
    - a PQC X.509 service certificate;
    - an internal CA certificate;
    - an external authorization policy JSON.

    The request is accepted only if identity validation and authorization
    both succeed.
    """

    certificate_verification = verify_service_certificate(
        VerifyServiceCertificateRequest(
            ca_certificate_pem=ca_certificate_pem,
            service_certificate_pem=service_certificate_pem,
            expected_service_subject=expected_service_subject,
        )
    )

    policy = _load_authorization_policy(authorization_policy_json)

    authorization_result = _is_action_authorized(
        policy=policy,
        calling_service=calling_service,
        target_api=target_api,
        action=action,
    )

    identity_valid = bool(certificate_verification["valid"])
    authorization_valid = bool(authorization_result["action_allowed"])

    call_allowed = identity_valid and authorization_valid

    steps = [
        f"Service '{calling_service}' attempts to call '{target_api}'.",
        "The calling service presents an X.509 PQC certificate.",
        "The target API verifies the certificate against the internal CA.",
        "The target API checks that the certificate subject matches the expected service identity.",
        "The target API loads an external authorization policy.",
        "The target API checks whether the calling service is allowed to perform the requested action.",
    ]

    if call_allowed:
        api_response = _execute_internal_action(
            target_api=target_api,
            action=action,
            resource=resource,
            calling_service=calling_service,
        )
        executed_action = action
        reason = "Internal service call allowed by certificate validation and authorization policy."
        steps.append("Identity and authorization checks succeeded. The internal action is executed.")
    else:
        api_response = None
        executed_action = None

        if not identity_valid:
            reason = "Internal service call denied because service identity validation failed."
            steps.append("Certificate validation failed. The internal action is not executed.")
        elif not authorization_valid:
            reason = "Internal service call denied by authorization policy."
            steps.append("Authorization policy denied the requested action. The internal action is not executed.")
        else:
            reason = "Internal service call denied."
            steps.append("The internal action is not executed.")

    return {
        "call_allowed": call_allowed,
        "identity_valid": identity_valid,
        "authorization_valid": authorization_valid,
        "calling_service": calling_service,
        "target_api": target_api,
        "action": action,
        "resource": resource,
        "reason": reason,
        "certificate_verification": certificate_verification,
        "authorization_result": authorization_result,
        "executed_action": executed_action,
        "api_response": api_response,
        "steps": steps,
    }