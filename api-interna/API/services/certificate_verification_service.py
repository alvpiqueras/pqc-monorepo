import subprocess
import tempfile
import json
from typing import Any, Dict
from pathlib import Path

from models.internal_api_models import (VerifyServiceCertificateRequest)

from services.artifact_storage_service import (
    get_authorization_policy_json,
    get_ca_certificate_pem,
    get_service_certificate_pem,
)

from services.secure_channel_service import establish_kem_session_and_encrypt_payload


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

def verify_service_certificate(request: VerifyServiceCertificateRequest) -> dict:
    """
    Verify a calling service certificate against an internal CA certificate.

    Checks:
    - the certificate is signed by the CA;
    - the certificate subject matches the expected service identity.
    """

    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)

        ca_cert_path = _write_temp_pem(
            temp_dir,
            "ca_cert.pem",
            request.ca_certificate_pem,
        )

        service_cert_path = _write_temp_pem(
            temp_dir,
            "service_cert.pem",
            request.service_certificate_pem,
        )

        openssl_result = _run_command(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(ca_cert_path),
                str(service_cert_path),
            ]
        )

        valid = openssl_result.returncode == 0
        openssl_output = openssl_result.stdout.strip() if valid else openssl_result.stderr.strip()

        cert_subject = _extract_certificate_field(service_cert_path, "-subject")
        cert_issuer = _extract_certificate_field(service_cert_path, "-issuer")
        cert_dates = _extract_certificate_field(service_cert_path, "-dates")

        subject_matches = cert_subject.endswith(f"CN={request.expected_service_subject}")

        return {
            "valid": valid,
            "reason": (
                "Certificate is valid and signed by the trusted CA."
                if valid
                else "Certificate validation failed. See OpenSSL output for details."
            ),
            "expected_service_subject": request.expected_service_subject,
            "subject_matches": subject_matches,
            "openssl_verify_output": openssl_output,
            "certificate_subject": cert_subject,
            "certificate_issuer": cert_issuer,
            "certificate_dates": cert_dates,
        }

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

def _expected_subject_from_calling_service(calling_service: str) -> str:
    return f"{calling_service}.local"

def verify_service_certificate_by_artifact_ids(
    ca_artifact_id: str,
    service_certificate_id: str,
    expected_service_subject: str,
) -> dict:
    """
    Verify a calling service certificate using previously uploaded artifact IDs.

    This is the frontend-oriented flow:
    - the CA certificate is uploaded once;
    - the service certificate is uploaded once;
    - later checks reference both artifacts by ID.
    """

    ca_certificate_pem = get_ca_certificate_pem(ca_artifact_id)
    service_certificate_pem = get_service_certificate_pem(service_certificate_id)

    return verify_service_certificate(
        VerifyServiceCertificateRequest(
            ca_certificate_pem=ca_certificate_pem,
            service_certificate_pem=service_certificate_pem,
            expected_service_subject=expected_service_subject,
        )
    )

def check_authorization_by_policy_id(
    policy_id: str,
    calling_service: str,
    target_api: str,
    action: str,
) -> dict:
    """
    Check authorization using a stored policy artifact.
    """

    policy_json = get_authorization_policy_json(policy_id)
    policy = _load_authorization_policy(policy_json)

    result = _is_action_authorized(
        policy=policy,
        calling_service=calling_service,
        target_api=target_api,
        action=action,
    )

    authorization_valid = bool(result["action_allowed"])

    return {
        "authorization_valid": authorization_valid,
        "policy_id": policy_id,
        "calling_service": calling_service,
        "target_api": target_api,
        "requested_action": action,
        "allowed_actions": result["allowed_actions"],
        "reason": (
            "Action is allowed by the authorization policy."
            if authorization_valid
            else "Action is not allowed by the authorization policy."
        ),
    }


def simulate_internal_service_call_by_artifact_ids(
    ca_artifact_id: str,
    service_certificate_id: str,
    policy_id: str,
    calling_service: str,
    target_api: str,
    action: str,
    resource: str,
    expected_service_subject: str,
) -> dict:
    """
    Simulate an internal service call using uploaded artifact IDs.
    """
    derived_expected_subject = _expected_subject_from_calling_service(
    calling_service
    )

    if expected_service_subject != derived_expected_subject:
        raise ValueError(
            f"Expected subject mismatch. "
            f"For calling_service '{calling_service}', "
            f"expected_service_subject must be "
            f"'{derived_expected_subject}'."
        )

    ca_certificate_pem = get_ca_certificate_pem(ca_artifact_id)
    service_certificate_pem = get_service_certificate_pem(service_certificate_id)
    policy_json = get_authorization_policy_json(policy_id)

    return simulate_internal_service_call_with_policy_from_files(
        calling_service=calling_service,
        target_api=target_api,
        action=action,
        resource=resource,
        ca_certificate_pem=ca_certificate_pem,
        service_certificate_pem=service_certificate_pem,
        expected_service_subject=expected_service_subject,
        authorization_policy_json=policy_json,
    )


def simulate_secure_internal_service_call_by_artifact_ids(
    ca_artifact_id: str,
    service_certificate_id: str,
    policy_id: str,
    calling_service: str,
    target_api: str,
    action: str,
    resource: str,
    expected_service_subject: str,
    plaintext_payload: dict,
) -> dict:
    """
    Simulate a complete secure internal API-to-API flow.

    Flow:
    - verify service identity with PQC X.509 certificate;
    - check authorization using stored policy;
    - establish ML-KEM shared secret;
    - encrypt/decrypt payload with AES-GCM;
    - execute internal action only if all checks succeed.
    """

    service_call_result = simulate_internal_service_call_by_artifact_ids(
        ca_artifact_id=ca_artifact_id,
        service_certificate_id=service_certificate_id,
        policy_id=policy_id,
        calling_service=calling_service,
        target_api=target_api,
        action=action,
        resource=resource,
        expected_service_subject=expected_service_subject,
    )

    identity_valid = bool(service_call_result["certificate_verification"]["valid"])
    authorization_valid = bool(service_call_result["authorization_result"]["action_allowed"])

    steps = [
        f"Service '{calling_service}' prepares a secure request to '{target_api}'.",
        "The service identity is validated using its X.509 PQC certificate.",
        "The target API checks the external authorization policy.",
    ]

    if not identity_valid or not authorization_valid:
        return {
            "call_allowed": False,
            "identity_valid": identity_valid,
            "authorization_valid": authorization_valid,
            "kem_session_established": False,
            "payload_encrypted": False,
            "payload_decrypted": False,
            "calling_service": calling_service,
            "target_api": target_api,
            "action": action,
            "resource": resource,
            "reason": (
                "Secure internal call denied before session establishment."
            ),
            "certificate_verification": service_call_result["certificate_verification"],
            "authorization_result": service_call_result["authorization_result"],
            "kem_session_layer": {},
            "payload_protection_layer": {},
            "execution_layer": {
                "executed": False,
                "api_response": None,
            },
            "steps": steps + [
                "Identity or authorization failed. ML-KEM session establishment is skipped."
            ],
        }

    secure_channel_result = establish_kem_session_and_encrypt_payload(
        plaintext_payload=plaintext_payload
    )

    kem_ok = bool(secure_channel_result["kem_session_established"])
    payload_ok = bool(
        secure_channel_result["payload_encrypted"]
        and secure_channel_result["payload_decrypted"]
    )

    call_allowed = identity_valid and authorization_valid and kem_ok and payload_ok

    if call_allowed:
        api_response = _execute_internal_action(
            target_api=target_api,
            action=action,
            resource=resource,
            calling_service=calling_service,
        )
        reason = (
            "Secure internal service call allowed. Identity, authorization, "
            "ML-KEM session and payload protection succeeded."
        )
        steps += [
            "The target API generates an ML-KEM keypair.",
            "The calling service encapsulates a shared secret.",
            "The calling service encrypts the payload with AES-GCM.",
            "The target API decapsulates the shared secret.",
            "The target API decrypts the payload.",
            "The internal action is executed.",
        ]
    else:
        api_response = None
        reason = "Secure internal service call denied due to secure channel failure."
        steps += [
            "Secure channel establishment or payload protection failed.",
            "The internal action is not executed.",
        ]

    return {
        "call_allowed": call_allowed,
        "identity_valid": identity_valid,
        "authorization_valid": authorization_valid,
        "kem_session_established": kem_ok,
        "payload_encrypted": bool(secure_channel_result["payload_encrypted"]),
        "payload_decrypted": bool(secure_channel_result["payload_decrypted"]),
        "calling_service": calling_service,
        "target_api": target_api,
        "action": action,
        "resource": resource,
        "reason": reason,
        "certificate_verification": service_call_result["certificate_verification"],
        "authorization_result": service_call_result["authorization_result"],
        "kem_session_layer": secure_channel_result["kem_session_layer"],
        "payload_protection_layer": secure_channel_result["payload_protection_layer"],
        "execution_layer": {
            "executed": call_allowed,
            "api_response": api_response,
        },
        "steps": steps,
    }