from __future__ import annotations

import time
from typing import Dict

from models.identity_models import (
    HttpsConnectionDemoRequest,
    VerifyIntranetIdentityRequest,
)
from models.intranet_models import VerifyIntranetCertificateRequest
from services.artifacts_service import get_artifact
from services.certificate_verification_service import verify_intranet_certificate


def _require_artifact(artifact_id: str) -> dict:
    artifact = get_artifact(artifact_id)

    if artifact is None:
        raise ValueError(f"Artifact not found: {artifact_id}")

    return artifact


def _require_artifact_type(
    artifact: dict,
    expected_type: str,
) -> None:
    actual_type = artifact.get("artifact_type")

    if actual_type != expected_type:
        raise ValueError(
            f"Invalid artifact type. Expected '{expected_type}', got '{actual_type}'."
        )


def verify_intranet_identity(
    request: VerifyIntranetIdentityRequest,
) -> dict:
    """
    Verify the identity of an internal HTTPS portal using previously registered
    certificate artifacts.

    This represents the client-side trust decision in an internal HTTPS flow:
    - load trusted internal CA artifact;
    - load server certificate artifact;
    - verify certificate chain with OpenSSL;
    - verify expected intranet identity.
    """

    total_start = time.perf_counter()

    load_start = time.perf_counter()

    ca_artifact = _require_artifact(request.ca_artifact_id)
    server_artifact = _require_artifact(request.server_certificate_id)

    _require_artifact_type(ca_artifact, "ca_certificate")
    _require_artifact_type(server_artifact, "server_certificate")

    ca_pem = ca_artifact["pem"]
    server_pem = server_artifact["pem"]

    load_end = time.perf_counter()

    verification_start = time.perf_counter()

    verification = verify_intranet_certificate(
        VerifyIntranetCertificateRequest(
            ca_certificate_pem=ca_pem,
            server_certificate_pem=server_pem,
            expected_subject=request.expected_subject,
        )
    )

    verification_end = time.perf_counter()

    trusted = bool(verification["valid"])

    if trusted:
        reason = (
            "The intranet portal certificate chains to the registered internal CA "
            "and matches the expected internal HTTPS identity."
        )
    else:
        reason = verification["reason"]

    total_end = time.perf_counter()

    measurements = {
        "artifact_loading_ms": round((load_end - load_start) * 1000, 3),
        "openssl_identity_verification_ms": round(
            (verification_end - verification_start) * 1000,
            3,
        ),
        "total_identity_verification_ms": round(
            (total_end - total_start) * 1000,
            3,
        ),
    }

    steps = [
        f"Corporate client '{request.client_id}' starts an internal HTTPS trust check.",
        f"The client loads trust anchor artifact '{request.ca_artifact_id}'.",
        f"The intranet portal presents server certificate artifact '{request.server_certificate_id}'.",
        "The client verifies the server certificate chain against the internal CA.",
        f"The client checks that the certificate subject matches '{request.expected_subject}'.",
    ]

    if trusted:
        steps.append("Trust decision: portal identity accepted.")
    else:
        steps.append("Trust decision: portal identity rejected.")

    return {
        "trusted": trusted,
        "reason": reason,
        "client": {
            "client_id": request.client_id,
            "role": "internal-corporate-client",
            "trust_anchor_id": request.ca_artifact_id,
        },
        "server": {
            "server_id": "intranet-portal",
            "role": "internal-https-server",
            "certificate_id": request.server_certificate_id,
            "expected_identity": request.expected_subject,
            "certificate_subject": verification.get("certificate_subject"),
            "certificate_issuer": verification.get("certificate_issuer"),
            "certificate_dates": verification.get("certificate_dates"),
        },
        "verification": {
            "openssl_chain_valid": verification.get("openssl_verify_output") is not None
            and "OK" in str(verification.get("openssl_verify_output")),
            "subject_matches": verification.get("subject_matches"),
            "expected_subject": verification.get("expected_subject"),
            "openssl_verify_output": verification.get("openssl_verify_output"),
            "raw_result": verification,
        },
        "measurements": measurements,
        "steps": steps,
    }


def simulate_https_connection(
    request: HttpsConnectionDemoRequest,
) -> dict:
    """
    Simulate a server-authenticated internal HTTPS connection.

    This is intentionally simpler than api-mTLS:
    - only the server presents a certificate;
    - the client validates the server identity;
    - if trusted, the HTTPS connection is considered established.
    """

    total_start = time.perf_counter()

    identity_verification = verify_intranet_identity(
        VerifyIntranetIdentityRequest(
            client_id=request.client_id,
            ca_artifact_id=request.ca_artifact_id,
            server_certificate_id=request.server_certificate_id,
            expected_subject=request.expected_subject,
        )
    )

    connection_allowed = bool(identity_verification["trusted"])

    steps = [
        f"Client '{request.client_id}' requests internal resource '{request.requested_resource}'.",
        "The intranet portal presents its PQC X.509 server certificate.",
        "The client performs a server-authenticated HTTPS trust check.",
    ]

    if connection_allowed:
        steps.extend(
            [
                "Certificate validation succeeded.",
                "A server-authenticated HTTPS session is considered established.",
                "The requested internal resource is returned to the client.",
            ]
        )

        resource_response = {
            "resource": request.requested_resource,
            "message": "Private intranet resource accessed through a trusted internal HTTPS session.",
            "classification": "internal-only",
            "transport_security": "server-authenticated-https-pqc-certificate",
        }

        reason = "HTTPS connection allowed."
    else:
        steps.extend(
            [
                "Certificate validation failed.",
                "The HTTPS session is not trusted.",
                "The requested internal resource is not returned.",
            ]
        )

        resource_response = None
        reason = "HTTPS connection denied."

    total_end = time.perf_counter()

    measurements: Dict[str, float] = {
        **identity_verification["measurements"],
        "total_https_connection_demo_ms": round(
            (total_end - total_start) * 1000,
            3,
        ),
    }

    return {
        "connection_allowed": connection_allowed,
        "reason": reason,
        "client": identity_verification["client"],
        "server": identity_verification["server"],
        "identity_verification": identity_verification,
        "requested_resource": request.requested_resource,
        "resource_response": resource_response,
        "steps": steps,
        "measurements": measurements,
    }