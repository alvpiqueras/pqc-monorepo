from fastapi import APIRouter, File, HTTPException, UploadFile, Query

from core.config import settings

from models.internal_api_models import (
    AuthorizationCheckByIdRequest,
    AuthorizationCheckResponse,
    SecureServiceCallByIdRequest,
    SecureServiceCallResponse,
    ServiceCallByIdRequest,
    ServiceCallWithPolicyResponse,
    VerifyServiceCertificateByIdRequest,
    VerifyServiceCertificateResponse,
)

from models.artifact_models import (
    ArtifactInfoResponse,
    StoredArtifactResponse,
    StoredPolicyResponse,
)

from services.certificate_verification_service import (
    check_authorization_by_policy_id,
    simulate_internal_service_call_by_artifact_ids,
    simulate_secure_internal_service_call_by_artifact_ids,
    verify_service_certificate_by_artifact_ids,
)

from services.artifact_storage_service import (
    get_artifact_info,
    store_authorization_policy,
    store_ca_certificate,
    store_service_certificate,
)


router = APIRouter(
    prefix="/internal-api",
    tags=["Internal APIs"],
)


@router.get("/info")
def get_internal_api_info():
    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "role": "internal-api-certificate-consumer",
        "default_calling_service_subject": settings.CALLING_SERVICE_DEFAULT_SUBJECT,
        "default_target_api": settings.TARGET_API_DEFAULT_NAME,
    }


@router.get("/scenario")
def get_internal_api_scenario():
    return {
        "title": "Internal APIs and Microservices with PQC Certificate Validation",
        "summary": (
            "This API simulates a service-to-service request inside a private "
            "microservices environment. The calling service presents an X.509 "
            "PQC certificate issued by the internal CA, and the target API "
            "verifies that identity before accepting the request."
        ),
        "actors": {
            "calling_service": "Example: billing-service.",
            "target_api": "Example: customer-api.",
            "internal_ca": "Private PQC certificate authority that issued the service certificate.",
        },
        "flow": [
            "The calling service attempts to access an internal API.",
            "The calling service presents its X.509 PQC certificate.",
            "The target API verifies the certificate against the internal CA certificate.",
            "The target API checks that the certificate subject matches the expected service identity.",
            "The target API checks whether the requested action is allowed.",
            "If all checks succeed, the internal API call is accepted.",
        ],
        "scope_note": (
            "This is not mTLS and does not implement a real service mesh. "
            "It is an academic simulation of application-level service identity "
            "validation using PQC X.509 certificates."
        ),
    }


@router.post(
    "/artifacts/ca-certificate",
    response_model=StoredArtifactResponse,
)
async def upload_ca_certificate_artifact(
    ca_certificate_file: UploadFile = File(...),
):
    """
    Store an internal CA certificate artifact.

    This endpoint prepares the backend for frontend-oriented workflows where
    certificates are uploaded once and then referenced by ID.
    """

    try:
        content = await ca_certificate_file.read()

        return store_ca_certificate(
            filename=ca_certificate_file.filename or "ca-certificate.pem",
            content=content,
        )

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/artifacts/service-certificate",
    response_model=StoredArtifactResponse,
)
async def upload_service_certificate_artifact(
    service_certificate_file: UploadFile = File(...),
):
    """
    Store a calling service certificate artifact.
    """

    try:
        content = await service_certificate_file.read()

        return store_service_certificate(
            filename=service_certificate_file.filename or "service-certificate.pem",
            content=content,
        )

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/artifacts/authorization-policy",
    response_model=StoredPolicyResponse,
)
async def upload_authorization_policy_artifact(
    authorization_policy_file: UploadFile = File(...),
):
    """
    Store an authorization policy JSON artifact.

    Expected policy format:

    {
      "billing-service": {
        "customer-api": [
          "read_customer_profile"
        ]
      }
    }
    """

    try:
        content = await authorization_policy_file.read()

        return store_authorization_policy(
            filename=authorization_policy_file.filename or "policy.json",
            content=content,
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/artifacts/{artifact_id}",
    response_model=ArtifactInfoResponse,
)
def get_artifact_metadata(
    artifact_id: str,
    include_preview: bool = Query(
        default=False,
        description="Whether to include the first characters of the stored artifact.",
    ),
):
    """
    Return metadata for a stored artifact.
    """

    try:
        return get_artifact_info(
            artifact_id=artifact_id,
            include_preview=include_preview,
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/identity/verify",
    response_model=VerifyServiceCertificateResponse,
)
def verify_identity_by_artifact_ids(
    request: VerifyServiceCertificateByIdRequest,
):
    """
    Verify a calling service identity using stored certificate artifacts.

    This endpoint represents the identity validation step in an internal
    API-to-API flow. It uses:
    - a stored CA certificate artifact;
    - a stored service certificate artifact;
    - an expected service subject.
    """

    try:
        return verify_service_certificate_by_artifact_ids(
            ca_artifact_id=request.ca_artifact_id,
            service_certificate_id=request.service_certificate_id,
            expected_service_subject=request.expected_service_subject,
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    

@router.post(
    "/authorization/check",
    response_model=AuthorizationCheckResponse,
)
def check_authorization_endpoint(request: AuthorizationCheckByIdRequest):
    """
    Check whether a service is authorized to perform an action using a stored policy.
    """

    try:
        return check_authorization_by_policy_id(
            policy_id=request.policy_id,
            calling_service=request.calling_service,
            target_api=request.target_api,
            action=request.action,
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    

@router.post(
    "/demo/service-call-by-id",
    response_model=ServiceCallWithPolicyResponse,
)
def demo_service_call_by_id(request: ServiceCallByIdRequest):
    """
    Simulate an internal API-to-API call using stored artifact IDs.
    """

    try:
        return simulate_internal_service_call_by_artifact_ids(
            ca_artifact_id=request.ca_artifact_id,
            service_certificate_id=request.service_certificate_id,
            policy_id=request.policy_id,
            calling_service=request.calling_service,
            target_api=request.target_api,
            action=request.action,
            resource=request.resource,
            expected_service_subject=request.expected_service_subject,
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    

@router.post(
    "/demo/secure-service-call-by-id",
    response_model=SecureServiceCallResponse,
)
def demo_secure_service_call_by_id(request: SecureServiceCallByIdRequest):
    """
    Simulate a secure internal API-to-API call using:
    - stored CA certificate;
    - stored service certificate;
    - stored authorization policy;
    - ML-KEM session establishment;
    - AES-GCM payload protection.
    """

    try:
        return simulate_secure_internal_service_call_by_artifact_ids(
            ca_artifact_id=request.ca_artifact_id,
            service_certificate_id=request.service_certificate_id,
            policy_id=request.policy_id,
            calling_service=request.calling_service,
            target_api=request.target_api,
            action=request.action,
            resource=request.resource,
            expected_service_subject=request.expected_service_subject,
            plaintext_payload=request.plaintext_payload,
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))