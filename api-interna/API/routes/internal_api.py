from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from core.config import settings
from models.internal_api_models import (
    ServiceCallRequest,
    ServiceCallResponse,
    VerifyServiceCertificateRequest,
    VerifyServiceCertificateResponse,
    ServiceCallWithPolicyResponse,
)
from services.certificate_verification_service import (
    simulate_internal_service_call,
    simulate_internal_service_call_from_files,
    verify_service_certificate,
    verify_service_certificate_from_files,
    simulate_internal_service_call_with_policy_from_files,
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
    "/verify-service-certificate",
    response_model=VerifyServiceCertificateResponse,
)
def verify_service_certificate_endpoint(request: VerifyServiceCertificateRequest):
    try:
        return verify_service_certificate(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/demo/service-call",
    response_model=ServiceCallResponse,
)
def demo_service_call(request: ServiceCallRequest):
    try:
        return simulate_internal_service_call(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/verify-service-certificate-file",
    response_model=VerifyServiceCertificateResponse,
)
async def verify_service_certificate_file(
    expected_service_subject: str = Form("billing-service.local"),
    ca_certificate_file: UploadFile = File(...),
    service_certificate_file: UploadFile = File(...),
):
    """
    Verify a calling service certificate using uploaded PEM files.
    """

    try:
        ca_certificate_pem = (await ca_certificate_file.read()).decode("utf-8")
        service_certificate_pem = (
            await service_certificate_file.read()
        ).decode("utf-8")

        return verify_service_certificate_from_files(
            ca_certificate_pem=ca_certificate_pem,
            service_certificate_pem=service_certificate_pem,
            expected_service_subject=expected_service_subject,
        )

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/demo/service-call-file",
    response_model=ServiceCallResponse,
)
async def demo_service_call_file(
    calling_service: str = Form("billing-service"),
    target_api: str = Form("customer-api"),
    action: str = Form("read_customer_profile"),
    resource: str = Form("/customers/123"),
    allowed_actions: str = Form("read_customer_profile"),
    expected_service_subject: str = Form("billing-service.local"),
    ca_certificate_file: UploadFile = File(...),
    service_certificate_file: UploadFile = File(...),
):
    """
    Simulate an internal API-to-API call using uploaded PEM certificates.

    allowed_actions must be provided as a comma-separated string, for example:
    read_customer_profile,read_invoice
    """

    try:
        ca_certificate_pem = (await ca_certificate_file.read()).decode("utf-8")
        service_certificate_pem = (
            await service_certificate_file.read()
        ).decode("utf-8")

        allowed_actions_list = [
            item.strip()
            for item in allowed_actions.split(",")
            if item.strip()
        ]

        return simulate_internal_service_call_from_files(
            calling_service=calling_service,
            target_api=target_api,
            action=action,
            resource=resource,
            allowed_actions=allowed_actions_list,
            ca_certificate_pem=ca_certificate_pem,
            service_certificate_pem=service_certificate_pem,
            expected_service_subject=expected_service_subject,
        )

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    

@router.post(
    "/demo/service-call-with-policy-file",
    response_model=ServiceCallWithPolicyResponse,
)
async def demo_service_call_with_policy_file(
    calling_service: str = Form("billing-service"),
    target_api: str = Form("customer-api"),
    action: str = Form("read_customer_profile"),
    resource: str = Form("/customers/123"),
    expected_service_subject: str = Form("billing-service.local"),
    ca_certificate_file: UploadFile = File(...),
    service_certificate_file: UploadFile = File(...),
    authorization_policy_file: UploadFile = File(...),
):
    """
    Simulate an internal API-to-API call using:
    - uploaded internal CA certificate;
    - uploaded calling service certificate;
    - uploaded authorization policy JSON.

    This endpoint demonstrates the separation between:
    - identity, validated with a PQC X.509 certificate;
    - authorization, validated with an external policy file;
    - action execution, allowed only if both checks succeed.
    """

    try:
        ca_certificate_pem = (await ca_certificate_file.read()).decode("utf-8")
        service_certificate_pem = (
            await service_certificate_file.read()
        ).decode("utf-8")
        authorization_policy_json = (
            await authorization_policy_file.read()
        ).decode("utf-8")

        return simulate_internal_service_call_with_policy_from_files(
            calling_service=calling_service,
            target_api=target_api,
            action=action,
            resource=resource,
            ca_certificate_pem=ca_certificate_pem,
            service_certificate_pem=service_certificate_pem,
            expected_service_subject=expected_service_subject,
            authorization_policy_json=authorization_policy_json,
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))