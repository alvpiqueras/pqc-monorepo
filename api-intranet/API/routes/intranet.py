from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from core.config import settings
from models.intranet_models import (
    IntranetConnectRequest,
    IntranetConnectResponse,
    VerifyIntranetCertificateRequest,
    VerifyIntranetCertificateResponse,
)
from services.certificate_verification_service import (
    simulate_intranet_connection,
    verify_intranet_certificate,
    simulate_intranet_connection_from_files,
    verify_intranet_certificate_from_files,
)


router = APIRouter(
    prefix="/intranet",
    tags=["Intranet HTTPS"],
)


@router.get("/info")
def intranet_info():
    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "role": "private-intranet-service-certificate-consumer",
        "expected_server_identity": settings.DEFAULT_EXPECTED_SUBJECT,
    }


@router.get("/scenario")
def intranet_scenario():
    return {
        "title": "Private Intranet HTTPS with PQC X.509 Certificate Validation",
        "summary": (
            "This API simulates an internal client connecting to a private "
            "intranet service. The intranet server presents an X.509 certificate "
            "issued by the internal PQC CA, and the client verifies it before "
            "accessing an internal resource."
        ),
        "actors": {
            "internal_client": "Employee, browser or corporate device inside the private network.",
            "intranet_server": "Private internal HTTPS service such as intranet.local.",
            "internal_ca": "Private PQC certificate authority that issued the server certificate.",
        },
        "flow": [
            "The internal client requests access to intranet.local.",
            "The intranet server presents its X.509 PQC certificate.",
            "The client validates the certificate against the internal CA certificate.",
            "The client checks that the certificate subject matches the expected intranet identity.",
            "If verification succeeds, access to the private resource is allowed.",
        ],
        "scope_note": (
            "This is not a production TLS implementation. It is an academic "
            "simulation of the certificate validation logic that appears in an "
            "internal HTTPS flow."
        ),
    }


@router.post(
    "/verify-certificate",
    response_model=VerifyIntranetCertificateResponse,
)
def verify_certificate(request: VerifyIntranetCertificateRequest):
    try:
        return verify_intranet_certificate(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/demo/connect",
    response_model=IntranetConnectResponse,
)
def demo_connect(request: IntranetConnectRequest):
    try:
        return simulate_intranet_connection(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    
@router.post(
    "/verify-certificate-file",
    response_model=VerifyIntranetCertificateResponse,
)
async def verify_certificate_file(
    expected_subject: str = Form("intranet.local"),
    ca_certificate_file: UploadFile = File(...),
    server_certificate_file: UploadFile = File(...),
):
    """
    Verify an intranet server certificate using uploaded PEM files.

    Upload:
    - internal CA certificate PEM;
    - intranet server certificate PEM.
    """

    try:
        ca_certificate_pem = (await ca_certificate_file.read()).decode("utf-8")
        server_certificate_pem = (await server_certificate_file.read()).decode("utf-8")

        return verify_intranet_certificate_from_files(
            ca_certificate_pem=ca_certificate_pem,
            server_certificate_pem=server_certificate_pem,
            expected_subject=expected_subject,
        )

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.post(
    "/demo/connect-file",
    response_model=IntranetConnectResponse,
)
async def demo_connect_file(
    client_id: str = Form("employee-001"),
    requested_resource: str = Form("/dashboard"),
    expected_subject: str = Form("intranet.local"),
    ca_certificate_file: UploadFile = File(...),
    server_certificate_file: UploadFile = File(...),
):
    """
    Simulate an internal client connecting to the intranet using uploaded
    CA/server certificate PEM files.
    """

    try:
        ca_certificate_pem = (await ca_certificate_file.read()).decode("utf-8")
        server_certificate_pem = (await server_certificate_file.read()).decode("utf-8")

        return simulate_intranet_connection_from_files(
            client_id=client_id,
            requested_resource=requested_resource,
            ca_certificate_pem=ca_certificate_pem,
            server_certificate_pem=server_certificate_pem,
            expected_subject=expected_subject,
        )

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))    