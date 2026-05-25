from fastapi import APIRouter, HTTPException, File, Form, UploadFile, Query
from fastapi.responses import FileResponse

from core.config import settings
from models.certificate_models import (
    GenerateCaRequest,
    GenerateCaResponse,
    GenerateCsrRequest,
    GenerateCsrResponse,
    IssueCertificateRequest,
    IssueCertificateResponse,
    IssueCertificateFromFileResponse,
    VerifyCertificateRequest,
    VerifyCertificateResponse,
    CertificateInfoResponse,
    CaMetricsDemoResponse,
)

from services.openssl_service import (
    generate_internal_ca,
    generate_service_csr,
    issue_certificate_from_csr,
    issue_certificate_from_uploaded_csr_file,
    verify_certificate,
    inspect_certificate,
    get_certificate_file_path,
    get_ca_certificate_file_path,
    get_csr_file_path,
    run_ca_metrics_demo,
)


router = APIRouter(
    prefix="/ca",
    tags=["Internal CA"],
)


@router.get("/info")
def ca_info():
    """
    Return basic information about the internal PQC CA.
    """

    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "trust_model": settings.TRUST_MODEL,
        "component_role": settings.COMPONENT_ROLE,
        "default_signature_algorithm": settings.DEFAULT_SIGNATURE_ALGORITHM,
        "default_certificate_validity_days": settings.DEFAULT_CERT_DAYS,
    }


@router.get("/scenario")
def ca_scenario():
    """
    Explain the role of this component inside the PQC migration laboratory.
    """

    return {
        "title": "Internal Post-Quantum Certificate Authority",
        "summary": (
            "This component represents an experimental private certificate "
            "authority for issuing post-quantum X.509 certificates inside a "
            "controlled private-trust environment."
        ),
        "role_in_laboratory": (
            "The internal CA acts as the trust anchor for later use cases. "
            "Services such as internal HTTPS, internal APIs, mTLS, SSH or VPN "
            "scenarios can consume certificates issued by this component instead "
            "of generating isolated identities."
        ),
        "main_flows": [
            "Generate an internal PQC CA.",
            "Generate a service keypair and CSR.",
            "Issue an X.509 certificate from the CSR.",
            "Download the certificate as a PEM file.",
            "Verify the certificate against the internal CA.",
        ],
        "not_a_public_ca": [
            "It is not integrated with the WebPKI.",
            "It is not trusted by browsers by default.",
            "It is intended for academic private-trust experimentation.",
        ],
    }


@router.get("/algorithms")
def ca_algorithms():
    """
    Return the signature algorithms exposed by this first internal CA version.

    These are the algorithms expected to be supported by the OpenSSL 3.5+
    build used in the Docker base image.
    """

    return {
        "standardized": [
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f",
            "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s",
            "SLH-DSA-SHAKE-256f",
        ],
        "default": settings.DEFAULT_SIGNATURE_ALGORITHM,
        "note": (
            "This endpoint lists the PQC signature algorithms intended for this "
            "demo. Actual availability depends on the OpenSSL build inside the "
            "runtime environment."
        ),
    }


@router.post("/generate", response_model=GenerateCaResponse)
def generate_ca(request: GenerateCaRequest):
    """
    Generate an internal PQC CA.

    This creates:
    - a PQC private key;
    - a self-signed X.509 CA certificate;
    - a PEM representation of the CA certificate.
    """

    try:
        return generate_internal_ca(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/csr/generate", response_model=GenerateCsrResponse)
def generate_csr(request: GenerateCsrRequest):
    """
    Generate a service PQC keypair and CSR.

    This simulates a service creating a certificate signing request that will
    later be signed by the internal CA.
    """

    try:
        return generate_service_csr(request)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))



@router.post("/certificate/issue", response_model=IssueCertificateResponse)
def issue_certificate(request: IssueCertificateRequest):
    """
    Issue an X.509 certificate from a previously generated CSR.
    """

    try:
        return issue_certificate_from_csr(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.post(
    "/certificate/issue-from-csr-file",
    response_model=IssueCertificateFromFileResponse,
)
async def issue_certificate_from_csr_file(
    ca_id: str = Form(...),
    validity_days: int = Form(365),
    csr_file: UploadFile = File(...),
):
    """
    Issue an X.509 certificate from an uploaded CSR PEM file.
    """

    try:
        csr_pem_bytes = await csr_file.read()

        return issue_certificate_from_uploaded_csr_file(
            ca_id=ca_id,
            csr_pem_bytes=csr_pem_bytes,
            validity_days=validity_days,
        )

    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    

@router.post("/certificate/verify", response_model=VerifyCertificateResponse)
def verify_issued_certificate(request: VerifyCertificateRequest):
    """
    Verify an issued certificate against the selected internal CA.
    """

    try:
        return verify_certificate(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/certificate/{certificate_id}/inspect",
    response_model=CertificateInfoResponse,
)
def inspect_issued_certificate(certificate_id: str):
    """
    Return the human-readable OpenSSL representation of an issued certificate.
    """

    try:
        return inspect_certificate(certificate_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/certificate/{certificate_id}/download")
def download_issued_certificate(certificate_id: str):
    """
    Download an issued certificate as a PEM file.
    """

    try:
        certificate_path = get_certificate_file_path(certificate_id)
        return FileResponse(
            path=certificate_path,
            media_type="application/x-pem-file",
            filename=f"{certificate_id}.cert.pem",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{ca_id}/download")
def download_ca_certificate(ca_id: str):
    """
    Download the internal CA certificate as a PEM file.
    """

    try:
        certificate_path = get_ca_certificate_file_path(ca_id)
        return FileResponse(
            path=certificate_path,
            media_type="application/x-pem-file",
            filename=f"{ca_id}.cert.pem",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/csr/{csr_id}/download")
def download_csr(csr_id: str):
    """
    Download a generated CSR as a PEM file.
    """

    try:
        request_path = get_csr_file_path(csr_id)
        return FileResponse(
            path=request_path,
            media_type="application/x-pem-file",
            filename=f"{csr_id}.csr.pem",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    
@router.get(
    "/metrics/demo",
    response_model=CaMetricsDemoResponse,
)
def get_ca_metrics_demo(
    signature_algorithm: str = Query(
        default="ML-DSA-65",
        description="PQC signature algorithm used for the demo flow.",
        examples=["ML-DSA-65"],
    ),
    validity_days: int = Query(
        default=365,
        ge=1,
        le=3650,
        description="Validity period for the generated CA and issued certificate.",
    ),
):
    """
    Run a complete CA demo flow and return timing and size metrics.

    This measures the practical impact of X.509 PQC certificates:
    - CA generation time;
    - CSR generation time;
    - certificate issuance time;
    - certificate verification time;
    - PEM artifact sizes.
    """

    try:
        return run_ca_metrics_demo(
            signature_algorithm=signature_algorithm,
            validity_days=validity_days,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))