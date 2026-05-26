from fastapi import APIRouter, File, HTTPException, UploadFile

from models.artifacts_models import (
    ArtifactListResponse,
    CertificateArtifactResponse,
    CertificateArtifactUploadResponse,
)
from services.artifacts_service import (
    get_artifact,
    list_artifacts,
    register_certificate_artifact,
)

router = APIRouter(
    prefix="/intranet/artifacts",
    tags=["Intranet Artifacts"],
)


async def _read_uploaded_pem(file: UploadFile) -> str:
    content = await file.read()

    try:
        pem = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file must be a valid UTF-8 PEM certificate.",
        ) from exc

    if "-----BEGIN CERTIFICATE-----" not in pem:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file does not look like a PEM-encoded certificate.",
        )

    return pem


@router.post(
    "/ca-certificate",
    response_model=CertificateArtifactUploadResponse,
)
async def upload_ca_certificate(
    file: UploadFile = File(...),
):
    pem = await _read_uploaded_pem(file)

    try:
        return register_certificate_artifact(
            pem=pem,
            artifact_type="ca_certificate",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not register CA certificate artifact: {exc}",
        ) from exc


@router.post(
    "/server-certificate",
    response_model=CertificateArtifactUploadResponse,
)
async def upload_server_certificate(
    file: UploadFile = File(...),
):
    pem = await _read_uploaded_pem(file)

    try:
        return register_certificate_artifact(
            pem=pem,
            artifact_type="server_certificate",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not register server certificate artifact: {exc}",
        ) from exc


@router.get(
    "",
    response_model=ArtifactListResponse,
)
def get_all_artifacts():
    artifacts = list_artifacts()

    return {
        "artifacts": artifacts,
        "total": len(artifacts),
    }


@router.get(
    "/{artifact_id}",
    response_model=CertificateArtifactResponse,
)
def get_certificate_artifact(artifact_id: str):
    artifact = get_artifact(artifact_id)

    if artifact is None:
        raise HTTPException(
            status_code=404,
            detail="Artifact not found.",
        )

    return artifact