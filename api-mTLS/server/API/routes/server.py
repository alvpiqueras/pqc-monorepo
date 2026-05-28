from fastapi import APIRouter, Header, HTTPException

from core.config import settings


router = APIRouter(
    prefix="/server",
)


def _require_internal_token(token: str | None) -> None:
    if token != settings.INTERNAL_DEMO_TOKEN:
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing internal demo token.",
        )


@router.get(
    "/info",
    tags=["mTLS Server Service - Overview"],
)
def server_info(
    x_qcs_demo_token: str | None = Header(default=None),
):
    _require_internal_token(x_qcs_demo_token)

    return {
        "service_name": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "service_id": settings.SERVICE_ID,
        "service_role": settings.SERVICE_ROLE,
        "status": "running",
    }