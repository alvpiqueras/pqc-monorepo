from fastapi import FastAPI

from core.config import settings
from routes.server import router as server_router


app = FastAPI(
    title="mTLS Server Service",
    description=(
        "Internal server service for the distributed application-level mTLS "
        "demonstration."
    ),
    version=settings.SERVICE_VERSION,
    openapi_tags=[
        {
            "name": "Overview",
            "description": "General information about the server service.",
        },
        {
            "name": "Identity",
            "description": "Identity configuration received from the gateway.",
        },
        {
            "name": "Handshake",
            "description": "Phase C1 handshake start with ephemeral ML-KEM material.",
        },
    ],
)

app.include_router(server_router)


@app.get(
    "/",
    tags=["Overview"],
)
def root():
    return {
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "status": "running",
    }