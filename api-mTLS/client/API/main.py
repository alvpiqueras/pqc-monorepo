from fastapi import FastAPI

from core.config import settings
from routes.client import router as client_router


app = FastAPI(
    title="mTLS Client Service",
    description=(
        "Internal client service for the distributed application-level mTLS "
        "demonstration."
    ),
    version=settings.SERVICE_VERSION,
    openapi_tags=[
        {
            "name": "Overview",
            "description": "General information about the client service.",
        },
        {
            "name": "Identity",
            "description": "Identity configuration received from the gateway.",
        },
        {
            "name": "Handshake",
            "description": "Handshake initiation against the server service.",
        },
        {
            "name": "Encrypted Request",
            "description": (
                "Encrypts an application payload with AES-GCM after ML-KEM "
                "session establishment."
            ),
        },
    ],
)

app.include_router(client_router)


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