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
            "description": "Phase C1 handshake initiation against the server service.",
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