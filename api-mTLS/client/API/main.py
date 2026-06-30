from fastapi import FastAPI

from fastapi import FastAPI

from core.config import settings
from routes.client import router as client_router


app = FastAPI(
    title="mTLS Client Service",
    description="Internal client service for the distributed mTLS demonstration.",
    version=settings.SERVICE_VERSION,
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