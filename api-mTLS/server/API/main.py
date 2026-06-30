from fastapi import FastAPI

from core.config import settings
from routes.server import router as server_router


app = FastAPI(
    title="mTLS Server Service",
    description="Internal server service for the distributed mTLS demonstration.",
    version=settings.SERVICE_VERSION,
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