from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from routes.intranet import router as intranet_router


allowed_origins = (
    ["*"]
    if settings.ALLOWED_ORIGINS == "*"
    else settings.ALLOWED_ORIGINS.split(",")
)


app = FastAPI(
    title="Private Intranet HTTPS",
    version=settings.SERVICE_VERSION,
    description=(
        "Academic simulation of an internal HTTPS intranet service consuming "
        "PQC X.509 certificates issued by an internal CA."
    ),
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["General"])
def root():
    return {
        "status": "running",
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "docs": "/docs",
        "health": "/health",
        "purpose": "Simulate certificate validation for a private intranet HTTPS service.",
    }


@app.get("/health", tags=["General"])
def health_check():
    return {
        "status": "ok",
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
    }


app.include_router(intranet_router)