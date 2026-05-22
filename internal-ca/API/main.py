from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from routes.ca import router as ca_router


allowed_origins = (
    ["*"]
    if settings.ALLOWED_ORIGINS == "*"
    else settings.ALLOWED_ORIGINS.split(",")
)


app = FastAPI(
    title="Internal CA",
    version=settings.SERVICE_VERSION,
    description=(
        "Experimental internal certificate authority for issuing and verifying "
        "post-quantum X.509 certificates in a private-trust environment."
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
        "purpose": "Internal PQC certificate authority for the migration laboratory.",
    }


@app.get("/health", tags=["General"])
def health_check():
    return {
        "status": "ok",
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
    }


app.include_router(ca_router)