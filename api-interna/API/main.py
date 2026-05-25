from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from routes.internal_api import router as internal_api_router


allowed_origins = (
    ["*"]
    if settings.ALLOWED_ORIGINS == "*"
    else settings.ALLOWED_ORIGINS.split(",")
)


app = FastAPI(
    title="Internal APIs and Microservices",
    version=settings.SERVICE_VERSION,
    description=(
        "Academic simulation of internal API-to-API communication using "
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
        "purpose": "Simulate certificate-based identity validation for internal APIs.",
    }


@app.get("/health", tags=["General"])
def health_check():
    return {
        "status": "ok",
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
    }


app.include_router(internal_api_router)