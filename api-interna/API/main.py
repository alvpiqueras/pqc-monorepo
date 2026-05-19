from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from routes.internal_api import router as internal_api_router


app = FastAPI(
    title="QCS Internal APIs API",
    description=(
        "Post-Quantum Cryptography laboratory API for internal "
        "API-to-API and microservice communication."
    ),
    version=settings.SERVICE_VERSION,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.ALLOWED_ORIGINS == "*" else settings.ALLOWED_ORIGINS.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    """
    Basic health endpoint for Docker, Render and monitoring systems.
    """

    return {
        "status": "ok",
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
    }

@app.get("/")
def root():
    """
    Root endpoint for quick service discovery.
    """

    return {
        "message": "QCS api-interna is running",
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "docs": "/docs",
        "health": "/health",
        "use_case": settings.USE_CASE,
    }

app.include_router(internal_api_router)