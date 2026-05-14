from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from routes.intranet import router as intranet_router


app = FastAPI(
    title="QCS API Intranet",
    description=settings.SERVICE_DESCRIPTION,
    version=settings.SERVICE_VERSION,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    """
    Root endpoint.

    Provides a minimal entry point for checking that the service is alive.
    """

    return {
        "message": "QCS api-intranet is running",
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "docs": "/docs",
    }


@app.get("/health")
def health_check():
    """
    Health check endpoint for local testing, Docker Compose and Render.
    """

    return {
        "status": "ok",
        "service": settings.SERVICE_NAME,
        "use_case": settings.USE_CASE,
    }


app.include_router(intranet_router)