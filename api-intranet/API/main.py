from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings

from routes.intranet import router as intranet_router
from routes.artifacts import router as artifacts_router
from routes.identity import router as identity_router
from routes.demo import router as demo_router



app = FastAPI(
    title="API Intranet",
    description="Academic simulation of internal HTTPS trust using PQC X.509 certificates.",
    version=settings.SERVICE_VERSION,
)

allowed_origins = (
    ["*"]
    if settings.ALLOWED_ORIGINS == "*"
    else settings.ALLOWED_ORIGINS.split(",")
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
app.include_router(artifacts_router)
app.include_router(identity_router)
app.include_router(demo_router)