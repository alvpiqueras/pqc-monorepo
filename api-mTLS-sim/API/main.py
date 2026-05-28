from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from routes.artifacts import router as artifacts_router
from routes.overview import router as overview_router
from routes.handshake import router as handshake_router
from routes.demo import router as demo_router


app = FastAPI(
    title="API mTLS Simulation",
    description=(
        "Academic simulation of mutual TLS-style service-to-service "
        "authentication using PQC X.509 certificates."
    ),
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

app.include_router(overview_router)
app.include_router(artifacts_router)
app.include_router(handshake_router)
app.include_router(demo_router)

@app.get(
    "/",
    tags=["mTLS Sim - Overview"],
)
def root():
    return {
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "use_case": settings.USE_CASE,
        "trust_model": settings.TRUST_MODEL,
        "status": "running",
        "docs": "/docs",
    }