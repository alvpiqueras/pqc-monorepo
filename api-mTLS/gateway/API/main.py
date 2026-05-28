from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from routes.gateway import router as gateway_router


app = FastAPI(
    title="mTLS Distributed Gateway",
    description=(
        "Public gateway for a distributed application-level mTLS demonstration "
        "using PQC X.509 certificates."
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

app.include_router(gateway_router)


@app.get(
    "/",
    tags=["mTLS Distributed - Overview"],
)
def root():
    return {
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "status": "running",
        "docs": "/docs",
    }