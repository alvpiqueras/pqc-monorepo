from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from routes.bootstrap import router as bootstrap_router
from routes.gateway import router as gateway_router


app = FastAPI(
    title="API mTLS Distributed Gateway",
    description=(
        "Public gateway for a distributed application-level mTLS demonstration "
        "using PQC X.509 certificates."
    ),
    version=settings.SERVICE_VERSION,
    openapi_tags=[
        {
            "name": "API mTLS Overview",
            "description": "General information about the distributed mTLS gateway.",
        },
        {
            "name": "Connectivity",
            "description": "Checks connectivity between gateway, client and server.",
        },
        {
            "name": "Bootstrap",
            "description": "Configures client and server identities using internal-ca.",
        },
    ],
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
app.include_router(bootstrap_router)


@app.get(
    "/",
    tags=["API mTLS Overview"],
)
def root():
    return {
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "status": "running",
        "docs": "/docs",
    }