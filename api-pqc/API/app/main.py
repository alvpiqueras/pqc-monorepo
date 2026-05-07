from fastapi import FastAPI, HTTPException

from app.crypto.kyber import generate_keypair as kyber_generate_keypair
from app.crypto.kyber import encapsulate as kyber_encapsulate
from app.crypto.kyber import decapsulate as kyber_decapsulate

from app.crypto.dilithium import generate_keypair as dilithium_generate_keypair
from app.crypto.dilithium import sign as dilithium_sign
from app.crypto.dilithium import verify as dilithium_verify

from app.models.schemas import (
    KyberEncapsulateRequest,
    KyberDecapsulateRequest,
    DilithiumSignRequest,
    DilithiumVerifyRequest,
)


app = FastAPI(title="PQC API", version="0.1.0")


@app.get("/")
def root():
    return {"status": "API running"}


@app.post("/kyber/keygen")
def kyber_keygen():
    try:
        return kyber_generate_keypair()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/kyber/encapsulate")
def kyber_encapsulate_endpoint(request: KyberEncapsulateRequest):
    try:
        return kyber_encapsulate(request.public_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/kyber/decapsulate")
def kyber_decapsulate_endpoint(request: KyberDecapsulateRequest):
    try:
        return kyber_decapsulate(request.ciphertext, request.secret_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dilithium/keygen")
def dilithium_keygen():
    try:
        return dilithium_generate_keypair()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dilithium/sign")
def dilithium_sign_endpoint(request: DilithiumSignRequest):
    try:
        return dilithium_sign(request.message, request.secret_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dilithium/verify")
def dilithium_verify_endpoint(request: DilithiumVerifyRequest):
    try:
        return dilithium_verify(
            request.message,
            request.signature,
            request.public_key,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))