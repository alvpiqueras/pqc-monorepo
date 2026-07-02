import base64
import time

import oqs


DEFAULT_SIG = "ML-DSA-65"


def bytes_to_b64(data: bytes) -> str:
    """Convierte bytes a string Base64."""
    return base64.b64encode(data).decode("utf-8")


def b64_to_bytes(data_b64: str) -> bytes:
    """Convierte string Base64 a bytes."""
    return base64.b64decode(data_b64.encode("utf-8"), validate=True)


def text_to_bytes(text: str) -> bytes:
    """Convierte texto plano a bytes UTF-8."""
    return text.encode("utf-8")


def generate_keypair(algorithm: str = DEFAULT_SIG) -> dict:
    """
    Genera un par de claves para ML-DSA y las devuelve en Base64.

    Measurements:
    - keypair_generation_ms: tiempo dedicado a generar el par de claves.
    - total_operation_ms: tiempo total de la función, incluyendo serialización Base64.
    """

    total_start = time.perf_counter()

    keygen_start = time.perf_counter()

    with oqs.Signature(algorithm) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()

    keygen_end = time.perf_counter()

    public_key_b64 = bytes_to_b64(public_key)
    secret_key_b64 = bytes_to_b64(secret_key)

    total_end = time.perf_counter()

    return {
        "algorithm": algorithm,
        "public_key": public_key_b64,
        "secret_key": secret_key_b64,
        "measurements": {
            "keypair_generation_ms": round((keygen_end - keygen_start) * 1000, 3),
            "total_operation_ms": round((total_end - total_start) * 1000, 3),
        },
        "sizes_bytes": {
            "public_key": len(public_key),
            "secret_key": len(secret_key),
            "public_key_b64": len(public_key_b64.encode("utf-8")),
            "secret_key_b64": len(secret_key_b64.encode("utf-8")),
        },
    }


def sign(message: str, secret_key_b64: str, algorithm: str = DEFAULT_SIG) -> dict:
    """
    Firma un mensaje en texto plano usando la clave privada.
    Devuelve la firma en Base64.

    Measurements:
    - signature_generation_ms: tiempo dedicado a la operación criptográfica de firma.
    - total_operation_ms: tiempo total, incluyendo conversión de mensaje, decodificación
      de clave y serialización Base64 de la firma.
    """

    total_start = time.perf_counter()

    message_bytes = text_to_bytes(message)
    secret_key = b64_to_bytes(secret_key_b64)

    sign_start = time.perf_counter()

    with oqs.Signature(algorithm, secret_key) as sig:
        signature = sig.sign(message_bytes)

    sign_end = time.perf_counter()

    signature_b64 = bytes_to_b64(signature)

    total_end = time.perf_counter()

    return {
        "algorithm": algorithm,
        "signature": signature_b64,
        "measurements": {
            "signature_generation_ms": round((sign_end - sign_start) * 1000, 3),
            "total_operation_ms": round((total_end - total_start) * 1000, 3),
        },
        "sizes_bytes": {
            "message": len(message_bytes),
            "secret_key": len(secret_key),
            "signature": len(signature),
            "signature_b64": len(signature_b64.encode("utf-8")),
        },
    }


def verify(
    message: str,
    signature_b64: str,
    public_key_b64: str,
    algorithm: str = DEFAULT_SIG,
) -> dict:
    """
    Verifica una firma sobre un mensaje en texto plano usando la clave pública.
    Devuelve un booleano indicando si la firma es válida.

    Measurements:
    - signature_verification_ms: tiempo dedicado a la verificación criptográfica.
    - total_operation_ms: tiempo total, incluyendo conversión de mensaje y decodificación
      de firma y clave pública.
    """

    total_start = time.perf_counter()

    message_bytes = text_to_bytes(message)
    signature = b64_to_bytes(signature_b64)
    public_key = b64_to_bytes(public_key_b64)

    verify_start = time.perf_counter()

    with oqs.Signature(algorithm) as sig:
        is_valid = sig.verify(message_bytes, signature, public_key)

    verify_end = time.perf_counter()
    total_end = time.perf_counter()

    return {
        "algorithm": algorithm,
        "is_valid": is_valid,
        "measurements": {
            "signature_verification_ms": round((verify_end - verify_start) * 1000, 3),
            "total_operation_ms": round((total_end - total_start) * 1000, 3),
        },
        "sizes_bytes": {
            "message": len(message_bytes),
            "public_key": len(public_key),
            "signature": len(signature),
        },
    }


if __name__ == "__main__":
    print("=== ML-DSA local test ===")

    message = "Hola, esta es una prueba de firma post-cuántica."

    keys = generate_keypair()
    print("Keypair generated.")
    print(keys["measurements"])
    print(keys["sizes_bytes"])

    signed = sign(message, keys["secret_key"])
    print("Signature generated.")
    print(signed["measurements"])
    print(signed["sizes_bytes"])

    verified = verify(
        message,
        signed["signature"],
        keys["public_key"],
    )
    print(f"Signature valid: {verified['is_valid']}")
    print(verified["measurements"])
    print(verified["sizes_bytes"])