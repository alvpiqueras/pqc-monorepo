import base64
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
    """
    with oqs.Signature(algorithm) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()

    return {
        "algorithm": algorithm,
        "public_key": bytes_to_b64(public_key),
        "secret_key": bytes_to_b64(secret_key),
    }


def sign(message: str, secret_key_b64: str, algorithm: str = DEFAULT_SIG) -> dict:
    """
    Firma un mensaje en texto plano usando la clave privada.
    Devuelve la firma en Base64.
    """
    message_bytes = text_to_bytes(message)
    secret_key = b64_to_bytes(secret_key_b64)

    with oqs.Signature(algorithm, secret_key) as sig:
        signature = sig.sign(message_bytes)

    return {
        "algorithm": algorithm,
        "signature": bytes_to_b64(signature),
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
    """
    message_bytes = text_to_bytes(message)
    signature = b64_to_bytes(signature_b64)
    public_key = b64_to_bytes(public_key_b64)

    with oqs.Signature(algorithm) as sig:
        is_valid = sig.verify(message_bytes, signature, public_key)

    return {
        "algorithm": algorithm,
        "is_valid": is_valid,
    }


if __name__ == "__main__":
    print("=== ML-DSA local test ===")

    message = "Hola, esta es una prueba de firma post-cuántica."

    keys = generate_keypair()
    print("Keypair generated.")

    signed = sign(message, keys["secret_key"])
    print("Signature generated.")

    verified = verify(
        message,
        signed["signature"],
        keys["public_key"],
    )
    print(f"Signature valid: {verified['is_valid']}")