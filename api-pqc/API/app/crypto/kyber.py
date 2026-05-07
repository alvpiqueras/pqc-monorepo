import base64
import oqs


DEFAULT_KEM = "ML-KEM-768"


def bytes_to_b64(data: bytes) -> str:
    """Convierte bytes a string Base64."""
    return base64.b64encode(data).decode("utf-8")


def b64_to_bytes(data_b64: str) -> bytes:
    """Convierte string Base64 a bytes."""
    return base64.b64decode(data_b64.encode("utf-8"), validate=True)


def generate_keypair(algorithm: str = DEFAULT_KEM) -> dict:
    """
    Genera un par de claves para ML-KEM y las devuelve en Base64.
    """
    with oqs.KeyEncapsulation(algorithm) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()

    return {
        "algorithm": algorithm,
        "public_key": bytes_to_b64(public_key),
        "secret_key": bytes_to_b64(secret_key),
    }


def encapsulate(public_key_b64: str, algorithm: str = DEFAULT_KEM) -> dict:
    """
    Encapsula un secreto compartido a partir de una clave pública.
    Devuelve ciphertext y shared_secret en Base64.
    """
    public_key = b64_to_bytes(public_key_b64)

    with oqs.KeyEncapsulation(algorithm) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)

    return {
        "algorithm": algorithm,
        "ciphertext": bytes_to_b64(ciphertext),
        "shared_secret": bytes_to_b64(shared_secret),
    }


def decapsulate(ciphertext_b64: str, secret_key_b64: str, algorithm: str = DEFAULT_KEM) -> dict:
    """
    Decapsula el secreto compartido a partir de ciphertext y clave privada.
    Devuelve shared_secret en Base64.
    """
    ciphertext = b64_to_bytes(ciphertext_b64)
    secret_key = b64_to_bytes(secret_key_b64)

    with oqs.KeyEncapsulation(algorithm, secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)

    return {
        "algorithm": algorithm,
        "shared_secret": bytes_to_b64(shared_secret),
    }


if __name__ == "__main__":
    print("=== ML-KEM local test ===")

    keys = generate_keypair()
    print("Keypair generated.")

    encapsulated = encapsulate(keys["public_key"])
    print("Encapsulation done.")

    decapsulated = decapsulate(
        encapsulated["ciphertext"],
        keys["secret_key"],
    )
    print("Decapsulation done.")

    same_secret = encapsulated["shared_secret"] == decapsulated["shared_secret"]
    print(f"Shared secrets match: {same_secret}")