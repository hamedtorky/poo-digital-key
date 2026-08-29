from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"T-Dongle-S3 document key v1"


def derive_file_key(shared_secret: bytes, salt: bytes) -> bytes:
    """Derive a unique AES-256 key from one ECDH secret."""
    if len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=INFO,
    ).derive(shared_secret)
