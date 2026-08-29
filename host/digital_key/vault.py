import base64
import json
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import derive_file_key

MAGIC = b"TDKEY01\n"
MAX_HEADER = 16 * 1024


class FormatError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise FormatError("invalid encrypted-file header") from exc


def _write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as output:
        output.write(data)


def encrypt_file(source, output, device) -> Path:
    source = Path(source)
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)

    plaintext = source.read_bytes()
    device_public = device.public_key()
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    salt = os.urandom(16)
    nonce = os.urandom(12)
    shared_secret = ephemeral_private.exchange(ec.ECDH(), device_public)
    key = derive_file_key(shared_secret, salt)

    header = {
        "algorithm": "P-256+HKDF-SHA256+AES-256-GCM",
        "ephemeral_public": _b64(ephemeral_public),
        "nonce": _b64(nonce),
        "original_name": source.name,
        "salt": _b64(salt),
    }
    encoded_header = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    prefix = MAGIC + struct.pack(">I", len(encoded_header)) + encoded_header
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, prefix)
    _write_new(output, prefix + ciphertext)
    return output


def decrypt_file(source, output, device) -> Path:
    source = Path(source)
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)
    data = source.read_bytes()
    if len(data) < len(MAGIC) + 4 or not data.startswith(MAGIC):
        raise FormatError("not a T-Dongle encrypted file")
    header_size = struct.unpack(">I", data[len(MAGIC):len(MAGIC) + 4])[0]
    if header_size > MAX_HEADER:
        raise FormatError("invalid encrypted-file header")
    header_end = len(MAGIC) + 4 + header_size
    if header_end > len(data):
        raise FormatError("truncated encrypted file")
    prefix = data[:header_end]
    try:
        header = json.loads(data[len(MAGIC) + 4:header_end].decode("utf-8"))
        if header["algorithm"] != "P-256+HKDF-SHA256+AES-256-GCM":
            raise FormatError("unsupported encryption algorithm")
        peer_raw = _unb64(header["ephemeral_public"])
        salt = _unb64(header["salt"])
        nonce = _unb64(header["nonce"])
        if len(salt) != 16 or len(nonce) != 12:
            raise FormatError("invalid encrypted-file header")
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_raw)
    except FormatError:
        raise
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise FormatError("invalid encrypted-file header") from exc

    key = device.derive_key(peer, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, data[header_end:], prefix)
    except InvalidTag as exc:
        raise FormatError("wrong dongle or damaged encrypted file") from exc
    _write_new(output, plaintext)
    return output
