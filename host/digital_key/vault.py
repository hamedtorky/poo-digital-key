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

# Binary magic marker for v2 format (not human-readable)
MAGIC_V2 = b"\xE3\xB1\x9A\x02\xD7\x5C\xA1\x4F"  # 8 bytes
MAGIC_V1 = b"TDKEY01\n"  # legacy text header
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
    # Keep uncompressed for widest device compatibility (65 bytes)
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    salt = os.urandom(16)
    nonce = os.urandom(12)
    shared_secret = ephemeral_private.exchange(ec.ECDH(), device_public)
    key = derive_file_key(shared_secret, salt)

    # v2 compact, binary, no human-readable metadata
    # Layout: MAGIC_V2 (8) | nonce (12) | salt (16) | klen (1=65) | eph_pub (klen)
    klen = len(ephemeral_public)
    if klen not in (65, 33):
        raise FormatError("invalid ephemeral key length")
    prefix = MAGIC_V2 + nonce + salt + struct.pack("B", klen) + ephemeral_public
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, prefix)
    _write_new(output, prefix + ciphertext)
    return output


def decrypt_file(source, output, device) -> Path:
    source = Path(source)
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)
    data = source.read_bytes()

    # v2 binary format
    if len(data) >= len(MAGIC_V2) + 12 + 16 + 1 and data.startswith(MAGIC_V2):
        idx = len(MAGIC_V2)
        nonce = data[idx:idx+12]; idx += 12
        salt = data[idx:idx+16]; idx += 16
        klen = data[idx]; idx += 1
        if klen not in (65, 33) or idx + klen > len(data):
            raise FormatError("invalid encrypted-file header")
        peer_raw = data[idx:idx+klen]
        header_end = idx + klen
        prefix = data[:header_end]
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_raw)
        except ValueError as exc:
            raise FormatError("invalid encrypted-file header") from exc
        key = device.derive_key(peer, salt)
        try:
            plaintext = AESGCM(key).decrypt(nonce, data[header_end:], prefix)
        except InvalidTag as exc:
            raise FormatError("wrong dongle or damaged encrypted file") from exc
        _write_new(output, plaintext)
        return output

    # legacy v1 JSON format
    if len(data) < len(MAGIC_V1) + 4 or not data.startswith(MAGIC_V1):
        raise FormatError("not a T-Dongle encrypted file")
    header_size = struct.unpack(">I", data[len(MAGIC_V1):len(MAGIC_V1) + 4])[0]
    if header_size > MAX_HEADER:
        raise FormatError("invalid encrypted-file header")
    header_end = len(MAGIC_V1) + 4 + header_size
    if header_end > len(data):
        raise FormatError("truncated encrypted file")
    prefix = data[:header_end]
    try:
        header = json.loads(data[len(MAGIC_V1) + 4:header_end].decode("utf-8"))
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
