from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from digital_key.vault import FormatError, decrypt_file, encrypt_file


class SoftwareDevice:
    """Test double that behaves like the dongle without exposing its private key."""

    def __init__(self):
        self._private = ec.generate_private_key(ec.SECP256R1())

    def public_key(self):
        return self._private.public_key()

    def derive_key(self, peer_public_key, salt):
        from digital_key.crypto import derive_file_key

        secret = self._private.exchange(ec.ECDH(), peer_public_key)
        return derive_file_key(secret, salt)


def test_document_round_trip_requires_same_device(tmp_path: Path):
    source = tmp_path / "report.pdf"
    encrypted = tmp_path / "report.pdf.tdkey"
    restored = tmp_path / "restored.pdf"
    source.write_bytes(b"confidential document\x00with binary data")
    device = SoftwareDevice()

    encrypt_file(source, encrypted, device)
    decrypt_file(encrypted, restored, device)

    assert restored.read_bytes() == source.read_bytes()
    assert encrypted.read_bytes() != source.read_bytes()


def test_different_device_cannot_decrypt(tmp_path: Path):
    source = tmp_path / "document.txt"
    encrypted = tmp_path / "document.tdkey"
    source.write_text("secret", encoding="utf-8")
    encrypt_file(source, encrypted, SoftwareDevice())

    with pytest.raises(FormatError, match="wrong dongle|damaged"):
        decrypt_file(encrypted, tmp_path / "output.txt", SoftwareDevice())


def test_tampered_ciphertext_is_rejected(tmp_path: Path):
    source = tmp_path / "document.txt"
    encrypted = tmp_path / "document.tdkey"
    source.write_text("secret", encoding="utf-8")
    device = SoftwareDevice()
    encrypt_file(source, encrypted, device)
    data = bytearray(encrypted.read_bytes())
    data[-1] ^= 1
    encrypted.write_bytes(data)

    with pytest.raises(FormatError, match="wrong dongle|damaged"):
        decrypt_file(encrypted, tmp_path / "output.txt", device)


def test_existing_output_is_not_overwritten(tmp_path: Path):
    source = tmp_path / "document.txt"
    source.write_text("secret", encoding="utf-8")
    output = tmp_path / "document.tdkey"
    output.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        encrypt_file(source, output, SoftwareDevice())

    assert output.read_text(encoding="utf-8") == "keep"
