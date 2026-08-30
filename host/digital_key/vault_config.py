import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .device import public_key_fingerprint


DESCRIPTOR_VERSION = 1
_CREDENTIAL_INFO = b"POO zero-knowledge vault rclone credentials v1"
_EXPECTED_FIELDS = {"version", "dongle_fingerprint", "peer_public", "salt"}


class VaultConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class VaultDescriptor:
    version: int
    dongle_fingerprint: str
    peer_public: bytes
    salt: bytes

    def to_json(self) -> str:
        value = {
            "version": self.version,
            "dongle_fingerprint": self.dongle_fingerprint,
            "peer_public": base64.b64encode(self.peer_public).decode("ascii"),
            "salt": base64.b64encode(self.salt).decode("ascii"),
        }
        return json.dumps(value, indent=2, sort_keys=True) + "\n"


@dataclass(frozen=True)
class VaultCredentials:
    password: str
    filename_password: str


def create_vault_descriptor(device, output: Path) -> VaultDescriptor:
    """Create a public vault descriptor without persisting a decrypting secret."""
    dongle_public = device.public_key()
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    peer_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    descriptor = VaultDescriptor(
        version=DESCRIPTOR_VERSION,
        dongle_fingerprint=public_key_fingerprint(dongle_public),
        peer_public=peer_public,
        salt=os.urandom(16),
    )

    output = Path(output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise FileExistsError(f"vault descriptor already exists: {output}") from None
    try:
        with os.fdopen(descriptor_fd, "w", encoding="utf-8") as descriptor_file:
            descriptor_file.write(descriptor.to_json())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return descriptor


def load_vault_descriptor(source: Path) -> VaultDescriptor:
    try:
        raw = Path(source).expanduser().read_bytes()
    except OSError as exc:
        raise VaultConfigError(f"could not read vault descriptor: {exc}") from exc
    if len(raw) > 4096:
        raise VaultConfigError("vault descriptor is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultConfigError("vault descriptor is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != _EXPECTED_FIELDS:
        raise VaultConfigError("vault descriptor has unexpected fields")
    if type(value["version"]) is not int or value["version"] != DESCRIPTOR_VERSION:
        raise VaultConfigError("unsupported vault descriptor version")
    if not isinstance(value["dongle_fingerprint"], str):
        raise VaultConfigError("invalid dongle fingerprint")
    try:
        peer_public = base64.b64decode(value["peer_public"], validate=True)
        salt = base64.b64decode(value["salt"], validate=True)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public)
    except (TypeError, ValueError) as exc:
        raise VaultConfigError("invalid vault cryptographic parameters") from exc
    if len(peer_public) != 65 or len(salt) != 16:
        raise VaultConfigError("invalid vault cryptographic parameter length")
    return VaultDescriptor(value["version"], value["dongle_fingerprint"], peer_public, salt)


def derive_vault_credentials(device, descriptor: VaultDescriptor) -> VaultCredentials:
    """Ask the matching dongle for a master and domain-expand rclone credentials."""
    actual_fingerprint = public_key_fingerprint(device.public_key())
    if actual_fingerprint != descriptor.dongle_fingerprint:
        raise VaultConfigError("the connected dongle does not match this vault")
    try:
        peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), descriptor.peer_public
        )
    except ValueError as exc:
        raise VaultConfigError("invalid vault peer public key") from exc
    master = device.derive_key(peer_public, descriptor.salt)
    if not isinstance(master, bytes) or len(master) != 32:
        raise VaultConfigError("dongle returned an invalid vault master key")
    expanded = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=64,
        info=_CREDENTIAL_INFO,
    ).derive(master)
    return VaultCredentials(
        password=base64.urlsafe_b64encode(expanded[:32]).rstrip(b"=").decode("ascii"),
        filename_password=base64.urlsafe_b64encode(expanded[32:]).rstrip(b"=").decode("ascii"),
    )
