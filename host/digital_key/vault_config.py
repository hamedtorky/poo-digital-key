import base64
import hmac
import json
import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from .device import public_key_fingerprint


DESCRIPTOR_VERSION = 2
LEGACY_DESCRIPTOR_VERSION = 1
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
_LEGACY_CREDENTIAL_INFO = b"POO zero-knowledge vault rclone credentials v1"
_CREDENTIAL_INFO = b"POO zero-knowledge vault rclone credentials v2"
_COMBINE_INFO = b"POO zero-knowledge vault dongle and password v2"
_VERIFICATION_INFO = b"POO zero-knowledge vault password verification v2"
_COMMON_FIELDS = {"version", "dongle_fingerprint", "peer_public", "salt"}
_V2_FIELDS = _COMMON_FIELDS | {
    "password_salt",
    "argon2_memory_kib",
    "argon2_iterations",
    "argon2_lanes",
    "verification_tag",
}


class VaultConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class VaultDescriptor:
    version: int
    dongle_fingerprint: str
    peer_public: bytes
    salt: bytes
    password_salt: bytes | None = None
    verification_tag: bytes | None = None

    def to_json(self) -> str:
        value = {
            "version": self.version,
            "dongle_fingerprint": self.dongle_fingerprint,
            "peer_public": base64.b64encode(self.peer_public).decode("ascii"),
            "salt": base64.b64encode(self.salt).decode("ascii"),
        }
        if self.version == DESCRIPTOR_VERSION:
            value.update({
                "password_salt": base64.b64encode(self.password_salt).decode("ascii"),
                "argon2_memory_kib": ARGON2_MEMORY_KIB,
                "argon2_iterations": ARGON2_ITERATIONS,
                "argon2_lanes": ARGON2_LANES,
                "verification_tag": base64.b64encode(self.verification_tag).decode("ascii"),
            })
        return json.dumps(value, indent=2, sort_keys=True) + "\n"


@dataclass(frozen=True)
class VaultCredentials:
    password: str
    filename_password: str


def create_vault_descriptor(device, output: Path, password: str) -> VaultDescriptor:
    """Create a public vault descriptor without persisting a decrypting secret."""
    password_bytes = _password_bytes(password, enforce_strength=True)
    output = Path(output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"vault descriptor already exists: {output}")

    dongle_public = device.public_key()
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    peer_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    salt = os.urandom(16)
    password_salt = os.urandom(16)
    hardware_secret = device.derive_key(ephemeral.public_key(), salt)
    combined_key = _combine_factors(hardware_secret, password_bytes, password_salt, salt)
    descriptor = VaultDescriptor(
        version=DESCRIPTOR_VERSION,
        dongle_fingerprint=public_key_fingerprint(dongle_public),
        peer_public=peer_public,
        salt=salt,
        password_salt=password_salt,
        verification_tag=_verification_tag(combined_key),
    )

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
    if not isinstance(value, dict):
        raise VaultConfigError("vault descriptor has unexpected fields")
    version = value.get("version")
    expected_fields = _COMMON_FIELDS if version == LEGACY_DESCRIPTOR_VERSION else _V2_FIELDS
    if set(value) != expected_fields:
        raise VaultConfigError("vault descriptor has unexpected fields")
    if type(version) is not int or version not in {LEGACY_DESCRIPTOR_VERSION, DESCRIPTOR_VERSION}:
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
    if version == LEGACY_DESCRIPTOR_VERSION:
        return VaultDescriptor(version, value["dongle_fingerprint"], peer_public, salt)
    if (
        type(value["argon2_memory_kib"]) is not int
        or value["argon2_memory_kib"] != ARGON2_MEMORY_KIB
        or type(value["argon2_iterations"]) is not int
        or value["argon2_iterations"] != ARGON2_ITERATIONS
        or type(value["argon2_lanes"]) is not int
        or value["argon2_lanes"] != ARGON2_LANES
    ):
        raise VaultConfigError("unsupported vault password parameters")
    try:
        password_salt = base64.b64decode(value["password_salt"], validate=True)
        verification_tag = base64.b64decode(value["verification_tag"], validate=True)
    except (TypeError, ValueError) as exc:
        raise VaultConfigError("invalid vault password parameters") from exc
    if len(password_salt) != 16 or len(verification_tag) != 16:
        raise VaultConfigError("invalid vault password parameter length")
    return VaultDescriptor(
        version,
        value["dongle_fingerprint"],
        peer_public,
        salt,
        password_salt,
        verification_tag,
    )


def derive_vault_credentials(
    device, descriptor: VaultDescriptor, password: str | None = None
) -> VaultCredentials:
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
    if descriptor.version == DESCRIPTOR_VERSION:
        if password is None:
            raise VaultConfigError("this vault requires a password")
        password_bytes = _password_bytes(password, enforce_strength=False)
        master = _combine_factors(
            master, password_bytes, descriptor.password_salt, descriptor.salt
        )
        if not hmac.compare_digest(_verification_tag(master), descriptor.verification_tag):
            raise VaultConfigError("incorrect vault password")
        credential_info = _CREDENTIAL_INFO
    elif descriptor.version == LEGACY_DESCRIPTOR_VERSION:
        credential_info = _LEGACY_CREDENTIAL_INFO
    else:
        raise VaultConfigError("unsupported vault descriptor version")
    expanded = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=64,
        info=credential_info,
    ).derive(master)
    return VaultCredentials(
        password=base64.urlsafe_b64encode(expanded[:32]).rstrip(b"=").decode("ascii"),
        filename_password=base64.urlsafe_b64encode(expanded[32:]).rstrip(b"=").decode("ascii"),
    )


def _password_bytes(password: str, enforce_strength: bool) -> bytes:
    if not isinstance(password, str):
        raise VaultConfigError("vault password must be text")
    normalized = unicodedata.normalize("NFC", password)
    encoded = normalized.encode("utf-8")
    if enforce_strength and len(normalized) < 12:
        raise VaultConfigError("vault password must contain at least 12 characters")
    if not encoded:
        raise VaultConfigError("vault password cannot be empty")
    if len(encoded) > 1024:
        raise VaultConfigError("vault password is too long")
    return encoded


def _combine_factors(
    hardware_secret: bytes, password: bytes, password_salt: bytes, vault_salt: bytes
) -> bytes:
    if not isinstance(hardware_secret, bytes) or len(hardware_secret) != 32:
        raise VaultConfigError("dongle returned an invalid vault master key")
    password_key = Argon2id(
        salt=password_salt,
        length=32,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_KIB,
    ).derive(password)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=vault_salt,
        info=_COMBINE_INFO,
    ).derive(hardware_secret + password_key)


def _verification_tag(combined_key: bytes) -> bytes:
    verifier = HMAC(combined_key, hashes.SHA256())
    verifier.update(_VERIFICATION_INFO)
    return verifier.finalize()[:16]
