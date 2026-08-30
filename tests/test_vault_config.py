import json
import stat

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from digital_key.device import public_key_fingerprint
from digital_key.vault_config import (
    ARGON2_ITERATIONS,
    ARGON2_LANES,
    ARGON2_MEMORY_KIB,
    VaultDescriptor,
    VaultConfigError,
    create_vault_descriptor,
    derive_vault_credentials,
    load_vault_descriptor,
)


PASSWORD = "correct horse battery staple"


class FakeDevice:
    def __init__(self, private_key=None):
        self.private_key = private_key or ec.generate_private_key(ec.SECP256R1())
        self.derive_calls = 0

    def public_key(self):
        return self.private_key.public_key()

    def derive_key(self, peer_public_key, salt):
        self.derive_calls += 1
        shared = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"tdkey-file-v1",
        ).derive(shared)


def test_descriptor_round_trip_and_stable_credentials(tmp_path):
    device = FakeDevice()
    path = tmp_path / "vault.json"

    created = create_vault_descriptor(device, path, PASSWORD)
    loaded = load_vault_descriptor(path)
    first = derive_vault_credentials(device, loaded, PASSWORD)
    second = derive_vault_credentials(device, loaded, PASSWORD)

    assert loaded == created
    assert first == second
    assert first.password != first.filename_password
    assert len(first.password) == 43
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert device.derive_calls == 3


def test_descriptor_contains_no_derived_credentials(tmp_path):
    device = FakeDevice()
    path = tmp_path / "vault.json"

    create_vault_descriptor(device, path, PASSWORD)
    value = json.loads(path.read_text())

    assert set(value) == {
        "version",
        "dongle_fingerprint",
        "peer_public",
        "salt",
        "password_salt",
        "argon2_memory_kib",
        "argon2_iterations",
        "argon2_lanes",
        "verification_tag",
    }
    assert value["argon2_memory_kib"] == ARGON2_MEMORY_KIB
    assert value["argon2_iterations"] == ARGON2_ITERATIONS
    assert value["argon2_lanes"] == ARGON2_LANES
    assert PASSWORD not in path.read_text()


def test_descriptor_refuses_overwrite(tmp_path):
    path = tmp_path / "vault.json"
    path.write_text("keep me")

    with pytest.raises(FileExistsError, match="already exists"):
        create_vault_descriptor(FakeDevice(), path, PASSWORD)

    assert path.read_text() == "keep me"


def test_wrong_dongle_is_rejected_before_derivation(tmp_path):
    path = tmp_path / "vault.json"
    create_vault_descriptor(FakeDevice(), path, PASSWORD)
    wrong_device = FakeDevice()

    with pytest.raises(VaultConfigError, match="does not match"):
        derive_vault_credentials(wrong_device, load_vault_descriptor(path), PASSWORD)

    assert wrong_device.derive_calls == 0


@pytest.mark.parametrize(
    "mutate,error",
    [
        (lambda value: value.update(version=3), "version"),
        (lambda value: value.update(extra=True), "unexpected fields"),
        (lambda value: value.update(salt="not base64!"), "cryptographic"),
        (lambda value: value.update(peer_public="AA=="), "cryptographic"),
        (lambda value: value.update(argon2_memory_kib=2**30), "password parameters"),
        (lambda value: value.update(password_salt="AA=="), "parameter length"),
    ],
)
def test_malformed_descriptor_is_rejected(tmp_path, mutate, error):
    path = tmp_path / "vault.json"
    create_vault_descriptor(FakeDevice(), path, PASSWORD)
    value = json.loads(path.read_text())
    mutate(value)
    path.write_text(json.dumps(value))

    with pytest.raises(VaultConfigError, match=error):
        load_vault_descriptor(path)


def test_wrong_password_is_rejected_after_dongle_confirmation(tmp_path):
    device = FakeDevice()
    path = tmp_path / "vault.json"
    create_vault_descriptor(device, path, PASSWORD)

    with pytest.raises(VaultConfigError, match="incorrect vault password"):
        derive_vault_credentials(device, load_vault_descriptor(path), "this is the wrong password")

    assert device.derive_calls == 2


@pytest.mark.parametrize("password", ["", "too-short"])
def test_new_vault_rejects_weak_password_before_using_dongle(tmp_path, password):
    device = FakeDevice()

    with pytest.raises(VaultConfigError, match="password"):
        create_vault_descriptor(device, tmp_path / "vault.json", password)

    assert device.derive_calls == 0


def test_legacy_descriptor_remains_readable_without_password(tmp_path):
    device = FakeDevice()
    peer = ec.generate_private_key(ec.SECP256R1()).public_key()
    peer_bytes = peer.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    descriptor = VaultDescriptor(
        version=1,
        dongle_fingerprint=public_key_fingerprint(device.public_key()),
        peer_public=peer_bytes,
        salt=b"legacy-salt-1234",
    )
    path = tmp_path / "legacy.json"
    path.write_text(descriptor.to_json())

    loaded = load_vault_descriptor(path)
    credentials = derive_vault_credentials(device, loaded)

    assert loaded.version == 1
    assert len(credentials.password) == 43
