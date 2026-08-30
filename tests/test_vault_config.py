import json
import stat

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from digital_key.vault_config import (
    VaultConfigError,
    create_vault_descriptor,
    derive_vault_credentials,
    load_vault_descriptor,
)


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

    created = create_vault_descriptor(device, path)
    loaded = load_vault_descriptor(path)
    first = derive_vault_credentials(device, loaded)
    second = derive_vault_credentials(device, loaded)

    assert loaded == created
    assert first == second
    assert first.password != first.filename_password
    assert len(first.password) == 43
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert device.derive_calls == 2


def test_descriptor_contains_no_derived_credentials(tmp_path):
    device = FakeDevice()
    path = tmp_path / "vault.json"

    create_vault_descriptor(device, path)
    value = json.loads(path.read_text())

    assert set(value) == {"version", "dongle_fingerprint", "peer_public", "salt"}


def test_descriptor_refuses_overwrite(tmp_path):
    path = tmp_path / "vault.json"
    path.write_text("keep me")

    with pytest.raises(FileExistsError, match="already exists"):
        create_vault_descriptor(FakeDevice(), path)

    assert path.read_text() == "keep me"


def test_wrong_dongle_is_rejected_before_derivation(tmp_path):
    path = tmp_path / "vault.json"
    create_vault_descriptor(FakeDevice(), path)
    wrong_device = FakeDevice()

    with pytest.raises(VaultConfigError, match="does not match"):
        derive_vault_credentials(wrong_device, load_vault_descriptor(path))

    assert wrong_device.derive_calls == 0


@pytest.mark.parametrize(
    "mutate,error",
    [
        (lambda value: value.update(version=2), "version"),
        (lambda value: value.update(extra=True), "unexpected fields"),
        (lambda value: value.update(salt="not base64!"), "cryptographic"),
        (lambda value: value.update(peer_public="AA=="), "cryptographic"),
    ],
)
def test_malformed_descriptor_is_rejected(tmp_path, mutate, error):
    path = tmp_path / "vault.json"
    create_vault_descriptor(FakeDevice(), path)
    value = json.loads(path.read_text())
    mutate(value)
    path.write_text(json.dumps(value))

    with pytest.raises(VaultConfigError, match=error):
        load_vault_descriptor(path)
