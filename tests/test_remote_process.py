from pathlib import Path

from types import SimpleNamespace

import pytest

from digital_key.remote import (
    RemoteError,
    SftpMountConfig,
    obscure_rclone_secret,
    run_encrypted_rclone_mount,
    run_rclone_mount,
)


def test_run_mount_resolves_unix_mountpoint(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("localhost ssh-ed25519 AAAAtest\n")
    captured = {}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("digital_key.remote.shutil.which", lambda executable: "/usr/bin/rclone")

    class Result:
        returncode = 0

    def fake_run(command, check):
        captured["command"] = command
        return Result()

    monkeypatch.setattr("digital_key.remote.subprocess.run", fake_run)
    config = SftpMountConfig(
        host="localhost",
        user="poo",
        remote_path="/files",
        mountpoint="relative-mount",
        known_hosts=known_hosts,
        mount_engine="mount",
    )

    assert run_rclone_mount(config) == 0
    assert captured["command"][3] == str(tmp_path / "relative-mount")
    assert (tmp_path / "relative-mount").is_dir()


def test_obscure_secret_uses_stdin_not_command_line(monkeypatch):
    captured = {}
    monkeypatch.setattr("digital_key.remote.shutil.which", lambda executable: "/usr/bin/rclone")

    class Result:
        returncode = 0
        stdout = "obscured-value\n"
        stderr = ""

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["input"] = kwargs["input"]
        return Result()

    monkeypatch.setattr("digital_key.remote.subprocess.run", fake_run)

    assert obscure_rclone_secret("very-secret") == "obscured-value"
    assert captured["command"] == ["rclone", "obscure", "-"]
    assert "very-secret" not in captured["command"]
    assert captured["input"] == "very-secret\n"


def test_encrypted_mount_stops_when_dongle_is_removed(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "client_key"
    cache_parent = tmp_path / "cache-parent"
    known_hosts.write_text("localhost ssh-ed25519 AAAAtest\n")
    identity.write_text("test key")
    captured = {}

    class FakeProcess:
        returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            captured["terminated"] = True
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    def fake_popen(command, env):
        captured["command"] = command
        captured["environment"] = dict(env)
        return FakeProcess()

    monkeypatch.setattr("digital_key.remote.shutil.which", lambda executable: "/usr/bin/rclone")
    monkeypatch.setattr("digital_key.remote.obscure_rclone_secret", lambda secret, rclone: "hidden")
    monkeypatch.setattr("digital_key.remote.subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        "digital_key.remote.list_ports.comports",
        lambda: [SimpleNamespace(device="/dev/cu.some-other-device")],
    )
    config = SftpMountConfig(
        host="localhost",
        user="poo",
        remote_path="/vault-v1",
        mountpoint=str(tmp_path / "mount"),
        known_hosts=known_hosts,
        identity_file=identity,
        cache_dir=cache_parent,
        mount_engine="mount",
    )

    with pytest.raises(RemoteError, match="dongle disconnected"):
        run_encrypted_rclone_mount(
            config, "content-secret", "name-secret", device_port="/dev/cu.usbmodem101"
        )

    assert captured["terminated"] is True
    assert captured["command"][2] == "poo_vault:"
    assert "content-secret" not in captured["command"]
    assert captured["environment"]["RCLONE_CONFIG_POO_VAULT_PASSWORD"] == "hidden"
    assert list(cache_parent.iterdir()) == []
