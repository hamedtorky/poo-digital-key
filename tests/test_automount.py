import plistlib
import stat
from pathlib import Path
from types import SimpleNamespace

from digital_key.automount import (
    LAUNCH_AGENT_LABEL,
    AutoMountConfig,
    find_esp_port,
    install_launch_agent,
    load_automount_config,
    save_automount_config,
    unlock_and_mount,
)
from digital_key.remote import DongleDisconnected
from digital_key.vault_config import VaultConfigError


def _config(tmp_path: Path) -> AutoMountConfig:
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "identity"
    descriptor = tmp_path / "vault.json"
    known_hosts.write_text("host key")
    identity.write_text("identity")
    descriptor.write_text("descriptor")
    return AutoMountConfig(
        host="127.0.0.1",
        user="poo",
        port=2222,
        remote_path="/vault-v1",
        mountpoint=str(tmp_path / "mount"),
        known_hosts=str(known_hosts),
        identity_file=str(identity),
        vault_config=str(descriptor),
        mount_engine="nfsmount",
    )


def test_automount_config_round_trip_is_private(tmp_path):
    config = _config(tmp_path)
    path = tmp_path / "config" / "automount.json"

    save_automount_config(config, path)

    assert load_automount_config(path) == config
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "password" not in path.read_text().lower()


def test_find_esp_port_ignores_unrelated_serial_devices(monkeypatch):
    monkeypatch.setattr(
        "digital_key.automount.list_ports.comports",
        lambda: [
            SimpleNamespace(device="/dev/cu.usbserial-other", vid=0x0403),
            SimpleNamespace(device="/dev/cu.usbmodem101", vid=0x303A),
        ],
    )

    assert find_esp_port() == "/dev/cu.usbmodem101"


def test_unlock_uses_existing_descriptor_and_password(tmp_path, monkeypatch):
    config = _config(tmp_path)
    captured = {}

    class FakeDevice:
        def __init__(self, port):
            captured["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("digital_key.automount.prompt_password", lambda: "secret phrase")
    monkeypatch.setattr("digital_key.automount.confirm_boot", lambda: True)
    monkeypatch.setattr("digital_key.automount.load_vault_descriptor", lambda path: "descriptor")
    monkeypatch.setattr("digital_key.automount.SerialDigitalKey", FakeDevice)
    monkeypatch.setattr(
        "digital_key.automount.derive_vault_credentials",
        lambda device, descriptor, password: SimpleNamespace(
            password="content-key", filename_password="name-key"
        ),
    )

    def fake_mount(sftp, password, filename_password, rclone, device_port):
        captured.update({
            "sftp": sftp,
            "password": password,
            "filename_password": filename_password,
            "rclone": rclone,
            "device_port": device_port,
        })
        return 0

    monkeypatch.setattr("digital_key.automount.run_encrypted_rclone_mount", fake_mount)

    assert unlock_and_mount(config, "/dev/cu.usbmodem101") is True
    assert captured["port"] == "/dev/cu.usbmodem101"
    assert captured["device_port"] == "/dev/cu.usbmodem101"
    assert captured["password"] == "content-key"
    assert captured["filename_password"] == "name-key"
    assert captured["sftp"].remote_path == "/vault-v1"


def test_cancelled_password_does_not_open_dongle(tmp_path, monkeypatch):
    monkeypatch.setattr("digital_key.automount.prompt_password", lambda: None)
    monkeypatch.setattr(
        "digital_key.automount.SerialDigitalKey",
        lambda port: (_ for _ in ()).throw(AssertionError("dongle must not open")),
    )

    assert unlock_and_mount(_config(tmp_path), "/dev/cu.usbmodem101") is False


def test_launch_agent_runs_installed_watcher(tmp_path, monkeypatch):
    monkeypatch.setattr("digital_key.automount.platform.system", lambda: "Darwin")
    config_path = tmp_path / "config" / "automount.json"
    agent_path = tmp_path / "LaunchAgents" / "agent.plist"
    executable = tmp_path / "bin" / "poo"
    executable.parent.mkdir()
    executable.write_text("launcher")

    returned = install_launch_agent(
        _config(tmp_path), executable, config_path=config_path, launch_agent_path=agent_path
    )
    with agent_path.open("rb") as stream:
        value = plistlib.load(stream)

    assert returned == (config_path, agent_path)
    assert value["Label"] == LAUNCH_AGENT_LABEL
    assert value["ProgramArguments"] == [
        str(executable.resolve()),
        "automount-run",
        str(config_path),
    ]
    assert value["RunAtLoad"] is True
    assert value["KeepAlive"] is True
    assert stat.S_IMODE(agent_path.stat().st_mode) == 0o600


def test_expected_disconnect_does_not_show_error_dialog(tmp_path, monkeypatch, capsys):
    ports = iter(["/dev/cu.usbmodem101", None])
    monkeypatch.setattr("digital_key.automount.platform.system", lambda: "Darwin")
    monkeypatch.setattr("digital_key.automount.load_automount_config", lambda path: _config(tmp_path))
    monkeypatch.setattr("digital_key.automount.find_esp_port", lambda: next(ports))
    monkeypatch.setattr(
        "digital_key.automount.unlock_and_mount",
        lambda config, port: (_ for _ in ()).throw(DongleDisconnected("removed")),
    )
    monkeypatch.setattr(
        "digital_key.automount.show_message",
        lambda message: (_ for _ in ()).throw(AssertionError("must not show an error")),
    )
    monkeypatch.setattr(
        "digital_key.automount.time.sleep",
        lambda seconds: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    from digital_key.automount import run_automount_loop

    try:
        run_automount_loop(tmp_path / "config.json")
    except KeyboardInterrupt:
        pass

    output = capsys.readouterr().out
    assert "Dongle detected" in output
    assert "vault unmounted" in output


def test_unlock_error_allows_retry_without_reconnect(tmp_path, monkeypatch):
    attempts = []
    monkeypatch.setattr("digital_key.automount.platform.system", lambda: "Darwin")
    monkeypatch.setattr("digital_key.automount.load_automount_config", lambda path: _config(tmp_path))
    monkeypatch.setattr("digital_key.automount.find_esp_port", lambda: "/dev/cu.usbmodem101")

    def fake_unlock(config, port):
        attempts.append(port)
        if len(attempts) == 1:
            raise VaultConfigError("incorrect vault password")
        raise KeyboardInterrupt()

    monkeypatch.setattr("digital_key.automount.unlock_and_mount", fake_unlock)
    monkeypatch.setattr("digital_key.automount.show_message", lambda message: None)

    try:
        from digital_key.automount import run_automount_loop

        run_automount_loop(tmp_path / "config.json")
    except KeyboardInterrupt:
        pass

    assert attempts == ["/dev/cu.usbmodem101", "/dev/cu.usbmodem101"]
