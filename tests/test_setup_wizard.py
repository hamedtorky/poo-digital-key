from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from digital_key.setup_wizard import (
    REMOTE_SETUP_SCRIPT,
    ServerInfo,
    SetupError,
    provision_server,
    run_setup_wizard,
)


def test_server_info_rejects_command_injection_and_bad_port():
    with pytest.raises(SetupError, match="server address"):
        ServerInfo("host\ncommand", "ubuntu").validate()
    with pytest.raises(SetupError, match="port"):
        ServerInfo("server.example", "ubuntu", port=70000).validate()


def test_remote_provisioning_uploads_static_script_and_cleans_up(tmp_path):
    public_key = tmp_path / "server_ed25519.pub"
    public_key.write_text("ssh-ed25519 AAAAtest poo-sftp-client\n")
    known_hosts = tmp_path / "server_known_hosts"
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if any("mktemp /tmp/poo-server-setup.XXXXXX" in part for part in command):
            return SimpleNamespace(returncode=0, stdout="/tmp/poo-server-setup.ABC123\n")
        return SimpleNamespace(returncode=0, stdout="")

    provision_server(
        ServerInfo("server.example", "ubuntu", port=2222),
        public_key,
        known_hosts,
        run=fake_run,
    )

    assert len(calls) == 4
    assert calls[1][1]["input"] == REMOTE_SETUP_SCRIPT
    install_command = calls[2][0][-1]
    assert "sudo /bin/sh /tmp/poo-server-setup.ABC123" in install_command
    assert "ssh-ed25519 AAAAtest poo-sftp-client" in install_command
    assert install_command.endswith(" 2222; fi")
    assert calls[3][0][-1] == "rm -f -- /tmp/poo-server-setup.ABC123"
    assert "PasswordAuthentication no" in REMOTE_SETUP_SCRIPT
    assert "ForceCommand internal-sftp" in REMOTE_SETUP_SCRIPT


def test_guided_setup_orchestrates_server_vault_and_automount(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    replies = iter(["server.example", "", "", ""])
    monkeypatch.setattr("builtins.input", lambda prompt: next(replies))
    monkeypatch.setattr("digital_key.setup_wizard.platform.system", lambda: "Darwin")
    monkeypatch.setattr("digital_key.setup_wizard._stop_existing_agent", lambda: None)
    monkeypatch.setattr("digital_key.setup_wizard.find_default_port", lambda: "/dev/cu.usbmodem101")

    private_key = ec.generate_private_key(ec.SECP256R1())

    class FakeDevice:
        def __init__(self, port):
            assert port == "/dev/cu.usbmodem101"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def public_key(self):
            return private_key.public_key()

    monkeypatch.setattr("digital_key.setup_wizard.SerialDigitalKey", FakeDevice)
    generated_public = tmp_path / ".config" / "poo" / "server_ed25519.pub"
    generated_public.parent.mkdir(parents=True)
    generated_public.write_text("ssh-ed25519 AAAAtest\n")
    monkeypatch.setattr(
        "digital_key.setup_wizard.ensure_server_identity", lambda path: generated_public
    )
    events = []
    monkeypatch.setattr(
        "digital_key.setup_wizard.provision_server",
        lambda info, public, known: events.append(("server", info.host, info.admin_user)),
    )
    monkeypatch.setattr(
        "digital_key.setup_wizard.verify_sftp",
        lambda info, identity, known: events.append(("sftp", info.host)),
    )

    def fake_create(device, path, password):
        events.append(("vault", password, path))

    monkeypatch.setattr("digital_key.setup_wizard.create_vault_descriptor", fake_create)
    monkeypatch.setattr(
        "digital_key.setup_wizard.shutil.which",
        lambda name: f"/opt/homebrew/bin/{name}",
    )
    captured = {}

    def fake_install(config, executable):
        captured["config"] = config
        return tmp_path / "automount.json", tmp_path / "agent.plist"

    monkeypatch.setattr("digital_key.setup_wizard.install_launch_agent", fake_install)
    monkeypatch.setattr(
        "digital_key.setup_wizard.activate_launch_agent",
        lambda path: events.append(("activate", path)),
    )
    monkeypatch.setattr(
        "digital_key.setup_wizard._wait_for_dongle",
        lambda present: events.append(("wait", present)),
    )
    monkeypatch.setattr("digital_key.setup_wizard.os.path.ismount", lambda path: True)

    run_setup_wizard(lambda: "correct horse battery staple")

    assert ("server", "server.example", "ubuntu") in events
    assert ("sftp", "server.example") in events
    assert any(event[:2] == ("vault", "correct horse battery staple") for event in events)
    assert ("wait", False) in events
    assert ("wait", True) in events
    assert captured["config"].host == "server.example"
    assert captured["config"].remote_path == "/vault"
    assert captured["config"].mountpoint == str(tmp_path / "POO-Vault")


def test_guided_setup_restores_previous_agent_after_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("digital_key.setup_wizard.platform.system", lambda: "Darwin")
    previous_agent = tmp_path / "previous.plist"
    monkeypatch.setattr(
        "digital_key.setup_wizard._stop_existing_agent", lambda: previous_agent
    )
    monkeypatch.setattr(
        "digital_key.setup_wizard._run_setup_wizard",
        lambda prompt: (_ for _ in ()).throw(SetupError("server failed")),
    )
    restored = []
    monkeypatch.setattr(
        "digital_key.setup_wizard.activate_launch_agent", lambda path: restored.append(path)
    )

    with pytest.raises(SetupError, match="server failed"):
        run_setup_wizard(lambda: "password")

    assert restored == [previous_agent]
