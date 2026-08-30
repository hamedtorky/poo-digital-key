from pathlib import Path

import pytest

from digital_key.remote import (
    RemoteError,
    SftpMountConfig,
    build_encrypted_mount_command,
    build_encrypted_rclone_environment,
    build_rclone_mount_command,
)


def _config(tmp_path: Path, **overrides) -> SftpMountConfig:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("[localhost]:2222 ssh-ed25519 AAAAtest\n")
    values = {
        "host": "localhost",
        "user": "poo",
        "port": 2222,
        "remote_path": "/files",
        "mountpoint": str(tmp_path / "mount"),
        "known_hosts": known_hosts,
        "cache_dir": tmp_path / "cache",
        "mount_engine": "mount",
    }
    values.update(overrides)
    return SftpMountConfig(**values)


def test_mount_command_uses_agent_and_pins_host(tmp_path):
    command = build_rclone_mount_command(_config(tmp_path))

    assert command[:4] == ["rclone", "mount", ":sftp:/files", str(tmp_path / "mount")]
    assert command[command.index("--sftp-known-hosts-file") + 1] == str(tmp_path / "known_hosts")
    assert command[command.index("--sftp-shell-type") + 1] == "none"
    assert "--sftp-key-use-agent" in command
    assert "--sftp-pass" not in command


def test_mount_command_can_use_development_identity(tmp_path):
    identity = tmp_path / "client_key"
    identity.write_text("test key")

    command = build_rclone_mount_command(_config(tmp_path, identity_file=identity))

    assert "--sftp-key-use-agent" not in command
    assert command[command.index("--sftp-key-file") + 1] == str(identity)


@pytest.mark.parametrize("port", [0, 65536])
def test_mount_rejects_invalid_port(tmp_path, port):
    with pytest.raises(RemoteError, match="port"):
        build_rclone_mount_command(_config(tmp_path, port=port))


def test_mount_requires_known_hosts(tmp_path):
    with pytest.raises(RemoteError, match="known_hosts"):
        build_rclone_mount_command(_config(tmp_path, known_hosts=tmp_path / "missing"))


def test_encrypted_mount_command_contains_no_secret(tmp_path):
    command = build_encrypted_mount_command(_config(tmp_path))

    assert command[:4] == ["rclone", "mount", "poo_vault:", str(tmp_path / "mount")]
    assert "password" not in " ".join(command).lower()
    assert ":sftp:" not in command


def test_encrypted_environment_layers_crypt_over_sftp(tmp_path):
    config = _config(tmp_path)
    environment = build_encrypted_rclone_environment(
        config, "obscured-content", "obscured-names", {"PATH": "/bin"}
    )

    assert environment["PATH"] == "/bin"
    assert environment["RCLONE_CONFIG_POO_SFTP_TYPE"] == "sftp"
    assert environment["RCLONE_CONFIG_POO_SFTP_KNOWN_HOSTS_FILE"] == str(config.known_hosts)
    assert environment["RCLONE_CONFIG_POO_SFTP_KEY_USE_AGENT"] == "true"
    assert environment["RCLONE_CONFIG_POO_VAULT_TYPE"] == "crypt"
    assert environment["RCLONE_CONFIG_POO_VAULT_REMOTE"] == "poo_sftp:/files"
    assert environment["RCLONE_CONFIG_POO_VAULT_PASSWORD"] == "obscured-content"
    assert environment["RCLONE_CONFIG_POO_VAULT_PASSWORD2"] == "obscured-names"


def test_encrypted_environment_uses_identity_file(tmp_path):
    identity = tmp_path / "client_key"
    identity.write_text("test key")

    environment = build_encrypted_rclone_environment(
        _config(tmp_path, identity_file=identity), "one", "two", {}
    )

    assert environment["RCLONE_CONFIG_POO_SFTP_KEY_FILE"] == str(identity)
    assert "RCLONE_CONFIG_POO_SFTP_KEY_USE_AGENT" not in environment
