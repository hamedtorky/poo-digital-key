from pathlib import Path

import pytest

from digital_key.remote import RemoteError, SftpMountConfig, build_rclone_mount_command


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
