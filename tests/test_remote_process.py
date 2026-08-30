from pathlib import Path

from digital_key.remote import SftpMountConfig, run_rclone_mount


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
