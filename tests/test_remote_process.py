from pathlib import Path

from digital_key.remote import SftpMountConfig, obscure_rclone_secret, run_rclone_mount


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
