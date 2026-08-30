from pathlib import Path

import pytest

from digital_key.cli import (
    default_decrypt_output,
    default_encrypt_output,
    main,
    prompt_new_vault_password,
)
from digital_key.vault_config import VaultConfigError


def test_default_encrypt_output_adds_tdkey_suffix():
    assert default_encrypt_output(Path("report.pdf")) == Path("report.pdf.tdkey")


def test_default_decrypt_output_removes_tdkey_suffix():
    assert default_decrypt_output(Path("report.pdf.tdkey")) == Path("report.pdf")


def test_default_decrypt_output_avoids_source_name_without_suffix():
    assert default_decrypt_output(Path("archive.bin")) == Path("archive.bin.decrypted")


def test_mount_dry_run_does_not_require_dongle(tmp_path, capsys):
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "client_key"
    known_hosts.write_text("[localhost]:2222 ssh-ed25519 AAAAtest\n")
    identity.write_text("test key")

    result = main([
        "mount",
        "--host", "localhost",
        "--user", "poo",
        "--sftp-port", "2222",
        "--remote-path", "/files",
        "--mountpoint", str(tmp_path / "mount"),
        "--known-hosts", str(known_hosts),
        "--identity-file", str(identity),
        "--mount-engine", "mount",
        "--dry-run",
    ])

    output = capsys.readouterr().out
    assert result == 0
    assert "rclone mount :sftp:/files" in output
    assert "--sftp-known-hosts-file" in output


def test_encrypted_mount_dry_run_does_not_unlock_dongle(tmp_path, capsys):
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "client_key"
    known_hosts.write_text("[localhost]:2222 ssh-ed25519 AAAAtest\n")
    identity.write_text("test key")

    result = main([
        "mount",
        "--host", "localhost",
        "--user", "poo",
        "--remote-path", "/vault-v1",
        "--mountpoint", str(tmp_path / "mount"),
        "--known-hosts", str(known_hosts),
        "--identity-file", str(identity),
        "--vault-config", str(tmp_path / "not-read-in-dry-run.json"),
        "--mount-engine", "mount",
        "--dry-run",
    ])

    output = capsys.readouterr().out
    assert result == 0
    assert "rclone mount poo_vault:" in output
    assert "password" not in output.lower()


def test_new_vault_password_is_confirmed_without_echo(monkeypatch):
    replies = iter(["correct horse battery staple", "correct horse battery staple"])
    prompts = []

    def fake_getpass(prompt):
        prompts.append(prompt)
        return next(replies)

    monkeypatch.setattr("digital_key.cli.getpass.getpass", fake_getpass)

    assert prompt_new_vault_password() == "correct horse battery staple"
    assert len(prompts) == 2


def test_new_vault_password_must_match(monkeypatch):
    replies = iter(["correct horse battery staple", "different battery staple"])
    monkeypatch.setattr("digital_key.cli.getpass.getpass", lambda prompt: next(replies))

    with pytest.raises(VaultConfigError, match="do not match"):
        prompt_new_vault_password()
