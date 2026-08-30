import os
import platform
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .automount import (
    LAUNCH_AGENT_LABEL,
    AutoMountConfig,
    activate_launch_agent,
    find_esp_port,
    install_launch_agent,
)
from .device import SerialDigitalKey, find_default_port, public_key_fingerprint
from .vault_config import create_vault_descriptor, load_vault_descriptor


class SetupError(RuntimeError):
    pass


@dataclass(frozen=True)
class ServerInfo:
    host: str
    admin_user: str
    port: int = 22
    admin_identity: Path | None = None

    def validate(self) -> None:
        for name, value in (("server address", self.host), ("admin username", self.admin_user)):
            if not value or any(character in value for character in "\r\n\0"):
                raise SetupError(f"invalid {name}")
        if not 1 <= self.port <= 65535:
            raise SetupError("SSH port must be between 1 and 65535")
        if self.admin_identity is not None and not self.admin_identity.expanduser().is_file():
            raise SetupError(f"admin SSH identity not found: {self.admin_identity}")


REMOTE_SETUP_SCRIPT = r"""#!/bin/sh
set -eu

AUTHORIZED_KEY=$1
SSH_PORT=$2
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y openssh-server ufw unattended-upgrades
getent group sftp-only >/dev/null || groupadd sftp-only
if id poo >/dev/null 2>&1; then
    usermod --gid sftp-only --home /vault --shell /usr/sbin/nologin poo
else
    useradd --gid sftp-only --home-dir /vault --shell /usr/sbin/nologin poo
fi

install -d -o root -g root -m 0755 /srv/poo
install -d -o poo -g sftp-only -m 0700 /srv/poo/vault
install -d -o root -g root -m 0755 /etc/ssh/authorized_keys
printf '%s\n' "$AUTHORIZED_KEY" > /etc/ssh/authorized_keys/poo
chown root:root /etc/ssh/authorized_keys/poo
chmod 0600 /etc/ssh/authorized_keys/poo

cat > /etc/ssh/sshd_config.d/poo-sftp.conf <<'EOF'
Match User poo
    ChrootDirectory /srv/poo
    ForceCommand internal-sftp
    PasswordAuthentication no
    PubkeyAuthentication yes
    AuthorizedKeysFile /etc/ssh/authorized_keys/%u
    DisableForwarding yes
    PermitTTY no
EOF

sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd
ufw allow "${SSH_PORT}/tcp" >/dev/null
printf 'POO_SERVER_READY\n'
"""


def _ssh_base(info: ServerInfo, known_hosts: Path) -> list[str]:
    command = [
        "ssh",
        "-p",
        str(info.port),
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "StrictHostKeyChecking=ask",
    ]
    if info.admin_identity is not None:
        command.extend(("-i", str(info.admin_identity.expanduser().resolve())))
    return command


def ensure_server_identity(private_key: Path, run=subprocess.run) -> Path:
    private_key = private_key.expanduser()
    public_key = Path(str(private_key) + ".pub")
    if private_key.is_file() and public_key.is_file():
        return public_key
    private_key.parent.mkdir(parents=True, exist_ok=True)
    result = run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "poo-sftp-client", "-f", str(private_key)],
        check=False,
    )
    if result.returncode != 0 or not private_key.is_file() or not public_key.is_file():
        raise SetupError("could not generate the POO server SSH key")
    private_key.chmod(0o600)
    return public_key


def provision_server(
    info: ServerInfo,
    public_key: Path,
    known_hosts: Path,
    run=subprocess.run,
) -> None:
    info.validate()
    known_hosts = known_hosts.expanduser().resolve()
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    target = f"{info.admin_user}@{info.host}"
    base = _ssh_base(info, known_hosts)
    create = run(
        base + [target, "umask 077; mktemp /tmp/poo-server-setup.XXXXXX"],
        text=True,
        stdout=subprocess.PIPE,
        check=False,
    )
    remote_script = create.stdout.strip()
    if create.returncode != 0 or not remote_script.startswith("/tmp/poo-server-setup."):
        raise SetupError("could not connect to the server or create its setup file")
    try:
        upload = run(
            base + [target, f"cat > {shlex.quote(remote_script)}"],
            input=REMOTE_SETUP_SCRIPT,
            text=True,
            check=False,
        )
        if upload.returncode != 0:
            raise SetupError("could not upload the server setup component")
        authorized_key = public_key.read_text(encoding="ascii").strip()
        script_command = (
            f"/bin/sh {shlex.quote(remote_script)} "
            f"{shlex.quote(authorized_key)} {info.port}"
        )
        remote_command = (
            f"if [ \"$(id -u)\" -eq 0 ]; then {script_command}; "
            f"else sudo {script_command}; fi"
        )
        install = run(base + ["-tt", target, remote_command], check=False)
        if install.returncode != 0:
            raise SetupError("server setup failed; review the SSH/sudo output above")
    finally:
        run(
            base + [target, f"rm -f -- {shlex.quote(remote_script)}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def verify_sftp(info: ServerInfo, identity: Path, known_hosts: Path, run=subprocess.run) -> None:
    command = [
        "sftp",
        "-q",
        "-b",
        "-",
        "-P",
        str(info.port),
        "-i",
        str(identity.expanduser().resolve()),
        "-o",
        f"UserKnownHostsFile={known_hosts.expanduser().resolve()}",
        f"poo@{info.host}",
    ]
    result = run(command, input="pwd\nls\n", text=True, check=False)
    if result.returncode != 0:
        raise SetupError("the new restricted SFTP account did not pass verification")


def _prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or (default or "")


def _wait_for_dongle(present: bool) -> str | None:
    while True:
        port = find_esp_port()
        if bool(port) == present:
            return port
        time.sleep(1)


def _stop_existing_agent() -> None:
    if platform.system() != "Darwin":
        return
    agent_path = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"
    if agent_path.exists():
        subprocess.run(
            ["/bin/launchctl", "bootout", f"gui/{os.getuid()}", str(agent_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def run_setup_wizard(prompt_new_password) -> None:
    if platform.system() != "Darwin":
        raise SetupError("the one-command setup currently supports macOS")
    _stop_existing_agent()
    print("1/5 Checking the USB dongle...")
    port = find_default_port()
    with SerialDigitalKey(port) as device:
        fingerprint = public_key_fingerprint(device.public_key())
    print(f"Dongle ready: {fingerprint}")

    print("\n2/5 Enter the SSH administrator information for your Ubuntu server.")
    host = _prompt("Server address or IP")
    admin_user = _prompt("Server admin username", "ubuntu")
    port_text = _prompt("SSH port", "22")
    identity_text = _prompt("Admin SSH identity path (leave empty for SSH agent/default keys)")
    try:
        ssh_port = int(port_text)
    except ValueError as exc:
        raise SetupError("SSH port must be a number") from exc
    info = ServerInfo(
        host=host,
        admin_user=admin_user,
        port=ssh_port,
        admin_identity=Path(identity_text).expanduser() if identity_text else None,
    )
    info.validate()

    config_dir = Path.home() / ".config" / "poo"
    server_key = config_dir / "server_ed25519"
    known_hosts = config_dir / "server_known_hosts"
    descriptor_path = config_dir / "vault.json"
    public_key = ensure_server_identity(server_key)

    print("\n3/5 Connecting by SSH. Confirm the host fingerprint and enter the admin/sudo password if asked.")
    provision_server(info, public_key, known_hosts)
    verify_sftp(info, server_key, known_hosts)
    print("Restricted SFTP server is ready.")

    print("\n4/5 Preparing the password-protected dongle vault.")
    if descriptor_path.exists():
        descriptor = load_vault_descriptor(descriptor_path)
        if descriptor.dongle_fingerprint != fingerprint:
            raise SetupError("the existing vault descriptor belongs to a different dongle")
        print("Existing vault descriptor verified; vault-init was not repeated.")
    else:
        password = prompt_new_password()
        print("Press the dongle BOOT button to bind this password.")
        with SerialDigitalKey(port) as device:
            create_vault_descriptor(device, descriptor_path, password)
        del password
        print(f"Vault descriptor created: {descriptor_path}")

    executable = Path(shutil.which("poo") or "poo")
    rclone = shutil.which("rclone")
    if rclone is None:
        raise SetupError("rclone is required; install it with: brew install rclone")
    automount = AutoMountConfig(
        host=info.host,
        user="poo",
        port=info.port,
        remote_path="/vault",
        mountpoint=str(Path.home() / "POO-Vault"),
        known_hosts=str(known_hosts),
        identity_file=str(server_key),
        vault_config=str(descriptor_path),
        rclone=str(Path(rclone).resolve()),
        mount_engine="nfsmount",
    )
    _, agent_path = install_launch_agent(automount, executable)

    print("\n5/5 Unplug the dongle now. Setup will continue automatically.")
    _wait_for_dongle(False)
    activate_launch_agent(agent_path)
    print("Now reconnect the dongle normally. Enter the vault password and press BOOT in the dialogs.")
    _wait_for_dongle(True)
    mountpoint = Path(automount.mountpoint)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if os.path.ismount(mountpoint):
            print(f"Setup complete. Encrypted drive mounted at {mountpoint}")
            return
        time.sleep(1)
    raise SetupError("automatic mount was not completed within three minutes")
