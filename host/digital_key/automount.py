import json
import os
import platform
import plistlib
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from serial.tools import list_ports

from .device import DeviceError, SerialDigitalKey
from .remote import (
    DongleDisconnected,
    RemoteError,
    SftpMountConfig,
    run_encrypted_rclone_mount,
)
from .vault_config import VaultConfigError, derive_vault_credentials, load_vault_descriptor


LAUNCH_AGENT_LABEL = "com.poo-digital-key.automount"
CONFIG_VERSION = 1


class AutoMountError(RuntimeError):
    pass


@dataclass(frozen=True)
class AutoMountConfig:
    host: str
    user: str
    remote_path: str
    mountpoint: str
    known_hosts: str
    vault_config: str
    port: int = 22
    identity_file: str | None = None
    cache_dir: str | None = None
    rclone: str = "rclone"
    mount_engine: str = "auto"
    version: int = CONFIG_VERSION

    def sftp_config(self) -> SftpMountConfig:
        return SftpMountConfig(
            host=self.host,
            user=self.user,
            port=self.port,
            remote_path=self.remote_path,
            mountpoint=self.mountpoint,
            known_hosts=Path(self.known_hosts).expanduser(),
            identity_file=Path(self.identity_file).expanduser() if self.identity_file else None,
            cache_dir=Path(self.cache_dir).expanduser() if self.cache_dir else None,
            mount_engine=self.mount_engine,
        )


def save_automount_config(config: AutoMountConfig, output: Path) -> None:
    output = Path(output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(asdict(config), indent=2, sort_keys=True) + "\n"
    temporary = output.with_name(output.name + ".new")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
        os.replace(temporary, output)
        output.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def load_automount_config(source: Path) -> AutoMountConfig:
    try:
        value = json.loads(Path(source).expanduser().read_text(encoding="utf-8"))
        config = AutoMountConfig(**value)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AutoMountError(f"invalid automatic-mount configuration: {exc}") from exc
    if config.version != CONFIG_VERSION:
        raise AutoMountError("unsupported automatic-mount configuration version")
    config.sftp_config().validate()
    if not Path(config.vault_config).expanduser().is_file():
        raise AutoMountError(f"vault descriptor not found: {config.vault_config}")
    return config


def find_esp_port() -> str | None:
    for port in list_ports.comports():
        if getattr(port, "vid", None) == 0x303A:
            return port.device
    return None


def serial_port_owners(device_port: str) -> list[str]:
    """Return other macOS processes that already have the dongle open."""
    if platform.system() != "Darwin":
        return []
    result = subprocess.run(
        ["/usr/sbin/lsof", "-Fpc", "--", device_port],
        text=True,
        capture_output=True,
        check=False,
    )
    owners = []
    current_pid = None
    for line in result.stdout.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            current_pid = int(line[1:])
        elif line.startswith("c") and current_pid not in (None, os.getpid()):
            owner = f"{line[1:]} (PID {current_pid})"
            if owner not in owners:
                owners.append(owner)
    return owners


def _run_applescript(script: str) -> str | None:
    result = subprocess.run(
        ["/usr/bin/osascript", "-e", script],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.rstrip("\n")


def prompt_password() -> str | None:
    return _run_applescript(
        'text returned of (display dialog "Enter the password for your POO encrypted drive." '
        'with title "POO Secure Vault" default answer "" with hidden answer '
        'buttons {"Cancel", "Unlock"} default button "Unlock" cancel button "Cancel")'
    )


def confirm_boot() -> bool:
    return _run_applescript(
        'button returned of (display dialog "Click Continue, then press the physical BOOT button '
        'on the USB dongle within 15 seconds." with title "POO Secure Vault" '
        'buttons {"Cancel", "Continue"} default button "Continue" cancel button "Cancel")'
    ) == "Continue"


def show_message(message: str) -> None:
    safe = message.replace("\\", "\\\\").replace('"', '\\"')
    _run_applescript(
        f'display dialog "{safe}" with title "POO Secure Vault" buttons {{"OK"}} default button "OK"'
    )


def unlock_and_mount(config: AutoMountConfig, device_port: str) -> bool:
    password = prompt_password()
    if password is None:
        print(f"Unlock canceled for {device_port}", flush=True)
        return False
    if not confirm_boot():
        print(f"BOOT confirmation canceled for {device_port}", flush=True)
        return False
    descriptor = load_vault_descriptor(Path(config.vault_config))
    with SerialDigitalKey(device_port) as device:
        credentials = derive_vault_credentials(device, descriptor, password)
    print(f"Vault unlocked; mounting at {config.mountpoint}", flush=True)
    return_code = run_encrypted_rclone_mount(
        config.sftp_config(),
        credentials.password,
        credentials.filename_password,
        config.rclone,
        device_port=device_port,
    )
    if return_code not in (0, 130):
        raise AutoMountError(f"encrypted mount exited with status {return_code}")
    print("Encrypted mount stopped", flush=True)
    return True


def run_automount_loop(config_path: Path, poll_interval: float = 1.0) -> None:
    if platform.system() != "Darwin":
        raise AutoMountError("automatic GUI mounting is currently supported only on macOS")
    config = load_automount_config(config_path)
    handled_port = None
    while True:
        port = find_esp_port()
        if port is None:
            handled_port = None
            time.sleep(poll_interval)
            continue
        if port == handled_port:
            time.sleep(poll_interval)
            continue
        handled_port = port
        print(f"Dongle detected: {port}", flush=True)
        owners = serial_port_owners(port)
        if owners:
            owner_text = ", ".join(owners)
            message = (
                f"The USB dongle is busy in {owner_text}. Quit that application, "
                "then unplug and reconnect the dongle."
            )
            print(f"Automatic mount blocked: {message}", flush=True)
            show_message(message)
            continue
        try:
            unlock_and_mount(config, port)
        except DongleDisconnected:
            print("Dongle removed; encrypted vault unmounted", flush=True)
        except (AutoMountError, DeviceError, RemoteError, VaultConfigError) as exc:
            print(f"Automatic mount error: {exc}", flush=True)
            show_message(str(exc))
            # Permit a deliberate retry while the dongle remains connected.
            # A canceled password/BOOT dialog returns normally and keeps the
            # port handled, so cancellation never creates prompt spam.
            handled_port = None


def install_launch_agent(
    config: AutoMountConfig,
    executable: Path,
    config_path: Path | None = None,
    launch_agent_path: Path | None = None,
) -> tuple[Path, Path]:
    if platform.system() != "Darwin":
        raise AutoMountError("automatic mount installation is currently supported only on macOS")
    config_path = config_path or Path.home() / ".config" / "poo" / "automount.json"
    launch_agent_path = launch_agent_path or (
        Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"
    )
    log_dir = Path.home() / ".local" / "state" / "poo-digital-key"
    log_dir.mkdir(parents=True, exist_ok=True)
    save_automount_config(config, config_path)
    launch_agent_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [str(Path(executable).resolve()), "automount-run", str(config_path)],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Interactive",
        "ThrottleInterval": 5,
        "StandardOutPath": str(log_dir / "automount.log"),
        "StandardErrorPath": str(log_dir / "automount-error.log"),
    }
    temporary = launch_agent_path.with_name(launch_agent_path.name + ".new")
    try:
        with temporary.open("wb") as stream:
            plistlib.dump(payload, stream)
        os.replace(temporary, launch_agent_path)
        launch_agent_path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return config_path, launch_agent_path


def activate_launch_agent(launch_agent_path: Path) -> None:
    domain = f"gui/{os.getuid()}"
    subprocess.run(
        ["/bin/launchctl", "bootout", domain, str(launch_agent_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    result = subprocess.run(
        ["/bin/launchctl", "bootstrap", domain, str(launch_agent_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AutoMountError(result.stderr.strip() or "could not activate automatic mount service")
