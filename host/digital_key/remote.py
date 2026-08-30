import os
import platform
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path

from serial.tools import list_ports


class RemoteError(RuntimeError):
    pass


_SFTP_REMOTE_NAME = "poo_sftp"
_VAULT_REMOTE_NAME = "poo_vault"


@dataclass(frozen=True)
class SftpMountConfig:
    host: str
    user: str
    remote_path: str
    mountpoint: str
    known_hosts: Path
    port: int = 22
    identity_file: Path | None = None
    cache_dir: Path | None = None
    volume_name: str = "POO Secure"
    mount_engine: str = "auto"

    def validate(self) -> None:
        for name, value in (("host", self.host), ("user", self.user)):
            if not value or any(character in value for character in "\r\n\0"):
                raise RemoteError(f"invalid SFTP {name}")
        if not 1 <= self.port <= 65535:
            raise RemoteError("SFTP port must be between 1 and 65535")
        if any(character in self.remote_path for character in "\r\n\0"):
            raise RemoteError("invalid remote path")
        if not self.mountpoint or any(character in self.mountpoint for character in "\r\n\0"):
            raise RemoteError("invalid mount point")
        if not self.known_hosts.is_file():
            raise RemoteError(f"known_hosts file not found: {self.known_hosts}")
        if self.identity_file is not None and not self.identity_file.is_file():
            raise RemoteError(f"SSH identity file not found: {self.identity_file}")
        if self.mount_engine not in {"auto", "mount", "nfsmount"}:
            raise RemoteError("mount engine must be auto, mount, or nfsmount")


def _mount_engine(configured: str) -> str:
    if configured != "auto":
        return configured
    return "nfsmount" if platform.system() == "Darwin" else "mount"


def _remote_spec(remote_path: str) -> str:
    path = remote_path or ""
    return f":sftp:{path}"


def build_rclone_mount_command(config: SftpMountConfig, rclone: str = "rclone") -> list[str]:
    """Build a config-free, host-key-verified SFTP mount command."""
    config.validate()
    cache_dir = config.cache_dir or Path.home() / ".cache" / "poo-digital-key"
    command = [
        rclone,
        _mount_engine(config.mount_engine),
        _remote_spec(config.remote_path),
        config.mountpoint,
        "--sftp-host",
        config.host,
        "--sftp-user",
        config.user,
        "--sftp-port",
        str(config.port),
        "--sftp-known-hosts-file",
        str(config.known_hosts),
        "--sftp-shell-type",
        "none",
        "--vfs-cache-mode",
        "writes",
        "--cache-dir",
        str(cache_dir),
        "--volname",
        config.volume_name,
    ]
    if config.identity_file is None:
        command.append("--sftp-key-use-agent")
    else:
        command.extend(("--sftp-key-file", str(config.identity_file)))
    return command


def build_encrypted_mount_command(config: SftpMountConfig, rclone: str = "rclone") -> list[str]:
    """Build a crypt-over-SFTP mount command; credentials live only in its environment."""
    config.validate()
    cache_dir = config.cache_dir or Path.home() / ".cache" / "poo-digital-key"
    return [
        rclone,
        _mount_engine(config.mount_engine),
        f"{_VAULT_REMOTE_NAME}:",
        config.mountpoint,
        "--vfs-cache-mode",
        "writes",
        "--cache-dir",
        str(cache_dir),
        "--volname",
        config.volume_name,
    ]


def obscure_rclone_secret(secret: str, rclone: str = "rclone") -> str:
    """Use rclone's supported reversible encoding without exposing input in argv."""
    _require_rclone(rclone)
    try:
        result = subprocess.run(
            [rclone, "obscure", "-"],
            input=secret + "\n",
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise RemoteError(f"could not start rclone: {exc}") from exc
    obscured = result.stdout.strip()
    if result.returncode != 0 or not obscured:
        detail = result.stderr.strip() or "unknown error"
        raise RemoteError(f"could not prepare encrypted mount credential: {detail}")
    return obscured


def build_encrypted_rclone_environment(
    config: SftpMountConfig,
    obscured_password: str,
    obscured_filename_password: str,
    base_environment: dict[str, str] | None = None,
) -> dict[str, str]:
    """Create ephemeral named-remote configuration for crypt over pinned SFTP."""
    config.validate()
    environment = dict(os.environ if base_environment is None else base_environment)
    prefix = f"RCLONE_CONFIG_{_SFTP_REMOTE_NAME.upper()}_"
    environment.update({
        prefix + "TYPE": "sftp",
        prefix + "HOST": config.host,
        prefix + "USER": config.user,
        prefix + "PORT": str(config.port),
        prefix + "KNOWN_HOSTS_FILE": str(config.known_hosts),
        prefix + "SHELL_TYPE": "none",
    })
    if config.identity_file is None:
        environment[prefix + "KEY_USE_AGENT"] = "true"
    else:
        environment[prefix + "KEY_FILE"] = str(config.identity_file)

    vault_prefix = f"RCLONE_CONFIG_{_VAULT_REMOTE_NAME.upper()}_"
    environment.update({
        vault_prefix + "TYPE": "crypt",
        vault_prefix + "REMOTE": f"{_SFTP_REMOTE_NAME}:{config.remote_path}",
        vault_prefix + "PASSWORD": obscured_password,
        vault_prefix + "PASSWORD2": obscured_filename_password,
        vault_prefix + "FILENAME_ENCRYPTION": "standard",
        vault_prefix + "DIRECTORY_NAME_ENCRYPTION": "true",
        vault_prefix + "STRICT_NAMES": "true",
    })
    return environment


def _require_rclone(rclone: str) -> None:
    if os.path.sep not in rclone and shutil.which(rclone) is None:
        raise RemoteError(f"rclone executable not found: {rclone}")


def _resolved_mount_config(config: SftpMountConfig) -> SftpMountConfig:
    mountpoint = config.mountpoint
    if len(mountpoint) == 2 and mountpoint[1] == ":":
        return config
    mount_path = Path(mountpoint).expanduser().resolve()
    mount_path.mkdir(parents=True, exist_ok=True)
    return replace(config, mountpoint=str(mount_path))


def run_rclone_mount(config: SftpMountConfig, rclone: str = "rclone") -> int:
    """Run the mount in the foreground so Ctrl-C safely unmounts it."""
    config = _resolved_mount_config(config)
    command = build_rclone_mount_command(config, rclone)
    _require_rclone(command[0])
    try:
        return subprocess.run(command, check=False).returncode
    except OSError as exc:
        raise RemoteError(f"could not start rclone: {exc}") from exc


def run_encrypted_rclone_mount(
    config: SftpMountConfig,
    password: str,
    filename_password: str,
    rclone: str = "rclone",
    device_port: str | None = None,
    poll_interval: float = 1.0,
) -> int:
    """Mount crypt over SFTP and stop access as soon as the dongle disappears."""
    config = _resolved_mount_config(config)
    obscured_password = obscure_rclone_secret(password, rclone)
    obscured_filename_password = obscure_rclone_secret(filename_password, rclone)
    cache_parent = None
    if config.cache_dir is not None:
        cache_parent = Path(config.cache_dir).expanduser().resolve()
        cache_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="poo-vault-", dir=cache_parent) as cache_dir:
        runtime_config = replace(config, cache_dir=Path(cache_dir))
        command = build_encrypted_mount_command(runtime_config, rclone)
        environment = build_encrypted_rclone_environment(
            runtime_config, obscured_password, obscured_filename_password
        )
        try:
            process = subprocess.Popen(command, env=environment)
        except OSError as exc:
            raise RemoteError(f"could not start rclone: {exc}") from exc
        finally:
            for name in (
                "RCLONE_CONFIG_POO_VAULT_PASSWORD",
                "RCLONE_CONFIG_POO_VAULT_PASSWORD2",
            ):
                environment.pop(name, None)

        try:
            if device_port is None:
                return process.wait()
            while process.poll() is None:
                if not any(port.device == device_port for port in list_ports.comports()):
                    _stop_mount_process(process)
                    raise RemoteError("dongle disconnected; encrypted vault was unmounted")
                time.sleep(poll_interval)
            return process.returncode
        except KeyboardInterrupt:
            _stop_mount_process(process)
            raise


def _stop_mount_process(process) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
