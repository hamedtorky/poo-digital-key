import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path


class RemoteError(RuntimeError):
    pass


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


def run_rclone_mount(config: SftpMountConfig, rclone: str = "rclone") -> int:
    """Run the mount in the foreground so Ctrl-C safely unmounts it."""
    mountpoint = config.mountpoint
    if not (len(mountpoint) == 2 and mountpoint[1] == ":"):
        mount_path = Path(mountpoint).expanduser().resolve()
        mount_path.mkdir(parents=True, exist_ok=True)
        config = replace(config, mountpoint=str(mount_path))

    command = build_rclone_mount_command(config, rclone)
    executable = command[0]
    if os.path.sep not in executable and shutil.which(executable) is None:
        raise RemoteError(f"rclone executable not found: {executable}")
    try:
        return subprocess.run(command, check=False).returncode
    except OSError as exc:
        raise RemoteError(f"could not start rclone: {exc}") from exc
