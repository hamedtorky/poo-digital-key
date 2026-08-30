import argparse
import getpass
import shlex
import sys
from pathlib import Path

from .device import DeviceError, SerialDigitalKey, find_default_port, public_key_fingerprint
from .remote import (
    RemoteError,
    SftpMountConfig,
    build_encrypted_mount_command,
    build_rclone_mount_command,
    run_encrypted_rclone_mount,
    run_rclone_mount,
)
from .vault import FormatError, decrypt_file, encrypt_file
from .vault_config import (
    DESCRIPTOR_VERSION,
    VaultConfigError,
    create_vault_descriptor,
    derive_vault_credentials,
    load_vault_descriptor,
)


def default_encrypt_output(source: Path) -> Path:
    return source.with_name(source.name + ".tdkey")


def default_decrypt_output(source: Path) -> Path:
    if source.name.endswith(".tdkey"):
        return source.with_name(source.name[:-6])
    return source.with_name(source.name + ".decrypted")


def prompt_new_vault_password() -> str:
    try:
        password = getpass.getpass("Create vault password (minimum 12 characters): ")
        confirmation = getpass.getpass("Repeat vault password: ")
    except (EOFError, OSError) as exc:
        raise VaultConfigError("could not securely read the vault password") from exc
    if password != confirmation:
        raise VaultConfigError("vault passwords do not match")
    return password


def prompt_vault_password() -> str:
    try:
        return getpass.getpass("Vault password: ")
    except (EOFError, OSError) as exc:
        raise VaultConfigError("could not securely read the vault password") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="poo",
        description="Encrypt documents for a LILYGO T-Dongle S3 hardware key.",
    )
    parser.add_argument("--port", help="serial port (default: auto-detect the USB dongle)")
    sub = parser.add_subparsers(dest="command", required=True)

    encrypt = sub.add_parser("encrypt", help="encrypt a file")
    encrypt.add_argument("source", type=Path)
    encrypt.add_argument("-o", "--output", type=Path)

    decrypt = sub.add_parser("decrypt", help="decrypt a file (requires BOOT-button confirmation)")
    decrypt.add_argument("source", type=Path)
    decrypt.add_argument("-o", "--output", type=Path)

    sub.add_parser("status", help="show the connected key fingerprint")

    vault_init = sub.add_parser("vault-init", help="create a vault descriptor for this dongle")
    vault_init.add_argument("descriptor", type=Path, help="new public vault descriptor JSON")

    mount = sub.add_parser("mount", help="mount an SSH/SFTP server as a local drive")
    mount.add_argument("--host", required=True, help="SSH server hostname")
    mount.add_argument("--user", required=True, help="SSH username")
    mount.add_argument("--sftp-port", type=int, default=22, help="SSH port (default: 22)")
    mount.add_argument("--remote-path", default="/", help="remote directory (default: /)")
    mount.add_argument("--mountpoint", required=True, help="drive letter or local mount directory")
    mount.add_argument("--known-hosts", required=True, type=Path, help="pinned OpenSSH known_hosts file")
    mount.add_argument("--identity-file", type=Path, help="test key; omit to use the SSH agent")
    mount.add_argument("--cache-dir", type=Path, help="local write cache directory")
    mount.add_argument("--rclone", default="rclone", help="rclone executable")
    mount.add_argument(
        "--vault-config",
        type=Path,
        help="encrypt file contents and names using this dongle-bound vault descriptor",
    )
    mount.add_argument(
        "--mount-engine",
        choices=("auto", "mount", "nfsmount"),
        default="auto",
        help="rclone mount backend (default: auto)",
    )
    mount.add_argument("--dry-run", action="store_true", help="print the command without mounting")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "mount":
            config = SftpMountConfig(
                host=args.host,
                user=args.user,
                port=args.sftp_port,
                remote_path=args.remote_path,
                mountpoint=args.mountpoint,
                known_hosts=args.known_hosts,
                identity_file=args.identity_file,
                cache_dir=args.cache_dir,
                mount_engine=args.mount_engine,
            )
            if args.dry_run:
                builder = build_encrypted_mount_command if args.vault_config else build_rclone_mount_command
                print(shlex.join(builder(config, args.rclone)))
                return 0
            if args.vault_config:
                descriptor = load_vault_descriptor(args.vault_config)
                password = None
                if descriptor.version == DESCRIPTOR_VERSION:
                    password = prompt_vault_password()
                else:
                    print(
                        "Warning: this legacy vault has no password protection.",
                        file=sys.stderr,
                    )
                port = args.port or find_default_port()
                print("Press the dongle BOOT button to unlock the encrypted vault.")
                with SerialDigitalKey(port) as device:
                    credentials = derive_vault_credentials(device, descriptor, password)
                print(f"Mounting encrypted vault at {args.mountpoint}")
                print("Keep this process running; press Ctrl-C to unmount.")
                return run_encrypted_rclone_mount(
                    config,
                    credentials.password,
                    credentials.filename_password,
                    args.rclone,
                    device_port=port,
                )
            print(f"Mounting {args.user}@{args.host}:{args.remote_path} at {args.mountpoint}")
            print("Keep this process running; press Ctrl-C to unmount.")
            return run_rclone_mount(config, args.rclone)

        new_vault_password = None
        if args.command == "vault-init":
            new_vault_password = prompt_new_vault_password()
        port = args.port or find_default_port()
        with SerialDigitalKey(port) as device:
            if args.command == "status":
                print(f"Dongle: {port}")
                print(f"Key fingerprint (SHA-256): {public_key_fingerprint(device.public_key())}")
                return 0
            if args.command == "vault-init":
                print("Press the dongle BOOT button to bind the password to this vault.")
                descriptor = create_vault_descriptor(
                    device, args.descriptor, new_vault_password
                )
                print(f"Vault descriptor created: {args.descriptor}")
                print(f"Bound dongle: {descriptor.dongle_fingerprint}")
                print("Back up this descriptor with the encrypted server data.")
                return 0
            if not args.source.is_file():
                raise FileNotFoundError(args.source)
            if args.command == "encrypt":
                output = args.output or default_encrypt_output(args.source)
                encrypt_file(args.source, output, device)
                print(f"Encrypted: {output}")
            else:
                output = args.output or default_decrypt_output(args.source)
                print("Confirm decryption by pressing the dongle BOOT button.")
                decrypt_file(args.source, output, device)
                print(f"Decrypted: {output}")
        return 0
    except (
        DeviceError,
        RemoteError,
        FormatError,
        VaultConfigError,
        FileNotFoundError,
        FileExistsError,
        PermissionError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nUnmounted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
