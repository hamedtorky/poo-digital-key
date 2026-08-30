import argparse
import shlex
import sys
from pathlib import Path

from .device import DeviceError, SerialDigitalKey, find_default_port, public_key_fingerprint
from .remote import RemoteError, SftpMountConfig, build_rclone_mount_command, run_rclone_mount
from .vault import FormatError, decrypt_file, encrypt_file


def default_encrypt_output(source: Path) -> Path:
    return source.with_name(source.name + ".tdkey")


def default_decrypt_output(source: Path) -> Path:
    if source.name.endswith(".tdkey"):
        return source.with_name(source.name[:-6])
    return source.with_name(source.name + ".decrypted")


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
                print(shlex.join(build_rclone_mount_command(config, args.rclone)))
                return 0
            print(f"Mounting {args.user}@{args.host}:{args.remote_path} at {args.mountpoint}")
            print("Keep this process running; press Ctrl-C to unmount.")
            return run_rclone_mount(config, args.rclone)

        port = args.port or find_default_port()
        with SerialDigitalKey(port) as device:
            if args.command == "status":
                print(f"Dongle: {port}")
                print(f"Key fingerprint (SHA-256): {public_key_fingerprint(device.public_key())}")
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
    except (DeviceError, RemoteError, FormatError, FileNotFoundError, FileExistsError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nUnmounted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
