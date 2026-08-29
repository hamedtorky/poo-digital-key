import argparse
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .device import DeviceError, SerialDigitalKey, find_default_port
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
    return parser


def _fingerprint(public_key) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(encoded).hexdigest()
    return ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        port = args.port or find_default_port()
        with SerialDigitalKey(port) as device:
            if args.command == "status":
                print(f"Dongle: {port}")
                print(f"Key fingerprint (SHA-256): {_fingerprint(device.public_key())}")
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
    except (DeviceError, FormatError, FileNotFoundError, FileExistsError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
