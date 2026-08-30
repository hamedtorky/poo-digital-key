import base64
import time

import serial
from serial.tools import list_ports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class DeviceError(RuntimeError):
    pass


class SerialDigitalKey:
    """Client for the small line protocol implemented by the dongle firmware."""

    def __init__(self, port: str = "/dev/ttyACM0", serial_port=None):
        if serial_port is None:
            self._serial = serial.Serial(port, 115200, timeout=20, write_timeout=5)
            time.sleep(1.5)
        else:
            self._serial = serial_port
        self._serial.reset_input_buffer()
        # Opening native USB normally resets the board. Ask for a fresh banner.
        self._serial.write(b"HELLO\n")
        self._serial.flush()
        line = self._read_line(expect_ready=True)
        if line != "READY TDKEY1":
            raise DeviceError(f"unexpected device greeting: {line}")

    def close(self):
        self._serial.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def _read_line(self, expect_ready=False) -> str:
        for _ in range(30):
            raw = self._serial.readline()
            if not raw:
                raise DeviceError("dongle did not respond")
            line = raw.decode("ascii", errors="replace").strip()
            if not line:
                continue
            if line.startswith("ERR "):
                raise DeviceError(line[4:])
            # Ignore firmware prompts during interactive flows
            if line.startswith("CONFIRM "):
                continue
            # Ignore stray READY banners when not explicitly waiting for them
            if not expect_ready and line == "READY TDKEY1":
                continue
            if expect_ready and line != "READY TDKEY1":
                continue
            return line
        raise DeviceError("no valid response from dongle")

    def public_key(self):
        self._serial.write(b"PUBLIC\n")
        self._serial.flush()
        line = self._read_line()
        if not line.startswith("PUB "):
            raise DeviceError(f"unexpected PUBLIC response: {line}")
        try:
            raw = base64.b64decode(line[4:], validate=True)
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        except (ValueError, TypeError) as exc:
            raise DeviceError("dongle returned an invalid public key") from exc

    def derive_key(self, peer_public_key, salt: bytes) -> bytes:
        if len(salt) != 16:
            raise ValueError("salt must be 16 bytes")
        peer = peer_public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        command = b"DERIVE " + base64.b64encode(peer) + b" " + base64.b64encode(salt) + b"\n"
        self._serial.write(command)
        self._serial.flush()
        line = self._read_line()
        if not line.startswith("KEY "):
            raise DeviceError(f"unexpected DERIVE response: {line}")
        try:
            key = base64.b64decode(line[4:], validate=True)
        except ValueError as exc:
            raise DeviceError("dongle returned an invalid key") from exc
        if len(key) != 32:
            raise DeviceError("dongle returned an invalid key length")
        return key


def find_default_port(ports=None) -> str:
    """Find the dongle on Linux, macOS, or Windows."""
    detected = list(list_ports.comports() if ports is None else ports)
    if not detected:
        raise DeviceError("no USB serial dongle found")
    for port in detected:
        if getattr(port, "vid", None) == 0x303A:
            return port.device
    if len(detected) == 1:
        return detected[0].device
    names = ", ".join(port.device for port in detected)
    raise DeviceError(f"multiple serial devices found; use --port ({names})")
