import base64
from types import SimpleNamespace

import pytest
import serial as pyserial
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from digital_key.device import DeviceError, SerialDigitalKey, find_default_port


class FakeSerial:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.writes = []

    def reset_input_buffer(self):
        pass

    def write(self, data):
        self.writes.append(data)

    def flush(self):
        pass

    def readline(self):
        return next(self.replies)

    def close(self):
        pass


def test_public_key_protocol_parses_uncompressed_p256_point():
    private = ec.generate_private_key(ec.SECP256R1())
    raw = private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    serial = FakeSerial([b"READY TDKEY1\n", b"PUB " + base64.b64encode(raw) + b"\n"])
    device = SerialDigitalKey(serial_port=serial)

    result = device.public_key()

    assert result.public_numbers() == private.public_key().public_numbers()
    assert serial.writes[-1] == b"PUBLIC\n"


def test_device_error_is_reported():
    serial = FakeSerial([b"READY TDKEY1\n", b"ERR confirmation-timeout\n"])
    device = SerialDigitalKey(serial_port=serial)
    peer = ec.generate_private_key(ec.SECP256R1()).public_key()

    with pytest.raises(DeviceError, match="confirmation-timeout"):
        device.derive_key(peer, b"0" * 16)


def test_port_discovery_works_with_windows_com_port():
    ports = [SimpleNamespace(device="COM7", vid=0x303A, pid=0x1001)]

    assert find_default_port(ports) == "COM7"


def test_port_discovery_prefers_espressif_device():
    ports = [
        SimpleNamespace(device="/dev/cu.Bluetooth-Incoming-Port", vid=None, pid=None),
        SimpleNamespace(device="/dev/cu.usbmodem101", vid=0x303A, pid=0x1001),
    ]

    assert find_default_port(ports) == "/dev/cu.usbmodem101"


def test_serial_control_lines_are_inactive_before_open(monkeypatch):
    events = []

    class UnopenedSerial(FakeSerial):
        def __init__(self):
            super().__init__([b"READY TDKEY1\n"])
            self._dtr = None
            self._rts = None
            self.exclusive = None

        @property
        def dtr(self):
            return self._dtr

        @dtr.setter
        def dtr(self, value):
            self._dtr = value
            events.append(("dtr", value))

        @property
        def rts(self):
            return self._rts

        @rts.setter
        def rts(self, value):
            self._rts = value
            events.append(("rts", value))

        def open(self):
            events.append(("open", self.port))

    serial_port = UnopenedSerial()
    monkeypatch.setattr("digital_key.device.serial.Serial", lambda: serial_port)
    monkeypatch.setattr("digital_key.device.time.sleep", lambda seconds: None)

    device = SerialDigitalKey("/dev/cu.usbmodem-test")

    assert events == [
        ("dtr", False),
        ("rts", False),
        ("open", "/dev/cu.usbmodem-test"),
    ]
    assert device._serial.baudrate == 115200
    assert device._serial.exclusive is True


def test_serial_read_conflict_has_actionable_error():
    class ConflictedSerial(FakeSerial):
        def readline(self):
            raise pyserial.SerialException("multiple access on port")

    conflicted = ConflictedSerial([])

    with pytest.raises(DeviceError, match="close Cura"):
        SerialDigitalKey(serial_port=conflicted)


def test_unexpected_derive_response_never_exposes_device_output():
    secret_fragment = "oO9iqDrxj4kFsKO4V+/lJydPO2vK7+U="
    serial = FakeSerial([
        b"READY TDKEY1\n",
        f"KY {secret_fragment}\n".encode(),
    ])
    device = SerialDigitalKey(serial_port=serial)
    peer = ec.generate_private_key(ec.SECP256R1()).public_key()

    with pytest.raises(DeviceError) as captured:
        device.derive_key(peer, b"0" * 16)

    assert "unexpected DERIVE response format" in str(captured.value)
    assert secret_fragment not in str(captured.value)
