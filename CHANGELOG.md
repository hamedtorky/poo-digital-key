# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-08-30

First public prototype release of POO Digital Key for the LILYGO T-Dongle S3.

### Added

- ESP32-S3 firmware that creates and retains a P-256 private key on the dongle.
- Authenticated document encryption using ephemeral P-256 ECDH, HKDF-SHA-256,
  and AES-256-GCM.
- BOOT-button confirmation before document or vault key derivation.
- Password-and-dongle protected encrypted SFTP vaults. File contents, file names,
  and directory names are encrypted locally before reaching the server.
- A guided `poo setup` command for provisioning an Ubuntu SFTP server and setting
  up the encrypted vault from macOS.
- Automatic macOS password prompt, mount, and unmount when the dongle is inserted
  or removed.
- A Docker-based local SFTP test server and host/firmware verification commands.
- Detection of competing applications holding the dongle serial port, retry logic
  for recoverable USB errors, and redaction of dongle protocol secrets from errors.

### Compatibility

- Document encryption and decryption support Python 3.10+ on macOS, Linux, and
  Windows.
- Manual SFTP vault mounting supports macOS, Linux, and Windows with the platform
  mount dependency installed.
- Guided server provisioning and connection-triggered automatic mounting are
  currently macOS client features; the provisioned server must be Ubuntu.

### Release files

- `tdongle_digital_key-0.1.0-py3-none-any.whl` is the Python host application.
- `poo-digital-key-v0.1.0-esp32s3-app.bin` is an app-only firmware update image
  for flash offset `0x10000`. It intentionally excludes the NVS region that holds
  the dongle key. Use the normal PlatformIO upload for a completely new device.
- Never erase the flash of an initialized dongle unless you intend to permanently
  destroy access to data protected by its existing key.

### Security and recovery limits

- This is an unaudited prototype, not a commercial hardware security module.
- ESP32 Secure Boot, flash encryption, and encrypted NVS are not enabled yet.
- A trusted host is required: mounted plaintext and active credentials exist in
  host memory while the vault is open.
- The server can observe ciphertext sizes, modification times, and access patterns,
  and can delete data or serve an older snapshot.
- Losing or erasing the dongle, losing the public vault descriptor, or forgetting
  the vault password can make data permanently unrecoverable.
- Back up the encrypted server data and its vault descriptor before relying on it.

[0.1.0]: https://github.com/hamedtorky/poo-digital-key/releases/tag/v0.1.0
