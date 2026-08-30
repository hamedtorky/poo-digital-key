# T-Dongle S3 Digital Document Key

This project turns a LILYGO T-Dongle S3 into a USB key for encrypted documents.
The private P-256 key is generated on the dongle at first boot and stored in its
NVS. It is never returned by the serial protocol.

## How it works

- Encryption asks the dongle for its public key.
- The computer creates an ephemeral P-256 key and performs ECDH.
- HKDF-SHA-256 derives a unique AES-256 key for each document.
- AES-256-GCM encrypts and authenticates the document into a `.tdkey` file.
- Decryption requires the original dongle and a physical press of its BOOT
  button. The dongle derives that document's key after confirmation.
- Existing output files are never overwritten.

The encrypted format is versioned. Current v2 uses a compact binary header with
an 8-byte non-readable magic; no human-readable metadata is stored. Legacy v1
files with the `TDKEY01` JSON header are still supported for decryption.

## Project layout

- `firmware/src/main.cpp` — ESP32-S3 firmware
- `host/digital_key/` — Python host application
- `host/digital_key/remote.py` — secure SFTP virtual-drive launcher
- `host/digital_key/vault_config.py` — dongle-bound zero-knowledge vault setup
- `dev/sftp/` — free local SFTP development server
- `tests/` — encryption, tamper detection, wrong-key, and serial-protocol tests
- `platformio.ini` — reproducible firmware build configuration

## Current status

The host tests pass, the firmware compiles for ESP32-S3, and the firmware has
been uploaded and verified on the original dongle. A computer that only uses
the key does not need PlatformIO or the firmware toolchain.

## Install the `poo` command on another computer

Copy or unzip this complete project folder onto the target computer first. The
installer needs an internet connection on its first run and Python 3.10 or
newer. The same flashed dongle works on Linux, macOS, and Windows.

### Linux

```sh
sh ./install/install.sh
```

Open a new terminal and run `poo status`. If Linux reports permission denied for
the serial device, add your account to the distro's serial group (commonly
`dialout`) and sign out and back in:

```sh
sudo usermod -aG dialout "$USER"
```

### macOS

Install Python 3.10 or newer from Python.org or Homebrew, then run:

```sh
sh ./install/install.sh
```

Open a new Terminal window and run `poo status`. The application automatically
recognizes `/dev/cu.usbmodem*` devices.

### Windows 10/11

Install Python 3.10 or newer from Python.org. Then open the project folder and
double-click:

```text
install\install-windows.cmd
```

Alternatively, from PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install\install.ps1
```

Open a new Command Prompt or PowerShell window and run `poo status`. Windows COM
ports are detected automatically.

## Build and upload firmware

From this directory:

```sh
source .venv/bin/activate
pio run
pio run --target upload
```

If automatic upload does not start, hold the BOOT button, briefly reconnect or
reset the board, begin the upload, and then release BOOT.

On first boot the firmware creates its permanent private key. Do not run an
"erase flash" operation after encrypting documents unless you intend to destroy
access to them.

## Verify the dongle

```sh
source .venv/bin/activate
poo status
```

The default serial port is detected automatically. To select it explicitly:

```sh
poo --port /dev/ttyACM0 status
```

## Mount an encrypted server vault as a virtual drive

The recommended mode encrypts file contents, file names, and directory names on
the computer before SFTP upload. The server stores only rclone `crypt`
ciphertext. The two vault credentials are regenerated from the dongle for each
mount and are not saved in an rclone configuration file.

Start the free local test server, then create a public descriptor while the
dongle is connected:

```sh
sh dev/sftp/start.sh
poo vault-init "$HOME/.config/poo/vault.json"
```

The descriptor is not a password, but it is required alongside the dongle.
Back it up with the encrypted server data. Creating a replacement descriptor
creates a different vault; the command deliberately refuses to overwrite one.

Mount the encrypted local test vault:

```sh
poo mount \
  --host 127.0.0.1 \
  --user poo \
  --sftp-port 2222 \
  --remote-path /vault-v1 \
  --mountpoint "$HOME/POO-Vault" \
  --known-hosts dev/sftp/state/known_hosts \
  --identity-file dev/sftp/state/client_ed25519 \
  --vault-config "$HOME/.config/poo/vault.json"
```

Press BOOT when prompted. Files copied into `POO-Vault` are readable through
the mounted drive and ciphertext on the server. Unplugging the dongle stops the
mount. Press Ctrl-C for a normal unmount. The host must be trusted while the
vault is open because applications and malware running as your user can read
mounted plaintext.

The local development server keeps encrypted `/vault-v1` data in a separate
Docker volume from the old plaintext `/files` directory. Do not use its test
SSH identity on a real server. For the complete threat model and production
hardening requirements, see `docs/zero-knowledge-vault.md`.

## Mount a plaintext SFTP server (legacy development mode)

The host application can use the computer's Internet connection to mount an
SSH/SFTP directory as a local drive. Server host-key validation is mandatory,
passwords are not accepted by this command, and remote shell execution is
disabled. The current development authentication uses an SSH identity file or
the system SSH agent. A later milestone will replace that agent with signing
performed by the dongle so its SSH private key never leaves the hardware.

For a free local test server, install and start Docker, then run:

```sh
sh dev/sftp/start.sh
```

Install rclone and the platform mount dependency:

- macOS: `brew install rclone`; the default uses `rclone nfsmount` and the
  built-in NFS client.
- Windows: install rclone and WinFsp; the mount point can be a drive such as
  `P:`.
- Linux: install rclone and FUSE 3; use a directory as the mount point.

Run the local macOS/Linux test mount from the repository root:

```sh
poo mount \
  --host 127.0.0.1 \
  --user poo \
  --sftp-port 2222 \
  --remote-path /files \
  --mountpoint "$PWD/build/poo-mount" \
  --known-hosts dev/sftp/state/known_hosts \
  --identity-file dev/sftp/state/client_ed25519
```

Keep the command running while using the drive and press Ctrl-C to unmount.
Stop the local server with `sh dev/sftp/stop.sh`. The generated test identity
under `dev/sftp/state/` is ignored by Git and must never be used in production.

## Encrypt a document

```sh
poo encrypt /path/to/document.pdf
```

This creates `/path/to/document.pdf.tdkey`. You may choose another output:

```sh
poo encrypt document.pdf -o private-document.tdkey
```

Encryption needs the dongle connected, but does not require a button press.
Do not delete the original until you have successfully tested decryption.

## Decrypt a document

```sh
poo decrypt /path/to/document.pdf.tdkey
```

Press the dongle's BOOT button when prompted. The default output removes the
`.tdkey` suffix. Use `-o` to select another output path.

### Optional: disable BOOT confirmation (testing only)
You can temporarily allow unattended decryption by compiling the firmware with
`-DDISABLE_CONFIRMATION=1` in `platformio.ini` under `build_flags`, then
rebuilding and uploading the firmware. This weakens security and should not be
used for real protection. Remove the flag and re-upload to restore BOOT
confirmation.

## Run verification

```sh
source .venv/bin/activate
pytest -q
pio run
```

## Important security and recovery limits

This is a functional prototype, not an audited commercial hardware security
module.

1. **No recovery key:** losing, damaging, or erasing this dongle makes its
   encrypted files unrecoverable. Keep encrypted files backed up, and consider
   building a deliberate recovery-key feature before important use.
2. **Flash extraction:** the private key is stored in ESP32 NVS, but flash
   encryption and Secure Boot are not enabled by this prototype. An attacker
   with physical access and suitable equipment may extract it.
3. **Trusted computer required:** after physical confirmation, the derived
   per-document AES key crosses USB to the host process. Malware running as your
   user could capture it while decrypting.
4. **Whole-file memory use:** the current host application loads one complete
   document into RAM. It is intended for normal documents, not very large disk
   images.
5. **Button confirmation:** the BOOT press prevents unattended decryption, but
   it is not a PIN and does not identify the person pressing it.

For stronger production use, enable ESP32-S3 Secure Boot and flash encryption,
add a PIN or trusted-display confirmation flow, design a carefully protected
recovery key, and obtain an independent security review.
