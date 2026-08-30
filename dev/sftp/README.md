# Local SFTP development server

This fixture provides a free, local, SFTP-only server for development. It binds
to `127.0.0.1:2222`, disables passwords and forwarding, and authenticates with
an ephemeral development key under the ignored `state/` directory.

Start it with:

```sh
sh dev/sftp/start.sh
```

After installing rclone and a supported filesystem driver, test the mount from
the repository root:

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

Keep the command running while using the mount. Press Ctrl-C to unmount, then
stop the test server with:

```sh
sh dev/sftp/stop.sh
```

The development identity is intentionally separate from the eventual hardware
SSH key and must never be used on a production server.

The fixture exposes two persistent paths: `/files` for the original plaintext
mount test and `/vault-v1` for encrypted-vault testing. Keep them separate. To
test the zero-knowledge mode, first run:

```sh
poo vault-init "$HOME/.config/poo/vault.json"
```

Enter and confirm a password of at least 12 characters, then press BOOT to bind
the password and dongle to the new vault. Change the mount example to
`--remote-path /vault-v1`, add
`--vault-config "$HOME/.config/poo/vault.json"`, enter the password, and press
the dongle BOOT button when prompted.

The default mount backend is selected by platform: `nfsmount` on macOS, using
the built-in NFS client, and `mount` on Windows or Linux. Windows requires
WinFsp; Linux requires FUSE 3. Pass `--mount-engine` to override the selection.
