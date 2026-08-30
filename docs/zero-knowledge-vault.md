# Zero-knowledge server vault design

## Security objective

Files stored on the SFTP server must remain confidential and tamper-evident if
the server, its administrator, or a server backup is compromised. Mounting the
readable drive requires the original T-Dongle and physical BOOT confirmation.

The design creates a POO-specific key lifecycle and workflow. It deliberately
does not create new cryptographic primitives.

## Vault architecture

Version 1 wraps the SFTP backend with rclone's `crypt` backend. Rclone encrypts
file content locally with NaCl SecretBox (XSalsa20 and Poly1305), encrypts file
and directory names, and sends only ciphertext to SFTP. The server still learns
encrypted object sizes, modification times, and access patterns.

The two high-entropy rclone secrets are not stored. For descriptor version 2,
they are expanded for each mount from both a 256-bit master secret derived by
the dongle and a user password:

1. `poo vault-init` asks for a password twice, creates a random P-256 peer point,
   and creates independent 128-bit dongle and password salts.
2. The peer private scalar is immediately discarded. The peer public point,
   salt, format version, and dongle fingerprint are stored in a non-secret JSON
   descriptor.
3. The password is processed with Argon2id using 64 MiB, three iterations, and
   four lanes. These are the RFC 9106 memory-constrained recommended settings.
4. At initialization and mount time the dongle performs P-256 ECDH with the
   peer point and derives the stable hardware secret with HKDF-SHA-256 after
   BOOT confirmation.
5. A domain-separated HKDF-SHA-256 combines the password key and hardware
   secret. Neither factor is sufficient alone. A truncated HMAC tag stored in
   the descriptor rejects an incorrect password only after the dongle has
   participated, so the descriptor does not provide an offline password oracle.
6. The host expands the combined key with domain-separated HKDF-SHA-256 into
   independent content/name credentials.
7. Credentials are supplied to the rclone child process through its private
   environment and are never written into the persistent rclone configuration.
8. Removing the dongle terminates rclone and unmounts the readable drive.

The descriptor is safe to back up with the encrypted server data: possession of
it does not permit derivation without the dongle private key.

## Trust boundaries

- The server receives ciphertext and cannot decrypt it.
- The dongle private key remains in device NVS.
- The host necessarily sees plaintext and the active mount credentials in
  memory. Malware already controlling the logged-in host can capture open data.
- A malicious server can delete data or return an older snapshot. Version 1
  authenticates file content but does not yet prevent rollback.
- Loss or erasure of the only dongle permanently loses the vault unless a
  separate recovery design is deliberately enabled.
- Forgetting the vault password also permanently loses a version 2 vault. The
  password is neither stored nor recoverable.

## Required hardening before production

- Enable ESP32-S3 Secure Boot v2, flash encryption, and encrypted NVS.
- Add a dedicated vault key instead of sharing the document ECDH key.
- Add a dongle signature over vault creation and accepted upload manifests.
- Add signed manifest generations and a device-held checkpoint to detect server
  rollback.
- Package and sign the host applications for Windows, macOS, and Linux.
- Obtain an independent cryptographic and implementation review.

## Migration rule

Plain and encrypted objects must never share an SFTP directory. Version 1 uses
a dedicated remote directory such as `/vault-v1`. Existing plaintext server
files are preserved until the user verifies an encrypted copy and explicitly
authorizes deletion of the plaintext originals.

Descriptor version 1 is retained as a read-compatible, dongle-only legacy
format. New descriptors are version 2 and require a password. Existing version
1 ciphertext cannot be changed to the new keys in place; mount it with the old
descriptor and copy it into a separate version 2 vault before retirement.
