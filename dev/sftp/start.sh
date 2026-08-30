#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STATE_DIR="$SCRIPT_DIR/state"
SSH_PORT=${POO_SFTP_PORT:-2222}
CLIENT_KEY="$STATE_DIR/client_ed25519"
KNOWN_HOSTS="$STATE_DIR/known_hosts"
SCAN_FILE="$STATE_DIR/known_hosts.new"

mkdir -p "$STATE_DIR"
if [ ! -f "$CLIENT_KEY" ]; then
    ssh-keygen -q -t ed25519 -N "" -C "poo-local-sftp-test" -f "$CLIENT_KEY"
fi

docker compose --project-directory "$SCRIPT_DIR" up --build --detach

attempt=0
while [ "$attempt" -lt 30 ]; do
    if ssh-keyscan -p "$SSH_PORT" localhost >"$SCAN_FILE" 2>/dev/null && [ -s "$SCAN_FILE" ]; then
        mv "$SCAN_FILE" "$KNOWN_HOSTS"
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
rm -f "$SCAN_FILE"

if [ ! -s "$KNOWN_HOSTS" ]; then
    printf 'The local SFTP server did not become ready.\n' >&2
    exit 1
fi

printf 'ls\n' | sftp \
    -q \
    -b - \
    -i "$CLIENT_KEY" \
    -o "UserKnownHostsFile=$KNOWN_HOSTS" \
    -P "$SSH_PORT" \
    poo@localhost

printf '\nLocal SFTP server is ready.\n'
printf 'Host: localhost\nPort: %s\nUser: poo\nRemote path: /files\n' "$SSH_PORT"
printf 'Identity: %s\nKnown hosts: %s\n' "$CLIENT_KEY" "$KNOWN_HOSTS"
