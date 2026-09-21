#!/usr/bin/env bash
# Build a minimal, disposable nodebox microVM rootfs (Debian minimal + systemd).
#
# The image deliberately ships WITHOUT an identity: /var/lib/nodebox is empty,
# so the node agent generates its key and node_id on first boot. Cloning the
# disk copies that key (a trust clone the controller will flag); the correct
# clone workflow is to wipe /var/lib/nodebox so first boot regenerates identity.
#
# Requires: debootstrap, qemu-img, root (loopback mount). Run on a Linux host.
set -euo pipefail

SUITE="${SUITE:-bookworm}"
ARCH="${ARCH:-amd64}"
SIZE="${SIZE:-512M}"
ROOT="${ROOT:-/tmp/nodebox-rootfs}"
OUT="${OUT:-nodebox-rootfs.ext4}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

command -v debootstrap >/dev/null || { echo "need debootstrap" >&2; exit 1; }

rm -rf "$ROOT"
debootstrap --arch="$ARCH" --variant=minbase --include=python3,systemd,openssh-server,ca-certificates \
    "$SUITE" "$ROOT" http://deb.debian.org/debian

# node agent code + unit
install -d "$ROOT/opt/nodebox" "$ROOT/etc/nodebox" "$ROOT/var/lib/nodebox" "$ROOT/var/log/nodebox"
cp "$REPO"/nodebox_*.py "$ROOT/opt/nodebox/"
cp "$REPO"/supervisor/nodebox-node.service "$ROOT/etc/systemd/system/"
install -m 0644 /dev/stdin "$ROOT/etc/nodebox/node.env" <<'ENV'
NODEBOX_DEVICE_TYPE=generic
NODEBOX_CONTROLLER=192.168.8.1:9443
NODEBOX_CONTROLLER_PUB=REPLACE_WITH_CONTROLLER_PUBKEY_B64
NODEBOX_CONTROLLER_ID=REPLACE_WITH_CONTROLLER_ID
ENV

# first-boot identity generation + service enable (no identity baked in)
install -m 0755 /dev/stdin "$ROOT/usr/local/sbin/nodebox-firstboot" <<'FB'
#!/bin/sh
# Runs once; the agent itself creates /var/lib/nodebox/identity.* on first start.
# A cloned disk keeps the old identity -> regenerate explicitly for a new node:
#   rm -f /var/lib/nodebox/identity.*
exit 0
FB
install -d "$ROOT/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/nodebox-node.service \
    "$ROOT/etc/systemd/system/multi-user.target.wants/nodebox-node.service"
# remove machine-id so a cloned image re-derives a fresh binding on boot
: > "$ROOT/etc/machine-id"

# pack to ext4
dd if=/dev/zero of="$OUT" bs=1M count="${SIZE%M}" status=none
mkfs.ext4 -q -d "$ROOT" -F "$OUT"
echo "[+] wrote $OUT ($SIZE) -- boot with vm/node-01.json"
echo "[!] set /etc/nodebox/node.env (controller pubkey/id) before boot"
