#!/bin/bash
# Build the ephemeral analysis guest from a Debian cloud image.
#
#   ./sandbox/kvm/provision-guest.sh /path/to/guest-dir
#   -> /path/to/guest-dir/base.qcow2   (frozen template; never written again)
#
# Then point the backend at it:
#   python3 -c "from sandbox.config import set_value; \
#     set_value('kvm.base_image', '/path/to/guest-dir/base.qcow2')"
#
# One-time cost: a ~330 MB download plus a few minutes of unattended install.
# Needs: qemu-system-x86, qemu-utils, genisoimage, /dev/kvm.
#
# The guest is deliberately EMPTY: no user data, no credentials, no host identity.
# It exists to run untrusted targets behind a separate kernel. Every analysis run
# gets a fresh qcow2 overlay on base.qcow2 and the overlay is deleted afterwards.
set -euo pipefail

DIR="${1:-$(cd "$(dirname "$0")/../.." && pwd)/guest}"
CLOUD_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DIR"

command -v qemu-system-x86_64 >/dev/null || { echo "install qemu-system-x86 qemu-utils first"; exit 1; }
command -v genisoimage >/dev/null || { echo "install genisoimage first"; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm missing - KVM is required"; exit 1; }

if [ ! -f "$DIR/debian-cloud.qcow2" ]; then
  echo "[1/4] downloading the Debian cloud image (~330 MB)"
  curl -fL --retry 3 -o "$DIR/debian-cloud.qcow2" "$CLOUD_URL"
else
  echo "[1/4] cloud image already downloaded"
fi

echo "[2/4] copy + resize -> 12G virtual (thin provisioned)"
cp --sparse=always "$DIR/debian-cloud.qcow2" "$DIR/base.qcow2"
qemu-img resize "$DIR/base.qcow2" 12G

echo "[3/4] build the cloud-init seed"
mkdir -p "$DIR/seed"
cp "$HERE/cloud-init-user-data.yaml" "$DIR/seed/user-data"
printf 'instance-id: bp-analyst-001\nlocal-hostname: bp-analyst\n' > "$DIR/seed/meta-data"
genisoimage -quiet -output "$DIR/seed.iso" -volid cidata -joliet -rock \
  "$DIR/seed/user-data" "$DIR/seed/meta-data"

echo "[4/4] provisioning: boots once, installs qemu-guest-agent + wine, powers off"
qemu-system-x86_64 \
  -enable-kvm -cpu host -m 4096 -smp 4 \
  -drive file="$DIR/base.qcow2",if=virtio,format=qcow2,cache=unsafe \
  -drive file="$DIR/seed.iso",media=cdrom,readonly=on \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -display none -monitor none -no-reboot \
  -serial "file:$DIR/provision.log"

echo "done. base.qcow2: $(du -h "$DIR/base.qcow2" | cut -f1) on disk, 12G virtual"
