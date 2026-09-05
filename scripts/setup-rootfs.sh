#!/bin/sh
# Build a minimal container rootfs from busybox-static.
#
# Usage: scripts/setup-rootfs.sh [target-dir]
# Default target: /tmp/myrun-rootfs
set -eu

ROOT="${1:-/tmp/myrun-rootfs}"

BUSYBOX=""
for candidate in /bin/busybox /usr/bin/busybox /sbin/busybox; do
    if [ -x "$candidate" ]; then BUSYBOX="$candidate"; break; fi
done
if [ -z "$BUSYBOX" ]; then
    echo "busybox not found; install busybox-static" >&2
    exit 1
fi

# A dynamically linked busybox would need the loader and libc copied in too.
if command -v file >/dev/null 2>&1 && file "$BUSYBOX" | grep -q "dynamically linked"; then
    echo "warning: $BUSYBOX is dynamically linked; the rootfs may not work" >&2
fi

mkdir -p "$ROOT"/bin "$ROOT"/etc "$ROOT"/proc "$ROOT"/sys "$ROOT"/dev "$ROOT"/tmp "$ROOT"/root
cp "$BUSYBOX" "$ROOT/bin/busybox"
chmod 755 "$ROOT/bin/busybox"

# Applet symlinks. Relative so the links resolve inside the container.
for applet in sh ls cat echo sleep ps id hostname mount ip ping true false \
              env wc grep head tail mkdir rm cp mv touch chmod dd sync \
              yes seq date uname whoami df free top kill printf test; do
    ln -sf busybox "$ROOT/bin/$applet"
done

printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\ntty:x:5:\nnobody:x:65534:\n' > "$ROOT/etc/group"
printf '127.0.0.1 localhost\n' > "$ROOT/etc/hosts"

echo "rootfs ready at $ROOT"
