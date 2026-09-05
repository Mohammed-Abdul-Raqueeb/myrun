#!/bin/sh
# Measure container startup and teardown cost.
#
# Usage: scripts/bench.sh [iterations] [rootfs]
set -eu

N="${1:-20}"
ROOTFS="${2:-/tmp/myrun-rootfs}"
MYRUN="${MYRUN:-./target/release/myrun}"
[ -x "$MYRUN" ] || MYRUN=./target/debug/myrun

if [ ! -x "$MYRUN" ]; then echo "build myrun first: cargo build --release" >&2; exit 1; fi
if [ ! -d "$ROOTFS" ]; then echo "no rootfs at $ROOTFS; run scripts/setup-rootfs.sh" >&2; exit 1; fi

now_ms() { date +%s%3N; }

bench() {
    label="$1"; shift
    total=0; min=999999; max=0
    i=0
    while [ $i -lt "$N" ]; do
        s=$(now_ms)
        "$@" >/dev/null 2>&1 || true
        e=$(now_ms)
        d=$((e - s))
        total=$((total + d))
        [ $d -lt $min ] && min=$d
        [ $d -gt $max ] && max=$d
        i=$((i + 1))
    done
    printf '%-34s n=%-4s avg=%-6s min=%-6s max=%s (ms)\n' "$label" "$N" "$((total / N))" "$min" "$max"
}

echo "myrun benchmark ($N iterations each)"
echo

bench "run /bin/true (no network)" \
    "$MYRUN" run --network none "$ROOTFS" /bin/true
bench "run /bin/true (bridge network)" \
    "$MYRUN" run --network bridge "$ROOTFS" /bin/true
bench "run --rm /bin/true" \
    "$MYRUN" run --rm --network none "$ROOTFS" /bin/true
bench "create (no start)" \
    "$MYRUN" create --network none "$ROOTFS" /bin/true

echo
echo "cleaning up"
"$MYRUN" gc >/dev/null 2>&1 || true
for id in $("$MYRUN" ls -a -q 2>/dev/null); do "$MYRUN" rm -f "$id" >/dev/null 2>&1 || true; done
"$MYRUN" gc >/dev/null 2>&1 || true
