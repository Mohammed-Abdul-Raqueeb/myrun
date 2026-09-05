#!/bin/sh
# Report host resources myrun may have left behind.
#
# Usage: scripts/check-leaks.sh [--fix]
# Exit status: 0 if clean, 1 if anything was found.
set -eu

FIX=0
[ "${1:-}" = "--fix" ] && FIX=1
MYRUN="${MYRUN:-./target/debug/myrun}"
ROOT="${MYRUN_ROOT:-/run/myrun}"
FOUND=0

say() { printf '%s\n' "$*"; }

say "== container state =="
if [ -d "$ROOT/containers" ]; then
    n=$(find "$ROOT/containers" -mindepth 1 -maxdepth 1 -type d | wc -l)
    say "  $n container directories under $ROOT/containers"
else
    say "  no state directory"
fi

say "== veth interfaces =="
VETHS=$(ip -o link 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep '^mrv' || true)
if [ -n "$VETHS" ]; then
    say "  found:"; printf '    %s\n' $VETHS; FOUND=1
else
    say "  none"
fi

say "== bridges =="
if ip link show myrun0 >/dev/null 2>&1; then
    PORTS=$(ip -o link 2>/dev/null | grep -c 'master myrun0' || true)
    say "  myrun0 exists with $PORTS port(s)"
    [ "$PORTS" = "0" ] && FOUND=1
else
    say "  none"
fi

say "== cgroups =="
CG=$(awk '$3 == "cgroup2" {print $2; exit}' /proc/self/mountinfo 2>/dev/null || true)
[ -z "$CG" ] && CG=$(awk '$1 == "cgroup2" {print $2; exit}' /proc/mounts 2>/dev/null || true)
if [ -n "$CG" ] && [ -d "$CG/myrun" ]; then
    LEAF=$(find "$CG/myrun" -mindepth 1 -maxdepth 1 -type d | wc -l)
    say "  $LEAF container cgroup(s) under $CG/myrun"
    [ "$LEAF" != "0" ] && FOUND=1
else
    say "  none"
fi

say "== iptables rules =="
RULES=0
for table in nat filter; do
    c=$(iptables -t $table -S 2>/dev/null | grep -c 'myrun:' || true)
    RULES=$((RULES + c))
done
say "  $RULES rule(s) tagged myrun:"
[ "$RULES" != "0" ] && FOUND=1

say "== IP leases =="
if [ -f "$ROOT/ipam.json" ]; then
    L=$(grep -c '"ip"' "$ROOT/ipam.json" || true)
    say "  $L lease(s)"
    [ "$L" != "0" ] && FOUND=1
else
    say "  none"
fi

if [ "$FIX" = "1" ] && [ "$FOUND" = "1" ]; then
    say ""
    say "== running myrun gc =="
    "$MYRUN" gc || true
    exit 0
fi

if [ "$FOUND" = "1" ]; then
    say ""
    say "Leftovers found. Run '$MYRUN gc' (or this script with --fix) to clean up."
    exit 1
fi
say ""
say "Clean."
