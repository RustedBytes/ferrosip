#!/usr/bin/env bash
# Kamailio config compatibility: `ferrosip -c` on each config in
# configs.txt (with its defines) must print "config OK", and so must its
# `ferrosip import` (ferrosip.toml + routes/main.fsr, checked by import).
#
#   tests/compat/check.sh [PATTERN]   # only the configs whose path contains PATTERN
#
# Run from anywhere after `cargo build --release`. Exit 0 when every config
# passes, 1 when one fails, 2 on a usage or setup error.
set -euo pipefail

die() { echo "check.sh: $*" >&2; exit 2; }
case "${1:-}" in
  -h | --help) sed -n '2,9s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac
FILTER=${1:-}

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(realpath -m "$HERE/../../target/release/ferrosip")
[ -x "$BIN" ] || die "$BIN not found: run \`cargo build --release\` first"
cd "$HERE/kamailio"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# run SECONDS DIR ARGS…: ferrosip from the config's directory (its
# includes are relative); prints its output, and TIMEOUT when it ran out of
# time.
run() {
  local secs=$1 dir=$2 rc=0
  shift 2
  (cd "$dir" && timeout "$secs" "$BIN" "$@" 2>&1) || rc=$?
  if [ "$rc" -eq 124 ]; then echo "TIMEOUT after ${secs}s"; fi
}

fail=0 n=0
while read -r cfg defs; do
  case "$cfg" in '' | \#*) continue ;; esac
  if [ -n "$FILTER" ] && [[ $cfg != *"$FILTER"* ]]; then continue; fi
  n=$((n + 1))
  args=()
  # $defs is a space-separated list of defines.
  for d in $defs; do args+=(--define "$d"); done
  dir=$(dirname "$cfg") file=$(basename "$cfg")
  out=$(run 20 "$dir" -c -f "$file" "${args[@]}")
  rm -rf "$TMP/import"
  iout=$(run 60 "$dir" import "$file" -o "$TMP/import" "${args[@]}")
  if ! grep -q "config OK" <<<"$iout"; then
    echo "FAIL $cfg $defs (ferrosip import)"
    grep -v "note" <<<"$iout" | tail -4 | sed 's/^/     /'
    fail=$((fail + 1))
  elif grep -q "config OK" <<<"$out"; then
    echo "PASS $cfg $defs"
  else
    echo "FAIL $cfg $defs"
    grep -v "note:" <<<"$out" | tail -3 | sed 's/^/     /'
    fail=$((fail + 1))
  fi
done <../configs.txt
[ "$n" -gt 0 ] || die "no config matches ${FILTER:-anything}"
echo
echo "$((n - fail))/$n passed"
[ "$fail" -eq 0 ]
