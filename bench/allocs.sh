#!/usr/bin/env bash
# Heap allocations per request, measured with valgrind's DHAT.
#
#   bench/allocs.sh [BIN]          # default target/release/ferrosip; SCEN="sl udp tcp reg"
#
# Each scenario runs twice under DHAT (N1 and N2 requests, low window so
# nothing is lost); allocations per request = (blocks2 - blocks1) / (N2 - N1),
# which cancels startup and shutdown allocations. Bytes likewise.
#
#   bench/allocs.sh --check [BIN]  # also fail when a scenario allocates more
#                                  # per request than bench/allocs-budget.txt
set -euo pipefail

die() { echo "allocs.sh: $*" >&2; exit 2; }
case "${1:-}" in -h | --help) sed -n '2,12s/^# \{0,1\}//p' "$0"; exit 0 ;; esac
BUDGET=''
if [ "${1:-}" = --check ]; then
  BUDGET=$(realpath "$(dirname "$0")/allocs-budget.txt")
  shift
fi
# BIN is relative to where you run this; the default to the repository.
if [ -n "${1:-}" ]; then BIN=$(realpath "$1"); fi
cd "$(dirname "$0")/.."
BIN=${BIN:-$PWD/target/release/ferrosip}
B=target/release
D=bench/kamailio
if [ -n "$BUDGET" ]; then
  [ -f "$BUDGET" ] || die "$BUDGET not found"
  SCEN=${SCEN:-$(awk '!/^#/ && NF { printf "%s ", $1 }' "$BUDGET")}
fi
SCEN=${SCEN:-sl udp tcp reg}
N1=${N1:-1000} N2=${N2:-6000}
OUT=$(realpath -m "${OUT:-target/bench-allocs}")
command -v valgrind >/dev/null || die "valgrind not installed"
[ -x "$BIN" ] || die "$BIN is not an executable ferrosip binary"
[ -x "$B/sipflood" ] || die "$B/sipflood not found: cargo build --release -p sipflood"
[ "$N2" -gt "$N1" ] || die "N2 ($N2) must be larger than N1 ($N1)"
scenario() { # name → "proto method"
  case $1 in
    sl) echo "udp OPTIONS" ;;
    udp) echo "udp MESSAGE" ;;
    tcp) echo "tcp MESSAGE" ;;
    reg) echo "udp REGISTER" ;;
    inv) echo "udp INVITE" ;;
    fsr) echo "udp MESSAGE" ;;
    *) return 1 ;;
  esac
}
cfg_file() { # scenario → routing file
  case $1 in
    inv) echo "$D/f_udp.cfg" ;;
    fsr) echo "$D/f_fsr.fsr" ;;
    *) echo "$D/f_$1.cfg" ;;
  esac
}
for name in $SCEN; do scenario "$name" >/dev/null || die "unknown scenario $name (sl udp tcp reg inv fsr)"; done
mkdir -p "$OUT"

UAS_U='' UAS_T=''
trap 'kill $UAS_U $UAS_T 2>/dev/null || true' EXIT
"$B/sipflood" uas udp:127.0.0.1:5070 >/dev/null 2>&1 & UAS_U=$!
"$B/sipflood" uas tcp:127.0.0.1:5071 >/dev/null 2>&1 & UAS_T=$!
sleep 0.3

# Prints "blocks bytes" for one DHAT run of N requests; nothing (and a
# message on stderr) when the proxy didn't come up.
run() {
  local name=$1 proto=$2 method=$3 n=$4 log="$OUT/dhat-$1-$4.log" p up=0 _
  echo "allocs: $name, $n requests" >&2
  valgrind --tool=dhat --dhat-out-file=/dev/null "$BIN" -f "$(cfg_file "$name")" -l udp:127.0.0.1:5090 -l tcp:127.0.0.1:5090 \
    -n 2 --tcp-readers 2 --rpc-socket none >"$log" 2>&1 &
  p=$!
  for _ in $(seq 300); do
    if (exec 3<>/dev/tcp/127.0.0.1/5090) 2>/dev/null; then up=1; break; fi
    kill -0 "$p" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$up" -eq 0 ]; then
    echo "allocs: the proxy didn't start under valgrind, see $log" >&2
    kill "$p" 2>/dev/null || true
    return 1
  fi
  sleep 0.5
  "$B/sipflood" bench "$proto:127.0.0.1:5090" "$n" 10 "$method" "a$n-$RANDOM-" >"$OUT/bench-$name-$n.log" 2>&1
  kill -TERM "$p" 2>/dev/null || true # (background jobs ignore SIGINT in scripts)
  wait "$p" 2>/dev/null || true
  # "==pid== Total:     1,234 bytes in 56 blocks"
  grep -m1 "Total:" "$log" | sed -E 's/.*Total: *([0-9,]+) bytes in ([0-9,]+) blocks.*/\2 \1/' | tr -d ,
}

printf '| scenario | allocations / request | bytes / request |\n|---|---|---|\n'
over=0
for name in $SCEN; do
  read -r proto method < <(scenario "$name")
  b1='' b2='' y1='' y2=''
  read -r b1 y1 < <(run "$name" "$proto" "$method" "$N1") || true
  read -r b2 y2 < <(run "$name" "$proto" "$method" "$N2") || true
  if [ -z "$b1" ] || [ -z "$b2" ]; then die "no DHAT totals for $name (logs in $OUT)"; fi
  per=$(awk -v b1="$b1" -v b2="$b2" -v d=$((N2 - N1)) 'BEGIN { printf "%.1f", (b2 - b1) / d }')
  awk -v n="$name" -v per="$per" -v y1="$y1" -v y2="$y2" -v d=$((N2 - N1)) \
    'BEGIN { printf "| %s | %s | %.0f |\n", n, per, (y2 - y1) / d }'
  if [ -n "$BUDGET" ]; then
    max=$(awk -v n="$name" '$1 == n { print $2 }' "$BUDGET")
    if [ -z "$max" ]; then
      echo "allocs: no budget for $name in $BUDGET" >&2
      over=1
    elif awk -v p="$per" -v m="$max" 'BEGIN { exit !(p > m) }'; then
      echo "allocs: $name allocates $per per request, over its budget of $max (bench/allocs-budget.txt)" >&2
      over=1
    fi
  fi
done
[ "$over" -eq 0 ]
