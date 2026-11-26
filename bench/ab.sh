#!/usr/bin/env bash
# A/B two ferrosip builds on the same box, same pinning, same load.
#
#   bench/ab.sh OLD_BIN NEW_BIN            # ROUNDS=7, SCEN="sl udp tcp reg"
#
# Build the old binary from another checkout, e.g.
#   git worktree add /tmp/old HEAD~1 && (cd /tmp/old && CARGO_TARGET_DIR=$PWD/target/old cargo build --release -p ferrosip)
#
# Old and new alternate run by run, so drift on a shared machine hits both.
# Scenarios use bench/kamailio/f_*.cfg (see bench/kamailio/run.sh). Output
# is one line per run plus a median table (old vs new): req/s, p50/p99, and
# proxy CPU µs per request (all threads, from /proc).
set -euo pipefail

die() { echo "ab.sh: $*" >&2; exit 2; }
usage() { sed -n '2,12s/^# \{0,1\}//p' "$0"; }
case "${1:-}" in -h | --help) usage; exit 0 ;; esac
[ $# -eq 2 ] || { usage >&2; exit 2; }
OLD=$(realpath "$1") NEW=$(realpath "$2")
cd "$(dirname "$0")/.."
B=target/release
for x in "$OLD" "$NEW"; do [ -x "$x" ] || die "$x is not an executable ferrosip binary"; done
[ -x "$B/sipflood" ] || die "$B/sipflood not found: cargo build --release -p sipflood"
command -v taskset >/dev/null || die "taskset not found (util-linux)"
D=bench/kamailio
ROUNDS=${ROUNDS:-7}
SCEN=${SCEN:-sl udp tcp reg}
OUT=$(realpath -m "${OUT:-target/bench-ab}")
mkdir -p "$OUT"
RES="$OUT/results.txt"
: > "$RES"
if [ "$(nproc)" -ge 4 ]; then
  PROXY_CPUS=${PROXY_CPUS:-0,1} UAS_CPUS=${UAS_CPUS:-3} CLIENT_CPUS=${CLIENT_CPUS:-2,3}
else
  PROXY_CPUS=${PROXY_CPUS:-0} UAS_CPUS=${UAS_CPUS:-1} CLIENT_CPUS=${CLIENT_CPUS:-1}
fi

stop() { pkill -f -- "-f $D/f_" 2>/dev/null || true; }
cfg_file() { # scenario → routing file
  case $1 in
    inv) echo "$D/f_udp.cfg" ;;
    fsr) echo "$D/f_fsr.fsr" ;;
    *) echo "$D/f_$1.cfg" ;;
  esac
}
cpu_ticks() {
  local t=0 f
  for f in /proc/"$1"/task/*/stat; do t=$((t + $(awk '{print $14+$15}' "$f" 2>/dev/null || echo 0))); done
  echo "$t"
}
ready() {
  local _
  for _ in $(seq 100); do
    kill -0 "$1" 2>/dev/null || return 1
    (exec 3<>/dev/tcp/127.0.0.1/5090) 2>/dev/null && { sleep 0.3; return 0; }
    sleep 0.1
  done
  return 1
}
UAS_U='' UAS_T=''
trap 'stop; kill $UAS_U $UAS_T 2>/dev/null || true' EXIT
stop
taskset -c "$UAS_CPUS" "$B/sipflood" uas udp:127.0.0.1:5070 >/dev/null 2>&1 & UAS_U=$!
taskset -c "$UAS_CPUS" "$B/sipflood" uas tcp:127.0.0.1:5071 >/dev/null 2>&1 & UAS_T=$!
sleep 0.3
echo "$(nproc) CPUs: proxy on $PROXY_CPUS, UAS on $UAS_CPUS, client on $CLIENT_CPUS; $ROUNDS rounds"
hz=$(getconf CLK_TCK)
for name in $SCEN; do
  case $name in
    sl) proto=udp method=OPTIONS total=200000 ;;
    udp) proto=udp method=MESSAGE total=200000 ;;
    tcp) proto=tcp method=MESSAGE total=100000 ;;
    reg) proto=udp method=REGISTER total=200000 ;;
    inv) proto=udp method=INVITE total=200000 ;; # 100 Trying + 200, f_udp.cfg
    fsr) proto=udp method=MESSAGE total=200000 ;; # udp's routing in .fsr (f_fsr.fsr)
    *) die "unknown scenario $name (sl udp tcp reg inv fsr)" ;;
  esac
  for r in $(seq "$ROUNDS"); do
    for v in old new; do
      bin=$OLD
      if [ "$v" = new ]; then bin=$NEW; fi
      taskset -c "$PROXY_CPUS" "$bin" -f "$(cfg_file "$name")" -l udp:127.0.0.1:5090 -l tcp:127.0.0.1:5090 -n 2 --tcp-readers 2 \
        --rpc-socket none >"$OUT/$v.log" 2>&1 & P=$!
      ready "$P" || { echo "$v failed to start:"; cat "$OUT/$v.log"; exit 1; }
      c0=$(cpu_ticks "$P")
      line=$(taskset -c "$CLIENT_CPUS" "$B/sipflood" bench "$proto:127.0.0.1:5090" "$total" 200 "$method" "$v$r-" 2>&1 | tail -1)
      c1=$(cpu_ticks "$P")
      cpu=$(awk -v d=$((c1 - c0)) -v hz="$hz" -v n="$total" 'BEGIN { printf "%.1f", d * 1e6 / hz / n }')
      echo "$name $v $line | cpu_us_per_req $cpu" | tee -a "$RES"
      kill "$P" 2>/dev/null || true
      wait "$P" 2>/dev/null || true
      sleep 0.3
    done
  done
done
python3 "$D/summary.py" "$RES" old new
