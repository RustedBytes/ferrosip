#!/usr/bin/env bash
# Kamailio vs ferrosip on the same box, same CPU pinning, same load.
#
#   bench/kamailio/run.sh            # ROUNDS=5 alternating runs per scenario
#
# Needs: `cargo build --release` and Kamailio: built from source with
# bench/kamailio/build.sh (KAMAILIO_PREFIX=$(bench/kamailio/build.sh)), or a
# `kamailio` on PATH (e.g. the distribution package) when KAMAILIO_PREFIX
# is unset.
# Layout with 4+ CPUs: proxy on CPUs 0-1, sipflood UAS on CPU 3, client on
# CPUs 2-3; with 2-3 CPUs: proxy on CPU 0, UAS and client on CPU 1 (override
# with PROXY_CPUS / UAS_CPUS / CLIENT_CPUS). Both proxies run 2 UDP workers
# (children) and 2 TCP readers (tcp_children) either way. Each scenario runs
# Kamailio and ferrosip alternately so drift on a shared machine hits both.
#
# Scenarios (configs in this directory, k_* Kamailio / f_* ferrosip):
#   sl   stateless sl_send_reply(200) to OPTIONS over UDP
#   udp  stateful t_relay of MESSAGE, UDP in → UDP out
#   tcp  stateful t_relay of MESSAGE, TCP in → TCP out
#   reg  REGISTER → registrar save() into in-memory usrloc, a new AoR each
# SCEN="sl udp" runs a subset.
set -euo pipefail

die() { echo "run.sh: $*" >&2; exit 2; }
case "${1:-}" in -h | --help) sed -n '2,21s/^# \{0,1\}//p' "$0"; exit 0 ;; esac
cd "$(dirname "$0")/../.."
B=target/release
for x in ferrosip sipflood; do [ -x "$B/$x" ] || die "$B/$x not found: cargo build --release -p ferrosip -p sipflood"; done
command -v taskset >/dev/null || die "taskset not found (util-linux)"
D=bench/kamailio
ROUNDS=${ROUNDS:-5}
# Kamailio memory manager for shm and pkg. TLSF is its fastest here: the
# packaged default (qm) is ~25-40% slower, and fm was erratic on the
# stateful path.
KAM_MM=${KAM_MM:-tlsf}
OUT=$(realpath -m "${OUT:-target/bench-kamailio}")  # absolute: kamailio chdirs to /
if [ -n "${KAMAILIO_PREFIX:-}" ]; then
  KAMAILIO="$KAMAILIO_PREFIX/sbin/kamailio"
  MODROOT=$KAMAILIO_PREFIX
else
  KAMAILIO=kamailio
  MODROOT=/usr/lib
fi
command -v "$KAMAILIO" >/dev/null || die "$KAMAILIO not found: build it with bench/kamailio/build.sh and set KAMAILIO_PREFIX"
if [ -z "${MODPATH:-}" ]; then
  tm=$(find "$MODROOT" -name tm.so -path '*kamailio/modules*' 2>/dev/null | head -1)
  [ -n "$tm" ] || die "no Kamailio modules (tm.so) under $MODROOT: set MODPATH"
  MODPATH=$(dirname "$tm")
fi
mkdir -p "$OUT/run"
if [ "$(nproc)" -ge 4 ]; then
  PROXY_CPUS=${PROXY_CPUS:-0,1} UAS_CPUS=${UAS_CPUS:-3} CLIENT_CPUS=${CLIENT_CPUS:-2,3}
else
  PROXY_CPUS=${PROXY_CPUS:-0} UAS_CPUS=${UAS_CPUS:-1} CLIENT_CPUS=${CLIENT_CPUS:-1}
fi
for c in "$D"/k_*.cfg; do sed "s|MODPATH|$MODPATH/|" "$c" > "$OUT/$(basename "$c")"; done
RES="$OUT/results.txt"
: > "$RES"

stop() { pkill -f "kamailio -f $OUT" 2>/dev/null || true; pkill -f "ferrosip -f $D" 2>/dev/null || true; }
hz=$(getconf CLK_TCK)
cpu_ticks() { # utime+stime of a process tree, all threads
  local t=0 p f
  for p in "$1" $(pgrep -P "$1" || true); do
    for f in /proc/"$p"/task/*/stat; do t=$((t + $(awk '{print $14+$15}' "$f" 2>/dev/null || echo 0))); done
  done
  echo "$t"
}
ready() { # proxy alive and accepting TCP on 5090 (UDP is bound before TCP in both)
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

"$KAMAILIO" -v | head -1
echo "Kamailio memory manager: $KAM_MM"
echo "$(nproc) CPUs: proxy on $PROXY_CPUS, UAS on $UAS_CPUS, client on $CLIENT_CPUS"
scenario() { # name → "proto method total"
  case $1 in
    sl) echo "udp OPTIONS 200000" ;;
    udp) echo "udp MESSAGE 200000" ;;
    tcp) echo "tcp MESSAGE 100000" ;;
    reg) echo "udp REGISTER 200000" ;;
    *) return 1 ;;
  esac
}
SCEN=${SCEN:-sl udp tcp reg}
for name in $SCEN; do scenario "$name" >/dev/null || die "unknown scenario $name (sl udp tcp reg)"; done
for name in $SCEN; do
  read -r proto method total < <(scenario "$name")
  for r in $(seq "$ROUNDS"); do
    for p in kamailio ferrosip; do
      if [ "$p" = kamailio ]; then
        taskset -c "$PROXY_CPUS" "$KAMAILIO" -f "$OUT/k_$name.cfg" -DD -E -m 2048 -M 64 -x "$KAM_MM" -X "$KAM_MM" -P "$OUT/k.pid" -Y "$OUT/run" >"$OUT/k.log" 2>&1 & P=$!
        ready "$P" || { echo "kamailio failed to start:"; cat "$OUT/k.log"; exit 1; }
      else
        taskset -c "$PROXY_CPUS" "$B/ferrosip" -f "$D/f_$name.cfg" -l udp:127.0.0.1:5090 -l tcp:127.0.0.1:5090 -n 2 --tcp-readers 2 \
          --rpc-socket none >"$OUT/f.log" 2>&1 & P=$!
        ready "$P" || { echo "ferrosip failed to start:"; cat "$OUT/f.log"; exit 1; }
      fi
      c0=$(cpu_ticks "$P")
      line=$(taskset -c "$CLIENT_CPUS" "$B/sipflood" bench "$proto:127.0.0.1:5090" "$total" 200 "$method" "$p$r-" 2>&1 | tail -1)
      c1=$(cpu_ticks "$P")
      echo "$name $p $line | cpu_us_per_req $(( (c1 - c0) * 1000000 / hz / total ))" | tee -a "$RES"
      kill "$P" 2>/dev/null || true
      wait "$P" 2>/dev/null || true
      stop
      sleep 0.5
    done
  done
done
python3 "$D/summary.py" "$RES"
