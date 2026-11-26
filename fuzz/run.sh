#!/usr/bin/env bash
# Run every fuzz target for SECONDS (default 60), starting from the seeds
# (plus whatever corpus/ already holds). Needs nightly + cargo-fuzz.
#
#   fuzz/run.sh [SECONDS]        # JOBS targets at a time (default: nproc)
#
# Exit status 1 if any target found a crash (inputs land in fuzz/artifacts/,
# logs in fuzz/logs/), 2 on a setup error.
set -euo pipefail

die() { echo "fuzz/run.sh: $*" >&2; exit 2; }
case "${1:-}" in
  -h | --help) sed -n '2,8s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac
[[ ${1:-60} =~ ^[0-9]+$ ]] || die "SECONDS must be a number, not '$1'"
cd "$(dirname "$0")"
SECONDS_PER_TARGET=${1:-60}
JOBS=${JOBS:-$(nproc)}
cargo +nightly fuzz --help >/dev/null 2>&1 ||
  die "needs a nightly toolchain and cargo-fuzz: rustup toolchain install nightly && cargo install cargo-fuzz"
targets=$(cargo +nightly fuzz list)
cargo +nightly fuzz build >/dev/null || die "cargo fuzz build failed"

# One target: seed its corpus (never overwriting what's there), fuzz it.
# shellcheck disable=SC2317,SC2329 # called by xargs through `export -f` (SC2317 before ShellCheck 0.10)
run() {
  local t=$1
  mkdir -p "corpus/$t"
  if [ -d "seeds/$t" ]; then cp -r --update=none "seeds/$t/." "corpus/$t/"; fi
  if cargo +nightly fuzz run "$t" "corpus/$t" -- -max_total_time="$SECONDS_PER_TARGET" -rss_limit_mb=2048 -max_len=8192 >"logs/$t.log" 2>&1; then
    echo "ok    $t: $(grep -oE 'Done [0-9]+ runs' "logs/$t.log" || true)"
  else
    echo "CRASH $t: $(grep -m1 -E 'panicked at|ERROR' "logs/$t.log" || echo "see fuzz/logs/$t.log")"
    return 1
  fi
}
mkdir -p logs
export -f run
export SECONDS_PER_TARGET
status=0
# The target name is passed as an argument, never spliced into the code.
# shellcheck disable=SC2016 # "$1" belongs to the inner bash
printf '%s\n' "$targets" | xargs -P "$JOBS" -I{} bash -c 'run "$1"' _ {} || status=1
exit "$status"
