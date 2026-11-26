#!/bin/sh
# l08-imported-kamailio: Kamailio's stock kamailio.cfg → ferrosip.toml +
# routes/main.fsr, cleaned up and checked. The test runs this script.
#
#   sh import.sh [OUT_DIR [--define NAME]…]   (default /tmp/ferrosip-l08, --define ACTIVE)
#   ferrosip --config OUT_DIR/ferrosip.toml -l udp:127.0.0.1:5060
#
# l12-imported-failure-routes runs it with more defines.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${1:-/tmp/ferrosip-l08}
[ $# -gt 0 ] && shift
[ $# -gt 0 ] || set -- --define ACTIVE
FERROSIP=${FERROSIP:-$ROOT/target/release/ferrosip}
[ -x "$FERROSIP" ] || { echo "import.sh: $FERROSIP not found: cargo build --release" >&2; exit 2; }

"$FERROSIP" import "$ROOT/tests/compat/kamailio/etc/kamailio.cfg" -o "$OUT" "$@" --force
echo "ok: import"
"$FERROSIP" lint --fix --config "$OUT/ferrosip.toml"
echo "ok: lint --fix"
"$FERROSIP" check --config "$OUT/ferrosip.toml"
echo "ok: check"
"$FERROSIP" lint --config "$OUT/ferrosip.toml" -D warnings
echo "ok: lint -D warnings"
"$FERROSIP" fmt --check "$OUT/routes"
echo "ok: fmt --check"
