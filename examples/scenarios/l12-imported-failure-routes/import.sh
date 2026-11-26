#!/bin/sh
# l12-imported-failure-routes: Kamailio's stock kamailio.cfg with voicemail
# and the 3xx / 401 / 407 blocks → ferrosip.toml + routes/main.fsr, cleaned
# up and checked by l08's script. The test runs this script.
#
#   sh import.sh [OUT_DIR]        (default /tmp/ferrosip-l12)
#   ferrosip --config OUT_DIR/ferrosip.toml -l udp:127.0.0.1:5060
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
exec sh "$HERE/../l08-imported-kamailio/import.sh" "${1:-/tmp/ferrosip-l12}" \
    --define ACTIVE --define WITH_VOICEMAIL --define WITH_BLOCK3XX --define WITH_BLOCK401407
