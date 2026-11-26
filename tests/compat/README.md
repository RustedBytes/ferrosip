# Kamailio config corpus

`kamailio/` holds configs from Kamailio's source tree, copied unmodified
from kamailio/kamailio at commit `b6505a67cf6bc71195df82b102db0267c04e3eaf`
(`etc/` and `misc/examples/`). Kamailio is GPL-2.0-or-later, so ferrosip
can distribute these files under its GPL-3.0-or-later. Their copyright
stays with their Kamailio authors.

`check.sh` runs `ferrosip -c` on every line of `configs.txt` (a path and
optional `--define`s) and fails unless each prints `config OK`. CI runs it
in the `check` job. `tests/e2e_compat.py` runs the stock `kamailio.cfg`
against real traffic.

A config joins the corpus once ferrosip accepts it. See
[`docs/kamailio-compat.md`](../../docs/kamailio-compat.md) for the ones
that don't pass yet, and why.
