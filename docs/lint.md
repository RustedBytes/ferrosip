# `ferrosip lint`

`ferrosip check` answers "will this run?". `ferrosip lint` answers "is
this what you meant?", in the way clippy does for Rust. It reads
ferrosip.toml and the routing (`.fsr` or `.cfg`) and points at code that
works but is probably a mistake, leaves the server open, or can be
simpler. Where the fix is mechanical, it can apply it.

```bash
ferrosip lint                          # ./ferrosip.toml and its [routing] entry
ferrosip lint --config ferrosip.toml   # the same, explicitly
ferrosip lint -f kamailio.cfg          # a routing script on its own
ferrosip lint --fix                    # apply the suggested fixes, then lint again
ferrosip lint --overlay envs/prod.toml --set feature.x=1   # one environment, as it runs
```

The output looks like this:

```text
warning: `caller` is never read
 --> routes/main.fsr:8:9
  |
8 |     let caller = msg.from.user
  |         ^^^^^^
  |
  = help: if this is intentional, prefix it with an underscore: `_caller` (fixable)
  = note: `unused_variable` on by default (suspicious); more: `ferrosip lint --explain unused_variable`

warning: anyone can send requests through this relay
  --> routes/main.fsr:38:17
   |
38 |                 relay(msg)
   |                 ^^^^^^^^^^
   |
   = help: authenticate callers, or check msg.src.ip / permissions / the dispatcher list first
   = note: `open_relay` on by default (security); more: `ferrosip lint --explain open_relay`

warning: 2 warnings emitted (1 fixable with `ferrosip lint --fix`)
```

The exit status is 1 when an error-level lint fires, and 0 otherwise.
Warnings don't fail the run unless you ask with `-D warnings`.

## Groups and levels

Every lint belongs to a group. The group sets its default level:

| group | default | what |
|---|---|---|
| `correctness` | deny | almost certainly a bug |
| `suspicious` | warn | probably a mistake |
| `security` | warn | leaves the server open to abuse |
| `style` | warn | works, but can be simpler |
| `pedantic` | allow | opinionated; turn on with `-W pedantic` |

The full list, with what each lint checks and why, is in
[lints-reference.md](lints-reference.md). `ferrosip lint --list` prints
it, and `ferrosip lint --explain NAME` explains one lint or one group.

### Changing a level

- **On the command line:** `-A NAME` (allow), `-W NAME` (warn) or
  `-D NAME` (deny). NAME is a lint or a group. Later flags win, and a
  lint's own level beats its group's. `-D warnings` turns every warning
  into an error, which is the usual setting in CI.
- **In ferrosip.toml, for the whole project:**

  ```toml
  [lint]
  allow = ["hardcoded_address"]
  warn = ["pedantic"]
  deny = ["security"]
  ```

  Command-line flags are applied after these.
- **In one place:** put a comment on the line before, or at the end of
  the line.

  ```fsr
  // lint: allow(open_relay)
  relay(msg)               // trunk side: the SBC in front checks callers

  while true {  // lint: allow(infinite_loop)
  ```

  In `.cfg` and ferrosip.toml the comment starts with `#`:

  ```toml
  # lint: allow(redundant_default)
  default_expires = "1h"    # stated on purpose: the SLA says 1h
  ```

  In `.fsr`, a comment before an item or statement covers all of it:
  before a `fn`, it covers the whole function. Several names can be
  given, separated by commas, and a group name works too.

## What it checks

- **`.fsr` routing.** This is the richest set, because the linter works
  on the typed syntax tree:
  - unused variables, functions, flags, imports, tables and dialog vars;
  - loops that never end;
  - constant conditions and unreachable match arms;
  - `x == true`, a reason phrase that `reply` would send anyway, and an
    `if` that can be merged with the one inside it.

  The file must compile first: lint reports compile errors and stops.
- **`.cfg` routing:** routes that nothing calls or arms, and `modparam`s
  set to their default.
- **Both routing languages:** routing-wide security checks:
  - requests relayed without a Max-Forwards check;
  - REGISTER saved without authentication;
  - an open relay, where nothing authenticates callers or checks where
    requests come from;
  - Record-Route added without `loose_route`.

  These look at the routing as a whole. A check in any route counts, so
  they can't prove a path is safe; they only notice when no check exists
  at all.
- **ferrosip.toml:**
  - parameters set to their default;
  - passwords and keys written in the file (as a key, or in a
    `scheme://user:password@` URL) rather than read from `${ENV}`;
  - `[feature]` values the routing never reads.

## `--fix`

`--fix` applies every fix marked "(fixable)":
- renaming to `_name`;
- removing an import, a redundant reason, or a line that sets a default;
- `x == false` → `!x`;
- merging nested ifs and `else { if … }`.

It works in rounds, so fixes that touch the same spot (two names in one
import list) all get applied. If a `.fsr` file was formatted before the
fix, it is formatted after it too. It never removes a function, a route,
or anything a lint only suspects; those are left for you.

## Editors and CI

`--format json` prints one JSON object per finding, on stdout:

```json
{"lint":"unused_import","level":"warn","group":"suspicious","file":"routes/main.fsr","line":1,"column":23,"end_line":1,"end_column":27,"message":"`auth` is imported but never used","help":"remove this import","fixable":true}
```

A CI step:

```bash
ferrosip lint --config ferrosip.toml -D warnings
```
