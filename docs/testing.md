# Testing, fuzzing and CI

```bash
cargo build --release --workspace --features ferrosip/db-all && etc/tls/gen-certs.sh
cargo test --release
python3 tests/run_e2e.py                # every e2e suite (e2e_sqldb needs root); `tm fork` picks some, -x skips
ruff check . && git ls-files -z '*.sh' | xargs -0 shellcheck   # script lint (ruff.toml)
tests/compat/check.sh                   # ferrosip -c on Kamailio's configs
cargo deny check && cargo audit         # licenses, bans, sources, RustSec (cargo install cargo-deny cargo-audit)
python3 tests/interop_sipp.py           # needs sipp (apt install sip-tester); SIPP_CALLS=200
python3 tests/soak.py 120               # SOAK_RATE=300 calls/s, SOAK_REG_RATE=20
target/release/ferroctl fmt --check etc/ferrosip.cfg   # script formatting
fuzz/run.sh 60                          # needs nightly + cargo-fuzz; seconds per target, JOBS=nproc
```

- **Scenarios** (`tests/e2e_scenarios.py`, [examples/scenarios](../examples/scenarios/README.md)):
  40 configurations in `ferrosip.toml` + `.fsr`, each checked with
  `check`, `lint -D warnings` and `fmt --check`, then run with real
  traffic by `tests/scenarios/<name>.py` on the shared kit
  `tests/sipkit.py` (UAs over UDP/TCP/TLS/WS, gateways, HTTP fakes).
  `--only NAME…` and `--size` pick a subset; 4 run in parallel.
- **e2e suites**: each starts its own proxy (and fake peers or real
  database servers) on fixed private ports, so they run one at a time.
  `tests/run_e2e.py` runs them: a log per suite in `target/e2e-logs/`,
  the output of failing ones, a timing table, and exit 1 if a suite
  exits non-zero, prints a `FAIL` line or times out. `tests/harness.py` waits for the
  proxy's "listening on" lines instead of sleeping. `e2e_sqldb` skips a
  database whose server binaries are missing. `e2e_ims` installs kernel
  IPsec SAs only where `ip xfrm` works.
- **A real media relay** (`tests/e2e_rtpflux.py`): calls go through the
  rtpengine module to [rtpflux](https://github.com/RustedBytes/rtpflux), a
  relay that speaks rtpengine's ng protocol, with real RTP both ways. CI checks
  out and builds rtpflux (pinned to a commit in `ci.yml`) for the e2e job.
  Locally the test uses
  `$RTPFLUX`, or `../rtpflux/target/release/rtpflux`, and is skipped when
  there is neither.
- **SIPp interop** (`tests/interop_sipp.py`): SIPp's built-in UAC and UAS
  run through the proxy over UDP, TCP and TLS, with 200 calls per transport.
  It also covers digest-authenticated REGISTERs (and a wrong password) and
  20 callers canceling a ringing call. Two SIPp quirks shape the script:
  - SIPp's UAC ignores Record-Route, so its ACK/BYE arrive without a Route
    header and are routed like the INVITE;
  - its TLS client needs `-tls_version 1.2`.

  The TLS leg first checks SIPp against itself. It is skipped where SIPp's
  non-blocking `SSL_connect` never completes. That happens with Ubuntu
  24.04's `sip-tester` (3.7.x) both in a gVisor sandbox and on GitHub
  runners, so TLS interop is covered by the Python and sipflood clients.
- **Soak** (`tests/soak.py`): SIPp calls (INVITE…BYE, tm + dialog) and an
  expiring REGISTER loop. It samples the proxy's RSS, `tm.stats`
  (`current`, `branch_index`) and `dlg.stats_active`. It fails on failed
  calls, on RSS growing past warmup + 10% + 8 MB, or if transactions and
  dialogs don't drain to 0 afterwards.
- **Fuzzing** (`fuzz/`, libFuzzer): there are 8 targets with hand-written
  seeds in `fuzz/seeds/`. An input that crashes a target is kept as a unit
  test (the `fuzz_regressions` modules).
- **CI** (`.github/workflows/ci.yml`, on push/PR and nightly):
  - build, `clippy -D warnings` and unit tests. Every crate takes the
    workspace lints (root `Cargo.toml`): `unsafe_code` is forbidden in
    every crate, so no `#[allow]` can bring it back (the two syscalls
    ferrosip makes itself go through rustix or /proc). Clippy denies:
    - lossy and widening `as` casts (`cast_possible_truncation`,
      `cast_sign_loss`, `cast_possible_wrap`, `cast_lossless`): a
      conversion says what happens out of range (`try_from` and reject,
      or saturate), and the few deliberate truncations carry a narrow
      `#[allow(…, reason = "…")]`;
    - `string_slice`: byte-index slicing of a `str` panics off a char
      boundary, and wire or config input must never panic;
    - `indexing_slicing` and `arithmetic_side_effects` outside tests: no
      `v[i]` or `&b[a..c]` that can panic, and no integer `+ - * / %`
      that can overflow. Code iterates, pattern-matches or uses `.get()`,
      and says what happens at the limit: `checked_*` to reject,
      `saturating_*` to clamp, `wrapping_*` for fields defined modulo 2^n
      (RTP, CSeq, hashes) and for script integers, which wrap like
      Kamailio's C ints. The release profile also has `overflow-checks`
      on, so anything the lint can't see (a macro, a dependency) panics
      in the worker, which panic isolation contains, instead of wrapping;
    - `unwrap_used`, `expect_used`, `panic`, `unreachable` and
      `mem_forget` outside tests (`clippy.toml`);
    - `allow_attributes_without_reason`: every `#[allow]` says why.

    The core crates
    (sip-core, sip-transport, sip-diameter, sip-db) also warn on
    `let _ =` of a `Result`, each kept one saying why;
  - allocations per request under valgrind DHAT (`bench/allocs.sh
    --check`): exact counts, so a hot path that gains an allocation goes
    over `bench/allocs-budget.txt` and fails;
  - the e2e suites (as root, with PostgreSQL, MariaDB and kernel XFRM),
    SIPp interop and a 90 s soak;
  - 60 s of fuzzing per target.

  - `cargo fmt --check` (`rustfmt.toml` allows 160-column lines);
  - ShellCheck on every `*.sh` (the scripts run with `set -euo pipefail`,
    or `set -eu` for the POSIX ones, check what they need first and take
    `--help`) and Ruff on every `*.py` (`ruff.toml`: correctness rules
    such as unused names, late-binding closures and syntax that needs a
    newer Python than 3.10);
  - the Kamailio config corpus (`tests/compat/check.sh`);
  - supply chain: `cargo deny check` (`deny.toml`: GPL-compatible licenses
    only, no OpenSSL/native-tls, crates.io only, advisories) and
    `cargo audit`. Dependabot opens weekly PRs for crates and actions.

  Each job runs only when the change can affect it: docs-only commits run
  nothing, Rust code runs the build, e2e and fuzz jobs, dependencies run
  the supply-chain and docker jobs, `sip_core::limit` runs loom. `ci-ok`
  sums it up for branch protection. Nightly runs every job, with a
  15-minute soak and 30 minutes per fuzz target.
- **Docs site** (`.github/workflows/docs.yml`, on changes to Markdown or
  `site/`): `site/build.py` stages every Markdown page at its repository
  path, mdBook builds the site, and `site/check_links.py` fails the job on
  any broken relative link or `#anchor`. From main it deploys to GitHub
  Pages. To preview locally (mdBook 0.5.4):

  ```bash
  python3 site/build.py && mdbook serve site
  ```
