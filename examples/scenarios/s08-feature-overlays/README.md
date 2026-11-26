# s08-feature-overlays (small)

This scenario models one routing used in two environments, dev and prod.
`envs/dev.toml` and `envs/prod.toml` are
[overlays](../../../docs/glossary.md#overlay) merged over
[`ferrosip.toml`](../../../docs/glossary.md#ferrosiptoml). The
[`[feature]`](../../../docs/glossary.md#feature-switch) values they set
decide what the routing does. It proves that each environment gets its own
behaviour and timers from one routing file, and that bad overlays are
refused.

```
                  ┌ dev:  no auth · X-Debug · X-Env: dev  · fr_timer 1s · log debug ──▶ UPSTREAM
ferrosip.toml ────┤
(safe defaults)   └ prod: 407 auth · X-Env: prod · fr_timer 3s · log notice ──────────▶ PROD_UPSTREAM
                    --set feature.x=… wins over both
```

**Shows**:
- `--overlay`: tables merge, values replace, and a later overlay wins;
- `--set`;
- `check --explain` with the source of every value (see
  [check](../../../docs/glossary.md#check));
- `[feature]` switches: `if features.require_auth { … }` is compiled out
  when false;
- module parameters (`fr_timer`) per environment.

The base file holds the safe defaults: authentication on, no debug
headers. So forgetting the overlay doesn't open the proxy. The runner
checks and lints the base file. The test checks the overlays
(`check --explain`). `ferrosip lint` has no `--overlay`, so an environment
can't be linted as it runs.

**Edge cases checked** (`tests/scenarios/s08_feature_overlays.py`):
- `check --explain`:
  - prod's `fr_timer`, `log_level`, `workers` come from `envs/prod.toml`;
  - `require_auth` stays the base's;
  - dev's values come from `envs/dev.toml`;
  - with both overlays the later one wins key by key;
  - `--set` wins over the overlay.
- These are refused: an overlay with a misspelt key (did-you-mean), an
  overlay with a value of the wrong type, and a missing overlay file.
- dev:
  - a [MESSAGE](../../../docs/glossary.md#message) is relayed without
    credentials, with `X-Env: dev` and an `X-Debug` naming the source and
    the upstream;
  - a silent upstream gives 408 after 1s.
- prod:
  - 407 first ([challenge](../../../docs/glossary.md#challenge)), and
    nothing is relayed;
  - with credentials it goes to `PROD_UPSTREAM`, never to dev's, with
    `X-Env: prod`, no `X-Debug` and no credentials;
  - a silent upstream gives 408 after 3s.
- prod with `--set feature.require_auth=false --set
  feature.env_name=staging`: relayed unchallenged with `X-Env: staging`.

**Run it by hand**, from this directory, because `users_file` is relative:
`ferrosip --config ferrosip.toml --overlay envs/dev.toml` (port 5060,
upstream `sip:127.0.0.1:5080`), or with `envs/prod.toml` (upstream
`sip:127.0.0.1:5090`). Set `SIP_PORT`, `UPSTREAM`, `PROD_UPSTREAM`,
`TRUSTED`.
