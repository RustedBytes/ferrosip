# sip-script

The engine that runs ferrosip's routing scripts. A routing script decides
what the proxy does with each message. This crate reads a
[Kamailio](../../docs/glossary.md#kamailio)-style configuration file
([`.cfg`](../../docs/glossary.md#cfg)), compiles it, and runs the compiled
routes for every message. You use it to load or reload a script, or to
format one.

It has a lexer, a parser and a compiler, plus the runtime. It corresponds to
Kamailio's `cfg.lex` / `cfg.y` (parsing), `route.c`
([fixups](../../docs/glossary.md#fixup)) and `action.c` / `rvalue.c`
(execution). The text becomes tokens, then an AST, then action trees. In
those trees every function name is already a function pointer with
pre-processed arguments.

It depends on `sip-parser` and `sip-core`, plus `regex`, `arc-swap` and
`serde_json`. Other parts use it like this:

- `bin/ferrosip` parses the config file with it and compiles the routes
  against the module registry. It hands the resulting `Live` engine to
  `sip-transport` as the message `Handler`.
- Modules reach the routes through `sip-core`'s `RouteHub`.
- `tools/ferroctl` uses the formatter (`ferroctl fmt`).
- The `script` fuzz target uses `parse` and the formatter.

The crate is `#![forbid(unsafe_code)]`.

## Contents

| File | Provides |
|---|---|
| `src/lexer.rs` | `Tok` and `lex`: tokens with line numbers. Strings, integers, identifiers, `$variables` (delimited with `sip_core::pv::pv_len`), operators, and `#`, `//` and `/* */` comments |
| `src/parser.rs` | `parse(src) -> Result<Ast, String>`: a recursive-descent parser. `Ast`, `ModParam`, `RawArg`, `Expr`, `Stmt`, `BinOp` |
| `src/fmt.rs` | `fmt::format(src)`: the script formatter behind `ferroctl fmt` |
| `src/lib.rs` | The compiler (`Engine::compile`), the interpreter, `convert_arg`, `Engine` (implements `Handler` and `RouteRunner`) and `Live` (the reloadable wrapper) |

## Key types and APIs

### Parsing

`parse(&str) -> Result<Ast, String>` produces an `Ast`. Names are not
resolved yet, because modules are loaded between parsing and compiling.

| Field | Source |
|---|---|
| `modules` | `loadmodule "tm"` (a trailing `.so` is dropped) |
| `modparams` | `modparam("module", "name", value)` with its line number |
| `request_route` | `request_route { … }` or an unnamed `route { … }` |
| `routes` | `route[NAME] { … }` |
| `failure_routes`, `onreply_routes`, `branch_routes`, `event_routes` | `failure_route[x]`, `onreply_route[x]`, `branch_route[x]`, `event_route[module:event]` |
| `reply_route` | `reply_route { … }` or an unnamed `onreply_route { … }` |

These are the [request route](../../docs/glossary.md#request-route),
[route blocks](../../docs/glossary.md#route-block),
[failure](../../docs/glossary.md#failure-route),
[onreply](../../docs/glossary.md#onreply-route),
[branch](../../docs/glossary.md#branch-route) and
[event](../../docs/glossary.md#event-route) routes, and the
[reply route](../../docs/glossary.md#reply-route). See also
[module](../../docs/glossary.md#module) and
[modparam](../../docs/glossary.md#modparam).

Errors carry the line number (`line 12: …`). Defining a named route twice is
an error.

### Compiling and running

```rust
use sip_core::{corefns::CoreModule, Registry};
use sip_script::{Engine, Live};
use std::sync::Arc;

fn build(src: &str) -> Result<Arc<Live>, String> {
    let ast = sip_script::parse(src)?;
    let mut reg = Registry::default();
    reg.load(Arc::new(CoreModule))?;
    // … load the modules named in ast.modules, applying ast.modparams first …
    let engine = Live::new(Engine::compile(&ast, Arc::new(reg))?);
    engine.install(); // modules (tm, events) can now run routes
    Ok(engine)
}
```

- `Engine::compile(&ast, Arc<Registry>)` first publishes the route names to
  `reg.hub`. This lets fixups like `t_on_failure("x")` resolve to an index.
  Then it compiles every block. These are all startup errors: unknown
  functions, wrong arguments, unknown variables, assignments to read-only
  variables and bad constant regexes.
- `Engine` implements `sip_core::Handler`. Its `handle` runs `request_route`
  for requests. For replies it runs `reply_route`, then offers the reply to
  each module's `on_reply`.
- `Engine` also implements `sip_core::RouteRunner`: `run_failure`,
  `run_onreply`, `run_branch`, `run_event`, `run_route`, `route_index`,
  `resume`, `export`, `pv_table`.
- `Engine::summary()` returns the number of compiled routes of each kind.
- `convert_arg(&RawArg, &Registry)` turns a literal argument into a
  `sip_core::Arg`. A string with variables becomes an `Arg::Fmt` template.

### Live reload

`Live` wraps the current `Engine` in an `ArcSwap`. This is the whole API:

- `Live::new(engine)`;
- `install()`;
- `load()`: the current engine;
- `reload(&ast)`: recompiles and swaps. It returns the summary as JSON.

`Live` implements `Handler` and `RouteRunner` by passing each call to the
current engine. `bin/ferrosip` wires `reload` to the `cfg.reload`
[RPC](../../docs/glossary.md#rpc) (see
[live reload](../../docs/glossary.md#live-reload)). It refuses the reload
when the `loadmodule` / `modparam` lines differ from the running ones.

`Engine::recompile` keeps route indices stable. An existing name keeps its
index. If the route was removed, that index gets an empty body. New names
are appended. This matters because live
[transactions](../../docs/glossary.md#transaction) and suspended requests
hold route indices.

### Formatter

`fmt::format(src) -> Result<String, String>` re-indents a script without
changing what it means. Its rules:

- 4 spaces per `{ }` level;
- `case` / `default` bodies one level below their label;
- continuation lines inside open `( )` one level deeper;
- trailing whitespace is trimmed;
- runs of blank lines collapse to one;
- blank lines at the start and end of the file, and of a block, are dropped;
- the file ends with one newline.

Everything else on a line is kept: spacing, comments and strings. Lines that
continue a multi-line token are kept too, such as a `/* */` comment or a
`$( … )` variable broken across lines.

The input must parse. The output must lex to exactly the same token stream.
Otherwise an error is returned and nothing changes. `ferroctl fmt
[--check] [FILE…]` formats files in place. Without files it reads stdin and
writes stdout.

## Design notes

- **Resolve everything at startup.** Function names become `ExportFn`
  pointers, with the fixup's result stored next to them. Every `$variable`
  becomes a `PvRef`. `route(NAME)` becomes an index. Strings with variables
  become templates. At run time nothing is looked up by name and no literal
  is re-parsed.
- **Fast paths.** `$rm == "INVITE"` (or `method == …`) compiles to an enum
  comparison when the method is one that `sip-parser` knows. A constant regex
  in `=~` / `!~` is compiled once. A regex built from variables is compiled
  each time it is evaluated.
- **Lock-free reload.** Each message does one atomic load of the current
  engine (`ArcSwap`). Messages that are already running finish on the old
  engine.
- **Guards.** A `while` loop stops after 10,000 iterations. `route()` calls
  nest at most 100 deep. This is like Kamailio's `max_while_loops`
  protection.
- **Async suspension.** A function can
  [suspend](../../docs/glossary.md#suspend-and-resume) the message: it
  pushes `AsyncPending` into the `Ctx` and returns 0. The interpreter then
  records the path through nested `if`/`while`/`switch` blocks while it
  unwinds. It hands the function a `Continuation` that points at the next
  action. Later `resume` continues exactly there, in `request_route` or a
  `route[...]`.
- **Lexer robustness.** The lexer works on characters, not bytes. So UTF-8
  in strings and non-ASCII whitespace are handled. The non-ASCII inputs that
  fuzzing found problems with are kept as regression tests.

## Script language summary

- **Top level**: `loadmodule`, `modparam`, `request_route`, `route[NAME]`,
  `failure_route[NAME]`, `onreply_route[NAME]`, `branch_route[NAME]`,
  `event_route[module:event]`, `reply_route`. Route names may be identifiers,
  strings, numbers, or `a:b-c` sequences.
- **Statements**:
  - `if (…) { } else if … else { }` and `while`;
  - `switch (…) { case "x": … break; default: … }`. Case labels must be
    literals. Cases fall through until `break`;
  - the assignment `$pv = expr;`;
  - function calls and `route(NAME);`;
  - `return;` / `return(expr);`, `exit;`, `drop;`, `break;`.
- **Expressions**, from lowest to highest precedence: `||`, `&&`,
  comparisons (`== != < > <= >= =~ !~`), `+ -`, `* / %`, unary `! -`.
  - A comparison is numeric when one side is an integer, and a string
    comparison otherwise.
  - `$null` only equals `$null`.
  - `+` is typed by its left operand: integer add or string concatenation.
    `$null + x` gives `x`.
  - Division or modulo by zero yields 0.
- **Truth**: a function or `route()` result is true when it is greater than
  0. Other values use Kamailio's rule: non-zero and non-empty is true.
- **Return codes**: a function's result is stored in `$rc`. A function that
  returns 0 ends the script. `return(0)` from a `route[...]` also ends it.
  See the [return code convention](../../docs/glossary.md#return-code-convention).
- **Keywords as values**: `method`, `uri`, `src_ip`, `src_port`, `proto`,
  `status`, `rc` / `retcode` map to `$rm $ru $si $sp $pr $rs $rc`. `true` /
  `false` are 1 / 0. [`myself`](../../docs/glossary.md#myself) can only be
  compared with `==` / `!=`.
- **Literals**:
  - Strings use double or single quotes, with `\n \r \t \\ \" \'` escapes.
    `\$` is a literal `$`. Unknown escapes keep the backslash, so regexes
    like `"\."` work.
  - Integers are non-negative decimals, with unary minus.
  - Function arguments may be strings, integers, variables or bare
    identifiers. Bare identifiers are taken as strings.
- **`drop`**: works like `exit`. In `branch_route`, `onreply_route` and
  `event_route` it also drops the branch, reply or event. In `reply_route`
  it stops [provisional replies](../../docs/glossary.md#provisional-reply)
  only.
- **`event_route[websocket:handshake]`**: `Engine::ws_handshake` runs it on
  a faked request built from the HTTP upgrade. The headers are in
  `$hdr(...)`, the path in `$hdr(X-WS-Path)`, and the peer in `$si` / `$sp`.
  `drop` refuses the upgrade.

Variables ([pseudo-variables](../../docs/glossary.md#pseudo-variable-pv)),
[transformations](../../docs/glossary.md#transformation) and core functions
are defined in `sip-core`. Module functions come from the `mod-*` crates.

## Testing

- Unit tests: `cargo test -p sip-script`. They cover:
  - the value semantics of `==`, `<`, `+`, `/`;
  - parser acceptance and error messages;
  - lexer regressions for non-ASCII input;
  - the formatter: indentation, preserved comments and strings, refusal of
    broken scripts, stable formatting of `etc/ferrosip.cfg`.
- Fuzz target: `fuzz/fuzz_targets/script.rs` runs `parse` on arbitrary
  UTF-8. For input that parses, it checks that `fmt::format` succeeds and is
  idempotent. Run it with `cd fuzz && cargo +nightly fuzz run script`.
- End-to-end:
  - `tests/e2e_script.py`: expressions, pseudo-variables,
    `route()`/`return`, `while`/`switch`, `branch_route`.
  - `tests/e2e_routes.py`: `failure_route`, `onreply_route`, `reply_route`.
  - `tests/e2e_reload.py`: `cfg.reload` with new routes, stable indices and
    refused reloads.
  - `tests/e2e_async.py`: suspend and resume.
