# sip-db

This crate gives ferrosip's modules one way to read and write database
tables, whatever the database is. Modules that keep data in tables use it:
subscribers, locations, dialogs, dispatcher sets, and so on. It offers one
`DbConn` trait. The `db_url` string picks the driver.

It is the counterpart of [Kamailio's](../../docs/glossary.md#kamailio)
`lib/srdb1` API plus the `db_text`, `db_sqlite`, `db_mysql` and
`db_postgres` [modules](../../docs/glossary.md#module).

The crate has no workspace dependencies. It uses `rusqlite` with bundled
SQLite, the `mysql` crate with rustls, and `postgres` with
`postgres_rustls`. These crates use it: `mod-auth`, `mod-routing`,
`mod-limits`, `mod-dialog`, `mod-carrier`, `mod-presence` and `mod-extra`.
The crate is `#![forbid(unsafe_code)]`.

## Contents

| File | Provides |
|---|---|
| `src/lib.rs` | `DbVal`, `Rows`, `Filter`, the `DbConn` trait, `connect(url)`, the db_text driver and the SQLite driver |
| `src/sql.rs` | The MySQL/MariaDB (`MySqlDb`) and PostgreSQL (`PgDb`) drivers: shared query builder, connection pool with retry, TLS options, Postgres type decoding |

## Key types and APIs

```rust
use sip_db::{connect, DbVal};

let db = connect("sqlite::memory:")?;                // Arc<dyn DbConn>
db.raw("CREATE TABLE subscriber (id INTEGER PRIMARY KEY AUTOINCREMENT, \
        username TEXT, domain TEXT, password TEXT)")?;
db.insert("subscriber", &["username", "domain", "password"],
          &["alice".into(), "example.com".into(), "secret".into()])?;
let rows = db.query("subscriber", &["id", "password"], &[("username", "alice".into())])?;
let id = rows.rows[0][0].int();                       // Some(1)
let n = db.update("subscriber", &[("username", DbVal::from("alice"))], &[("password", "new".into())])?;
let gone = db.delete("subscriber", &[("username", "alice".into())])?;
```

- `connect(url) -> Result<Arc<dyn DbConn>, DbError>` picks the driver by
  URL prefix (see below). The SQL drivers open their first connection right
  away. So a bad URL or an unreachable server fails at startup.
- `DbError` says why a call failed:
  - `Conn`: the database can't be reached. This covers a connection that
    broke even after a retry on a fresh one, and a db_text file that can't
    be read or written. It is shown as `database unreachable: …`.
  - `Stmt`: the statement was refused, for example an unknown table or
    column, or an SQL error.
  - `Config`: an unusable `db_url`.

  `is_conn()` tells a database that is down from a bad query.
  `From<DbError> for String` keeps `?` working in callers that report
  errors as strings.
- `DbConn` (all methods return `Result<_, DbError>`):
  - `query(table, cols, filter) -> Rows`: `SELECT cols FROM table WHERE
    filter`. Empty `cols` means all columns.
  - `insert(table, cols, vals)`.
  - `update(table, filter, set) -> usize` and `delete(table, filter) ->
    usize`: they return the number of rows affected.
  - `raw(sql) -> Rows`: raw SQL. The default implementation (db_text)
    returns an error.
- `Filter` is `&[(&str, DbVal)]`. Every pair must match (equality, AND).
- `DbVal` is `Null`, `Int(i64)`, `Double(f64)` or `Str(String)`. It has
  these helpers:
  - `str()`;
  - `int()`, which also parses strings and truncates doubles;
  - `is_null()`;
  - `text()`, which gives `""` for NULL;
  - `From<&str>`, `From<String>`, `From<i64>`.
- `Rows { cols, rows }`: column names and rows of values.

## URL schemes

| URL | Driver |
|---|---|
| `text:///path/to/dir` (or `text:/path`) | Kamailio db_text: one file per table in that directory (it must exist) |
| `sqlite:///path/to/file.db` (or `sqlite:path`), `sqlite::memory:` | SQLite via bundled `rusqlite`, 2 s busy timeout |
| `mysql://user:pass@host[:port]/db` | MySQL / MariaDB |
| `postgres://user:pass@host[:port]/db` or `postgresql://…` | PostgreSQL |

ferrosip handles some query parameters itself. It removes them before the
URL reaches the driver:

- PostgreSQL `sslmode`:
  - `disable` (default), `allow` and `prefer` all run without TLS here;
  - `require` encrypts without verifying the server, as libpq does;
  - `verify-ca` / `verify-full` verify against `sslrootcert=/path/ca.pem`,
    which is then required.

  Other values are an error.
- MySQL:
  - `ssl=1` (also `true` / `on`) turns TLS on;
  - `ssl_ca=/path/ca.pem` adds a CA and makes verification the default;
  - `ssl_verify=0|1` (or `false`) overrides it.

## Cargo features

`sqlite` is on by default for this crate; `mysql` and `postgres` are
opt-in (they bring about 95 crates, tokio among them). The
workspace depends on `sip-db` with `default-features = false`. The binary
turns the drivers on with the `bin/ferrosip` features `db-sqlite`,
`db-mysql` and `db-postgres`. So no module can pull a driver in by itself.

A URL whose driver isn't built fails in `connect` with "built without the X
database driver (ferrosip cargo feature `db-X`)". `text://` is always
available.

Layout:
- SQLite is in `src/sqlite.rs`.
- The shared SQL builder and connection pool are in `src/sql.rs`.
- The drivers are in `src/sql/my.rs` and `src/sql/pg.rs`.

## Design notes

- **db_text compatibility.** Files use Kamailio's format:
  - a typed header line (`id(int,auto) username(string) rpid(string,null)`);
  - then rows of `:`-separated values with `\:` and `\\` escapes (also
    `\n`, `\r`, `\t`).

  Empty values are NULL for nullable or non-string columns. Types `int`
  and `datetime` become `Int`, `double` becomes `Double`, and the rest
  become `Str`. `auto` columns get max + 1 on insert. A table is re-read
  when its modification time changes. Writes go to a temporary file that
  is renamed over the table. So you can edit a file by hand and reload.
  Table names with `/`, `\` or `.` are refused.
- **Identifier validation.** The SQL drivers accept only `[A-Za-z0-9_]`
  identifiers. They quote them per dialect: backticks for SQLite and
  MySQL, double quotes for PostgreSQL. SQLite uses backticks because it
  treats an unknown double-quoted name as a string literal. Values are
  always bound parameters (`?` or `$n`).
- **Shared query builder.** MySQL and PostgreSQL build `SELECT` / `INSERT` /
  `UPDATE` / `DELETE` from the same code. They differ only in quoting and
  placeholders.
- **Connection pool with one retry.** Up to 8 idle connections are kept.
  A statement can fail because the connection is broken, rather than
  because the statement was refused. Then the connection is dropped and the
  statement is retried once on a fresh connection. So ferrosip picks up a
  restarted database server without a restart of its own.
- **PostgreSQL typing.** Parameters are sent in text format, so the server
  converts them to the column type (int, bigint, timestamp, bool, …).
  Result columns are decoded from the binary format by type, dates and
  timestamps included.
- **Raw SQL** (`sqlops`): on SQLite, statements starting with `select`,
  `with` or `pragma` return rows. Anything else runs as a batch and
  returns one `affected` column. The MySQL and PostgreSQL drivers also
  implement `raw`.
- **Schema.** Table and column names follow Kamailio's schema. `etc/schema/postgres.sql` and
  `etc/schema/mysql.sql` create the tables the modules use. Times such as
  `expires` are stored as Unix seconds.

## Testing

- Unit tests: `cargo test -p sip-db`. They cover:
  - the db_text and SQLite drivers through the same
    insert/query/update/delete sequence;
  - escaping, auto ids, reload after an on-disk change, identifier
    validation;
  - the SQL query builder, URL parameter splitting and Postgres date
    conversion.
- End-to-end: `tests/e2e_sqldb.py` runs the proxy against real PostgreSQL
  and MariaDB servers that it starts itself. Both require TLS. It skips a
  database whose server binaries are missing. `tests/e2e_routing.py` and
  `tests/e2e_state.py` use db_text tables. `tests/e2e_state.py` restarts
  the proxy to check persistence.
