//! Database layer (Kamailio `lib/srdb1` + `db_text` + `db_sqlite`).
//!
//! Modules talk to one `DbConn` trait; the driver is chosen by `db_url`:
//! * `text:///var/lib/ferrosip/db` — Kamailio db_text files: one file per
//!   table, a typed header line (`id(int,auto) username(string) …`), rows of
//!   `:`-separated values (`\:` and `\\` escaped, empty = NULL for nullable
//!   columns). Files are re-read when they change on disk and rewritten
//!   atomically on writes, so `vi` + `ferroctl …reload` works.
//! * `sqlite:///var/lib/ferrosip/ferrosip.db` (or `sqlite::memory:`) —
//!   SQLite via rusqlite (bundled); also supports raw SQL (`sqlops`).
//! * `mysql://user:pass@host[:port]/db` and `postgres://…` — production
//!   servers (see `sql.rs`); schemas in `etc/schema/`.
//!
//! Table and column names follow Kamailio's schema (see `etc/schema/`).
#![forbid(unsafe_code)]
// An ignored Result here is a decision: say why (`#[allow]` + reason).
#![warn(clippy::let_underscore_must_use)]

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[cfg(any(feature = "mysql", feature = "postgres"))]
mod sql;
#[cfg(feature = "sqlite")]
mod sqlite;

#[derive(Clone, Debug, PartialEq)]
pub enum DbVal {
    Null,
    Int(i64),
    Double(f64),
    Str(String),
}

/// A DB double read as an integer: truncated toward zero, saturating at the
/// `i64` range, NaN reads 0 (what `as` does, spelled out).
fn double_to_int(d: f64) -> i64 {
    #[allow(clippy::cast_possible_truncation, reason = "float to int `as` saturates and maps NaN to 0, the wanted semantics")]
    let i = d.trunc() as i64;
    i
}

/// An affected-row or similar count from a driver, as a script integer.
#[cfg(any(feature = "sqlite", feature = "mysql", feature = "postgres"))]
pub(crate) fn count_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// An affected-row count from a driver, as `usize`.
#[cfg(any(feature = "mysql", feature = "postgres"))]
pub(crate) fn count_usize(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

impl DbVal {
    pub fn str(&self) -> Option<&str> {
        match self {
            DbVal::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn int(&self) -> Option<i64> {
        match self {
            DbVal::Int(i) => Some(*i),
            DbVal::Double(d) => Some(double_to_int(*d)),
            DbVal::Str(s) => s.trim().parse().ok(),
            DbVal::Null => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, DbVal::Null)
    }
    /// Text form (`""` for NULL).
    pub fn text(&self) -> String {
        match self {
            DbVal::Null => String::new(),
            DbVal::Int(i) => i.to_string(),
            DbVal::Double(d) => d.to_string(),
            DbVal::Str(s) => s.clone(),
        }
    }
    fn loose_eq(&self, other: &DbVal) -> bool {
        match (self, other) {
            (DbVal::Null, DbVal::Null) => true,
            (DbVal::Null, _) | (_, DbVal::Null) => false,
            // An integer never equals a double with a fractional part.
            (DbVal::Int(_), DbVal::Double(d)) | (DbVal::Double(d), DbVal::Int(_)) if d.fract() != 0.0 => false,
            (DbVal::Int(_), _) | (_, DbVal::Int(_)) => self.int().is_some() && self.int() == other.int(),
            _ => self.text() == other.text(),
        }
    }
}

impl From<&str> for DbVal {
    fn from(s: &str) -> Self {
        DbVal::Str(s.to_string())
    }
}
impl From<String> for DbVal {
    fn from(s: String) -> Self {
        DbVal::Str(s)
    }
}
impl From<i64> for DbVal {
    fn from(i: i64) -> Self {
        DbVal::Int(i)
    }
}

impl fmt::Display for DbVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

/// Result of a raw query.
#[derive(Debug, Default)]
pub struct Rows {
    pub cols: Vec<String>,
    pub rows: Vec<Vec<DbVal>>,
}

/// Why a database call failed. Callers that only report it can use `?`
/// into a `String` error or print it; callers that care can tell a
/// database that is down from a statement it refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DbError {
    /// The database can't be reached: connecting failed, the connection
    /// broke (after one retry on a fresh one), or a db_text file can't be
    /// read or written. Retrying later may work.
    Conn(String),
    /// The statement was refused: unknown table or column, bad identifier,
    /// an SQL error or a constraint, a malformed db_text table.
    Stmt(String),
    /// The `db_url` can't be used: bad URL or options, unknown scheme, a
    /// driver left out of this build.
    Config(String),
}

impl DbError {
    /// The database is unreachable (not a problem with the statement).
    pub fn is_conn(&self) -> bool {
        matches!(self, Self::Conn(_))
    }

    /// The driver's message, without the kind.
    pub fn message(&self) -> &str {
        match self {
            Self::Conn(m) | Self::Stmt(m) | Self::Config(m) => m,
        }
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conn(m) => write!(f, "database unreachable: {m}"),
            Self::Stmt(m) | Self::Config(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for DbError {}

impl From<DbError> for String {
    fn from(e: DbError) -> Self {
        e.to_string()
    }
}

/// Equality filter: all `(column, value)` pairs must match.
pub type Filter<'a> = &'a [(&'a str, DbVal)];

pub trait DbConn: Send + Sync {
    /// `SELECT cols FROM table WHERE filter` (empty `cols` = all columns).
    fn query(&self, table: &str, cols: &[&str], filter: Filter<'_>) -> Result<Rows, DbError>;
    fn insert(&self, table: &str, cols: &[&str], vals: &[DbVal]) -> Result<(), DbError>;
    /// Returns the number of updated rows.
    fn update(&self, table: &str, filter: Filter<'_>, set: &[(&str, DbVal)]) -> Result<usize, DbError>;
    /// Returns the number of deleted rows.
    fn delete(&self, table: &str, filter: Filter<'_>) -> Result<usize, DbError>;
    /// Raw SQL (only SQL drivers).
    fn raw(&self, _sql: &str) -> Result<Rows, DbError> {
        Err(DbError::Stmt("raw queries need an SQL driver (sqlite://)".into()))
    }
}

/// Kamailio's default `db_url` for modules that need a database.
pub const DEFAULT_URL: &str = "mysql://kamailio:kamailiorw@localhost/kamailio";

/// The URL a module without `db_url` uses (as in Kamailio), with a notice.
pub fn default_url(module: &str) -> String {
    eprintln!("ferrosip: note: {module}: no db_url, using Kamailio's default {DEFAULT_URL}");
    DEFAULT_URL.to_string()
}

static CHECK_ONLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Config check mode (`ferrosip -c`): [`connect`] validates the URL but
/// opens nothing, and returns a database that is empty and accepts writes.
pub fn set_check_only(on: bool) {
    CHECK_ONLY.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Stand-in database for check mode.
struct NullDb;

impl DbConn for NullDb {
    fn query(&self, _: &str, _: &[&str], _: Filter<'_>) -> Result<Rows, DbError> {
        Ok(Rows::default())
    }
    fn insert(&self, _: &str, _: &[&str], _: &[DbVal]) -> Result<(), DbError> {
        Ok(())
    }
    fn update(&self, _: &str, _: Filter<'_>, _: &[(&str, DbVal)]) -> Result<usize, DbError> {
        Ok(0)
    }
    fn delete(&self, _: &str, _: Filter<'_>) -> Result<usize, DbError> {
        Ok(0)
    }
    fn raw(&self, _: &str) -> Result<Rows, DbError> {
        Ok(Rows::default())
    }
}

/// Open a database by URL (`text://…`, `sqlite://…`, `mysql://…`, `postgres://…`).
pub fn connect(url: &str) -> Result<Arc<dyn DbConn>, DbError> {
    if CHECK_ONLY.load(std::sync::atomic::Ordering::Relaxed) {
        const SCHEMES: [&str; 7] = ["text:", "sqlite:", "mysql://", "postgres://", "postgresql://", "text://", "sqlite://"];
        if !SCHEMES.iter().any(|s| url.starts_with(s)) {
            return Err(DbError::Config(format!("unsupported db_url {url:?} (use text:///dir, sqlite:///file, mysql://… or postgres://…)")));
        }
        return Ok(Arc::new(NullDb));
    }
    if let Some(p) = url.strip_prefix("text://").or_else(|| url.strip_prefix("text:")) {
        let dir = PathBuf::from(p);
        if !dir.is_dir() {
            return Err(DbError::Conn(format!("db_text directory {} does not exist", dir.display())));
        }
        return Ok(Arc::new(TextDb { dir, tables: Mutex::new(HashMap::new()) }));
    }
    if let Some(p) = url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:")) {
        #[cfg(feature = "sqlite")]
        return Ok(Arc::new(sqlite::SqliteDb::open(p)?));
        #[cfg(not(feature = "sqlite"))]
        return Err(not_built(p, "sqlite"));
    }
    if url.starts_with("mysql://") {
        #[cfg(feature = "mysql")]
        return Ok(Arc::new(sql::MySqlDb::open(url)?));
        #[cfg(not(feature = "mysql"))]
        return Err(not_built(url, "mysql"));
    }
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        #[cfg(feature = "postgres")]
        return Ok(Arc::new(sql::PgDb::open(url)?));
        #[cfg(not(feature = "postgres"))]
        return Err(not_built(url, "postgres"));
    }
    Err(DbError::Config(format!("unsupported db_url {url:?} (use text:///dir, sqlite:///file, mysql://… or postgres://…)")))
}

/// A db_url whose driver was left out of this build (Cargo features).
#[allow(dead_code, reason = "unused when every driver is built")]
fn not_built(_url: &str, feature: &str) -> DbError {
    DbError::Config(format!("this ferrosip was built without the {feature} database driver (ferrosip cargo feature `db-{feature}`)"))
}

// ---------------------------------------------------------------- db_text --

#[derive(Clone, Debug)]
struct Col {
    name: String,
    ty: String,
    null: bool,
    auto: bool,
}

struct Table {
    mtime: Option<SystemTime>,
    cols: Vec<Col>,
    rows: Vec<Vec<DbVal>>,
}

struct TextDb {
    dir: PathBuf,
    tables: Mutex<HashMap<String, Table>>,
}

fn unescape_split(line: &str) -> Vec<(String, bool)> {
    // (value, was_empty_raw)
    let (mut out, mut cur, mut esc) = (Vec::new(), String::new(), false);
    for c in line.chars() {
        match c {
            _ if esc => {
                cur.push(match c {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '0' => '\0',
                    c => c,
                });
                esc = false;
            }
            '\\' => esc = true,
            ':' => out.push((std::mem::take(&mut cur), false)),
            c => cur.push(c),
        }
    }
    out.push((cur, false));
    for v in out.iter_mut() {
        v.1 = v.0.is_empty();
    }
    out
}

fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ':' => o.push_str("\\:"),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c => o.push(c),
        }
    }
    o
}

fn parse_header(h: &str) -> Result<Vec<Col>, String> {
    h.split_whitespace()
        .map(|c| {
            let (name, rest) = c.split_once('(').ok_or_else(|| format!("bad column definition {c:?}"))?;
            let flags: Vec<&str> = rest.trim_end_matches(')').split(',').map(str::trim).collect();
            let ty = flags.first().map_or_else(String::new, |t| t.to_ascii_lowercase());
            Ok(Col { name: name.to_string(), ty, null: flags.contains(&"null"), auto: flags.contains(&"auto") })
        })
        .collect()
}

fn typed(col: &Col, raw: &str, empty: bool) -> DbVal {
    if empty && (col.null || col.ty != "string" && col.ty != "str") {
        return DbVal::Null;
    }
    match col.ty.as_str() {
        "int" | "datetime" => raw.trim().parse().map_or(DbVal::Null, DbVal::Int),
        "double" => raw.trim().parse().map_or(DbVal::Null, DbVal::Double),
        _ => DbVal::Str(raw.to_string()),
    }
}

impl TextDb {
    fn path(&self, table: &str) -> Result<PathBuf, DbError> {
        if table.is_empty() || table.contains(['/', '\\', '.']) {
            return Err(DbError::Stmt(format!("bad table name {table:?}")));
        }
        Ok(self.dir.join(table))
    }

    fn load(path: &Path) -> Result<Table, DbError> {
        let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        let text = std::fs::read_to_string(path).map_err(|e| DbError::Conn(format!("{}: {e}", path.display())))?;
        Self::parse(path, &text, mtime).map_err(DbError::Stmt)
    }

    /// A table file's contents.
    fn parse(path: &Path, text: &str, mtime: Option<SystemTime>) -> Result<Table, String> {
        let mut lines = text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#'));
        let cols = parse_header(lines.next().ok_or_else(|| format!("{}: missing header line", path.display()))?)?;
        let mut rows = Vec::new();
        for (n, l) in (1usize..).zip(lines) {
            let vals = unescape_split(l);
            if vals.len() != cols.len() {
                return Err(format!("{}: row {n} has {} values, expected {}", path.display(), vals.len(), cols.len()));
            }
            rows.push(cols.iter().zip(vals).map(|(c, (v, e))| typed(c, &v, e)).collect());
        }
        Ok(Table { mtime, cols, rows })
    }

    /// Runs `f` on the (re)loaded table; its errors are refused statements.
    fn with_table<R>(&self, table: &str, f: impl FnOnce(&mut Table) -> Result<(R, bool), String>) -> Result<R, DbError> {
        let path = self.path(table)?;
        let mut tables = self.tables.lock().unwrap_or_else(|e| e.into_inner());
        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        if tables.get(table).is_none_or(|t| t.mtime != mtime) {
            tables.insert(table.to_string(), Self::load(&path)?);
        }
        let Some(t) = tables.get_mut(table) else { return Err(DbError::Conn(format!("db_text: table {table} not loaded"))) };
        let (r, dirty) = f(t).map_err(DbError::Stmt)?;
        if dirty {
            let mut out = t
                .cols
                .iter()
                .map(|c| {
                    let mut flags = vec![c.ty.clone()];
                    if c.auto {
                        flags.push("auto".into());
                    }
                    if c.null {
                        flags.push("null".into());
                    }
                    format!("{}({})", c.name, flags.join(","))
                })
                .collect::<Vec<_>>()
                .join(" ");
            out.push('\n');
            for row in &t.rows {
                let line = row.iter().map(|v| escape(&v.text())).collect::<Vec<_>>().join(":");
                if line.starts_with('#') || line.is_empty() {
                    // Not a comment or blank line: `\#` reads back as `#`,
                    // a lone `\` as one empty value.
                    out.push('\\');
                }
                out.push_str(&line);
                out.push('\n');
            }
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, out).and_then(|_| std::fs::rename(&tmp, &path)).map_err(|e| DbError::Conn(format!("{}: {e}", path.display())))?;
            t.mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        }
        Ok(r)
    }
}

fn col_idx(cols: &[Col], name: &str) -> Result<usize, String> {
    cols.iter().position(|c| c.name == name).ok_or_else(|| format!("no column {name:?}"))
}

fn matches(cols: &[Col], row: &[DbVal], filter: Filter<'_>) -> Result<bool, String> {
    for (c, v) in filter {
        if !row.get(col_idx(cols, c)?).is_some_and(|x| x.loose_eq(v)) {
            return Ok(false);
        }
    }
    Ok(true)
}

impl DbConn for TextDb {
    fn query(&self, table: &str, cols: &[&str], filter: Filter<'_>) -> Result<Rows, DbError> {
        self.with_table(table, |t| {
            let idx: Vec<usize> =
                if cols.is_empty() { (0..t.cols.len()).collect() } else { cols.iter().map(|c| col_idx(&t.cols, c)).collect::<Result<_, _>>()? };
            let mut rows = Vec::new();
            for r in &t.rows {
                if matches(&t.cols, r, filter)? {
                    rows.push(idx.iter().filter_map(|&i| r.get(i).cloned()).collect());
                }
            }
            Ok((Rows { cols: idx.iter().filter_map(|&i| Some(t.cols.get(i)?.name.clone())).collect(), rows }, false))
        })
    }

    fn insert(&self, table: &str, cols: &[&str], vals: &[DbVal]) -> Result<(), DbError> {
        self.with_table(table, |t| {
            let mut row = vec![DbVal::Null; t.cols.len()];
            for (c, v) in cols.iter().zip(vals) {
                if let Some(cell) = row.get_mut(col_idx(&t.cols, c)?) {
                    *cell = v.clone();
                }
            }
            for (i, (c, cell)) in t.cols.iter().zip(row.iter_mut()).enumerate() {
                if c.auto && cell.is_null() {
                    // The next id after the largest in the file (which may be anything).
                    let last = t.rows.iter().filter_map(|r| r.get(i)?.int()).max().unwrap_or(0);
                    *cell = DbVal::Int(last.checked_add(1).ok_or_else(|| format!("{table}: column {} is out of ids", c.name))?);
                }
            }
            t.rows.push(row);
            Ok(((), true))
        })
    }

    fn update(&self, table: &str, filter: Filter<'_>, set: &[(&str, DbVal)]) -> Result<usize, DbError> {
        self.with_table(table, |t| {
            let idx: Vec<(usize, DbVal)> = set.iter().map(|(c, v)| Ok((col_idx(&t.cols, c)?, v.clone()))).collect::<Result<_, String>>()?;
            let mut n = 0usize;
            for row in &mut t.rows {
                if matches(&t.cols, row, filter)? {
                    for (i, v) in &idx {
                        if let Some(cell) = row.get_mut(*i) {
                            *cell = v.clone();
                        }
                    }
                    n = n.saturating_add(1);
                }
            }
            Ok((n, n > 0))
        })
    }

    fn delete(&self, table: &str, filter: Filter<'_>) -> Result<usize, DbError> {
        self.with_table(table, |t| {
            let before = t.rows.len();
            let mut keep = Vec::with_capacity(before);
            for r in std::mem::take(&mut t.rows) {
                if !matches(&t.cols, &r, filter)? {
                    keep.push(r);
                }
            }
            t.rows = keep;
            let n = before.saturating_sub(t.rows.len());
            Ok((n, n > 0))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_reads_as_int() {
        assert_eq!(DbVal::Double(-2.9).int(), Some(-2));
        assert_eq!(DbVal::Double(1e300).int(), Some(i64::MAX));
        assert_eq!(DbVal::Double(f64::NAN).int(), Some(0));
    }

    fn exercise(db: &dyn DbConn) {
        db.insert("subscriber", &["username", "domain", "password"], &["alice".into(), "ex.com".into(), "s:e\\cret".into()]).unwrap();
        db.insert("subscriber", &["username", "domain", "password"], &["bob".into(), "ex.com".into(), "x".into()]).unwrap();
        let r = db.query("subscriber", &["id", "password"], &[("username", "alice".into())]).unwrap();
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0][1], DbVal::Str("s:e\\cret".into()), "escaping round-trips");
        assert_eq!(r.rows[0][0], DbVal::Int(1), "auto id");
        assert_eq!(db.update("subscriber", &[("username", "bob".into())], &[("password", "y".into())]).unwrap(), 1);
        assert_eq!(db.query("subscriber", &[], &[("domain", "ex.com".into())]).unwrap().rows.len(), 2);
        assert_eq!(db.delete("subscriber", &[("username", "alice".into())]).unwrap(), 1);
        let r = db.query("subscriber", &["username", "password"], &[]).unwrap();
        assert_eq!(r.rows, vec![vec![DbVal::Str("bob".into()), DbVal::Str("y".into())]]);
        assert!(db.query("subscriber", &["nope"], &[]).is_err());
    }

    #[test]
    fn text_driver() {
        let dir = std::env::temp_dir().join(format!("ferrosip-dbtext-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("subscriber"), "id(int,auto) username(string) domain(string) password(string) rpid(string,null)\n").unwrap();
        let db = connect(&format!("text://{}", dir.display())).unwrap();
        exercise(&*db);
        // Changed on disk → reloaded. Each rewrite gets its own mtime, so the
        // change is seen whatever the filesystem's timestamp resolution.
        let rewrite = |text: &str, at: u64| {
            let path = dir.join("subscriber");
            std::fs::write(&path, text).unwrap();
            let f = std::fs::File::options().write(true).open(&path).unwrap();
            f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(at)).unwrap();
        };
        rewrite("id(int,auto) username(string) domain(string) password(string) rpid(string,null)\n7:carol:ex.com:pw:\n", 1_000_000);
        let r = db.query("subscriber", &["id", "rpid"], &[("username", "carol".into())]).unwrap();
        assert_eq!(r.rows, vec![vec![DbVal::Int(7), DbVal::Null]]);
        // The largest id is i64::MAX: there is no next auto id.
        rewrite("id(int,auto) username(string) domain(string) password(string) rpid(string,null)\n9223372036854775807:dave:ex.com:pw:\n", 2_000_000);
        assert!(db.insert("subscriber", &["username"], &["eve".into()]).is_err());
        assert!(db.raw("select 1").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_driver() {
        let db = connect("sqlite::memory:").unwrap();
        db.raw("CREATE TABLE subscriber (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, domain TEXT, password TEXT)").unwrap();
        exercise(&*db);
        let r = db.raw("SELECT count(*) AS n FROM subscriber").unwrap();
        assert_eq!((r.cols[0].as_str(), r.rows[0][0].clone()), ("n", DbVal::Int(1)));
        assert!(db.query("bad;table", &[], &[]).is_err(), "identifiers are validated");
    }

    /// A fresh db_text directory with `tables` (name, file contents);
    /// removed on drop.
    struct TextDir(PathBuf);

    impl TextDir {
        fn new(name: &str, tables: &[(&str, &str)]) -> Self {
            let dir = std::env::temp_dir().join(format!("ferrosip-dbtext-{name}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&dir));
            std::fs::create_dir_all(&dir).unwrap();
            for (t, text) in tables {
                std::fs::write(dir.join(t), text).unwrap();
            }
            Self(dir)
        }
        fn db(&self) -> Arc<dyn DbConn> {
            connect(&format!("text://{}", self.0.display())).unwrap()
        }
        fn file(&self, t: &str) -> String {
            std::fs::read_to_string(self.0.join(t)).unwrap()
        }
    }

    impl Drop for TextDir {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    fn s(v: &str) -> DbVal {
        DbVal::Str(v.into())
    }

    #[test]
    fn db_text_column_types_and_nulls() {
        let d = TextDir::new(
            "types",
            &[(
                "t",
                "# a comment line\n\
             id(int,auto) name(string) note(str,null) price(double) at(datetime) n(INT,null)\n\
             \n\
             1:alice:hi:1.5:1700000000:7\n\
             2::::x:\n\
             3:  padded  : : 2 :  9 :\n",
            )],
        );
        let r = d.db().query("t", &[], &[]).unwrap();
        assert_eq!(r.cols, ["id", "name", "note", "price", "at", "n"]);
        assert_eq!(r.rows[0], [DbVal::Int(1), s("alice"), s("hi"), DbVal::Double(1.5), DbVal::Int(1_700_000_000), DbVal::Int(7)]);
        // Empty: "" for a string column, NULL for a nullable or a non-string one; bad numbers are NULL.
        assert_eq!(r.rows[1], [DbVal::Int(2), s(""), DbVal::Null, DbVal::Null, DbVal::Null, DbVal::Null]);
        // Strings keep their spaces; numbers are trimmed.
        assert_eq!(r.rows[2], [DbVal::Int(3), s("  padded  "), s(" "), DbVal::Double(2.0), DbVal::Int(9), DbVal::Null]);
    }

    #[test]
    fn db_text_escaping_round_trips() {
        let d = TextDir::new("escape", &[("t", "id(int,auto) v(string)\n")]);
        let values = ["a:b", "back\\slash", "two\nlines", "cr\rx", "tab\tx", "trailing\\", "::", "#hash", "# spaced", "ünï"];
        {
            let db = d.db();
            for v in values {
                db.insert("t", &["v"], &[s(v)]).unwrap();
            }
        }
        let file = d.file("t");
        assert!(file.contains("a\\:b") && file.contains("back\\\\slash") && file.contains("two\\nlines"), "{file}");
        // A new connection reads the file back.
        let r = d.db().query("t", &["v"], &[]).unwrap();
        let got: Vec<String> = r.rows.iter().map(|row| row[0].text()).collect();
        assert_eq!(got, values, "every value survives a write and a re-read");
    }

    #[test]
    fn db_text_rows_that_look_like_comments_survive() {
        let d = TextDir::new("comment-rows", &[("t", "v(string) n(int,null)\n")]);
        let values = ["#not a comment", "  ", "#", "x"];
        {
            let db = d.db();
            for v in values {
                db.insert("t", &["v"], &[s(v)]).unwrap();
            }
        }
        let r = d.db().query("t", &["v"], &[]).unwrap();
        let got: Vec<String> = r.rows.iter().map(|row| row[0].text()).collect();
        assert_eq!(got, values);
    }

    #[test]
    fn db_text_empty_value_in_a_one_column_table_survives() {
        let d = TextDir::new("one-col-empty", &[("t", "v(string)\n")]);
        {
            let db = d.db();
            for v in ["a", "", "b"] {
                db.insert("t", &["v"], &[s(v)]).unwrap();
            }
        }
        let r = d.db().query("t", &["v"], &[]).unwrap();
        assert_eq!(r.rows, [[s("a")], [s("")], [s("b")]], "{}", d.file("t"));
        assert_eq!(d.file("t"), "v(string)\na\n\\\nb\n");
    }

    #[test]
    fn db_text_escapes_in_hand_written_files() {
        let d = TextDir::new("unescape", &[("t", "a(string) b(string)\nx\\:y:\\n\\r\\t\\0\\\\\\q\n")]);
        let r = d.db().query("t", &[], &[]).unwrap();
        assert_eq!(r.rows, [[s("x:y"), s("\n\r\t\0\\q")]]);
    }

    #[test]
    fn db_text_auto_ids() {
        let d = TextDir::new("auto", &[("t", "id(int,auto) v(string)\n5:a\n2:b\n")]);
        let db = d.db();
        db.insert("t", &["v"], &[s("c")]).unwrap();
        db.insert("t", &["id", "v"], &[DbVal::Int(100), s("d")]).unwrap();
        db.insert("t", &["v", "id"], &[s("e"), DbVal::Null]).unwrap();
        let ids: Vec<DbVal> = db.query("t", &["id"], &[]).unwrap().rows.into_iter().map(|mut r| r.remove(0)).collect();
        assert_eq!(ids, [DbVal::Int(5), DbVal::Int(2), DbVal::Int(6), DbVal::Int(100), DbVal::Int(101)], "max + 1; explicit ids kept; NULL means auto");
        let e = TextDir::new("auto-empty", &[("t", "id(int,auto) v(string)\n")]);
        e.db().insert("t", &["v"], &[s("x")]).unwrap();
        assert!(e.file("t").ends_with("1:x\n"), "{}", e.file("t"));
        assert!(e.file("t").starts_with("id(int,auto) v(string)\n"), "the header is written back as read");
    }

    #[test]
    fn db_text_filters_compare_loosely_by_type() {
        let d = TextDir::new("filter", &[("t", "id(int) u(string) d(string) x(double,null)\n1:alice:a.com:2.5\n2:bob:a.com:\n3:alice:b.com:2\n")]);
        let db = d.db();
        let ids = |f: Filter<'_>| -> Vec<i64> { db.query("t", &["id"], f).unwrap().rows.iter().map(|r| r[0].int().unwrap()).collect() };
        assert_eq!(ids(&[]), [1, 2, 3]);
        assert_eq!(ids(&[("u", s("alice"))]), [1, 3]);
        assert_eq!(ids(&[("u", s("alice")), ("d", s("b.com"))]), [3], "all conditions must hold");
        assert_eq!(ids(&[("id", s(" 2 "))]), [2], "a string filter on an int column");
        assert_eq!(ids(&[("u", s("ALICE"))]), Vec::<i64>::new(), "strings compare exactly");
        assert_eq!(ids(&[("x", DbVal::Null)]), [2], "NULL matches NULL");
        assert_eq!(ids(&[("x", DbVal::Double(2.5))]), [1]);
        assert_eq!(ids(&[("x", DbVal::Int(2))]), [3], "2 is not 2.5");
        assert!(db.query("t", &["id"], &[("nope", s("x"))]).is_err(), "unknown filter column");
        assert_eq!(db.query("t", &["d", "u"], &[("id", DbVal::Int(1))]).unwrap().cols, ["d", "u"], "columns in the order asked");
    }

    #[test]
    fn db_text_update_and_delete() {
        let d = TextDir::new("upd", &[("t", "id(int) u(string) n(int,null)\n1:a:1\n2:b:2\n3:a:3\n")]);
        let db = d.db();
        assert_eq!(db.update("t", &[("u", s("a"))], &[("n", DbVal::Int(9)), ("u", s("A"))]).unwrap(), 2);
        assert_eq!(d.file("t"), "id(int) u(string) n(int,null)\n1:A:9\n2:b:2\n3:A:9\n");
        assert_eq!(db.update("t", &[("u", s("zzz"))], &[("n", DbVal::Int(0))]).unwrap(), 0);
        assert_eq!(db.update("t", &[], &[("n", DbVal::Null)]).unwrap(), 3, "no filter: every row");
        assert_eq!(d.file("t"), "id(int) u(string) n(int,null)\n1:A:\n2:b:\n3:A:\n", "NULL is written empty");
        assert!(db.update("t", &[], &[("nope", DbVal::Int(1))]).is_err());
        assert_eq!(db.delete("t", &[("u", s("A"))]).unwrap(), 2);
        assert_eq!(db.delete("t", &[("u", s("A"))]).unwrap(), 0);
        assert_eq!(db.query("t", &["id"], &[]).unwrap().rows, [[DbVal::Int(2)]]);
        assert_eq!(db.delete("t", &[]).unwrap(), 1);
        assert_eq!(d.file("t"), "id(int) u(string) n(int,null)\n");
    }

    #[test]
    fn db_text_errors() {
        let d =
            TextDir::new("errors", &[("short", "a(int) b(int)\n1:2\n3\n"), ("empty", "# only a comment\n\n"), ("badhdr", "a(int) b\n"), ("ok", "a(int)\n")]);
        let db = d.db();
        let err = |t: &str| db.query(t, &[], &[]).unwrap_err();
        assert!(matches!(err("short"), DbError::Stmt(m) if m.contains("row 2 has 1 values, expected 2")));
        assert!(matches!(err("empty"), DbError::Stmt(m) if m.contains("missing header")));
        assert!(matches!(err("badhdr"), DbError::Stmt(m) if m.contains("bad column definition")));
        assert!(err("missing").is_conn(), "a table file that can't be read");
        for bad in ["", "../ok", "a.b", "a/b", "a\\b"] {
            assert!(matches!(err(bad), DbError::Stmt(m) if m.contains("bad table name")), "{bad:?}");
        }
        assert!(db.insert("ok", &["zz"], &[DbVal::Int(1)]).is_err());
        assert_eq!(d.file("ok"), "a(int)\n", "a refused insert leaves the file alone");
    }

    #[test]
    fn connect_urls() {
        let d = TextDir::new("urls", &[("t", "a(int)\n1\n")]);
        for url in [format!("text://{}", d.0.display()), format!("text:{}", d.0.display())] {
            assert_eq!(connect(&url).unwrap().query("t", &[], &[]).unwrap().rows.len(), 1, "{url}");
        }
        assert!(connect("text:///nonexistent/ferrosip-db").err().unwrap().is_conn());
        for bad in ["", "foo://x", "text", "sqlite", "mysql:/x", "redis://h"] {
            assert!(matches!(connect(bad), Err(DbError::Config(_))), "{bad:?}");
        }
        #[cfg(feature = "sqlite")]
        for url in ["sqlite::memory:", "sqlite://:memory:"] {
            assert!(connect(url).unwrap().raw("SELECT 1").is_ok(), "{url}");
        }
        #[cfg(not(feature = "mysql"))]
        assert!(matches!(connect("mysql://u:p@h/db"), Err(DbError::Config(m)) if m.contains("without the mysql")));
        #[cfg(not(feature = "postgres"))]
        assert!(matches!(connect("postgresql://u@h/db"), Err(DbError::Config(m)) if m.contains("without the postgres")));
    }

    #[test]
    fn db_val_conversions_and_loose_equality() {
        let cases: &[(DbVal, Option<&str>, Option<i64>, &str)] = &[
            (DbVal::Null, None, None, ""),
            (DbVal::Int(-4), None, Some(-4), "-4"),
            (DbVal::Double(2.0), None, Some(2), "2"),
            (DbVal::Double(0.25), None, Some(0), "0.25"),
            (s(" 12 "), Some(" 12 "), Some(12), " 12 "),
            (s("x"), Some("x"), None, "x"),
        ];
        for (v, st, int, text) in cases {
            assert_eq!((v.str(), v.int(), v.text().as_str(), v.to_string().as_str()), (*st, *int, *text, *text), "{v:?}");
        }
        let eq: &[(DbVal, DbVal, bool)] = &[
            (DbVal::Null, DbVal::Null, true),
            (DbVal::Null, s(""), false),
            (DbVal::Int(3), s("3"), true),
            (DbVal::Int(3), s("x"), false),
            (DbVal::Int(3), DbVal::Double(3.0), true),
            (DbVal::Int(3), DbVal::Double(3.9), false),
            (DbVal::Double(3.9), DbVal::Int(3), false),
            (DbVal::Double(1.5), s("1.5"), true),
            (s("a"), s("a"), true),
            (s("a"), s("A"), false),
        ];
        for (a, b, want) in eq {
            assert_eq!(a.loose_eq(b), *want, "{a:?} vs {b:?}");
        }
        assert_eq!(DbVal::from("x"), s("x"));
        assert_eq!(DbVal::from(String::from("y")), s("y"));
        assert_eq!(DbVal::from(5i64), DbVal::Int(5));
    }

    #[test]
    fn db_error_kinds() {
        let cases = [
            (DbError::Conn("down".into()), true, "database unreachable: down"),
            (DbError::Stmt("no column".into()), false, "no column"),
            (DbError::Config("bad url".into()), false, "bad url"),
        ];
        for (e, conn, shown) in cases {
            assert_eq!((e.is_conn(), e.to_string().as_str(), String::from(e.clone())), (conn, shown, shown.to_string()));
            assert!(shown.ends_with(e.message()));
        }
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_values_counts_and_errors() {
        let db = connect("sqlite::memory:").unwrap();
        db.raw("CREATE TABLE t (id INTEGER PRIMARY KEY, s TEXT, d REAL, n INTEGER)").unwrap();
        let vals = [DbVal::Int(1), s("o'brien \"q\" ; DROP TABLE t; --"), DbVal::Double(-0.5), DbVal::Null];
        db.insert("t", &["id", "s", "d", "n"], &vals).unwrap();
        db.insert("t", &["id", "s", "n"], &[DbVal::Int(2), s("ünï"), DbVal::Int(i64::MIN)]).unwrap();
        let r = db.query("t", &[], &[]).unwrap();
        assert_eq!(r.cols, ["id", "s", "d", "n"]);
        assert_eq!(r.rows[0], vals, "values are bound, never spliced into the SQL");
        assert_eq!(r.rows[1], [DbVal::Int(2), s("ünï"), DbVal::Null, DbVal::Int(i64::MIN)]);
        assert_eq!(db.update("t", &[("id", DbVal::Int(2))], &[("s", s("x")), ("d", DbVal::Double(1.0))]).unwrap(), 1);
        assert_eq!(db.update("t", &[("id", DbVal::Int(9))], &[("s", s("x"))]).unwrap(), 0);
        assert_eq!(db.query("t", &["d"], &[("s", s("x"))]).unwrap().rows, [[DbVal::Double(1.0)]]);
        assert_eq!(db.delete("t", &[("id", DbVal::Int(1)), ("s", s("nope"))]).unwrap(), 0, "all conditions must hold");
        assert_eq!(db.delete("t", &[]).unwrap(), 2);
        let affected = db.raw("INSERT INTO t (id) VALUES (7); INSERT INTO t (id) VALUES (8)").unwrap();
        assert_eq!(affected.cols, ["affected"]);
        assert_eq!(db.raw("  with x as (select 2 as v) select v from x").unwrap().rows, [[DbVal::Int(2)]]);
        assert_eq!(db.raw("PRAGMA user_version").unwrap().cols, ["user_version"]);
        for e in [
            db.query("nope", &[], &[]).unwrap_err(),
            db.query("t", &["nope"], &[]).unwrap_err(),
            db.insert("t", &["id"], &[DbVal::Int(7)]).unwrap_err(),
            db.query("t", &["s; --"], &[]).unwrap_err(),
            db.update("t", &[("x y", DbVal::Null)], &[("s", s("x"))]).unwrap_err(),
            db.delete("", &[]).unwrap_err(),
            db.raw("SELEC 1").unwrap_err(),
        ] {
            assert!(matches!(e, DbError::Stmt(_)), "{e:?}");
        }
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_file_url() {
        let d = TextDir::new("sqlite-file", &[]);
        let url = format!("sqlite://{}", d.0.join("x.db").display());
        connect(&url).unwrap().raw("CREATE TABLE t (a TEXT)").unwrap();
        connect(&url).unwrap().insert("t", &["a"], &[s("kept")]).unwrap();
        assert_eq!(connect(&url).unwrap().query("t", &[], &[]).unwrap().rows, [[s("kept")]]);
        assert!(connect(&format!("sqlite://{}", d.0.join("no/such/dir/x.db").display())).err().unwrap().is_conn());
    }

    #[test]
    fn null_db_is_empty_and_accepts_writes() {
        let db = NullDb;
        let r = db.query("t", &["a"], &[("a", s("x"))]).unwrap();
        assert!(r.cols.is_empty() && r.rows.is_empty());
        assert_eq!(db.insert("t", &["a"], &[s("x")]), Ok(()));
        assert_eq!(db.update("t", &[], &[("a", s("y"))]), Ok(0));
        assert_eq!(db.delete("t", &[]), Ok(0));
        let r = db.raw("DROP TABLE t").unwrap();
        assert!(r.cols.is_empty() && r.rows.is_empty());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_file_that_is_not_a_database_is_a_connection_error() {
        let d = TextDir::new("sqlite-notdb", &[("x.db", "this is not an SQLite database file, just text long enough to have a header\n")]);
        let db = connect(&format!("sqlite://{}", d.0.join("x.db").display())).unwrap();
        for e in [db.query("t", &[], &[]).unwrap_err(), db.raw("SELECT 1 FROM sqlite_master").unwrap_err()] {
            assert!(e.is_conn(), "{e:?}");
        }
    }
}
