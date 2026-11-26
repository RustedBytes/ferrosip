//! `ndb_redis` — Redis client (RESP over TCP, no external library):
//! `modparam("ndb_redis", "server", "name=srv1;addr=127.0.0.1;port=6379;db=0;pass=x")`,
//! `redis_cmd(srv, "SET key %s", "$var(v)", res)` — the command is split on
//! spaces, `%s`/`%d` take the following arguments as whole tokens —
//! and `$redis(res=>type|value|info|size|value[n])` (types as hiredis:
//! 1 string, 2 array, 3 integer, 4 nil, 5 status, 6 error),
//! `redis_free(res)`. One connection per server, reconnected (AUTH,
//! SELECT) on failure.

use crate::kv_list;
use sip_core::module::DynStr;
use sip_core::pv::{PvSpec, Val};
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Registry};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub enum Reply {
    Str(Vec<u8>),
    Array(Vec<Reply>),
    Int(i64),
    Nil,
    Status(String),
    Error(String),
}

impl Reply {
    fn kind(&self) -> i64 {
        match self {
            Reply::Str(_) => 1,
            Reply::Array(_) => 2,
            Reply::Int(_) => 3,
            Reply::Nil => 4,
            Reply::Status(_) => 5,
            Reply::Error(_) => 6,
        }
    }
    fn value(&self) -> Val {
        match self {
            Reply::Str(s) => Val::str(s),
            Reply::Int(i) => Val::Int(*i),
            Reply::Status(s) | Reply::Error(s) => Val::str(s),
            Reply::Nil | Reply::Array(_) => Val::Null,
        }
    }
}

pub fn encode(args: &[Vec<u8>]) -> Vec<u8> {
    let mut o = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        o.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        o.extend_from_slice(a);
        o.extend_from_slice(b"\r\n");
    }
    o
}

/// Largest bulk string or array length accepted (Redis's own default
/// `proto-max-bulk-len`, 512 MB). A bigger one is a broken reply, not an
/// allocation to attempt.
const MAX_RESP_LEN: usize = 512 * 1024 * 1024;

/// Nesting deeper than this is refused: each level is a stack frame, and a
/// hostile or broken server could otherwise send `*1\r\n` forever and
/// overflow the stack. Real replies (SCAN, XREAD, …) nest a few levels.
const MAX_RESP_DEPTH: usize = 32;

pub fn read_reply(r: &mut impl BufRead) -> std::io::Result<Reply> {
    read_nested(r, 0)
}

fn read_nested(r: &mut impl BufRead, depth: usize) -> std::io::Result<Reply> {
    if depth > MAX_RESP_DEPTH {
        return Err(std::io::Error::other("RESP nested too deep"));
    }
    let mut line = Vec::new();
    r.read_until(b'\n', &mut line)?;
    if line.len() < 3 {
        return Err(std::io::Error::other("connection closed"));
    }
    let bad = || std::io::Error::other("bad RESP");
    // A type byte, the body, CRLF.
    let (&kind, rest) = line.split_first().ok_or_else(bad)?;
    let body = String::from_utf8_lossy(rest.strip_suffix(b"\r\n").ok_or_else(bad)?).into_owned();
    let len = |n: i64| usize::try_from(n).ok().filter(|&n| n <= MAX_RESP_LEN).ok_or_else(bad);
    Ok(match kind {
        b'+' => Reply::Status(body),
        b'-' => Reply::Error(body),
        b':' => Reply::Int(body.parse().map_err(|_| bad())?),
        b'$' => {
            let n: i64 = body.parse().map_err(|_| bad())?;
            if n < 0 {
                Reply::Nil
            } else {
                let mut b = vec![0u8; len(n)?];
                r.read_exact(&mut b)?;
                let mut crlf = [0u8; 2];
                r.read_exact(&mut crlf)?;
                // Anything else means the length was wrong: the stream is
                // out of step, and every later reply would be misread.
                if &crlf != b"\r\n" {
                    return Err(bad());
                }
                Reply::Str(b)
            }
        }
        b'*' => {
            let n: i64 = body.parse().map_err(|_| bad())?;
            if n < 0 {
                Reply::Nil
            } else {
                let n = len(n)?;
                // Grown as elements arrive: the count alone reserves little.
                let mut v = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    // depth <= MAX_RESP_DEPTH (checked on entry).
                    v.push(read_nested(r, depth.saturating_add(1))?);
                }
                Reply::Array(v)
            }
        }
        _ => return Err(bad()),
    })
}

/// Timeouts shared by every server (Kamailio's ndb_redis parameters).
struct Limits {
    connect_ms: AtomicU64,
    cmd_ms: AtomicU64,
    /// Consecutive timeouts allowed before the server is skipped for
    /// `disable_secs` (-1: never skipped).
    allowed_timeouts: AtomicI64,
    disable_secs: AtomicU64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { connect_ms: AtomicU64::new(1000), cmd_ms: AtomicU64::new(1000), allowed_timeouts: AtomicI64::new(-1), disable_secs: AtomicU64::new(0) }
    }
}

struct Server {
    addr: String,
    db: Option<String>,
    pass: Option<String>,
    conn: Mutex<Option<BufReader<TcpStream>>>,
    limits: Arc<Limits>,
    /// Consecutive timeouts, and until when (unix s) the server is skipped.
    timeouts: AtomicU32,
    down_until: AtomicU64,
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
}

impl Server {
    fn connect(&self) -> std::io::Result<BufReader<TcpStream>> {
        use std::net::ToSocketAddrs;
        let ms = |a: &AtomicU64| Duration::from_millis(a.load(Ordering::Relaxed).max(1));
        let mut last = std::io::Error::other("no address");
        let mut conn = None;
        for a in self.addr.to_socket_addrs()? {
            match TcpStream::connect_timeout(&a, ms(&self.limits.connect_ms)) {
                Ok(s) => {
                    conn = Some(s);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let s = conn.ok_or(last)?;
        s.set_read_timeout(Some(ms(&self.limits.cmd_ms)))?;
        s.set_write_timeout(Some(ms(&self.limits.cmd_ms)))?;
        let _ = s.set_nodelay(true);
        let mut r = BufReader::new(s);
        let mut cmd = |args: Vec<Vec<u8>>| -> std::io::Result<Reply> {
            r.get_mut().write_all(&encode(&args))?;
            read_reply(&mut r)
        };
        if let Some(p) = &self.pass
            && let Reply::Error(e) = cmd(vec![b"AUTH".to_vec(), p.clone().into_bytes()])?
        {
            return Err(std::io::Error::other(e));
        }
        if let Some(d) = &self.db
            && let Reply::Error(e) = cmd(vec![b"SELECT".to_vec(), d.clone().into_bytes()])?
        {
            return Err(std::io::Error::other(e));
        }
        Ok(r)
    }

    fn command(&self, args: Vec<Vec<u8>>) -> std::io::Result<Reply> {
        if self.down_until.load(Ordering::Relaxed) > unix_secs() {
            return Err(std::io::Error::other("server disabled after timeouts (disable_time)"));
        }
        let res = self.command_once(args);
        match &res {
            Ok(_) => self.timeouts.store(0, Ordering::Relaxed),
            Err(e) if is_timeout(e) => {
                let n = self.timeouts.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                let allowed = self.limits.allowed_timeouts.load(Ordering::Relaxed);
                if allowed >= 0 && i64::from(n) > allowed {
                    self.down_until.store(unix_secs().saturating_add(self.limits.disable_secs.load(Ordering::Relaxed)), Ordering::Relaxed);
                    self.timeouts.store(0, Ordering::Relaxed);
                }
            }
            // Timeouts are handled above (allowed_timeouts/disable_time).
            Err(_) => sip_core::stats::inc(sip_core::stats::counter("redis", "errors")),
        }
        res
    }

    fn command_once(&self, args: Vec<Vec<u8>>) -> std::io::Result<Reply> {
        let mut g = lock(&self.conn);
        for attempt in 0..2 {
            let c = match &mut *g {
                Some(c) => c,
                slot @ None => slot.insert(self.connect()?),
            };
            let res = c.get_mut().write_all(&encode(&args)).and_then(|_| read_reply(c));
            match res {
                Ok(r) => return Ok(r),
                // A dropped connection: reconnect and try once more. A
                // timeout is not retried (that would double the wait).
                Err(e) if attempt == 0 && !is_timeout(&e) => *g = None,
                Err(e) => {
                    *g = None;
                    return Err(e);
                }
            }
        }
        Err(std::io::Error::other("unreachable"))
    }
}

/// Results of `redis_cmd()` for this message.
#[derive(Default)]
struct Results(HashMap<String, Reply>);

#[derive(Default)]
pub struct NdbRedis {
    specs: Mutex<Vec<String>>,
    limits: Arc<Limits>,
    servers: OnceLock<HashMap<String, Arc<Server>>>,
}

/// Split the command on spaces; `%s`/`%d` placeholders take whole arguments.
fn tokens(fmt: &str, args: &[String]) -> Vec<Vec<u8>> {
    let mut it = args.iter();
    fmt.split_whitespace()
        .map(|t| {
            if t.contains('%') {
                let mut out = String::new();
                let mut chars = t.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '%' && matches!(chars.peek(), Some('s') | Some('d') | Some('b')) {
                        chars.next();
                        out.push_str(it.next().map(String::as_str).unwrap_or(""));
                    } else {
                        out.push(c);
                    }
                }
                out.into_bytes()
            } else {
                t.as_bytes().to_vec()
            }
        })
        .collect()
}

impl Module for NdbRedis {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("server", Ty::List(&Ty::Str), "", "Redis servers, each \"name=srv1;addr=127.0.0.1;port=6379;db=0;pass=x\""),
            p("connect_timeout", Ty::Duration(Unit::Ms), "1s", "Timeout of a connection attempt"),
            p("cmd_timeout", Ty::Duration(Unit::Ms), "1s", "Timeout of a command (reading its reply)"),
            p("allowed_timeouts", Ty::Int { min: -1, max: i64::MAX }, "-1", "Consecutive timeouts before a server is skipped for disable_time (-1: never)"),
            p("disable_time", Ty::Duration(Unit::Sec), "0s", "How long a server is skipped after allowed_timeouts"),
        ])
    }

    fn name(&self) -> &'static str {
        "ndb_redis"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "server" => lock(&self.specs).push(v.str()?.into()),
            "connect_timeout" => self.limits.connect_ms.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "cmd_timeout" => self.limits.cmd_ms.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "allowed_timeouts" => self.limits.allowed_timeouts.store(v.int()?, Ordering::Relaxed),
            "disable_time" => self.limits.disable_secs.store(u64::try_from(v.int()?).unwrap_or(0), Ordering::Relaxed),
            "init_without_redis" | "cluster" | "flush_on_reconnect" | "allow_dynamic_nodes" | "debug" | "ca_path" => {}
            _ => return Err(format!("ndb_redis: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const EXEC: &[Param] = &[arg("server", Str).lit(), arg("command", Str), arg("result", Str).lit()];
        const EXEC1: &[Param] = &[arg("server", Str).lit(), arg("command", Str), arg("arg", Str), arg("result", Str).lit()];
        const EXEC2: &[Param] = &[arg("server", Str).lit(), arg("command", Str), arg("arg1", Str), arg("arg2", Str), arg("result", Str).lit()];
        const RESULT: &[Param] = &[arg("result", Str).lit()];
        Some(vec![
            sig("redis_cmd", "exec", EXEC, Ret::Bool, "Run a Redis command (split on spaces) on `server`; the reply is kept as `result` for $redis")
                .allowed(ctx::ANY),
            sig("redis_cmd", "exec_with", EXEC1, Ret::Bool, "Run a Redis command whose %s / %d takes `arg` as one whole token").allowed(ctx::ANY),
            sig("redis_cmd", "exec_with2", EXEC2, Ret::Bool, "Run a Redis command whose two %s / %d take `arg1` and `arg2` as whole tokens").allowed(ctx::ANY),
            sig("redis_free", "free", RESULT, Ret::Void, "Drop the reply kept as `result`").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let mut servers = HashMap::new();
        for s in lock(&self.specs).iter() {
            let kv = kv_list(s);
            let get = |k: &str| kv.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
            let name = get("name").ok_or_else(|| format!("ndb_redis server {s:?}: name= is required"))?;
            let addr = format!("{}:{}", get("addr").unwrap_or_else(|| "127.0.0.1".into()), get("port").unwrap_or_else(|| "6379".into()));
            servers.insert(
                name,
                Arc::new(Server {
                    addr,
                    db: get("db"),
                    pass: get("pass"),
                    conn: Mutex::new(None),
                    limits: self.limits.clone(),
                    timeouts: AtomicU32::new(0),
                    down_until: AtomicU64::new(0),
                }),
            );
        }
        let _ = self.servers.set(servers);
        let me = self.clone();
        reg.export(
            "ndb_redis",
            "redis_cmd",
            |a: &[Arg]| -> Result<(String, DynStr, Vec<DynStr>, String), String> {
                let [srv, cmd, args @ .., res] = a else { return Err("expected srv, command[, args…], result".into()) };
                let res = res.str()?.to_string();
                Ok((srv.str()?.to_string(), cmd.dyn_str()?, args.iter().map(Arg::dyn_str).collect::<Result<_, _>>()?, res))
            },
            move |ctx: &mut Ctx, (srv, cmd, args, res): &(String, DynStr, Vec<DynStr>, String)| {
                let Some(server) = me.servers.get().and_then(|s| s.get(srv)).cloned() else { return -1 };
                let cmd = cmd.eval(ctx).into_owned();
                let args: Vec<String> = args.iter().map(|a| a.eval(ctx).into_owned()).collect();
                match server.command(tokens(&cmd, &args)) {
                    Ok(r) => {
                        let ok = !matches!(r, Reply::Error(_));
                        ctx.ext_mut::<Results>().0.insert(res.clone(), r);
                        if ok { 1 } else { -1 }
                    }
                    Err(e) => {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("ndb_redis: {srv}: {e}"));
                        -1
                    }
                }
            },
        );
        reg.export(
            "ndb_redis",
            "redis_free",
            |a: &[Arg]| {
                let [res] = crate::fixed_args(a)?;
                Ok(res.str()?.to_string())
            },
            |ctx: &mut Ctx, r: &String| {
                if let Some(x) = ctx.ext_get_mut::<Results>() {
                    x.0.remove(r);
                }
                1
            },
        );
        reg.pv(
            "redis",
            PvSpec::ro(|ctx, p| {
                let Some((res, key)) = p.name.split_once("=>") else { return Val::Null };
                let Some(r) = ctx.ext::<Results>().and_then(|x| x.0.get(res.trim())) else { return Val::Null };
                let key = key.trim();
                match key {
                    "type" => Val::Int(r.kind()),
                    "value" => r.value(),
                    "info" => match r {
                        Reply::Error(e) | Reply::Status(e) => Val::str(e),
                        _ => Val::Null,
                    },
                    "size" => Val::Int(if let Reply::Array(a) = r { i64::try_from(a.len()).unwrap_or(i64::MAX) } else { 0 }),
                    _ => match key.strip_prefix("value[").and_then(|x| x.strip_suffix(']')).and_then(|i| i.trim().parse::<usize>().ok()) {
                        Some(i) => match r {
                            Reply::Array(a) => a.get(i).map_or(Val::Null, Reply::value),
                            _ => Val::Null,
                        },
                        None => Val::Null,
                    },
                }
            })
            .with_param(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resp() {
        assert_eq!(encode(&[b"GET".to_vec(), b"k".to_vec()]), b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n");
        let mut r = std::io::Cursor::new(b"*3\r\n$3\r\nabc\r\n:5\r\n$-1\r\n+OK\r\n-ERR x\r\n".to_vec());
        assert_eq!(read_reply(&mut r).unwrap(), Reply::Array(vec![Reply::Str(b"abc".to_vec()), Reply::Int(5), Reply::Nil]));
        // A bulk string must be followed by CRLF: a wrong length is an error,
        // not a desynchronised stream.
        assert!(read_reply(&mut std::io::Cursor::new(b"$3\r\nabcXY".to_vec())).is_err());
        assert!(read_reply(&mut std::io::Cursor::new(b"$2\r\nabc\r\n".to_vec())).is_err());
        assert_eq!(read_reply(&mut std::io::Cursor::new(b"$0\r\n\r\n".to_vec())).unwrap(), Reply::Str(vec![]));
        assert_eq!(read_reply(&mut r).unwrap(), Reply::Status("OK".into()));
        assert_eq!(read_reply(&mut r).unwrap(), Reply::Error("ERR x".into()));
        // Lengths beyond any real reply are errors, not huge allocations.
        assert!(read_reply(&mut std::io::Cursor::new(b"$9223372036854775807\r\n".to_vec())).is_err());
        assert!(read_reply(&mut std::io::Cursor::new(b"$536870913\r\n".to_vec())).is_err());
        assert!(read_reply(&mut std::io::Cursor::new(b"*9223372036854775807\r\n".to_vec())).is_err());
        assert_eq!(read_reply(&mut std::io::Cursor::new(b"$-1\r\n".to_vec())).unwrap(), Reply::Nil);
        assert_eq!(read_reply(&mut std::io::Cursor::new(b"$0\r\n\r\n".to_vec())).unwrap(), Reply::Str(vec![]));
        assert!(read_reply(&mut std::io::Cursor::new(b"$3\r\nab".to_vec())).is_err(), "truncated bulk");
        assert!(read_reply(&mut std::io::Cursor::new(b"+OK".to_vec())).is_err(), "status line cut off");
        // Nesting is bounded: no stack overflow from an endless `*1`.
        let nested = |d: usize| [b"*1\r\n".repeat(d), b":1\r\n".to_vec()].concat();
        assert!(read_reply(&mut std::io::Cursor::new(nested(MAX_RESP_DEPTH))).is_ok());
        assert!(read_reply(&mut std::io::Cursor::new(nested(MAX_RESP_DEPTH + 1))).is_err());
        assert!(read_reply(&mut std::io::Cursor::new(b"*1\r\n".repeat(1_000_000))).is_err());
        assert_eq!(tokens("SET user:%s %s", &["a b".into(), "v".into()]), vec![b"SET".to_vec(), b"user:a b".to_vec(), b"v".to_vec()]);
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;
    use std::io::Cursor;

    fn read(bytes: &[u8]) -> std::io::Result<Reply> {
        read_reply(&mut Cursor::new(bytes.to_vec()))
    }

    #[test]
    fn encode_writes_an_array_of_bulk_strings() {
        let cases: &[(&[&[u8]], &[u8])] = &[
            (&[], b"*0\r\n"),
            (&[b"PING"], b"*1\r\n$4\r\nPING\r\n"),
            (&[b"SET", b"k", b""], b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$0\r\n\r\n"),
            (&[b"SET", b"a b", b"\r\n\x00"], b"*3\r\n$3\r\nSET\r\n$3\r\na b\r\n$3\r\n\r\n\x00\r\n"),
        ];
        for &(args, want) in cases {
            let args: Vec<Vec<u8>> = args.iter().map(|a| a.to_vec()).collect();
            assert_eq!(encode(&args), want, "{args:?}");
        }
        let long = vec![b'x'; 1000];
        assert!(encode(&[long]).starts_with(b"*1\r\n$1000\r\n"));
    }

    #[test]
    fn read_reply_decodes_each_resp_type() {
        let cases: &[(&[u8], Reply)] = &[
            (b"+OK\r\n", Reply::Status("OK".into())),
            (b"+\r\n", Reply::Status(String::new())),
            (b"-WRONGTYPE Operation\r\n", Reply::Error("WRONGTYPE Operation".into())),
            (b":0\r\n", Reply::Int(0)),
            (b":-42\r\n", Reply::Int(-42)),
            (b":9223372036854775807\r\n", Reply::Int(i64::MAX)),
            (b"$5\r\nhello\r\n", Reply::Str(b"hello".to_vec())),
            (b"$4\r\na\r\nb\r\n", Reply::Str(b"a\r\nb".to_vec())),
            (b"$-1\r\n", Reply::Nil),
            (b"*-1\r\n", Reply::Nil),
            (b"*0\r\n", Reply::Array(vec![])),
            (b"*2\r\n*1\r\n:1\r\n$-1\r\n", Reply::Array(vec![Reply::Array(vec![Reply::Int(1)]), Reply::Nil])),
            (b"*2\r\n+a\r\n-b\r\n", Reply::Array(vec![Reply::Status("a".into()), Reply::Error("b".into())])),
        ];
        for (bytes, want) in cases {
            assert_eq!(&read(bytes).unwrap(), want, "{:?}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn read_reply_rejects_malformed_input() {
        let cases: &[&[u8]] = &[
            b"",
            b"\r\n",
            b"?x\r\n",
            b"+OK\n",
            b":abc\r\n",
            b":1.5\r\n",
            b":99999999999999999999\r\n",
            b"$x\r\n",
            b"$5\r\nabc",
            b"*x\r\n",
            b"*2\r\n:1\r\n",
            b"$536870913\r\n",
        ];
        for bytes in cases {
            assert!(read(bytes).is_err(), "{:?}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn read_reply_consumes_exactly_one_reply() {
        let mut c = Cursor::new(b"$3\r\nabc\r\n:7\r\n*1\r\n+x\r\n".to_vec());
        assert_eq!(read_reply(&mut c).unwrap(), Reply::Str(b"abc".to_vec()));
        assert_eq!(read_reply(&mut c).unwrap(), Reply::Int(7));
        assert_eq!(read_reply(&mut c).unwrap(), Reply::Array(vec![Reply::Status("x".into())]));
        assert!(read_reply(&mut c).is_err(), "nothing left: connection closed");
    }

    #[test]
    fn an_encoded_command_reads_back_as_an_array_of_strings() {
        let args = vec![b"HSET".to_vec(), b"h".to_vec(), b"f i\r\neld".to_vec(), Vec::new(), vec![0xff, 0]];
        let back = read(&encode(&args)).unwrap();
        assert_eq!(back, Reply::Array(args.into_iter().map(Reply::Str).collect()));
    }

    #[test]
    fn reply_kind_and_value_follow_hiredis_types() {
        let cases = [
            (Reply::Str(b"s".to_vec()), 1, Val::str("s")),
            (Reply::Array(vec![Reply::Int(1)]), 2, Val::Null),
            (Reply::Int(-3), 3, Val::Int(-3)),
            (Reply::Nil, 4, Val::Null),
            (Reply::Status("OK".into()), 5, Val::str("OK")),
            (Reply::Error("ERR".into()), 6, Val::str("ERR")),
        ];
        for (r, kind, value) in cases {
            assert_eq!((r.kind(), r.value()), (kind, value), "{r:?}");
        }
    }

    #[test]
    fn tokens_split_on_whitespace_and_fill_placeholders_whole() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let b = |v: &[&str]| v.iter().map(|x| x.as_bytes().to_vec()).collect::<Vec<_>>();
        // (command, arguments, tokens)
        type Case<'a> = (&'a str, Vec<String>, Vec<Vec<u8>>);
        let cases: &[Case] = &[
            ("GET k", s(&[]), b(&["GET", "k"])),
            ("  GET   k  ", s(&[]), b(&["GET", "k"])),
            ("SET %s %s", s(&["k", "a value"]), b(&["SET", "k", "a value"])),
            ("INCRBY c %d", s(&["5"]), b(&["INCRBY", "c", "5"])),
            ("SET %b x", s(&["bin"]), b(&["SET", "bin", "x"])),
            ("HSET u:%s:%s f", s(&["a", "b"]), b(&["HSET", "u:a:b", "f"])),
            ("SET %s %s", s(&["only"]), b(&["SET", "only", ""])),
            ("SET k 100%", s(&["unused"]), b(&["SET", "k", "100%"])),
            ("SET k %x", s(&["unused"]), b(&["SET", "k", "%x"])),
            ("", s(&["a"]), b(&[])),
        ];
        for (fmt, args, want) in cases {
            assert_eq!(&tokens(fmt, args), want, "{fmt:?}");
        }
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::testutil::{FakeNet, call, fixup, invite, pv, registry, with_ctx};
    use std::net::TcpListener;

    /// A loopback Redis that answers the commands of one connection with
    /// `replies`, in order, then keeps the connection open without answering
    /// until the client closes it. Returns its port and the commands it got.
    fn server(replies: Vec<&'static [u8]>) -> (u16, std::sync::mpsc::Receiver<Reply>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((s, _)) = l.accept() else { return };
            let mut w = s.try_clone().unwrap();
            let mut r = BufReader::new(s);
            let mut replies = replies.into_iter();
            while let Ok(cmd) = read_reply(&mut r) {
                let _ = tx.send(cmd);
                match replies.next() {
                    Some(rep) => w.write_all(rep).unwrap(),
                    None => continue,
                }
            }
        });
        (port, rx)
    }

    fn redis(spec: &str, cmd_ms: i64, allowed_timeouts: i64) -> Registry {
        let m = NdbRedis::default();
        m.set_param("server", &Arg::Str(spec.into())).unwrap();
        m.set_param("cmd_timeout", &Arg::Int(cmd_ms)).unwrap();
        m.set_param("allowed_timeouts", &Arg::Int(allowed_timeouts)).unwrap();
        m.set_param("disable_time", &Arg::Int(3600)).unwrap();
        registry(vec![Arc::new(m)])
    }

    fn strs(r: &Reply) -> Vec<String> {
        match r {
            Reply::Array(a) => a.iter().map(|x| x.value().as_str().into_owned()).collect(),
            _ => vec![],
        }
    }

    #[test]
    fn ndb_redis_parameters() {
        let m = NdbRedis::default();
        for ok in ["init_without_redis", "cluster", "debug"] {
            assert!(m.set_param(ok, &Arg::Int(1)).is_ok(), "{ok}");
        }
        assert!(m.set_param("nope", &Arg::Int(1)).is_err());
        m.set_param("connect_timeout", &Arg::Int(-5)).unwrap();
        assert_eq!(m.limits.connect_ms.load(Ordering::Relaxed), 1, "at least 1 ms");
        m.set_param("server", &Arg::Str("addr=127.0.0.1".into())).unwrap();
        let err = Arc::new(m).register(&mut Registry::default()).err().unwrap();
        assert!(err.contains("name= is required"), "{err}");
    }

    #[test]
    fn auth_and_select_run_on_connect_and_replies_are_kept() {
        let (port, cmds) = server(vec![b"+OK\r\n", b"+OK\r\n", b"*3\r\n$1\r\na\r\n:2\r\n$-1\r\n", b"+PONG\r\n", b"-ERR wrong\r\n"]);
        let reg = redis(&format!("name=s;addr=127.0.0.1;port={port};db=2;pass=pw"), 5000, -1);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "redis_cmd", &["s", "LRANGE %s 0 -1", "my list", "r"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "redis_cmd", &["s", "PING", "p"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "redis_cmd", &["s", "BAD", "e"]).unwrap(), -1, "an error reply");
            assert_eq!(call(&reg, ctx, "redis_cmd", &["none", "PING", "x"]).unwrap(), -1, "unknown server");
            let cases: &[(&str, Val)] = &[
                ("$redis(r=>type)", Val::Int(2)),
                ("$redis(r=>size)", Val::Int(3)),
                ("$redis(r=>value)", Val::Null),
                ("$redis(r=>info)", Val::Null),
                ("$redis(r=>value[0])", Val::str("a")),
                ("$redis(r=>value[ 1 ])", Val::Int(2)),
                ("$redis(r=>value[2])", Val::Null),
                ("$redis(r=>value[3])", Val::Null),
                ("$redis(r=>value[x])", Val::Null),
                ("$redis(r=>other)", Val::Null),
                ("$redis(p=>type)", Val::Int(5)),
                ("$redis(p=>info)", Val::str("PONG")),
                ("$redis(p=>size)", Val::Int(0)),
                ("$redis(p=>value[0])", Val::Null),
                ("$redis(e=>type)", Val::Int(6)),
                ("$redis(e=>info)", Val::str("ERR wrong")),
                ("$redis(x=>type)", Val::Null),
                ("$redis(r)", Val::Null),
            ];
            for (spec, want) in cases {
                assert_eq!(&pv(&reg, ctx, spec), want, "{spec}");
            }
            assert_eq!(call(&reg, ctx, "redis_free", &["r"]).unwrap(), 1);
            assert_eq!(pv(&reg, ctx, "$redis(r=>type)"), Val::Null, "freed");
            assert_eq!(pv(&reg, ctx, "$redis(p=>type)"), Val::Int(5));
        });
        with_ctx(&invite(""), &FakeNet(None), |ctx| assert_eq!(call(&reg, ctx, "redis_free", &["r"]).unwrap(), 1, "nothing to free"));
        let got: Vec<Vec<String>> = cmds.try_iter().map(|c| strs(&c)).collect();
        assert_eq!(got, [vec!["AUTH", "pw"], vec!["SELECT", "2"], vec!["LRANGE", "my list", "0", "-1"], vec!["PING"], vec!["BAD"]]);
        let s = |x: &str| Arg::Str(x.into());
        assert!(fixup(&reg, "redis_cmd", &[s("s"), s("PING"), s("r")]).is_ok());
        assert!(fixup(&reg, "redis_cmd", &[s("s"), s("PING")]).is_err(), "the result name is required");
    }

    #[test]
    fn a_refused_auth_or_select_fails_the_command() {
        for (spec, reply) in [("pass=bad", &b"-WRONGPASS invalid\r\n"[..]), ("db=99", &b"-ERR DB index is out of range\r\n"[..])] {
            let (port, _cmds) = server(vec![reply]);
            let reg = redis(&format!("name=s;port={port};{spec}"), 5000, -1);
            with_ctx(&invite(""), &FakeNet(None), |ctx| assert_eq!(call(&reg, ctx, "redis_cmd", &["s", "PING", "r"]).unwrap(), -1, "{spec}"));
        }
    }

    #[test]
    fn a_server_is_skipped_after_too_many_timeouts() {
        // Connects, but never answers: the 1 ms command timeout expires.
        let (port, cmds) = server(vec![]);
        let m = Arc::new(NdbRedis::default());
        m.set_param("server", &Arg::Str(format!("name=s;port={port}"))).unwrap();
        m.set_param("cmd_timeout", &Arg::Int(1)).unwrap();
        m.set_param("allowed_timeouts", &Arg::Int(0)).unwrap();
        m.set_param("disable_time", &Arg::Int(3600)).unwrap();
        let reg = registry(vec![m.clone()]);
        let srv = m.servers.get().unwrap()["s"].clone();
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "redis_cmd", &["s", "PING", "r"]).unwrap(), -1, "timed out");
            assert!(srv.down_until.load(Ordering::Relaxed) >= unix_secs().saturating_add(3500), "disabled for disable_time");
            assert_eq!(srv.timeouts.load(Ordering::Relaxed), 0, "the count starts over");
            assert!(lock(&srv.conn).is_none(), "the connection is dropped");
            assert_eq!(call(&reg, ctx, "redis_cmd", &["s", "PING", "r"]).unwrap(), -1, "disabled: not even sent");
            assert!(lock(&srv.conn).is_none(), "no new connection");
        });
        assert_eq!(cmds.recv_timeout(Duration::from_secs(5)).map(|c| strs(&c)).ok(), Some(vec!["PING".to_string()]));
    }
}
