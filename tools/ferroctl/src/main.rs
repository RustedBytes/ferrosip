//! ferroctl — command-line client for ferrosip's JSON-RPC control socket
//! (like Kamailio's `kamcmd`).
//!
//!   ferroctl [-s /tmp/ferrosip-rpc.sock] <method> [params…]
//!   ferroctl stats.get_statistics tm:
//!   ferroctl ul.dump
//!   ferroctl system.listMethods
//!   ferroctl fmt [--check] [FILE…]      # format routing scripts (local, no socket)
//!   ferroctl webui-hash [PASSWORD]      # password_hash for the webui module (reads stdin without an argument)
//!
//! Parameters that parse as JSON (numbers, true/false, objects) are sent as
//! such; everything else as a string. Prints the result as pretty JSON and
//! exits non-zero on an RPC error.
#![allow(clippy::unwrap_used, reason = "a command-line tool: a failed unwrap ends it with a message, which is what it should do")]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::exit;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut sock = "/tmp/ferrosip-rpc.sock".to_string();
    if let [flag, path, ..] = args.as_slice()
        && flag == "-s"
    {
        sock = path.clone();
        args.drain(..2);
    }
    let Some((method, rest)) = args.split_first() else {
        eprintln!(
            "usage: ferroctl [-s socket] <method> [params…]   (try: ferroctl system.listMethods)\n       ferroctl fmt [--check] [FILE…]\n       ferroctl webui-hash [PASSWORD]"
        );
        exit(2);
    };
    if method == "fmt" {
        exit(fmt(rest));
    }
    if method == "webui-hash" {
        exit(webui_hash(rest.first()));
    }
    let params: Vec<Value> = rest.iter().map(|a| serde_json::from_str::<Value>(a).ok().filter(|v| !v.is_string()).unwrap_or_else(|| json!(a))).collect();
    let mut s = UnixStream::connect(&sock).unwrap_or_else(|e| {
        eprintln!("ferroctl: connect {sock}: {e}");
        exit(1)
    });
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    if let Err(e) = writeln!(s, "{req}") {
        eprintln!("ferroctl: write to {sock}: {e}");
        exit(1);
    }
    let mut line = String::new();
    if let Err(e) = BufReader::new(&s).read_line(&mut line) {
        eprintln!("ferroctl: read from {sock}: {e}");
        exit(1);
    }
    let resp: Value = serde_json::from_str(&line).unwrap_or_else(|e| {
        eprintln!("ferroctl: bad response ({e}): {line}");
        exit(1)
    });
    if let Some(err) = resp.get("error") {
        eprintln!("error: {}", err.get("message").and_then(Value::as_str).unwrap_or("unknown"));
        exit(1);
    }
    println!("{}", serde_json::to_string_pretty(resp.get("result").unwrap_or(&Value::Null)).unwrap_or_default());
}

/// `ferroctl webui-hash [PASSWORD]`: prints `sha256:<salt>:<hex>` for
/// `modparam("webui", "password_hash", …)`, with a random salt. Without an
/// argument the password is read from stdin (keeps it out of shell history).
fn webui_hash(arg: Option<&String>) -> i32 {
    use ring::rand::SecureRandom;
    let password = match arg {
        Some(p) => p.clone(),
        None => {
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() {
                eprintln!("ferroctl: can't read the password from stdin");
                return 2;
            }
            line.trim_end_matches(['\r', '\n']).to_string()
        }
    };
    if password.is_empty() {
        eprintln!("ferroctl: empty password");
        return 2;
    }
    let mut salt = [0u8; 12];
    if ring::rand::SystemRandom::new().fill(&mut salt).is_err() {
        eprintln!("ferroctl: no random source");
        return 1;
    }
    let salt: String = salt.iter().map(|b| format!("{b:02x}")).collect();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(salt.as_bytes());
    ctx.update(password.as_bytes());
    let hex: String = ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect();
    println!("sha256:{salt}:{hex}");
    0
}

/// `ferroctl fmt [--check] [FILE…]`: format routing scripts in place (stdin →
/// stdout without files). `--check` changes nothing and exits 1 if any file
/// would change. Exit 2 on a file that can't be read or doesn't parse.
fn fmt(args: &[String]) -> i32 {
    let check = args.iter().any(|a| a == "--check");
    let files: Vec<&String> = args.iter().filter(|a| *a != "--check").collect();
    if let Some(bad) = files.iter().find(|f| f.starts_with('-') && f.len() > 1) {
        eprintln!("ferroctl fmt: unknown option {bad}\nusage: ferroctl fmt [--check] [FILE…]");
        return 2;
    }
    if files.is_empty() || files == ["-"] {
        let mut src = String::new();
        if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut src) {
            eprintln!("ferroctl fmt: stdin: {e}");
            return 2;
        }
        return match sip_script::fmt::format(&src) {
            Ok(out) if check => i32::from(out != src),
            Ok(out) => {
                print!("{out}");
                0
            }
            Err(e) => {
                eprintln!("<stdin>: {e}");
                2
            }
        };
    }
    let mut status = 0;
    for f in files {
        let src = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{f}: {e}");
                status = 2;
                continue;
            }
        };
        match sip_script::fmt::format(&src) {
            Err(e) => {
                eprintln!("{f}: {e}");
                status = 2;
            }
            Ok(out) if out == src => {}
            Ok(_) if check => {
                println!("would reformat {f}");
                status = status.max(1);
            }
            Ok(out) => match std::fs::write(f, out) {
                Ok(()) => println!("formatted {f}"),
                Err(e) => {
                    eprintln!("{f}: {e}");
                    status = 2;
                }
            },
        }
    }
    status
}
