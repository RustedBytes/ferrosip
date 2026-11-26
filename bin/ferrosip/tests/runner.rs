//! `ferrosip test` on a small routing: passing and failing tests, mocks,
//! `--filter`, and the exit status. Each test runs in its own child
//! process with the real modules and no sockets.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers")]

use std::path::PathBuf;
use std::process::Command;

const ROUTING: &str = r#"import location

route main(msg: Request) {
    guard msg.max_forwards > 0 else reply(TooManyHops)
    if msg.method == OPTIONS {
        reply(OK)
    }
    let found = location.lookup() else return reply(NotFound)
    relay(msg)
}

test "options get 200" {
    send("OPTIONS sip:x@example.com")
    assert(reply_code() == OK)
    assert(relays() == 0)
}

test "a mocked lookup relays" {
    location.lookup = true
    send("INVITE sip:bob@10.0.0.5:5070")
    assert(relays() == 1)
    assert(relay_uri() == "sip:bob@10.0.0.5:5070")
    assert(relay_dest() == "10.0.0.5:5070")
    assert(calls(location.lookup) == 1)
    answer(BusyHere)
    assert(reply_code() == BusyHere)
}

test "hops run out" {
    send("""MESSAGE sip:bob@example.com
Max-Forwards: 0
""")
    assert(reply_code() == TooManyHops)
}

test "deliberately failing" {
    send("INVITE sip:bob@example.com")
    assert(reply_code() == OK)
}
"#;

/// A directory holding ferrosip.toml and main.fsr.
fn fixture(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ferrosip-runner-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("ferrosip.toml"), "[routing]\nentry = \"main.fsr\"\n").unwrap();
    std::fs::write(d.join("main.fsr"), ROUTING).unwrap();
    d
}

/// Exit status and stdout, with the timings (`(12 ms)`) taken out.
fn run(dir: &PathBuf, extra: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ferrosip")).current_dir(dir).args(["test", "--config", "ferrosip.toml"]).args(extra).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let cleaned: Vec<String> = text
        .lines()
        .map(|l| match l.rfind(" (") {
            Some(i) if l.ends_with(" ms)") => l.get(..i).unwrap_or(l).to_string(),
            _ => l.to_string(),
        })
        .collect();
    (out.status.success(), cleaned.join("\n"))
}

#[test]
fn runs_every_test_and_reports_the_failure() {
    let d = fixture("all");
    let (ok, out) = run(&d, &[]);
    assert!(!ok, "a failing test fails the run");
    assert_eq!(
        out,
        "ok    options get 200\nok    a mocked lookup relays\nok    hops run out\nFAIL  deliberately failing  (main.fsr:36)\n      main.fsr:38: assert(reply_code() == OK) failed: reply_code() is \"404\"\n\n3 passed, 1 failed"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn filter_picks_tests_by_name() {
    let d = fixture("filter");
    assert_eq!(run(&d, &["--filter", "hops"]), (true, "ok    hops run out\n\n1 passed, 0 failed".to_string()));
    let (ok, out) = run(&d, &["--filter", "nothing matches this"]);
    assert!(!ok && out.is_empty(), "{out}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_test_file_named_on_the_command_line_is_compiled_with_the_routing() {
    let d = fixture("file");
    std::fs::write(d.join("extra_test.fsr"), "test \"from another file\" {\n    send(\"OPTIONS sip:x@example.com\")\n    assert(reply_code() == OK)\n}\n")
        .unwrap();
    assert_eq!(run(&d, &["extra_test.fsr", "--filter", "another"]), (true, "ok    from another file\n\n1 passed, 0 failed".to_string()));
    let _ = std::fs::remove_dir_all(&d);
}
