#!/usr/bin/env python3
"""Run the e2e suites (tests/e2e_*.py) one after another and sum them up.

    python3 tests/run_e2e.py                 # every suite
    python3 tests/run_e2e.py tm fork dns     # suites whose name contains a word
    python3 tests/run_e2e.py -x scenarios    # all but those
    python3 tests/run_e2e.py --list

Each suite's output goes to target/e2e-logs/<suite>.log (printed in full
for a suite that fails, or with -v for all). A suite fails when it exits
non-zero, prints a FAIL line, or runs past --timeout. The suites share
fixed ports, so they never run in parallel.

Exit status: 0 when every suite passed, 1 when one failed, 2 on a setup
error (no release build). Under GitHub Actions each suite's output is a
collapsible group and failures are annotated.
"""
import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")
GITHUB = os.environ.get("GITHUB_ACTIONS") == "true"


def suites():
    return sorted(f[:-3] for f in os.listdir(TESTS) if f.startswith("e2e_") and f.endswith(".py"))


def pick(names, include, exclude):
    out = [n for n in names if not include or any(w in n for w in include)]
    return [n for n in out if not any(w in n for w in exclude)]


def run(name, timeout, log_dir):
    log = os.path.join(log_dir, f"{name}.log")
    started = time.monotonic()
    with open(log, "w") as out:
        try:
            rc = subprocess.run([sys.executable, os.path.join(TESTS, f"{name}.py")], cwd=ROOT, stdout=out, stderr=subprocess.STDOUT, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            rc = None
    took = time.monotonic() - started
    with open(log, errors="replace") as f:
        text = f.read()
    fails = [line for line in text.splitlines() if line.startswith("FAIL")]
    skips = [line for line in text.splitlines() if line.startswith("SKIP")]
    if rc is None:
        status = f"TIMEOUT after {timeout}s"
    elif rc != 0 or fails:
        status = f"FAILED (exit {rc}, {len(fails)} FAIL)"
    else:
        status = "ok" + (f" ({len(skips)} skipped)" if skips else "")
    return status, took, text, fails


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n", 1)[1])
    ap.add_argument("words", nargs="*", help="run only suites whose name contains one of these")
    ap.add_argument("-x", "--exclude", action="append", default=[], metavar="WORD", help="skip suites whose name contains WORD (repeatable)")
    ap.add_argument("--timeout", type=int, default=600, help="seconds per suite (default 600)")
    ap.add_argument("--list", action="store_true", help="list the suites that would run")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every suite's output, not only failing ones")
    args = ap.parse_args()

    chosen = pick(suites(), args.words, args.exclude)
    if args.list:
        print("\n".join(chosen))
        return 0
    if not chosen:
        print(f"run_e2e: no suite matches {args.words}", file=sys.stderr)
        return 2
    for b in ("ferrosip", "ferroctl", "sipflood"):
        if not os.access(os.path.join(ROOT, "target/release", b), os.X_OK):
            print(f"run_e2e: target/release/{b} not found: cargo build --release --workspace first", file=sys.stderr)
            return 2

    log_dir = os.path.join(ROOT, "target/e2e-logs")
    os.makedirs(log_dir, exist_ok=True)
    results, total = [], time.monotonic()
    for i, name in enumerate(chosen, 1):
        print(f"[{i}/{len(chosen)}] {name} …", flush=True)
        status, took, text, fails = run(name, args.timeout, log_dir)
        results.append((name, status, took))
        failed = status != "ok" and not status.startswith("ok ")
        if failed or args.verbose:
            if GITHUB:
                print(f"::group::{name} output")
            print(text.rstrip())
            if GITHUB:
                print("::endgroup::")
        if failed and GITHUB:
            first = fails[0] if fails else status
            print(f"::error title={name}::{first}")
        print(f"[{i}/{len(chosen)}] {name}: {status} in {took:.1f}s", flush=True)

    width = max(len(n) for n, _, _ in results)
    bad = [n for n, s, _ in results if not s.startswith("ok")]
    print(f"\n{'suite'.ljust(width)}  {'time':>7}  result")
    for name, status, took in results:
        print(f"{name.ljust(width)}  {took:6.1f}s  {status}")
    print(f"\n{len(results) - len(bad)}/{len(results)} suites passed in {time.monotonic() - total:.0f}s; logs in {os.path.relpath(log_dir, ROOT)}/")
    if bad:
        print("failed: " + " ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
