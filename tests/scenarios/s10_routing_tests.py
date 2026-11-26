"""s10-routing-tests: the routing is checked by `ferrosip test` alone. The
module runs it and checks its output and exit codes: the green suite, a
filter, a deliberately failing test and a test file that doesn't compile."""
import os
import re
import subprocess

import sipkit


def ftest(sc, *args):
    env = {**os.environ, "RPC_SOCK": os.path.join(sc.tmp, "test.sock"), "STATE_DIR": sc.tmp}
    r = subprocess.run([sipkit.BIN, "test", "--config", "ferrosip.toml", *args], capture_output=True, text=True, env=env, cwd=sc.dir,
                       timeout=180)
    return r.returncode, r.stdout, r.stderr


def summary(out):
    m = re.search(r"(\d+) passed, (\d+) failed", out)
    return (int(m.group(1)), int(m.group(2))) if m else None


def run(sc):
    # Test files are not part of the routing: fmt them here (the runner only formats routes/).
    r = subprocess.run([sipkit.BIN, "fmt", "--check", os.path.join(sc.dir, "failing")], capture_output=True, text=True, timeout=60)
    sc.check("failing/*.fsr are formatted", r.returncode == 0, r.stdout + r.stderr)

    # The green suite.
    n_tests = len(re.findall(r'(?m)^test "', open(os.path.join(sc.dir, "routes/main_test.fsr")).read()))
    rc, out, err = ftest(sc, "routes/main_test.fsr")
    fails = [l for l in out.splitlines() if l.startswith("FAIL") or l.startswith("      ")]
    sc.check(f"ferrosip test routes/main_test.fsr: all {n_tests} tests pass", summary(out) == (n_tests, 0), "\n".join(fails) or out[-800:])
    sc.check("…and it exits 0", rc == 0, (rc, err[-300:]))

    # --filter: only matching tests run.
    rc, out, _ = ftest(sc, "routes/main_test.fsr", "--filter", "gw1")
    sc.check("--filter gw1 runs exactly the one matching test", rc == 0 and summary(out) == (1, 0) and "a number goes to gw1" in out, out)

    # The routing itself has no tests: test files are passed explicitly.
    rc, out, err = ftest(sc)
    sc.check("ferrosip test without files: the routing has no test blocks → an error, not a silent pass",
             rc != 0 and "no `test" in (out + err), (rc, out + err))

    # A deliberately failing test: reported with file, line, the assert and the value seen.
    rc, out, err = ftest(sc, "failing/expected_failure_test.fsr")
    sc.check("the deliberately failing test fails the run (exit code ≠ 0)", rc != 0, rc)
    sc.check("…summary 0 passed, 1 failed", summary(out) == (0, 1), out)
    sc.check("…FAIL line with the test's name and file:line",
             "FAIL  deliberately wrong: an unregistered user does not get 200  (failing/expected_failure_test.fsr:4)" in out, out)
    sc.check("…the failing assert with what reply_code() was",
             'failing/expected_failure_test.fsr:8: assert(reply_code() == OK) failed: reply_code() is "404"' in out, out)

    # Green and failing together: the failure doesn't hide the passes.
    rc, out, _ = ftest(sc, "routes/main_test.fsr", "failing/expected_failure_test.fsr", "--filter", "unregistered")
    sc.check("both files with --filter unregistered: 1 passed, 1 failed, exit ≠ 0", rc != 0 and summary(out) == (1, 1), out)

    # A test file that doesn't compile (a mock of a misspelt function): refused, nothing runs.
    rc, out, err = ftest(sc, "failing/does_not_compile_test.fsr")
    sc.check("a mock of a misspelt function: refused with its position, no test runs",
             rc != 0 and "does_not_compile_test.fsr:6" in err and summary(out) is None, (rc, out, err))
    sc.check("…with a did-you-mean (location.lookup), like any unknown function", "lookup" in err.replace("lokup", ""), err)
