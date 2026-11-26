#!/usr/bin/env python3
"""The scenario suite: every configuration in examples/scenarios/, small to
large, run end to end.

Each scenario is a directory with a ferrosip.toml and .fsr routing (one
directory per proxy for multi-proxy topologies) and a test module
tests/scenarios/<name>.py with `run(sc)`. For every scenario the runner:
1. checks each configuration: `ferrosip check`, `ferrosip lint -D warnings`
   and `ferrosip fmt --check` on its routes;
2. calls `run(sc)`, which starts the proxies (ports and peers come in the
   environment: the files read them as ${ENV:-default}) and the fake peers,
   sends real traffic and checks the results; it fails on any panic in a
   proxy's log.

Scenarios run in parallel (4 workers), each with its own port block and
temp directory.

    python3 tests/e2e_scenarios.py [--only NAME…] [--size small|medium|large] [-j N]

Run from the repo root after `cargo build --release`.
"""
import argparse, concurrent.futures, importlib, io, os, subprocess, sys, tempfile, threading, time, traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sipkit  # noqa: E402

ROOT = sipkit.ROOT
SCEN = f"{ROOT}/examples/scenarios"
SIZES = {"s": "small", "m": "medium", "l": "large"}
BASE_PORT = 21000
BLOCK = 60


class Skip(Exception):
    pass


class Scenario:
    def __init__(self, name, index):
        self.name, self.size = name, SIZES.get(name[0], "?")
        self.dir = os.path.join(SCEN, name)
        self.tmp = tempfile.mkdtemp(prefix=f"ferrosip-scn-{name}-")
        self.base = BASE_PORT + BLOCK * index
        self._next = self.base
        self.out = io.StringIO()
        self.failures = 0
        self.skipped = None
        self.proxies, self.closers = [], []

    def port(self):
        """The next free port of this scenario's block."""
        p = self._next
        self._next += 1
        if p >= self.base + BLOCK:
            raise RuntimeError("port block exhausted")
        return p

    def skip(self, why):
        """Stop here without failing: something the scenario needs (a
        database server, a binary) isn't installed."""
        raise Skip(why)

    def check(self, what, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + f"{self.name}: {what}" + ("" if cond else f"  -- {str(detail)[:2000]}"), file=self.out)
        self.failures += 0 if cond else 1
        return cond

    def env(self, **kw):
        """Environment for a proxy: an RPC socket of its own, plus `kw`."""
        e = {"RPC_SOCK": os.path.join(self.tmp, f"rpc-{len(self.proxies)}.sock"), "STATE_DIR": self.tmp}
        e.update({k: str(v) for k, v in kw.items()})
        return e

    def proxy(self, sub="", env=None, extra=(), name=None, start=True):
        p = sipkit.Proxy(os.path.join(self.dir, sub), env or self.env(), extra, name or sub or self.name)
        self.proxies.append(p)
        return p.start() if start else p

    def ua(self, user, proxy_port, transport="udp", **kw):
        u = sipkit.UA(user, self.port(), ("127.0.0.1", proxy_port), transport, **kw)
        self.closers.append(u.close)
        return u

    def service(self, routes=None):
        s = sipkit.HttpService(self.port(), routes)
        self.closers.append(s.close)
        return s

    def finish(self):
        for c in self.closers:
            try:
                c()
            except Exception:  # noqa: BLE001
                pass
        for p in self.proxies:
            log = p.stop()
            self.check(f"{p.name}: no panics", "panicked" not in log, log[-800:])


def configs(d):
    """Directories with a ferrosip.toml under scenario dir `d`."""
    out = []
    for root, _, files in os.walk(d):
        if "ferrosip.toml" in files:
            out.append(root)
    return sorted(out)


def static_checks(sc):
    for c in configs(sc.dir):
        rel = os.path.relpath(c, sc.dir) or "."
        env = {**os.environ, "RPC_SOCK": os.path.join(sc.tmp, "check.sock"), "STATE_DIR": sc.tmp}
        r = subprocess.run([sipkit.BIN, "check", "--config", f"{c}/ferrosip.toml"], capture_output=True, text=True, env=env, timeout=60, cwd=c)
        sc.check(f"{rel}: ferrosip check", "config OK" in r.stderr, r.stderr[-800:])
        r = subprocess.run([sipkit.BIN, "lint", "--config", f"{c}/ferrosip.toml", "-D", "warnings"], capture_output=True, text=True, env=env, timeout=60, cwd=c)
        sc.check(f"{rel}: ferrosip lint -D warnings", r.returncode == 0, r.stderr[-1500:])
        routes = os.path.join(c, "routes")
        if os.path.isdir(routes):
            r = subprocess.run([sipkit.BIN, "fmt", "--check", routes], capture_output=True, text=True, timeout=60)
            sc.check(f"{rel}: ferrosip fmt --check", r.returncode == 0, r.stdout + r.stderr)


def run_one(name, index):
    sc = Scenario(name, index)
    t0 = time.time()
    try:
        mod = importlib.import_module(f"scenarios.{name.replace('-', '_')}")
        if not os.path.isdir(sc.dir):
            sc.check("scenario directory exists", False, sc.dir)
        else:
            static_checks(sc)
            mod.run(sc)
    except Skip as e:
        sc.skipped = str(e)
    except Exception:  # noqa: BLE001
        sc.check("ran without an exception", False, traceback.format_exc())
    finally:
        sc.finish()
    state = f"{sc.failures} FAILED" if sc.failures else f"skipped ({sc.skipped})" if sc.skipped else "ok"
    print(f"---- {name} ({sc.size}): {state} in {time.time() - t0:.1f}s", file=sc.out)
    return sc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--size", choices=["small", "medium", "large"])
    ap.add_argument("-j", type=int, default=4)
    a = ap.parse_args()
    names = sorted(n for n in os.listdir(SCEN) if os.path.isdir(os.path.join(SCEN, n)) and n[0] in SIZES)
    if a.only:
        names = [n for n in names if any(n == o or n.startswith(o) for o in a.only)]
    if a.size:
        names = [n for n in names if SIZES[n[0]] == a.size]
    lock = threading.Lock()
    failed, skipped = [], []
    with concurrent.futures.ThreadPoolExecutor(a.j) as ex:
        futs = {ex.submit(run_one, n, i): n for i, n in enumerate(sorted(os.listdir(SCEN))) if n in names}
        for f in concurrent.futures.as_completed(futs):
            sc = f.result()
            with lock:
                print(sc.out.getvalue(), end="", flush=True)
                if sc.failures:
                    failed.append(sc.name)
                elif sc.skipped:
                    skipped.append(sc.name)
    print(f"\n{len(names) - len(failed) - len(skipped)}/{len(names)} scenarios passed"
          + (f"; skipped: {', '.join(sorted(skipped))}" if skipped else "")
          + (f"; failed: {', '.join(sorted(failed))}" if failed else ""))
    print("all passed" if not failed else f"{len(failed)} FAILED")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
