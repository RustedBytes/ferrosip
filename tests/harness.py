"""Shared helpers for the e2e suites."""
import select
import time


def wait_listening(p, timeout=10.0):
    """Block until the proxy `p` (stderr piped, text mode) has logged
    "listening on" once per `-l` listener, or has exited, instead of a fixed
    sleep (flaky on loaded CI runners). Returns the lines read; they are no
    longer in `p.stderr`, so they are also kept in `p.early_log`."""
    want = max(1, sum(1 for a in p.args if a == "-l"))
    seen, lines = 0, []
    end = time.time() + timeout
    while seen < want and time.time() < end and p.poll() is None:
        r, _, _ = select.select([p.stderr], [], [], max(0.0, end - time.time()))
        if not r:
            break
        line = p.stderr.readline()
        if not line:
            break
        lines.append(line)
        if "listening on" in line:
            seen += 1
    p.early_log = "".join(lines)
    return lines
