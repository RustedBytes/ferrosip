#!/usr/bin/env python3
"""siptrace → Homer (HEP v3), with the Kamailio configs from Homer's wiki
(github.com/sipcapture/homer/wiki/Examples:-Kamailio), addresses adapted.

- 4.x style: `trace_flag` 22 + `setflag(22)` + `sip_trace()`. The whole
  transaction reaches the collector: the INVITE in and out, and 100/180/200
  in and out, each once. `setflag(22)` alone also traces; an unflagged
  request sends nothing.
- 5.x style: `send_sock_addr`, `sip_trace_mode("t")`, a second collector
  given to `sip_trace("sip:…")`, a correlation id `"$ci-abc"`, and `hlog()`
  with a correlation id from a header.
- `hep_mode_on 0`: plain SIP copies instead of HEP.
Run from the repo root after `cargo build --release`.
"""
import os, socket, struct, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, UAS, UAC, H1, H2 = 7700, 7701, 7702, 7703, 7704
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


class Collector(threading.Thread):
    """A Homer stand-in: HEP3 records (chunk type → bytes), or raw packets."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.pkts, self.raw = [], []
        self.start()

    def run(self):
        while True:
            d, a = self.s.recvfrom(65535)
            if d[:4] != b"HEP3":
                self.raw.append(d)
                continue
            chunks, i = {"from": a}, 6
            while i + 6 <= len(d):
                _, t, ln = struct.unpack("!HHH", d[i:i + 6])
                chunks[t] = d[i + 6:i + ln]
                i += ln
            self.pkts.append(chunks)

    def clear(self):
        self.pkts.clear()
        self.raw.clear()

    def of(self, cid):
        """First lines of the SIP records of one call."""
        return [p[15].split(b"\r\n", 1)[0].decode() for p in self.pkts if p.get(11) == b"\x01" and callid(p[15]) == cid]


def callid(msg):
    for line in msg.split(b"\r\n")[1:]:
        if line.lower().startswith(b"call-id:"):
            return line.split(b":", 1)[1].strip().decode()
    return None


class Uas(threading.Thread):
    """Answers INVITE with 180 then 200, everything else with 200."""

    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", UAS))
        self.start()

    def reply(self, req, code, a):
        keep = [h for h in req.split("\r\n")[1:] if h.split(":", 1)[0].lower() in ("via", "from", "to", "call-id", "cseq")]
        keep = [h + ";tag=uas" if h.lower().startswith("to:") and code > 100 else h for h in keep]
        self.s.sendto((f"SIP/2.0 {code} X\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n").encode(), a)

    def run(self):
        while True:
            d, a = self.s.recvfrom(65535)
            m = d.decode()
            if m.startswith("ACK"):
                continue
            if m.startswith("INVITE"):
                self.reply(m, 180, a)
                time.sleep(0.05)
            self.reply(m, 200, a)


def request(method, user, cid, extra=""):
    return (f"{method} sip:{user}@127.0.0.1:{PROXY} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch=z9hG4bK{cid};rport\r\n"
            f"From: <sip:alice@127.0.0.1>;tag=a\r\nTo: <sip:{user}@127.0.0.1>\r\nCall-ID: {cid}\r\nCSeq: 1 {method}\r\n"
            f"Max-Forwards: 70\r\nContact: <sip:alice@127.0.0.1:{UAC}>\r\n{extra}Content-Length: 0\r\n\r\n").encode()


def transaction(uac, method, user, cid, extra=""):
    """Send a request, wait for its final reply (ACK a 2xx INVITE)."""
    uac.sendto(request(method, user, cid, extra), ("127.0.0.1", PROXY))
    uac.settimeout(3)
    while True:
        r = uac.recv(65535).decode()
        if not r.startswith("SIP/2.0 1"):
            break
    time.sleep(0.4)  # HEP copies of the last messages
    return r.split("\r\n", 1)[0]


def run_proxy(name, cfg):
    path = os.path.join(ROOT, f"target/e2e_siptrace_{name}.cfg")
    open(path, "w").write(cfg)
    p = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", path, "-l", f"udp:127.0.0.1:{PROXY}", "--rpc-socket", "none"],
                         stderr=subprocess.PIPE, text=True)
    wait_listening(p)
    return p


def stop(p):
    p.terminate()
    try:
        out = p.early_log + p.communicate(timeout=10)[1]
    except subprocess.TimeoutExpired:
        p.kill()
        out = p.early_log + p.communicate()[1]
    check(f"no panics ({p.args[2].rsplit('_', 1)[1]})", "panicked" not in out, out[-500:])
    return out


# Homer wiki, "KAMAILIO 4.x Trace Node" (collector address adapted).
CFG_4X = f"""#!define WITH_HOMER
loadmodule "tm"
loadmodule "sl"
#!ifdef WITH_HOMER
loadmodule "siptrace"
#!endif

#!ifdef WITH_HOMER
modparam("siptrace", "duplicate_uri", "sip:127.0.0.1:{H1}")
modparam("siptrace", "hep_mode_on", 1)
modparam("siptrace", "trace_to_database", 0)
modparam("siptrace", "trace_flag", 22)
modparam("siptrace", "trace_on", 1)
#!endif

request_route {{
    if ($rU == "plain") {{ t_relay("udp:127.0.0.1:{UAS}"); exit; }}
    if ($rU != "flagonly") {{
        sip_trace();
    }}
    setflag(22);
    t_relay("udp:127.0.0.1:{UAS}");
}}
"""

# Homer wiki, "KAMAILIO 5.x Trace Node".
CFG_5X = f"""loadmodule "tm"
loadmodule "sl"
loadmodule "siptrace"
modparam("siptrace", "duplicate_uri", "sip:127.0.0.1:{H1}")
modparam("siptrace", "send_sock_addr", "sip:127.0.0.1:5000")
modparam("siptrace", "hep_mode_on", 1)
modparam("siptrace", "trace_to_database", 0)
modparam("siptrace", "trace_flag", 22)
modparam("siptrace", "trace_on", 1)
modparam("siptrace", "hep_capture_id", 2001)

request_route {{
    if ($rU == "multi") {{
        sip_trace("sip:127.0.0.1:{H2}");
    }} else if ($rU == "corr") {{
        sip_trace("sip:127.0.0.1:{H2}", "$ci-abc", "t");
    }} else {{
        setflag(22);
        sip_trace_mode("t");
        sip_trace();
        hlog("$hdr(P-MyID)", "Another one with a custom correlation ID");
    }}
    t_relay("udp:127.0.0.1:{UAS}");
}}
"""

CFG_PLAIN = f"""loadmodule "tm"
loadmodule "siptrace"
modparam("siptrace", "duplicate_uri", "sip:127.0.0.1:{H1}")
modparam("siptrace", "hep_mode_on", 0)
request_route {{ sip_trace(); t_relay("udp:127.0.0.1:{UAS}"); }}
"""


def main():
    h1, h2, _uas = Collector(H1), Collector(H2), Uas()
    uac = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    uac.bind(("127.0.0.1", UAC))

    p = run_proxy("4x", CFG_4X)
    try:
        r = transaction(uac, "INVITE", "bob", "w4-inv")
        lines = h1.of("w4-inv")
        want = {"INVITE sip:bob@127.0.0.1:7700 SIP/2.0": 2, "SIP/2.0 100 Trying": 1, "SIP/2.0 180 X": 2, "SIP/2.0 200 X": 2}
        got = {k: lines.count(k) for k in want}
        check("4.x: the call completes", r == "SIP/2.0 200 X", r)
        check("4.x: INVITE in + out, our 100, 180 in + out, 200 in + out, each once", got == want, lines)
        recs = [x for x in h1.pkts if callid(x.get(15, b"")) == "w4-inv"]
        check("4.x: HEP3 SIP records with capture id 1 and the Call-ID as correlation id",
              all(x[11] == b"\x01" and struct.unpack("!I", x[12])[0] == 1 and x.get(17) == b"w4-inv" for x in recs), recs[:1])
        inv_in = next((x for x in recs if x[15].startswith(b"INVITE") and struct.unpack("!H", x[7])[0] == UAC), None)
        check("4.x: the received INVITE is recorded from the caller to the proxy",
              inv_in is not None and struct.unpack("!H", inv_in[8])[0] == PROXY and inv_in[2] == b"\x11", inv_in)
        transaction(uac, "MESSAGE", "flagonly", "w4-flag")
        lines = h1.of("w4-flag")
        check("4.x: setflag(22) alone traces the transaction (MESSAGE in/out, 200 in/out)",
              lines.count("MESSAGE sip:flagonly@127.0.0.1:7700 SIP/2.0") == 2 and lines.count("SIP/2.0 200 X") == 2, lines)
        transaction(uac, "MESSAGE", "plain", "w4-plain")
        check("4.x: an unflagged request is not traced", h1.of("w4-plain") == [], h1.of("w4-plain"))
    finally:
        stop(p)

    h1.clear()
    p = run_proxy("5x", CFG_5X)
    try:
        transaction(uac, "INVITE", "carol", "w5-inv", "P-MyID: my-id-42\r\n")
        lines = h1.of("w5-inv")
        check("5.x: sip_trace_mode(\"t\") + sip_trace(): the transaction both ways",
              lines.count("INVITE sip:carol@127.0.0.1:7700 SIP/2.0") == 2 and lines.count("SIP/2.0 200 X") == 2, lines)
        check("5.x: hep_capture_id 2001",
              all(struct.unpack("!I", x[12])[0] == 2001 for x in h1.pkts), {struct.unpack("!I", x[12])[0] for x in h1.pkts})
        check("5.x: send_sock_addr: HEP comes from 127.0.0.1", all(x["from"][0] == "127.0.0.1" for x in h1.pkts))
        logs = [x for x in h1.pkts if x.get(11) == b"\x64"]
        check("5.x: hlog(): a HEP log record with the header's correlation id",
              len(logs) == 1 and logs[0].get(17) == b"my-id-42" and logs[0][15] == b"Another one with a custom correlation ID", logs)
        transaction(uac, "MESSAGE", "multi", "w5-multi")
        check("5.x: sip_trace(\"sip:…\") sends to that collector, not duplicate_uri",
              h2.of("w5-multi") == ["MESSAGE sip:multi@127.0.0.1:7700 SIP/2.0"] and h1.of("w5-multi") == [], (h1.of("w5-multi"), h2.of("w5-multi")))
        transaction(uac, "MESSAGE", "corr", "w5-corr")
        corr = [x.get(17) for x in h2.pkts if callid(x.get(15, b"")) == "w5-corr"]
        check("5.x: sip_trace(dst, \"$ci-abc\", \"t\"): correlation id, whole transaction to that collector",
              len(corr) == 4 and set(corr) == {b"w5-corr-abc"}, corr)
    finally:
        stop(p)

    h1.clear()
    p = run_proxy("plain", CFG_PLAIN)
    try:
        transaction(uac, "MESSAGE", "dave", "w-plain")
        check("hep_mode_on 0: a plain SIP copy instead of HEP",
              h1.pkts == [] and any(r.startswith(b"MESSAGE sip:dave@") for r in h1.raw), (len(h1.pkts), h1.raw[:1]))
    finally:
        stop(p)

    print(f"\n{'all passed' if failures == 0 else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
