"""A small SIP test kit for the scenario suite (tests/e2e_scenarios.py).

- `Proxy`: a ferrosip started from a scenario directory's ferrosip.toml,
  with its ports and peers in the environment;
- `UA`: a user agent over UDP, TCP or WebSocket: requests, replies,
  registration with digest auth, calls (INVITE/ACK/BYE/CANCEL), and an
  optional handler that answers what it receives;
- `HttpService`: a scripted HTTP server (responses, delays, a request log);
- `Msg`: a parsed SIP message.

Everything binds 127.0.0.1. Each UA reads in its own thread into a queue,
so requests and replies are never lost while a test waits on something
else.
"""
import base64, hashlib, http.server, json, os, queue, random, re, shutil, socket, ssl, subprocess, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = f"{ROOT}/target/release/ferrosip"
CTL = f"{ROOT}/target/release/ferroctl"
TLS_DIR = f"{ROOT}/etc/tls"


_FEATURES = None


def built_with(feature):
    """Whether the ferrosip binary under test was built with a Cargo
    feature (`ferrosip --version` lists them), e.g. "db-postgres"."""
    global _FEATURES
    if _FEATURES is None:
        out = subprocess.run([BIN, "--version"], capture_output=True, text=True).stdout
        m = re.search(r"\(features: ([^)]*)\)", out)
        _FEATURES = set(m.group(1).split()) if m else set()
    return feature in _FEATURES
COMPACT = {"v": "via", "f": "from", "t": "to", "i": "call-id", "m": "contact", "l": "content-length", "c": "content-type", "k": "supported"}


def rnd(n=8):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


# ----------------------------------------------------------------- messages ---

class Msg:
    def __init__(self, raw, src=None):
        self.raw = raw
        self.src = src
        head, _, self.body = raw.partition("\r\n\r\n")
        lines = head.split("\r\n")
        self.first = lines[0]
        self.headers = []
        for l in lines[1:]:
            if l[:1] in (" ", "\t") and self.headers:
                n, v = self.headers[-1]
                self.headers[-1] = (n, v + " " + l.strip())
            elif ":" in l:
                n, v = l.split(":", 1)
                n = n.strip().lower()
                self.headers.append((COMPACT.get(n, n), v.strip()))

    @property
    def is_reply(self):
        return self.first.startswith("SIP/2.0 ")

    @property
    def code(self):
        return int(self.first.split()[1]) if self.is_reply else None

    @property
    def reason(self):
        return self.first.split(" ", 2)[2] if self.is_reply else None

    @property
    def method(self):
        return self.cseq_method if self.is_reply else self.first.split()[0]

    @property
    def ruri(self):
        return None if self.is_reply else self.first.split()[1]

    @property
    def cseq_method(self):
        return (self.get("cseq") or "0 X").split()[1]

    def get(self, name):
        name = COMPACT.get(name.lower(), name.lower())
        for n, v in self.headers:
            if n == name:
                return v
        return None

    def all(self, name):
        name = COMPACT.get(name.lower(), name.lower())
        out = []
        for n, v in self.headers:
            if n == name:
                out.extend(x.strip() for x in split_commas(v)) if name in ("via", "record-route", "route", "contact") else out.append(v)
        return out

    def tag(self, which):
        m = re.search(r";\s*tag=([^;>\s]+)", self.get(which) or "")
        return m.group(1) if m else None

    def sdp_media(self):
        """(address, port) of the SDP's c= and first m= line."""
        c = re.search(r"c=IN IP4 (\S+)", self.body)
        m = re.search(r"m=\w+ (\d+)", self.body)
        return (c.group(1) if c else None, int(m.group(1)) if m else None)

    def __repr__(self):
        return f"<{self.first}>"


def split_commas(v):
    out, depth, cur, q = [], 0, "", False
    for ch in v:
        if ch == '"':
            q = not q
        if not q:
            depth += ch == "<"
            depth -= ch == ">"
        if ch == "," and depth == 0 and not q:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def uri_of(nameaddr):
    m = re.search(r"<([^>]+)>", nameaddr)
    return m.group(1) if m else nameaddr.split(";")[0].strip()


def sdp(port, sess=None, addr="127.0.0.1"):
    sess = sess or random.randint(1, 10**6)
    return (f"v=0\r\no=- {sess} 1 IN IP4 {addr}\r\ns=-\r\nc=IN IP4 {addr}\r\nt=0 0\r\n"
            f"m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n")


# ----------------------------------------------------------------- digest ---

H = {"MD5": lambda s: hashlib.md5(s.encode()).hexdigest(), "SHA-256": lambda s: hashlib.sha256(s.encode()).hexdigest()}


def challenges(reply):
    """[(algorithm, {params})] of the WWW-/Proxy-Authenticate headers."""
    out = []
    for n, v in reply.headers:
        if n in ("www-authenticate", "proxy-authenticate") and v.startswith("Digest"):
            p = {k: a or b for k, a, b in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', v)}
            out.append((p.get("algorithm", "MD5"), p, n))
    return out


def credentials(user, password, ch, method, uri, hdr, alg="MD5", nc=1):
    h = H[alg]
    ha1 = h(f"{user}:{ch['realm']}:{password}")
    ha2 = h(f"{method}:{uri}")
    ncs, cnonce = f"{nc:08x}", rnd(8)
    if "auth" in (ch.get("qop") or ""):
        resp = h(f"{ha1}:{ch['nonce']}:{ncs}:{cnonce}:auth:{ha2}")
        extra = f', qop=auth, nc={ncs}, cnonce="{cnonce}"'
    else:
        resp, extra = h(f"{ha1}:{ch['nonce']}:{ha2}"), ""
    name = "Authorization" if hdr == "www-authenticate" else "Proxy-Authorization"
    return (name, f'Digest username="{user}", realm="{ch["realm"]}", nonce="{ch["nonce"]}", uri="{uri}", '
                  f'response="{resp}", algorithm={alg}{extra}')


# ---------------------------------------------------------------- transports ---

class _Udp:
    proto = "UDP"

    def __init__(self, port, peer):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", port))
        self.peer = peer

    def send(self, data, to=None):
        self.s.sendto(data, to or self.peer)

    def read(self):
        """Yields (bytes, addr) until closed."""
        while True:
            try:
                d, a = self.s.recvfrom(65535)
            except OSError:
                return
            if not d:  # shutdown() wakes the reader with an empty datagram
                return
            yield d, a

    def close(self):
        _shut(self.s)


def _shut(s):
    """Close a socket for real: shutdown() first, so a reader blocked in
    recv wakes up, TCP sends its FIN and a UDP port is free again."""
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


class _Stream:
    """TCP or TLS: one connection to the proxy, messages framed by Content-Length."""

    def __init__(self, port, peer, tls=False):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.connect(peer)
        if tls:
            ctx = ssl.create_default_context(cafile=f"{TLS_DIR}/ca.pem")
            ctx.check_hostname = False
            s = ctx.wrap_socket(s)
        self.s, self.peer, self.proto = s, peer, "TLS" if tls else "TCP"

    def send(self, data, to=None):
        self.s.sendall(data)

    def read(self):
        buf = b""
        while True:
            while True:
                i = buf.find(b"\r\n\r\n")
                if i < 0:
                    break
                m = re.search(rb"(?im)^(?:content-length|l)\s*:\s*(\d+)", buf[:i])
                n = int(m.group(1)) if m else 0
                if len(buf) < i + 4 + n:
                    break
                msg, buf = buf[:i + 4 + n], buf[i + 4 + n:]
                yield msg.lstrip(b"\r\n"), self.peer
            try:
                d = self.s.recv(65536)
            except OSError:
                return
            if not d:
                return
            buf += d

    def close(self):
        _shut(self.s)


class _Ws:
    """A WebSocket (RFC 7118) client connection to the proxy."""
    proto = "WS"

    def __init__(self, port, peer):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.connect(peer)
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall((f"GET / HTTP/1.1\r\nHost: {peer[0]}:{peer[1]}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                raise OSError("websocket handshake: connection closed")
            buf += d
        head, _, self.rest = buf.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise OSError(f"websocket handshake refused: {head[:80]!r}")
        self.s, self.peer = s, peer

    def send(self, data, to=None):
        n = len(data)
        b1 = n if n < 126 else 126 if n < 65536 else 127
        ext = b"" if n < 126 else n.to_bytes(2 if n < 65536 else 8, "big")
        key = os.urandom(4)
        self.s.sendall(bytes([0x81, 0x80 | b1]) + ext + key + bytes(b ^ key[i % 4] for i, b in enumerate(data)))

    def read(self):
        buf = self.rest
        while True:
            while len(buf) >= 2:
                n, off = buf[1] & 0x7F, 2
                if n == 126:
                    if len(buf) < 4:
                        break
                    n, off = int.from_bytes(buf[2:4], "big"), 4
                elif n == 127:
                    if len(buf) < 10:
                        break
                    n, off = int.from_bytes(buf[2:10], "big"), 10
                if len(buf) < off + n:
                    break
                op, payload, buf = buf[0] & 0x0F, buf[off:off + n], buf[off + n:]
                if op == 9:  # ping
                    self.s.sendall(bytes([0x8A, 0x80 | len(payload)]) + b"\0\0\0\0" + payload)
                elif op in (1, 2):
                    yield payload, self.peer
                elif op == 8:
                    return
            try:
                d = self.s.recv(65536)
            except OSError:
                return
            if not d:
                return
            buf += d

    def close(self):
        _shut(self.s)


# ------------------------------------------------------------------------ UA ---

class Dialog:
    """The caller's side of an established call."""

    def __init__(self, ua, invite, reply):
        self.ua, self.invite, self.reply = ua, invite, reply
        self.call_id = invite["call_id"]
        self.local_tag = invite["from_tag"]
        self.remote_tag = reply.tag("to")
        self.remote_target = uri_of(reply.get("contact") or "") or invite["ruri"]
        self.route = list(reversed(reply.all("record-route")))
        self.to = reply.get("to")
        self.cseq = invite["cseq"]

    def request(self, method, cseq=None, body="", headers=None):
        if cseq is None:
            self.cseq += 1
            cseq = self.cseq
        hs = dict(headers or {})
        if self.route:
            hs["Route"] = ", ".join(self.route)
        return self.ua.request(method, self.remote_target, to=self.to, call_id=self.call_id, from_tag=self.local_tag,
                               cseq=cseq, headers=hs, body=body)

    def ack(self):
        return self.request("ACK", cseq=self.invite["cseq"])

    def bye(self, timeout=3.0):
        self.request("BYE")
        return self.ua.final(timeout, method="BYE")


class UA:
    """A SIP user agent. `user@domain` is its AoR; requests go to `proxy`."""

    def __init__(self, user, port, proxy, transport="udp", domain="example.com", password=None):
        self.user, self.port, self.proxy, self.domain, self.password = user, port, proxy, domain, password
        self.transport = transport.lower()
        if self.transport == "udp":
            self.t = _Udp(port, proxy)
        elif self.transport in ("tcp", "tls"):
            self.t = _Stream(port, proxy, tls=self.transport == "tls")
        elif self.transport == "ws":
            self.t = _Ws(port, proxy)
        else:
            raise ValueError(transport)
        self.q = queue.Queue()
        self.handler = None  # f(Msg) -> None | (code, reason[, headers][, body])
        self.received = []   # every request seen (for checks)
        self.nc = {}
        self.tags = {}
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    # -- plumbing
    def _reader(self):
        for data, addr in self.t.read():
            try:
                m = Msg(data.decode(errors="replace"), addr)
            except Exception:  # noqa: BLE001
                continue
            if not m.is_reply:
                self.received.append(m)
                if self.handler:
                    r = self.handler(m)
                    if r:
                        self.respond(m, *r) if isinstance(r, tuple) else None
                        continue
            self.q.put(m)

    def close(self):
        self.t.close()
        # The port is free only once the reader has left recvfrom (a
        # blocked call keeps the socket alive past close()).
        if self._thread is not threading.current_thread():
            self._thread.join(2)

    @property
    def aor(self):
        return f"sip:{self.user}@{self.domain}"

    @property
    def contact(self):
        tp = "" if self.transport == "udp" else f";transport={self.transport}"
        return f"sip:{self.user}@127.0.0.1:{self.port}{tp}"

    def via(self, branch):
        proto = {"udp": "UDP", "tcp": "TCP", "tls": "TLS", "ws": "WS"}[self.transport]
        return f"SIP/2.0/{proto} 127.0.0.1:{self.port};branch=z9hG4bK{branch};rport"

    def send(self, raw, to=None):
        self.t.send(raw.encode() if isinstance(raw, str) else raw, to)

    # -- requests
    def request(self, method, ruri, to=None, call_id=None, from_tag=None, cseq=1, headers=None, body="",
                content_type="application/sdp", max_forwards=70, branch=None, contact=True, from_uri=None):
        """Send a request; returns its parameters (for CANCEL, dialogs and checks)."""
        branch = branch or rnd(12)
        call_id = call_id or f"{rnd(10)}@127.0.0.1"
        from_tag = from_tag or rnd(8)
        to = to or f"<{ruri.split(';')[0]}>"
        hs = [f"Via: {self.via(branch)}", f"From: <{from_uri or self.aor}>;tag={from_tag}", f"To: {to}", f"Call-ID: {call_id}",
              f"CSeq: {cseq} {method}", f"Max-Forwards: {max_forwards}"]
        if contact and method in ("INVITE", "REGISTER", "SUBSCRIBE") and not any(k.lower() == "contact" for k in (headers or {})):
            hs.append(f"Contact: <{self.contact}>")
        for k, v in (headers or {}).items():
            for x in v if isinstance(v, list) else [v]:
                hs.append(f"{k}: {x}")
        if body:
            hs.append(f"Content-Type: {content_type}")
        hs.append(f"Content-Length: {len(body.encode())}")
        raw = f"{method} {ruri} SIP/2.0\r\n" + "\r\n".join(hs) + "\r\n\r\n" + body
        self.send(raw)
        return {"method": method, "ruri": ruri, "branch": branch, "call_id": call_id, "from_tag": from_tag, "cseq": cseq,
                "to": to, "raw": raw, "headers": headers or {}, "body": body}

    def recv(self, timeout=3.0, cond=None):
        """The next message (matching `cond`); None on timeout. Skipped ones are dropped."""
        end = time.time() + timeout
        while True:
            left = end - time.time()
            if left <= 0:
                return None
            try:
                m = self.q.get(timeout=left)
            except queue.Empty:
                return None
            if cond is None or cond(m):
                return m

    def final(self, timeout=4.0, method=None, call_id=None, cseq=None):
        """The next final reply (to `method` / `call_id` / CSeq number `cseq`:
        a retransmitted earlier final of the same call is skipped)."""
        return self.recv(timeout, lambda m: m.is_reply and m.code >= 200 and (method is None or m.cseq_method == method)
                         and (call_id is None or m.get("call-id") == call_id)
                         and (cseq is None or (m.get("cseq") or "").split()[0] == str(cseq)))

    def request_in(self, method=None, timeout=4.0):
        """The next request received (not handled by `handler`)."""
        return self.recv(timeout, lambda m: not m.is_reply and (method is None or m.method == method))

    def respond(self, req, code, reason="OK", headers=None, body=""):
        """Reply to a received request (adds a To tag on its dialog)."""
        keep = [f"{'Via' if n == 'via' else n.title()}: {v}" for n, v in req.headers if n in ("via", "from", "call-id", "cseq", "record-route")]
        to = req.get("to") or ""
        if code > 100 and ";tag=" not in to:
            key = (req.get("call-id"), req.tag("from"))
            to += f";tag={self.tags.setdefault(key, rnd(8))}"
        hs = keep + [f"To: {to}"]
        if code < 300 and req.method in ("INVITE", "SUBSCRIBE"):
            hs.append(f"Contact: <{self.contact}>")
        for k, v in (headers or {}).items():
            hs.append(f"{k}: {v}")
        if body:
            hs.append("Content-Type: application/sdp")
        hs.append(f"Content-Length: {len(body.encode())}")
        self.send(f"SIP/2.0 {code} {reason}\r\n" + "\r\n".join(hs) + "\r\n\r\n" + body, req.src if self.transport == "udp" else None)

    def with_auth(self, sent, reply, timeout=4.0):
        """Resend `sent` with credentials for `reply`'s challenge; (the new
        final reply, waited for up to `timeout`, the resent request). Without
        a challenge or a password: (`reply`, `sent`)."""
        ch = challenges(reply)
        if not ch or self.password is None:
            return reply, sent
        alg, p, hdr = ch[0]
        key = p["nonce"]
        self.nc[key] = self.nc.get(key, 0) + 1
        name, value = credentials(self.user, self.password, p, sent["method"], sent["ruri"], hdr, alg, self.nc[key])
        hs = dict(sent["headers"])
        hs[name] = value
        r = self.request(sent["method"], sent["ruri"], to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                         cseq=sent["cseq"] + 1, headers=hs, body=sent["body"])
        return self.final(timeout, method=sent["method"], call_id=r["call_id"], cseq=r["cseq"]), r

    def register(self, expires=3600, contact=None, registrar=None, headers=None, auth=True):
        """REGISTER (answering one digest challenge); the final reply."""
        hs = dict(headers or {})
        hs.setdefault("Contact", f"<{contact or self.contact}>")
        hs.setdefault("Expires", str(expires))
        sent = self.request("REGISTER", registrar or f"sip:{self.domain}", to=f"<{self.aor}>", headers=hs)
        r = self.final(method="REGISTER", call_id=sent["call_id"], cseq=sent["cseq"])
        if auth and r is not None and r.code in (401, 407) and self.password is not None:
            r, _ = self.with_auth(sent, r)
        return r

    def call(self, ruri, body=None, headers=None, timeout=5.0, auth=True):
        """INVITE `ruri`; returns (final reply, Dialog or None). ACKs 2xx itself."""
        body = sdp(self.port + 1000) if body is None else body
        sent = self.request("INVITE", ruri, headers=headers, body=body)
        r = self.final(timeout, method="INVITE", call_id=sent["call_id"], cseq=sent["cseq"])
        if auth and r is not None and r.code in (401, 407) and self.password is not None:
            self._ack_neg(sent, r)
            r, sent = self.with_auth(sent, r, timeout)
        if r is None:
            return None, None
        if r.code >= 300:
            self._ack_neg(sent, r)
            return r, None
        d = Dialog(self, sent, r)
        d.ack()
        return r, d

    def invite(self, ruri, body=None, headers=None):
        """INVITE without waiting (for CANCEL and ringing tests); the sent request."""
        return self.request("INVITE", ruri, headers=headers, body=sdp(self.port + 1000) if body is None else body)

    def cancel(self, sent):
        hs = {k: v for k, v in sent["headers"].items() if k.lower() == "route"}
        self.request("CANCEL", sent["ruri"], to=sent["to"], call_id=sent["call_id"], from_tag=sent["from_tag"],
                     cseq=sent["cseq"], branch=sent["branch"], headers=hs)

    def _ack_neg(self, sent, reply):
        """ACK for a negative final (same branch, To from the reply)."""
        raw = (f"ACK {sent['ruri']} SIP/2.0\r\nVia: {self.via(sent['branch'])}\r\nFrom: <{self.aor}>;tag={sent['from_tag']}\r\n"
               f"To: {reply.get('to')}\r\nCall-ID: {sent['call_id']}\r\nCSeq: {sent['cseq']} ACK\r\nMax-Forwards: 70\r\n"
               f"Content-Length: 0\r\n\r\n")
        self.send(raw)

    # -- answering
    def auto_answer(self, code=200, reason="OK", delay=0.0, ring=False, sdp_port=None):
        """Answer every INVITE (180 first when `ring`), and BYE/CANCEL/OPTIONS/MESSAGE with 200."""
        def h(m):
            if m.method == "INVITE":
                def later():
                    if ring:
                        self.respond(m, 180, "Ringing")
                    if delay:
                        time.sleep(delay)
                    if code is not None and m.get("call-id") not in self.canceled:
                        self.respond(m, code, reason, body=sdp(sdp_port or self.port + 1000) if code < 300 else "")
                if ring or delay:
                    self.respond(m, 100, "Trying")
                threading.Thread(target=later, daemon=True).start()
                return None
            if m.method == "CANCEL":
                self.canceled.add(m.get("call-id"))
                self.respond(m, 200)
                inv = next((x for x in reversed(self.received) if x.method == "INVITE" and x.get("call-id") == m.get("call-id")), None)
                if inv is not None:
                    self.respond(inv, 487, "Request Terminated")
                return None
            if m.method in ("BYE", "OPTIONS", "MESSAGE", "NOTIFY", "INFO", "UPDATE"):
                return (200, "OK")
            return None
        self.canceled = set()
        self.handler = h
        return self

    def reachable_from(self, host_port):
        return self


# ----------------------------------------------------------------------- Proxy ---

class Proxy:
    """ferrosip run from `<dir>/ferrosip.toml` with `env` (ports, peers, paths)."""

    def __init__(self, conf_dir, env, extra=(), name="proxy"):
        self.dir, self.name = conf_dir, name
        self.env = {**os.environ, **{k: str(v) for k, v in env.items()}}
        toml = open(os.path.join(conf_dir, "ferrosip.toml")).read()
        self.want = max(1, len(re.findall(r"(?m)^\[\[listen\]\]", toml)))
        self.args = [BIN, "--config", os.path.join(conf_dir, "ferrosip.toml"), *extra]
        self.p = None
        self.log = ""
        self.lines = []
        self._seen = threading.Condition()

    def start(self, timeout=10.0):
        """Start and wait for one "listening on" per [[listen]]; stderr is
        read by a thread from the start (also so a chatty proxy never blocks)."""
        self.lines = []
        self.p = subprocess.Popen(self.args, env=self.env, stderr=subprocess.PIPE, text=True, cwd=self.dir)
        threading.Thread(target=self._drain, daemon=True).start()
        listening = lambda: sum("listening on" in l for l in list(self.lines))  # noqa: E731
        with self._seen:
            self._seen.wait_for(lambda: listening() >= self.want or self.p.poll() is not None, timeout)
        self.early = "".join(self.lines)
        if self.p.poll() is not None:
            time.sleep(0.1)
            raise RuntimeError(f"{self.name} exited at startup:\n{''.join(self.lines)}")
        return self

    def _drain(self):
        for line in self.p.stderr:
            self.lines.append(line)
            with self._seen:
                self._seen.notify_all()
        with self._seen:
            self._seen.notify_all()

    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        time.sleep(0.05)
        self.log = "".join(self.lines)
        return self.log

    def kill(self):
        if self.p:
            self.p.kill()
            self.p.wait()

    def rpc(self, method, *args):
        """ferroctl's answer, parsed as JSON when it is; a refusal comes back
        as its error text (stderr)."""
        sock = self.env.get("RPC_SOCK")
        r = subprocess.run([CTL, "-s", sock, method, *map(str, args)], capture_output=True, text=True, timeout=5)
        try:
            return json.loads(r.stdout)
        except ValueError:
            return r.stdout or r.stderr


# ------------------------------------------------------------------ HTTP fake ---

class HttpService:
    """`routes`: path → (status, body[, delay_s]) or a callable(method, path, query, body) → that.
    Records every request as (method, path, query, body, headers)."""

    def __init__(self, port, routes=None):
        self.routes, self.log = dict(routes or {}), []
        svc = self

        class H(http.server.BaseHTTPRequestHandler):
            def handle_one(self, method):
                path, _, query = self.path.partition("?")
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode() if n else ""
                svc.log.append((method, path, query, body, dict(self.headers)))
                r = svc.routes.get(path) or svc.routes.get("*")
                if callable(r):
                    r = r(method, path, query, body)
                if r is None:
                    r = (404, "not found")
                status, text, delay = (list(r) + [0])[:3]
                if delay:
                    time.sleep(delay)
                data = text.encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass

            def do_GET(self):
                self.handle_one("GET")

            def do_POST(self):
                self.handle_one("POST")

            def log_message(self, *a):
                pass

        self.port = port
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def http_get(url, timeout=3.0, method="GET", body=None):
    import urllib.error, urllib.request
    req = urllib.request.Request(url, data=body.encode() if body is not None else None, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except OSError as e:
        return None, str(e)


# -------------------------------------------------------- database servers ---
# Throwaway servers for scenarios that need one, on a scenario's port, in
# its temp directory. `available()` is False where the binaries are
# missing: the scenario then calls `sc.skip(...)`.

def _run(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=60, **kw)


def _pgbin():
    import glob
    found = sorted(glob.glob("/usr/lib/postgresql/*/bin/initdb"))
    return os.path.dirname(found[-1]) if found else None


class Postgres:
    """A private PostgreSQL with the ferrosip schema (etc/schema/postgres.sql)
    in database `ferrosip`, plain TCP on 127.0.0.1:`port`. `url` for db_url."""

    def __init__(self, port, tmp):
        self.port, self.dir, self.bin = port, os.path.join(tmp, "pg"), _pgbin()
        self.url = f"postgres://postgres@127.0.0.1:{port}/ferrosip"

    @staticmethod
    def available():
        return _pgbin() is not None and shutil.which("psql") is not None and _have_user("postgres")

    def _as_pg(self, args):
        return _run(["su", "postgres", "-c", args])

    def start(self, first=True):
        if first:
            os.makedirs(self.dir, exist_ok=True)
            shutil.chown(self.dir, "postgres", "postgres")
            os.chmod(self.dir, 0o700)
            os.chmod(os.path.dirname(self.dir), 0o755)
            r = self._as_pg(f"{self.bin}/initdb -D {self.dir}/data -U postgres --auth=trust -E UTF8")
            if r.returncode:
                raise RuntimeError(r.stderr)
        r = self._as_pg(f"{self.bin}/pg_ctl -D {self.dir}/data -w -l {self.dir}/log -o '-p {self.port} -k {self.dir} -c listen_addresses=127.0.0.1' start")
        if r.returncode:
            raise RuntimeError(r.stderr)
        if first:
            self.sql("create database ferrosip", db="postgres")
            r = _run(["psql", "-q", "-h", "127.0.0.1", "-p", str(self.port), "-U", "postgres", "-d", "ferrosip", "-v", "ON_ERROR_STOP=1", "-f", f"{ROOT}/etc/schema/postgres.sql"])
            if r.returncode:
                raise RuntimeError(r.stderr)
        return self

    def sql(self, q, db="ferrosip"):
        """Rows of a query, each a list of strings."""
        r = _run(["psql", "-h", "127.0.0.1", "-p", str(self.port), "-U", "postgres", "-d", db, "-t", "-A", "-F", "|", "-c", q])
        if r.returncode:
            raise RuntimeError(r.stderr)
        return [l.split("|") for l in r.stdout.strip().splitlines() if l]

    def stop(self):
        if os.path.isdir(f"{self.dir}/data"):
            self._as_pg(f"{self.bin}/pg_ctl -D {self.dir}/data -w -m fast stop")

    close = stop


class MariaDb:
    """A private MariaDB/MySQL with the ferrosip schema (etc/schema/mysql.sql)
    in database `ferrosip` on 127.0.0.1:`port`. `url` for db_url."""

    def __init__(self, port, tmp):
        self.port, self.dir, self.proc = port, os.path.join(tmp, "my"), None
        self.url = f"mysql://root@127.0.0.1:{port}/ferrosip"

    @staticmethod
    def available():
        return shutil.which("mariadbd") is not None and shutil.which("mariadb-install-db") is not None

    def start(self, first=True):
        if first:
            os.makedirs(self.dir, exist_ok=True)
            r = _run(["mariadb-install-db", "--no-defaults", f"--datadir={self.dir}/data", "--user=root", "--auth-root-authentication-method=normal"])
            if r.returncode:
                raise RuntimeError(r.stderr)
        self.proc = subprocess.Popen(["mariadbd", "--no-defaults", f"--datadir={self.dir}/data", f"--port={self.port}", "--bind-address=127.0.0.1",
                                      f"--socket={self.dir}/sock", "--user=root", "--skip-grant-tables", "--skip-log-bin", f"--log-error={self.dir}/err"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 30
        while time.time() < end and _run(["mariadb", "--no-defaults", "-S", f"{self.dir}/sock", "-u", "root", "-e", "select 1"]).returncode:
            time.sleep(0.2)
        if first:
            self.sql("create database ferrosip", db="")
            r = _run(f"mariadb --no-defaults -S {self.dir}/sock -u root ferrosip < {ROOT}/etc/schema/mysql.sql")
            if r.returncode:
                raise RuntimeError(r.stderr)
        return self

    def sql(self, q, db="ferrosip"):
        r = _run(["mariadb", "--no-defaults", "-S", f"{self.dir}/sock", "-u", "root", "-N", "-B"] + ([db] if db else []) + ["-e", q])
        if r.returncode:
            raise RuntimeError(r.stderr)
        return [l.split("\t") for l in r.stdout.strip().splitlines() if l]

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(30)

    close = stop


class Redis:
    """A private redis-server on 127.0.0.1:`port` (no persistence)."""

    def __init__(self, port, tmp):
        self.port, self.dir, self.proc = port, tmp, None

    @staticmethod
    def available():
        return shutil.which("redis-server") is not None and shutil.which("redis-cli") is not None

    def start(self):
        self.proc = subprocess.Popen(["redis-server", "--port", str(self.port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", self.dir],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 10
        while time.time() < end and self.cmd("PING") != "PONG":
            time.sleep(0.1)
        return self

    def cmd(self, *args):
        """redis-cli's answer as text."""
        return _run(["redis-cli", "-p", str(self.port), *map(str, args)]).stdout.strip()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(10)

    close = stop


def _have_user(name):
    import pwd
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False
