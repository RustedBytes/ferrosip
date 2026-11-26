#!/usr/bin/env python3
"""Voice AI calls (loadmodule "ai") against mock OpenAI Realtime and Gemini
Live servers (a local WebSocket server that speaks just enough of each).

- OpenAI, PCMU: the INVITE's X-AI-Prompt becomes the session's
  instructions (with the model, key and voice from modparams); 100 then
  200 with an SDP answer; the mock echoes the caller's audio and it comes
  back over RTP byte for byte; the greeting is requested; a retransmitted
  INVITE is answered again without a second session; ai.list shows the
  call; BYE closes the provider session.
- Gemini, PCMA, over wss:// (a self-signed CA given as tls_ca_file): a base64 multi-line prompt and a per-call voice reach the
  setup message; caller audio goes up as 16 kHz PCM, the mock's 24 kHz
  tone comes down as audible 8 kHz A-law.
- The model's end_call function makes ferrosip send BYE (after answering
  the function call); a provider that drops the session gets the caller a
  BYE too; so does a caller who stops sending RTP.
- CANCEL while the provider is still connecting: 200, then 487.
- Provider refusing the session (401): 503 with a Warning. No PCMU/PCMA,
  or SRTP: 488.
- The web UI (/api/v1/ai-calls) shows the call in progress with its
  prompt; ai-calls/recent and ai.recent list the ended ones newest first
  with outcome and reason.
Run from the repo root after `cargo build --release`.
"""
import base64, hashlib, http.client, json, math, os, random, socket, ssl, struct, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import wait_listening  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY, UAC, WS, WSS, WEB = 7600, 7602, 7690, 7691, 7695
RTP_PORTS = iter(range(7650, 7680, 2))
failures = 0


def check(name, cond, detail=""):
    global failures
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))
    failures += 0 if cond else 1


# ---------------------------------------------------------------- G.711 ---
def lin2ulaw(s):
    s = s >> 2
    mask = 0x7F if s < 0 else 0xFF
    s = min(abs(s), 8159) + (0x84 >> 2)
    ends = [0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF]
    seg = next((i for i, e in enumerate(ends) if s <= e), 8)
    return (0x7F ^ mask) if seg >= 8 else (((seg << 4) | ((s >> (seg + 1)) & 0xF)) ^ mask)


def alaw2lin(a):
    a ^= 0x55
    t = (a & 0x0F) << 4
    seg = (a & 0x70) >> 4
    t = t + 8 if seg == 0 else (t + 0x108) << max(0, seg - 1)
    return t if a & 0x80 else -t


def lin2alaw(s):
    s = s >> 3
    if s >= 0:
        mask = 0xD5
    else:
        mask, s = 0x55, -s - 1
    ends = [0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF]
    seg = next((i for i, e in enumerate(ends) if s <= e), 8)
    if seg >= 8:
        return 0x7F ^ mask
    q = (s >> 1) & 0xF if seg < 2 else (s >> seg) & 0xF
    return ((seg << 4) | q) ^ mask


def tone(hz, rate, n, start=0, amp=8000):
    return [int(amp * math.sin(2 * math.pi * hz * (start + i) / rate)) for i in range(n)]


# ------------------------------------------------------ mock providers ---
class Conn:
    def __init__(self, sock, path, headers):
        self.sock, self.path, self.headers = sock, path, headers
        self.msgs, self.closed, self.lock = [], False, threading.Lock()

    def send(self, obj, binary=False):
        data = json.dumps(obj).encode()
        n = len(data)
        hdr = bytes([0x82 if binary else 0x81]) + (bytes([n]) if n < 126 else bytes([126]) + struct.pack(">H", n) if n < 65536 else bytes([127]) + struct.pack(">Q", n))
        with self.lock:
            try:
                self.sock.sendall(hdr + data)
            except OSError:
                pass

    def of(self, key):
        return [m for m in self.msgs if key(m)]


class Mock:
    def __init__(self):
        self.conns, self.delay_next, self.refuse_next = [], 0, False
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(CERT, KEY)
        for port, ctx in ((WS, None), (WSS, tls)):
            ls = socket.socket()
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind(("127.0.0.1", port))
            ls.listen(16)
            threading.Thread(target=self.accept, args=(ls, ctx), daemon=True).start()

    def accept(self, ls, tls):
        while True:
            s, _ = ls.accept()
            threading.Thread(target=self.serve, args=(s, tls), daemon=True).start()

    def serve(self, s, tls=None):
        if tls:
            try:
                s = tls.wrap_socket(s, server_side=True)
            except (ssl.SSLError, OSError) as e:
                print("mock: TLS handshake failed:", e)
                return
        head = b""
        while b"\r\n\r\n" not in head:
            d = s.recv(4096)
            if not d:
                return
            head += d
        lines = head.split(b"\r\n\r\n")[0].decode().split("\r\n")
        path = lines[0].split()[1]
        headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
        c = Conn(s, path, headers)
        self.conns.append(c)
        if self.delay_next:
            d, self.delay_next = self.delay_next, 0
            time.sleep(d)
        if self.refuse_next:
            self.refuse_next = False
            body = b'{"error":{"message":"Incorrect API key provided"}}'
            s.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
            s.close()
            c.closed = True
            return
        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        try:
            s.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode())
        except OSError:
            c.closed = True
            return
        buf, t_phase = b"", 0
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                buf += d
                while len(buf) >= 2:
                    op, n, off = buf[0] & 0x0F, buf[1] & 0x7F, 2
                    if n == 126:
                        n, off = struct.unpack(">H", buf[2:4])[0], 4
                    elif n == 127:
                        n, off = struct.unpack(">Q", buf[2:10])[0], 10
                    if len(buf) < off + 4 + n:
                        break
                    mask, payload = buf[off:off + 4], bytearray(buf[off + 4:off + 4 + n])
                    buf = buf[off + 4 + n:]
                    for i in range(n):
                        payload[i] ^= mask[i & 3]
                    if op == 8:
                        raise EOFError
                    if op in (1, 2):
                        m = json.loads(payload)
                        c.msgs.append(m)
                        t_phase = self.react(c, m, t_phase)
        except (EOFError, OSError):
            pass
        c.closed = True
        s.close()

    def react(self, c, m, phase):
        if c.path.startswith("/v1/realtime"):
            t = m.get("type")
            if t == "session.update":
                instr = m["session"]["instructions"]
                if "HANGUP" in instr:
                    threading.Timer(1.0, lambda: c.send({"type": "response.output_item.done", "item": {"type": "function_call", "name": "end_call", "call_id": "call_9", "arguments": "{}"}})).start()
                if "CLOSE" in instr:
                    threading.Timer(1.0, lambda: (c.sock.shutdown(socket.SHUT_RDWR))).start()
            elif t == "input_audio_buffer.append":
                c.send({"type": "response.output_audio.delta", "item_id": "item_1", "delta": m["audio"]})
        else:
            if "setup" in m:
                c.send({"setupComplete": {}}, binary=True)
            elif "realtimeInput" in m:
                n = len(base64.b64decode(m["realtimeInput"]["audio"]["data"])) // 2
                out = tone(1000, 24000, n * 3 // 2, phase)
                c.send({"serverContent": {"modelTurn": {"parts": [{"inlineData": {"mimeType": "audio/pcm;rate=24000", "data": base64.b64encode(struct.pack("<%dh" % len(out), *out)).decode()}}]}}}, binary=True)
                return phase + len(out)
        return phase


# --------------------------------------------------------------- SIP UAC ---
sip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sip.bind(("127.0.0.1", UAC))


def sdp(port, pts=(0, 8, 101), proto="RTP/AVP"):
    body = f"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {port} {proto} {' '.join(map(str, pts))}\r\na=rtpmap:101 telephone-event/8000\r\n"
    return body


def request(method, cid, cseq, extra="", body="", to_tag="", branch=None, ruri=f"sip:ai@127.0.0.1:{PROXY}"):
    branch = branch or f"z9hG4bK{random.randrange(1 << 30)}"
    tt = f";tag={to_tag}" if to_tag else ""
    ctype = "Content-Type: application/sdp\r\n" if body else ""
    msg = (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{UAC};branch={branch};rport\r\n"
           f"From: <sip:caller@127.0.0.1>;tag=c{cid}\r\nTo: <sip:ai@127.0.0.1>{tt}\r\nCall-ID: {cid}\r\nCSeq: {cseq} {method}\r\n"
           f"Contact: <sip:caller@127.0.0.1:{UAC}>\r\nMax-Forwards: 70\r\n{extra}{ctype}Content-Length: {len(body.encode())}\r\n\r\n{body}")
    sip.sendto(msg.encode(), ("127.0.0.1", PROXY))
    return branch


inbox = []


def recv_sip(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        for m in inbox:
            if pred(m):
                inbox.remove(m)
                return m
        sip.settimeout(max(0.01, end - time.time()))
        try:
            inbox.append(sip.recv(65535).decode(errors="replace"))
        except socket.timeout:
            pass
    return None


def hdr(m, name):
    for l in m.split("\r\n"):
        if l.lower().startswith(name.lower() + ":"):
            return l.split(":", 1)[1].strip()
    return ""


def resp(cid, code=None, method="INVITE"):
    return lambda m: m.startswith("SIP/2.0") and hdr(m, "Call-ID") == cid and hdr(m, "CSeq").endswith(method) and (code is None or m.split()[1] == str(code))


def answer_bye(m):
    """200 to a BYE from the proxy."""
    vias = "".join(l + "\r\n" for l in m.split("\r\n") if l.lower().startswith("via:"))
    r = f"SIP/2.0 200 OK\r\n{vias}From: {hdr(m, 'From')}\r\nTo: {hdr(m, 'To')}\r\nCall-ID: {hdr(m, 'Call-ID')}\r\nCSeq: {hdr(m, 'CSeq')}\r\nContent-Length: 0\r\n\r\n"
    sip.sendto(r.encode(), ("127.0.0.1", PROXY))


def media(m):
    body = m.split("\r\n\r\n", 1)[1]
    ma = next(l for l in body.split("\r\n") if l.startswith("m=audio"))
    port, pt = int(ma.split()[1]), int(ma.split()[3])
    return port, pt


def rtp_packet(seq, ts, pt, payload):
    return struct.pack(">BBHII", 0x80, pt, seq, ts, 0x1234) + bytes(payload)


def converse(rtp, dst, pt, frames, encode, seconds=1.0):
    """Send `frames` 20 ms frames (tone) and collect what comes back."""
    got, seq = [], 0
    rtp.settimeout(0.005)
    start = time.time()
    for i in range(frames):
        pcm = tone(440, 8000, 160, i * 160)
        rtp.sendto(rtp_packet(seq, i * 160, pt, [encode(s) for s in pcm]), dst)
        seq += 1
        until = start + (i + 1) * 0.02
        while time.time() < until:
            try:
                got.append(rtp.recv(2048))
            except socket.timeout:
                pass
    end = time.time() + seconds
    while time.time() < end:
        try:
            got.append(rtp.recv(2048))
        except socket.timeout:
            pass
    return got


def ferroctl(*a):
    r = subprocess.run([f"{ROOT}/target/release/ferroctl", "-s", f"{ROOT}/target/e2e_ai.sock", *a], capture_output=True, text=True)
    return r.stdout


def web(path):
    c = http.client.HTTPConnection("127.0.0.1", WEB, timeout=5)
    c.request("GET", "/api/v1/" + path, headers={"Authorization": "Basic " + base64.b64encode(b"admin:pw").decode()})
    r = c.getresponse()
    return r.status, json.loads(r.read() or b"null")


def invite(cid, provider, prompt, rtp_port, extra="", pts=(0, 8, 101), proto="RTP/AVP"):
    hdrs = f"X-AI-Provider: {provider}\r\nX-AI-Prompt: {prompt}\r\n{extra}"
    return request("INVITE", cid, 1, hdrs, sdp(rtp_port, pts, proto))


def call_up(cid, provider, prompt, extra="", pts=(0, 8, 101)):
    port = next(RTP_PORTS)
    rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtp.bind(("127.0.0.1", port))
    invite(cid, provider, prompt, port, extra, pts)
    ok = recv_sip(resp(cid, 200))
    if ok:
        request("ACK", cid, 1, to_tag=hdr(ok, "To").split("tag=")[1])
    return ok, rtp


# A private CA (given to ferrosip as tls_ca_file) and a localhost
# certificate it signed: the mock's wss:// listener.
CA, CAKEY = f"{ROOT}/target/e2e_ai_ca.crt", f"{ROOT}/target/e2e_ai_ca.key"
CERT, KEY = f"{ROOT}/target/e2e_ai.crt", f"{ROOT}/target/e2e_ai.key"
ossl = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)
ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=e2e test CA", "-keyout", CAKEY, "-out", CA)
ossl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", KEY, "-out", CERT + ".csr")
ext = f"{ROOT}/target/e2e_ai.ext"
open(ext, "w").write("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
ossl("x509", "-req", "-in", CERT + ".csr", "-CA", CA, "-CAkey", CAKEY, "-CAcreateserial", "-days", "2", "-extfile", ext, "-out", CERT)

CFG = f"""loadmodule "sl"
loadmodule "textops"
loadmodule "tm"
loadmodule "ai"
loadmodule "webui"
modparam("webui", "listen", "127.0.0.1:{WEB}")
modparam("webui", "user", "admin")
modparam("webui", "password_hash", "sha256:s:{hashlib.sha256(b"spw").hexdigest()}")
modparam("ai", "openai_url", "ws://127.0.0.1:{WS}/v1/realtime")
modparam("ai", "openai_model", "test-model")
modparam("ai", "openai_key", "sk-test")
modparam("ai", "openai_voice", "verse")
modparam("ai", "gemini_url", "wss://localhost:{WSS}/gemini")
modparam("ai", "tls_ca_file", "{CA}")
modparam("ai", "gemini_model", "gem-test")
modparam("ai", "gemini_key", "gk-test")
modparam("ai", "media_ip", "127.0.0.1")
modparam("ai", "rtp_port_min", 7620)
modparam("ai", "rtp_port_max", 7639)
modparam("ai", "rtp_timeout", 3)
modparam("ai", "connect_timeout", 5000)

request_route {{
    if (ai_dialog()) exit;
    if (is_method("INVITE")) {{
        if (is_present_hf("X-AI-Voice")) {{
            ai_answer("$hdr(X-AI-Provider)", "$hdr(X-AI-Prompt)", "$hdr(X-AI-Voice)");
        }} else {{
            ai_answer("$hdr(X-AI-Provider)", "$hdr(X-AI-Prompt)");
        }}
        exit;
    }}
    sl_send_reply(404, "Not Here");
}}
"""

mock = Mock()
cfg = f"{ROOT}/target/e2e_ai.cfg"
open(cfg, "w").write(CFG)
proxy = subprocess.Popen([f"{ROOT}/target/release/ferrosip", "-f", cfg, "-l", f"udp:127.0.0.1:{PROXY}", "--rpc-socket", f"{ROOT}/target/e2e_ai.sock"],
                         stderr=subprocess.PIPE, text=True)
wait_listening(proxy)
log = []
threading.Thread(target=lambda: [log.append(l) for l in proxy.stderr], daemon=True).start()

try:
    # ---------------------------------------------------- OpenAI, PCMU ---
    PROMPT = "You are Ada, a test bot. Answer in one word."
    port = next(RTP_PORTS)
    rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtp.bind(("127.0.0.1", port))
    br = invite("oa-1", "openai", PROMPT, port)
    check("openai: 100 Trying first", recv_sip(resp("oa-1", 100), 1) is not None)
    time.sleep(0.05)
    invite("oa-1", "openai", PROMPT, port)  # retransmission (new branch is fine for the test)
    ok = recv_sip(resp("oa-1", 200))
    check("openai: 200 OK with an SDP answer", ok is not None and "m=audio" in ok, ok)
    port_ai, pt = media(ok)
    check("openai: PCMU chosen, RTP port from the range", pt == 0 and 7620 <= port_ai <= 7639, (pt, port_ai))
    check("openai: Contact in the 200", "sip:ai@127.0.0.1" in hdr(ok, "Contact"), hdr(ok, "Contact"))
    to_tag = hdr(ok, "To").split("tag=")[1]
    request("ACK", "oa-1", 1, to_tag=to_tag)
    got = converse(rtp, ("127.0.0.1", port_ai), 0, 50, lin2ulaw)
    sent = {bytes(lin2ulaw(s) for s in tone(440, 8000, 160, i * 160)) for i in range(50)}
    payloads = [p[12:] for p in got]
    check("openai: RTP flows back (~50 packets/s)", len(got) >= 50, len(got))
    check("openai: the echoed audio arrives byte for byte", sum(p in sent for p in payloads) >= 40, sum(p in sent for p in payloads))
    oa = [c for c in mock.conns if c.path.startswith("/v1/realtime")]
    check("openai: one session for a retransmitted INVITE", len(oa) == 1, len(oa))
    c = oa[0]
    check("openai: model in the URL, key as a bearer token", "model=test-model" in c.path and c.headers.get("authorization") == "Bearer sk-test", (c.path, c.headers.get("authorization")))
    su = c.of(lambda m: m.get("type") == "session.update")
    s = su[0]["session"] if su else {}
    check("openai: the header's prompt is the instructions", s.get("instructions") == PROMPT, s.get("instructions"))
    check("openai: µ-law both ways, the configured voice, end_call tool",
          s.get("audio", {}).get("input", {}).get("format", {}).get("type") == "audio/pcmu" and s.get("audio", {}).get("output", {}).get("voice") == "verse"
          and s.get("tools", [{}])[0].get("name") == "end_call", s)
    check("openai: asks the model to greet the caller", len(c.of(lambda m: m.get("type") == "response.create")) == 1)
    check("openai: caller audio sent as input_audio_buffer.append", len(c.of(lambda m: m.get("type") == "input_audio_buffer.append")) >= 45)
    invite("oa-1", "openai", PROMPT, port)
    check("openai: a late INVITE retransmission gets the 200 again", recv_sip(resp("oa-1", 200), 2) is not None)
    lst = json.loads(ferroctl("ai.list") or "[]")
    code, page = web("ai-calls")
    row = (page or {}).get("rows", [{}])[0] if page and page.get("rows") else {}
    check("webui: /api/v1/ai-calls shows the call with its prompt", code == 200 and page["total"] == 1 and row.get("state") == "up" and row.get("provider") == "openai" and row.get("prompt") == PROMPT, (code, page))
    check("webui: meta lists the AI paths under calls", {"ai-calls", "ai-calls/recent"} <= set(web("meta")[1]["sections"].get("calls", [])))
    check("openai: ai.list shows the call", len(lst) == 1 and lst[0]["provider"] == "openai" and lst[0]["state"] == "up" and lst[0]["rtp_in"] >= 50, lst)
    request("BYE", "oa-1", 2, to_tag=to_tag)
    check("openai: BYE answered 200", recv_sip(resp("oa-1", 200, "BYE")) is not None)
    time.sleep(0.5)
    check("openai: provider session closed on BYE", c.closed)
    check("openai: ai.list empty afterwards", json.loads(ferroctl("ai.list") or "null") == [])
    rtp.close()

    # ---------------------------------------------------- Gemini, PCMA ---
    GPROMPT = "Line one: you are Gemma.\nLine two: speak slowly."
    b64 = "b64:" + base64.b64encode(GPROMPT.encode()).decode()
    ok, rtp = call_up("gm-1", "gemini", b64, "X-AI-Voice: Kore\r\n", pts=(8, 101))
    check("gemini: 200 OK", ok is not None)
    port_ai, pt = media(ok)
    check("gemini: PCMA chosen", pt == 8, pt)
    time.sleep(0.3)
    got = converse(rtp, ("127.0.0.1", port_ai), 8, 50, lin2alaw)
    loud = [p for p in got if (sum(alaw2lin(b) ** 2 for b in p[12:]) / 160) ** 0.5 > 3000]
    check("gemini: the 24 kHz answer arrives as audible 8 kHz A-law", len(loud) >= 30, f"{len(loud)} loud of {len(got)}")
    gm = [c for c in mock.conns if c.path.startswith("/gemini")][0]
    check("gemini: API key in the URL", "key=gk-test" in gm.path, gm.path)
    check("gemini: over TLS (wss://)", isinstance(gm.sock, ssl.SSLSocket))
    st = gm.msgs[0].get("setup", {})
    check("gemini: setup carries model, the decoded prompt and the call's voice",
          st.get("model") == "models/gem-test" and st.get("systemInstruction", {}).get("parts", [{}])[0].get("text") == GPROMPT
          and st["generationConfig"]["speechConfig"]["voiceConfig"]["prebuiltVoiceConfig"]["voiceName"] == "Kore", st)
    ups = gm.of(lambda m: "realtimeInput" in m)
    rates = {m["realtimeInput"]["audio"]["mimeType"] for m in ups}
    avg = sum(len(base64.b64decode(m["realtimeInput"]["audio"]["data"])) // 2 for m in ups) / max(1, len(ups))
    check("gemini: caller audio up as 16 kHz PCM", rates == {"audio/pcm;rate=16000"} and 300 <= avg <= 330, (rates, avg))
    check("gemini: greeting sent after setupComplete", len(gm.of(lambda m: "clientContent" in m)) == 1)
    to_tag = hdr(ok, "To").split("tag=")[1]
    request("BYE", "gm-1", 2, to_tag=to_tag)
    check("gemini: BYE answered", recv_sip(resp("gm-1", 200, "BYE")) is not None)
    rtp.close()

    # ------------------------------------------------- AI ends the call ---
    ok, rtp = call_up("hang-1", "openai", "HANGUP after one second")
    port_ai, _ = media(ok)
    converse(rtp, ("127.0.0.1", port_ai), 0, 10, lin2ulaw, 0)
    bye = recv_sip(lambda m: m.startswith("BYE ") and hdr(m, "Call-ID") == "hang-1", 5)
    check("end_call: ferrosip sends BYE to the caller", bye is not None)
    if bye:
        answer_bye(bye)
        check("end_call: BYE goes to the caller's Contact, from our To-tag",
              bye.startswith(f"BYE sip:caller@127.0.0.1:{UAC} ") and f"tag={hdr(ok, 'To').split('tag=')[1]}" in hdr(bye, "From") and "tag=chang-1" in hdr(bye, "To"), bye)
    hc = [c for c in mock.conns if any("HANGUP" in m.get("session", {}).get("instructions", "") for m in c.msgs)][0]
    check("end_call: the function call is answered", len(hc.of(lambda m: m.get("item", {}).get("type") == "function_call_output")) == 1)
    rtp.close()

    ok, rtp = call_up("drop-1", "openai", "CLOSE after one second")
    port_ai, _ = media(ok)
    converse(rtp, ("127.0.0.1", port_ai), 0, 10, lin2ulaw, 0)
    bye = recv_sip(lambda m: m.startswith("BYE ") and hdr(m, "Call-ID") == "drop-1", 5)
    check("provider drop: the caller gets a BYE", bye is not None)
    if bye:
        answer_bye(bye)
    rtp.close()

    ok, rtp = call_up("quiet-1", "openai", "Say nothing.")
    t0 = time.time()
    bye = recv_sip(lambda m: m.startswith("BYE ") and hdr(m, "Call-ID") == "quiet-1", 8)
    check("no RTP from the caller: BYE after rtp_timeout", bye is not None and 2.5 < time.time() - t0 < 6, time.time() - t0)
    if bye:
        answer_bye(bye)
    rtp.close()

    # ------------------------------------------------------ failures ---
    mock.delay_next = 3
    invite("cancel-1", "openai", "x", next(RTP_PORTS))
    recv_sip(resp("cancel-1", 100), 1)
    time.sleep(0.3)
    request("CANCEL", "cancel-1", 1)
    check("CANCEL while connecting: 200 for the CANCEL", recv_sip(resp("cancel-1", 200, "CANCEL"), 2) is not None)
    r487 = recv_sip(resp("cancel-1", 487), 2)
    check("CANCEL while connecting: 487 for the INVITE (without waiting out the connect)", r487 is not None)
    if r487:
        request("ACK", "cancel-1", 1, to_tag=hdr(r487, "To").split("tag=")[1])

    mock.refuse_next = True
    invite("refused-1", "openai", "x", next(RTP_PORTS))
    r = recv_sip(resp("refused-1", 503), 5)
    check("provider refuses (401): 503 with the reason in a Warning", r is not None and "401" in hdr(r, "Warning"), r)

    invite("codec-1", "openai", "x", next(RTP_PORTS), pts=(9, 101))
    r = recv_sip(resp("codec-1", 488), 2)
    check("no PCMU/PCMA offered: 488", r is not None and "PCMU" in hdr(r, "Warning"), r)
    invite("srtp-1", "openai", "x", next(RTP_PORTS), proto="RTP/SAVP")
    check("SRTP offer: 488", recv_sip(resp("srtp-1", 488), 2) is not None)
    invite("prov-1", "watson", "x", next(RTP_PORTS))
    check("unknown provider: 500", recv_sip(resp("prov-1", 500), 2) is not None)

    time.sleep(0.5)
    code, page = web("ai-calls/recent?limit=50")
    rows = page["rows"] if code == 200 else []
    by = {r["call_id"]: r for r in rows}
    check("webui: recent calls, newest first", [r["call_id"] for r in rows][:3] == ["refused-1", "cancel-1", "quiet-1"], [r["call_id"] for r in rows])
    want = {
        "oa-1": ("answered", "caller hung up"),
        "gm-1": ("answered", "caller hung up"),
        "hang-1": ("answered", "the AI ended the call"),
        "drop-1": ("answered", "AI session closed"),
        "quiet-1": ("answered", "no RTP from the caller"),
        "cancel-1": ("cancelled", "cancelled by the caller"),
        "refused-1": ("failed", "provider unavailable: HTTP/1.1 401"),
    }
    for cid, (outcome, reason) in want.items():
        r = by.get(cid, {})
        check(f"webui: {cid} ended '{outcome}': {reason}", r.get("outcome") == outcome and r.get("reason", "").startswith(reason) and r.get("state") == "ended", r)
    check("webui: the Gemini call keeps its decoded prompt and voice", by.get("gm-1", {}).get("prompt") == GPROMPT and by.get("gm-1", {}).get("voice") == "Kore", by.get("gm-1"))
    code, page = web("ai-calls/recent?q=gemini")
    check("webui: recent calls searchable", code == 200 and page["total"] == 1, page)
    check("ai.recent over RPC matches", [r["call_id"] for r in json.loads(ferroctl("ai.recent") or "[]")] == [r["call_id"] for r in rows])

    stats = ferroctl("stats.get_statistics", "ai:")
    check("stats: ai counters", "ai:calls" in stats and "ai:failed_calls" in stats, stats)
finally:
    proxy.terminate()
    proxy.wait(5)

text = "".join(log)
check("proxy: no panics", "panicked" not in text, text[-600:])
check("proxy: the Gemini key never appears in the log", "gk-test" not in text)
print(f"\n{failures} FAILED" if failures else "\nall passed")
sys.exit(1 if failures else 0)
