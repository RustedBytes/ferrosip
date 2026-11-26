#!/usr/bin/env python3
"""Smoke test of the ferrosip + HOMER example (docker compose up first).

A phone registers as alice; a caller calls her through ferrosip (INVITE,
180, 200, ACK, BYE, 200). Then the script checks that HOMER stored the
call and the REGISTER: it reads them from the database through
`docker compose exec db psql`, and logs in to homer-app's API.

    python3 smoke.py [--proxy 127.0.0.1:5060] [--homer http://127.0.0.1:9080]
Exit status 0 when everything is found.
"""
import argparse, json, socket, subprocess, sys, threading, time, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--proxy", default="127.0.0.1:5060")
ap.add_argument("--homer", default="http://127.0.0.1:9080")
ap.add_argument("--wait", type=int, default=60, help="seconds to wait for HOMER to store the messages")
args = ap.parse_args()
PH, PP = args.proxy.split(":")[0], int(args.proxy.split(":")[1])
ME = "127.0.0.1"
stamp = str(int(time.time()))
CALL, REG = f"smoke-call-{stamp}", f"smoke-reg-{stamp}"
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -- {detail}"))
    failures += 0 if ok else 1


def udp(port=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ME, port))
    s.settimeout(5)
    return s


callee = udp()
caller = udp()
CALLEE, CALLER = callee.getsockname()[1], caller.getsockname()[1]


def headers(m):
    return [h for h in m.split("\r\n")[1:] if h]


def answer_loop():
    """alice's phone: 180 + 200 to INVITE, 200 to BYE."""
    while True:
        try:
            d, a = callee.recvfrom(65535)
        except OSError:
            return
        m = d.decode()
        if m.startswith("ACK") or m.startswith("SIP/2.0"):
            continue
        keep = [h for h in headers(m) if h.split(":", 1)[0].lower() in ("via", "from", "to", "call-id", "cseq", "record-route")]
        keep = [h + ";tag=alice" if h.lower().startswith("to:") and ";tag=" not in h else h for h in keep]
        rr = [h for h in keep if h.lower().startswith("record-route")]
        keep = [h for h in keep if not h.lower().startswith("record-route")]
        if m.startswith("INVITE"):
            callee.sendto(("SIP/2.0 180 Ringing\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n").encode(), a)
            time.sleep(0.2)
        extra = rr + [f"Contact: <sip:alice@{ME}:{CALLEE}>"] if m.startswith("INVITE") else []
        callee.sendto(("SIP/2.0 200 OK\r\n" + "\r\n".join(keep + extra) + "\r\nContent-Length: 0\r\n\r\n").encode(), a)


def request(sock, method, ruri, cid, cseq, to_tag="", extra="", user="bob"):
    """A request from `user` to alice, sent from `sock` (its Contact)."""
    port = sock.getsockname()[1]
    msg = (f"{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP {ME}:{port};branch=z9hG4bK{cid}{cseq}{method};rport\r\n"
           f"Max-Forwards: 70\r\nFrom: <sip:{user}@{PH}>;tag={user}\r\nTo: <sip:alice@{PH}>{to_tag}\r\nCall-ID: {cid}\r\n"
           f"CSeq: {cseq} {method}\r\nContact: <sip:{user}@{ME}:{port}>\r\n{extra}Content-Length: 0\r\n\r\n")
    sock.sendto(msg.encode(), (PH, PP))


def final(sock):
    while True:
        r = sock.recv(65535).decode()
        if r.startswith("SIP/2.0 ") and not r.startswith("SIP/2.0 1"):
            return r


# alice's phone registers (its Contact is the callee socket).
request(callee, "REGISTER", f"sip:{PH}", REG, 1, extra="Expires: 300\r\n", user="alice")
r = callee.recv(65535).decode()
check("REGISTER → 200", r.startswith("SIP/2.0 200"), r.split("\r\n", 1)[0])

threading.Thread(target=answer_loop, daemon=True).start()

# bob calls alice through ferrosip.
request(caller, "INVITE", f"sip:alice@{PH}", CALL, 1)
r = final(caller)
check("INVITE alice through ferrosip → 200", r.startswith("SIP/2.0 200"), r.split("\r\n", 1)[0])
to = next(h for h in headers(r) if h.lower().startswith("to:"))
rr = [h.split(":", 1)[1].strip() for h in headers(r) if h.lower().startswith("record-route")]
route = "".join(f"Route: {x}\r\n" for x in reversed(rr))
contact = next(h for h in headers(r) if h.lower().startswith("contact:")).split("<", 1)[1].split(">", 1)[0]
tag = ";tag=" + to.split(";tag=", 1)[1]
request(caller, "ACK", contact, CALL, 1, tag, route)
time.sleep(0.3)
request(caller, "BYE", contact, CALL, 2, tag, route)
r = final(caller)
check("BYE → 200", r.startswith("SIP/2.0 200"), r.split("\r\n", 1)[0])


def psql(sql):
    out = subprocess.run(["docker", "compose", "exec", "-T", "db", "psql", "-U", "root", "-d", "homer_data", "-tAc", sql],
                         capture_output=True, text=True, timeout=30)
    return out.stdout.strip() or out.stderr.strip()


def stored(table, cid):
    return psql(f"SELECT count(*) FROM {table} WHERE sid = '{cid}'")


deadline = time.time() + args.wait
calls = regs = "0"
while time.time() < deadline:
    calls, regs = stored("hep_proto_1_call", CALL), stored("hep_proto_1_registration", REG)
    if calls.isdigit() and int(calls) >= 12 and regs.isdigit() and int(regs) >= 2:
        break
    time.sleep(2)
# The call is INVITE, 100, 180, 200, ACK, BYE and 200, each received and sent (14).
check("HOMER stored the call (hep_proto_1_call: INVITE/180/200/ACK/BYE/200, in and out)", calls.isdigit() and int(calls) >= 12, calls)
check("HOMER stored the REGISTER and its 200 (hep_proto_1_registration)", regs.isdigit() and int(regs) >= 2, regs)
logs = psql(f"SELECT count(*) FROM hep_proto_100_default WHERE sid = '{CALL}'")
check("HOMER stored ferrosip's hlog() record (hep_proto_100_default)", logs.isdigit() and int(logs) >= 1, logs)

try:
    req = urllib.request.Request(f"{args.homer}/api/v3/auth", data=json.dumps({"username": "admin", "password": "sipcapture"}).encode(),
                                 headers={"Content-Type": "application/json"})
    token = json.load(urllib.request.urlopen(req, timeout=10)).get("token")
    check("homer-app: log in as admin", bool(token), token)
except Exception as e:  # noqa: BLE001
    check("homer-app: log in as admin", False, e)

print(f"\ncall-id {CALL}: search for it in HOMER ({args.homer}, admin / sipcapture)")
print("all passed" if failures == 0 else f"{failures} FAILED")
sys.exit(1 if failures else 0)
