"""l10-mysql-accounting: acc rows (answered / missed: busy, no answer,
canceled) and dialog CDRs in MariaDB, dialogs stored with db_mode so a BYE
after a proxy restart still ends the call and writes its CDR, and the
database down while a call ends."""
import threading, time

import sipkit


def wait_for(pred, timeout):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.1)
    return pred()


def code(r):
    return r.code if r is not None else None


def pbx_handler(pbx):
    """The PBX answers by R-URI user: busy → 486; ring → 180 at once, and
    noanswer → 180 after 1.5s, then nothing more (until a CANCEL: 200 +
    487); anything else → 200 with SDP (a local helper: auto_answer gives
    every call the same answer)."""
    def h(m):
        if m.method == "INVITE":
            user = m.ruri.split("@")[0].split(":")[-1]
            if user == "busy":
                return (486, "Busy Here")
            if user == "ring":
                pbx.respond(m, 180, "Ringing")
                return None
            if user == "noanswer":
                threading.Timer(1.5, pbx.respond, (m, 180, "Ringing")).start()
                return None
            return (200, "OK", None, sipkit.sdp(pbx.port + 1000))
        if m.method == "CANCEL":
            pbx.respond(m, 200)
            inv = next((x for x in reversed(pbx.received) if x.method == "INVITE" and x.get("call-id") == m.get("call-id")), None)
            if inv is not None:
                pbx.respond(inv, 487, "Request Terminated")
            return None
        if m.method == "BYE":
            return (200, "OK")
        return None
    pbx.handler = h


def run(sc):
    if not sipkit.built_with("db-mysql"):
        sc.skip("ferrosip built without db-mysql (cargo build --features ferrosip/db-all)")
    if not sipkit.MariaDb.available():
        sc.skip("mariadb-server not installed")
    db = sipkit.MariaDb(sc.port(), sc.tmp).start()
    sc.closers.append(db.stop)

    def rows(table, cols, cid, key="callid"):
        return db.sql(f"SELECT {cols} FROM {table} WHERE {key} = '{cid}'")

    def acc(cid):
        return rows("acc", "method, sip_code, src_user, dst_user", cid)

    def missed(cid):
        return rows("missed_calls", "method, sip_code, src_user, dst_user", cid)

    def cdrs(cid):
        return rows("cdrs", "src_username, dst_username, duration, call_start_time", cid, key="sip_call_id")

    def dialogs(cid):
        return rows("dialog", "state", cid)

    pbx = sc.ua("pbx", sc.port())
    pbx_handler(pbx)
    sip = sc.port()
    px = sc.proxy(env=sc.env(SIP_PORT=sip, CALLEE=f"sip:127.0.0.1:{pbx.port}", DB_URL=db.url))
    alice = sc.ua("alice", sip)

    # --- Answered: acc row, a dialog row while it lasts, a CDR at the end.
    t0 = time.time()
    r, d = alice.call("sip:200@example.com", timeout=6)
    sc.check("alice → 200: answered (200)", code(r) == 200 and d is not None, r)
    cid = d.call_id if d else "-"
    sc.check("…an acc row: INVITE 200, src_user alice, dst_user 200",
             wait_for(lambda: acc(cid) == [["INVITE", "200", "alice", "200"]], 3), acc(cid))
    sc.check("…its dialog is in the dialog table while the call lasts", wait_for(lambda: dialogs(cid), 3), dialogs(cid))
    time.sleep(1.2)
    bye = d.bye() if d else None
    held = time.time() - t0
    sc.check("…caller BYE → 200", code(bye) == 200, bye)
    c = wait_for(lambda: cdrs(cid), 3)
    sc.check("…one CDR row: alice → 200", c and len(c) == 1 and c[0][0] == "alice" and c[0][1] == "200", c)
    sc.check(f"…duration 1..{held + 1:.0f}s (held {held:.1f}s), start near the call's",
             c and 1 <= int(c[0][2]) <= held + 1 and abs(int(c[0][3]) - t0) <= 3, c)
    sc.check("…the dialog row is deleted when the call ends", wait_for(lambda: not dialogs(cid), 3), dialogs(cid))
    sc.check("…no missed_calls row for an answered call", missed(cid) == [], missed(cid))

    # --- Missed: busy, no answer, canceled.
    r, _ = alice.call("sip:busy@example.com", timeout=6)
    cid = r.get("call-id") if r is not None else "-"
    sc.check("alice → busy: 486", code(r) == 486, r)
    sc.check("…a missed_calls row with 486", wait_for(lambda: missed(cid) == [["INVITE", "486", "alice", "busy"]], 3), missed(cid))
    sc.check("…no acc row, no CDR, no dialog row", acc(cid) == [] and cdrs(cid) == [] and dialogs(cid) == [],
             (acc(cid), cdrs(cid), dialogs(cid)))

    # The PBX rings after 1.5s and never answers: fr_inv_timer (3s) runs
    # from the 180 (RFC 3261 timer C, Kamailio's tm), so 408 about 4.5s
    # after the INVITE; fr_timer (2s) only covers the wait for the 1xx.
    sent = alice.invite("sip:noanswer@example.com")
    cid = sent["call_id"]
    t0 = time.time()
    ring = alice.recv(5, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == cid)
    t180 = time.time()
    r = alice.final(12, method="INVITE", call_id=cid, cseq=sent["cseq"])
    t408 = time.time()
    if r is not None:
        alice._ack_neg(sent, r)
    sc.check("alice → noanswer: 180 after about 1.5s", ring is not None and 1.0 <= t180 - t0 <= 3, t180 - t0)
    sc.check(f"…then 408 fr_inv_timer (3s) after the 180 (got {code(r)} {t408 - t180:.1f}s after the 180, {t408 - t0:.1f}s after the INVITE)",
             code(r) == 408 and 2.5 <= t408 - t180 <= 5.5, (r, t408 - t180))
    sc.check("…a missed_calls row with 408", wait_for(lambda: missed(cid) == [["INVITE", "408", "alice", "noanswer"]], 3), missed(cid))
    sc.check("…no acc row and no CDR", acc(cid) == [] and cdrs(cid) == [], (acc(cid), cdrs(cid)))

    sent = alice.invite("sip:ring@example.com")
    cid = sent["call_id"]
    ring = alice.recv(4, lambda m: m.is_reply and m.code == 180 and m.get("call-id") == cid)
    sc.check("alice → ring: 180", ring is not None, ring)
    alice.cancel(sent)
    r = alice.final(6, method="INVITE", call_id=cid, cseq=sent["cseq"])
    sc.check("…alice CANCELs: 487", code(r) == 487, r)
    if r is not None:
        alice._ack_neg(sent, r)
    sc.check("…a missed_calls row with 487 for the INVITE", wait_for(lambda: missed(cid) == [["INVITE", "487", "alice", "ring"]], 3), missed(cid))
    sc.check("…no acc row (the CANCEL isn't accounted) and no CDR", acc(cid) == [] and cdrs(cid) == [], (acc(cid), cdrs(cid)))

    # --- A BYE after a proxy restart: the dialog comes back from the table.
    t0 = time.time()
    r, d = alice.call("sip:201@example.com", timeout=6)
    sc.check("alice → 201: 200", code(r) == 200 and d is not None, r)
    cid = d.call_id if d else "-"
    sc.check("…dialog row stored", wait_for(lambda: dialogs(cid), 3), dialogs(cid))
    time.sleep(1.2)
    px.stop()
    px.start()
    lst = px.rpc("dlg.list")
    sc.check("after a proxy restart dlg.list has the call again (loaded from the dialog table)",
             isinstance(lst, list) and any(x.get("call-id") == cid for x in lst), lst)
    bye = d.bye(timeout=5) if d else None
    held = time.time() - t0
    sc.check("…alice's BYE through the restarted proxy → 200", code(bye) == 200, bye)
    sc.check("…the PBX got that BYE", wait_for(lambda: any(m.method == "BYE" and m.get("call-id") == cid for m in pbx.received), 3))
    c = wait_for(lambda: cdrs(cid), 3)
    sc.check("…the CDR is written (the restored dialog ended)", c and len(c) == 1 and c[0][0] == "alice", c)
    sc.check(f"…its duration counts from the answer before the restart (1..{held + 1:.0f}s)",
             c and 1 <= int(c[0][2]) <= held + 1, (c, held))
    sc.check("…the dialog row is deleted", wait_for(lambda: not dialogs(cid), 3), dialogs(cid))

    # --- The database down while a call ends.
    r, d = alice.call("sip:202@example.com", timeout=6)
    sc.check("alice → 202: 200", code(r) == 200 and d is not None, r)
    cid = d.call_id if d else "-"
    sc.check("…dialog row stored", wait_for(lambda: dialogs(cid), 3), dialogs(cid))
    db.stop()
    t0 = time.time()
    bye = d.bye(timeout=8) if d else None
    took = time.time() - t0
    sc.check("database down: alice's BYE still gets 200", code(bye) == 200, bye)
    sc.check(f"…at once (took {took:.1f}s, < 3s)", took < 3, took)
    r, d2 = alice.call("sip:203@example.com", timeout=8)
    sc.check("database down: a new call is still connected (200)", code(r) == 200, r)
    if d2:
        d2.bye(timeout=8)
    sc.check("…the proxy logs that the CDR couldn't be written (ERROR: acc: writing cdrs …)",
             wait_for(lambda: any(l.startswith("ERROR: acc: writing cdrs") for l in list(px.lines)), 3),
             "".join(px.lines[-8:]))
    db.start(first=False)
    ghost = cid
    sc.check("database back: the row of the call that ended during the outage is left behind (the delete failed; "
             "nothing retries it, as in Kamailio)", dialogs(ghost) != [], dialogs(ghost))
    r, d = alice.call("sip:204@example.com", timeout=6)
    sc.check("database back: alice → 204: 200", code(r) == 200 and d is not None, r)
    cid = d.call_id if d else "-"
    sc.check("…its acc row is written (the proxy reconnected)", wait_for(lambda: acc(cid), 3), acc(cid))
    if d:
        d.bye()
    sc.check("…and its CDR", wait_for(lambda: cdrs(cid), 3), cdrs(cid))
    sc.check("the proxy kept running", px.p.poll() is None)
    px.stop()
    px.start()
    lst = px.rpc("dlg.list")
    sc.check("after the next restart the call that ended during the outage is loaded as a live dialog (its stale row)",
             isinstance(lst, list) and any(x.get("call-id") == ghost for x in lst), lst)
