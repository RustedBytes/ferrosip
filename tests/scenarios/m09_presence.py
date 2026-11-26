"""m09-presence: PUBLISH, SUBSCRIBE/NOTIFY (presence and dialog events),
publication expiry, a resource list (rls), dialog-info published from a
routed call (pua_dialoginfo)."""
import os, re, shutil, time

import sipkit


def pidf(entity, tid, basic, note=None):
    n = f"<note>{note}</note>" if note else ""
    return (f'<?xml version="1.0" encoding="UTF-8"?><presence xmlns="urn:ietf:params:xml:ns:pidf" entity="{entity}">'
            f'<tuple id="{tid}"><status><basic>{basic}</basic></status>{n}</tuple></presence>')


def dialog_info(entity, did, state, version=0):
    return (f'<?xml version="1.0"?><dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info" version="{version}" state="full" '
            f'entity="{entity}"><dialog id="{did}" direction="recipient"><state>{state}</state></dialog></dialog-info>')


def phone(sc, sip, user):
    """A UA that answers NOTIFYs (200) and calls; NOTIFYs stay in .received."""
    u = sc.ua(user, sip)
    u.auto_answer()
    return u


def notifies(u, cid):
    return [m for m in list(u.received) if m.method == "NOTIFY" and m.get("call-id") == cid]


def wait_notify(u, cid, n, timeout=5.0):
    """The n-th NOTIFY (1-based) of subscription `cid`, or None."""
    end = time.time() + timeout
    while time.time() < end:
        ns = notifies(u, cid)
        if len(ns) >= n:
            return ns[n - 1]
        time.sleep(0.1)
    ns = notifies(u, cid)
    return ns[n - 1] if len(ns) >= n else None


def basic(m):
    return re.findall(r"<basic>(\w+)</basic>", m.body if m else "")


class Sub:
    """A SUBSCRIBE dialog from `u` to `ruri`."""

    def __init__(self, u, ruri, event, expires=60, headers=None):
        self.u, self.ruri, self.event = u, ruri, event
        hs = {"Event": event, "Expires": str(expires), **(headers or {})}
        self.sent = u.request("SUBSCRIBE", ruri, headers=hs)
        self.cid, self.cseq = self.sent["call_id"], 1
        self.reply = u.final(method="SUBSCRIBE", call_id=self.cid, cseq=1)
        self.to = self.reply.get("to") if self.reply is not None else None

    def again(self, expires):
        self.cseq += 1
        target = sipkit.uri_of(self.reply.get("contact") or "") or self.ruri
        self.u.request("SUBSCRIBE", target, to=self.to, call_id=self.cid, from_tag=self.sent["from_tag"], cseq=self.cseq,
                       headers={"Event": self.event, "Expires": str(expires)})
        return self.u.final(method="SUBSCRIBE", call_id=self.cid, cseq=self.cseq)


def publish(u, ruri, event, body, expires=None, etag=None, ctype="application/pidf+xml"):
    hs = {"Event": event}
    if expires is not None:
        hs["Expires"] = str(expires)
    if etag:
        hs["SIP-If-Match"] = etag
    s = u.request("PUBLISH", ruri, headers=hs, body=body, content_type=ctype)
    return u.final(method="PUBLISH", call_id=s["call_id"])


def run(sc):
    sip = sc.port()
    bob = phone(sc, sip, "bob")              # bob's phone: also the callee of calls
    db = os.path.join(sc.tmp, "db")
    shutil.copytree(os.path.join(sc.dir, "db"), db)
    px = sc.proxy(env=sc.env(SIP_PORT=sip, CALLEE=f"sip:127.0.0.1:{bob.port}", RLS_DB=f"text://{db}"))
    watcher = phone(sc, sip, "watcher")
    dev = sc.ua("bobdesk", sip)              # bob's desk client, publishes for bob
    alice = sc.ua("alice", sip)
    bob_aor, alice_aor, carol_aor = "sip:bob@example.com", "sip:alice@example.com", "sip:carol@example.com"

    # ---------------------------------------------------------- presence
    s = Sub(watcher, bob_aor, "presence")
    sc.check("SUBSCRIBE presence for bob → 200 with Expires", s.reply is not None and s.reply.code == 200 and s.reply.get("expires") == "60",
             s.reply and s.reply.raw)
    n1 = wait_notify(watcher, s.cid, 1)
    sc.check("…initial NOTIFY: Subscription-State active, Event presence",
             n1 is not None and (n1.get("subscription-state") or "").startswith("active") and n1.get("event") == "presence", n1 and n1.raw)
    sc.check("…no publication yet: the dummy PIDF says closed (force_dummy_presence)", basic(n1) == ["closed"], n1 and n1.body)

    r = publish(dev, bob_aor, "presence", pidf(bob_aor, "desk", "open", "at desk"), expires=7200)
    etag = r.get("sip-etag") if r is not None else None
    sc.check("PUBLISH open → 200 with SIP-ETag", r is not None and r.code == 200 and etag, r and r.raw)
    sc.check("…Expires 7200 cut to max_expires (30m = 1800)", r is not None and r.get("expires") == "1800", r and r.get("expires"))
    n2 = wait_notify(watcher, s.cid, 2)
    sc.check("…the watcher is notified: open, with the published note", basic(n2) == ["open"] and "at desk" in n2.body, n2 and n2.body)
    sc.check("…as application/pidf+xml", n2 is not None and (n2.get("content-type") or "").startswith("application/pidf+xml"),
             n2 and n2.get("content-type"))
    show = px.rpc("presence.presentity_show", bob_aor)
    sc.check("presence.presentity_show has the open state", "open" in str(show), show)

    # A second device: both tuples aggregated in one document.
    r2 = publish(bob, bob_aor, "presence", pidf(bob_aor, "mobile", "closed"), expires=3)
    sc.check("second device PUBLISH (Expires 3) → 200, its own entity tag",
             r2 is not None and r2.code == 200 and r2.get("sip-etag") and r2.get("sip-etag") != etag, r2 and r2.raw)
    n3 = wait_notify(watcher, s.cid, 3)
    sc.check("…NOTIFY aggregates both devices (two tuples)", sorted(basic(n3)) == ["closed", "open"], n3 and n3.body)
    # It expires: the watcher is told, the desk publication stays.
    n4 = wait_notify(watcher, s.cid, 4, timeout=10)
    sc.check("…the 3s publication expires: NOTIFY with only the desk tuple left", basic(n4) == ["open"] and "mobile" not in n4.body,
             n4 and n4.body)

    # Refresh with SIP-If-Match (no body), a new body, an unknown entity tag.
    r = publish(dev, bob_aor, "presence", "", expires=60, etag=etag)
    etag2 = r.get("sip-etag") if r is not None else None
    sc.check("refresh with SIP-If-Match and no body → 200, a new entity tag", r is not None and r.code == 200 and etag2 and etag2 != etag,
             r and r.raw)
    r = publish(dev, bob_aor, "presence", pidf(bob_aor, "desk", "closed", "lunch"), expires=60, etag=etag2)
    etag3 = r.get("sip-etag") if r is not None else None
    sc.check("modify with SIP-If-Match and a body → 200", r is not None and r.code == 200, r)
    n = wait_notify(watcher, s.cid, 5)
    sc.check("…the watcher sees the change (closed, lunch)", basic(n) == ["closed"] and "lunch" in n.body, n and n.body)
    r = publish(dev, bob_aor, "presence", "", expires=60, etag="no-such-etag")
    sc.check("SIP-If-Match with an unknown entity tag → 412", r is not None and r.code == 412, r)
    r = publish(dev, bob_aor, "presence", "", expires=60)
    sc.check("a new PUBLISH without a body → 400", r is not None and r.code == 400, r)
    r = publish(dev, bob_aor, "message-summary", "Messages-Waiting: yes\r\n", expires=60, ctype="application/simple-message-summary")
    sc.check("PUBLISH for an unknown event package → 489 with Allow-Events", r is not None and r.code == 489 and r.get("allow-events"),
             r and r.raw)
    r = publish(dev, "sip:bob@elsewhere.net", "presence", pidf("sip:bob@elsewhere.net", "x", "open"), expires=60)
    sc.check("PUBLISH for another domain → 404", r is not None and r.code == 404, r)

    # Removal (Expires 0): the dummy closed state again.
    count = len(notifies(watcher, s.cid))
    r = publish(dev, bob_aor, "presence", "", expires=0, etag=etag3)
    sc.check("PUBLISH Expires 0 with SIP-If-Match → 200 (removed)", r is not None and r.code == 200, r)
    n = wait_notify(watcher, s.cid, count + 1)
    sc.check("…the watcher is notified: closed (dummy), no note", basic(n) == ["closed"] and "lunch" not in n.body, n and n.body)

    # SUBSCRIBE edge cases.
    s2 = Sub(watcher, bob_aor, "presence", expires=5)
    sc.check("SUBSCRIBE below min_expires (5 < 10s) → 423 with Min-Expires: 10",
             s2.reply is not None and s2.reply.code == 423 and s2.reply.get("min-expires") == "10", s2.reply and s2.reply.raw)
    s3 = Sub(watcher, bob_aor, "presence", expires=86400)
    sc.check("SUBSCRIBE above max_expires_subscribe → 200 with Expires cut to 600",
             s3.reply is not None and s3.reply.code == 200 and s3.reply.get("expires") == "600", s3.reply and s3.reply.raw)
    s3.again(0)
    s4 = Sub(watcher, bob_aor, "foo")
    sc.check("SUBSCRIBE for an unknown event → 489", s4.reply is not None and s4.reply.code == 489, s4.reply)
    s5 = Sub(watcher, bob_aor, "presence", expires=0)
    n = wait_notify(watcher, s5.cid, 1)
    sc.check("SUBSCRIBE Expires 0 (a fetch) → 200 and one terminated NOTIFY",
             s5.reply is not None and s5.reply.code == 200 and n is not None
             and (n.get("subscription-state") or "").startswith("terminated"), (s5.reply, n and n.raw))

    # Refresh and unsubscribe.
    count = len(notifies(watcher, s.cid))
    r = s.again(120)
    n = wait_notify(watcher, s.cid, count + 1)
    sc.check("in-dialog refresh → 200 (Expires 120) and a NOTIFY", r is not None and r.code == 200 and r.get("expires") == "120"
             and n is not None, (r, n))
    r = s.again(0)
    n = wait_notify(watcher, s.cid, count + 2)
    sc.check("unsubscribe (Expires 0) → 200 and a terminated NOTIFY",
             r is not None and r.code == 200 and n is not None and (n.get("subscription-state") or "").startswith("terminated"),
             (r, n and n.raw))
    wl = px.rpc("presence.watcher_list")
    sc.check("…the subscription is gone from presence.watcher_list", s.cid not in str(wl), wl)
    r = s.again(60)
    sc.check("…refreshing it afterwards → 481", r is not None and r.code == 481, r)

    # ---------------------------------------------------------- dialog-info
    d = Sub(watcher, bob_aor, "dialog")
    nd1 = wait_notify(watcher, d.cid, 1)
    sc.check("SUBSCRIBE dialog for bob → 200, NOTIFY with an empty dialog-info (force_dummy_dialog)",
             d.reply is not None and d.reply.code == 200 and nd1 is not None and "<dialog-info" in nd1.body and "<dialog " not in nd1.body
             and (nd1.get("content-type") or "").startswith("application/dialog-info+xml"), nd1 and nd1.raw)
    # A call alice → bob through the proxy: pua_dialoginfo publishes it.
    bob.auto_answer(ring=True, delay=0.5)
    r, call = alice.call(bob_aor, timeout=6)
    sc.check("a call alice → bob through the proxy: 200", r is not None and r.code == 200 and call is not None, r)
    states = []
    end = time.time() + 6
    while time.time() < end and "confirmed" not in states:
        states = [x for m in notifies(watcher, d.cid) for x in re.findall(r"<state[^>]*>(\w+)</state>", m.body)]
        time.sleep(0.1)
    sc.check("…the dialog watcher sees bob's call early, then confirmed", "early" in states and "confirmed" in states
             and states.index("early") < states.index("confirmed"), states)
    vs = [int(v) for m in notifies(watcher, d.cid) for v in re.findall(r'<dialog-info[^>]*version="(\d+)"', m.body)]
    sc.check("…dialog-info versions increase with every NOTIFY", vs == sorted(vs) and len(set(vs)) == len(vs), vs)
    last = notifies(watcher, d.cid)[-1].body if notifies(watcher, d.cid) else ""
    sc.check("…bob is the recipient, with the call's Call-ID", 'direction="recipient"' in last and call is not None
             and f'call-id="{call.call_id}"' in last, last)
    count = len(notifies(watcher, d.cid))
    rep = call.bye() if call else None
    sc.check("BYE → 200", rep is not None and rep.code == 200, rep)
    n = wait_notify(watcher, d.cid, count + 1)
    sc.check("…the dialog watcher sees terminated", n is not None and "terminated" in n.body, n and n.body)
    d.again(0)

    # ---------------------------------------------------------- resource list
    lst = "sip:friends@example.com"
    l1 = Sub(watcher, lst, "presence")
    sc.check("SUBSCRIBE to the list without Supported: eventlist → 421", l1.reply is not None and l1.reply.code == 421, l1.reply)
    l2 = Sub(watcher, lst, "presence", headers={"Supported": "eventlist", "Accept": "application/pidf+xml, application/rlmi+xml, multipart/related"})
    nl = wait_notify(watcher, l2.cid, 1)
    body = nl.body if nl else ""
    sc.check("SUBSCRIBE to the list with eventlist → 200 and a multipart/related NOTIFY with Require: eventlist",
             l2.reply is not None and l2.reply.code == 200 and nl is not None
             and (nl.get("content-type") or "").startswith("multipart/related") and "eventlist" in (nl.get("require") or ""),
             nl and nl.raw[:600])
    sc.check("…the RLMI lists both members", f'<resource uri="{alice_aor}"' in body and f'<resource uri="{carol_aor}"' in body, body[:800])
    count = len(notifies(watcher, l2.cid))
    r = publish(alice, alice_aor, "presence", pidf(alice_aor, "a1", "open", "alice here"), expires=60)
    sc.check("alice publishes open → 200", r is not None and r.code == 200, r)
    n = wait_notify(watcher, l2.cid, count + 1)
    sc.check("…the list subscriber is notified with alice's state in it", n is not None and "alice here" in n.body, n and n.body[:800])
    r = publish(dev, "sip:dave@example.com", "presence", pidf("sip:dave@example.com", "d1", "open"), expires=60)
    time.sleep(1.0)
    sc.check("a publication by someone not on the list doesn't notify the list",
             len(notifies(watcher, l2.cid)) == count + 1, len(notifies(watcher, l2.cid)))
    s6 = Sub(watcher, "sip:dave@example.com", "presence", headers={"Supported": "eventlist"})
    n = wait_notify(watcher, s6.cid, 1)
    sc.check("a non-list URI with eventlist falls through to presence: 200, plain PIDF",
             s6.reply is not None and s6.reply.code == 200 and n is not None and basic(n) == ["open"]
             and not (n.get("content-type") or "").startswith("multipart"), n and n.raw[:400])
    count = len(notifies(watcher, l2.cid))
    r = l2.again(120)
    n = wait_notify(watcher, l2.cid, count + 1)
    sc.check("list subscription refresh in the dialog → 200 and a multipart NOTIFY",
             r is not None and r.code == 200 and n is not None and (n.get("content-type") or "").startswith("multipart/related"),
             (r, n and n.raw[:400]))
    r = l2.again(0)
    n = wait_notify(watcher, l2.cid, count + 2)
    sc.check("list unsubscribe → 200 and a terminated NOTIFY",
             r is not None and r.code == 200 and n is not None and (n.get("subscription-state") or "").startswith("terminated"),
             (r, n and n.raw[:400]))
    count = len(notifies(watcher, l2.cid))
    publish(alice, alice_aor, "presence", pidf(alice_aor, "a1", "closed"), expires=60)
    time.sleep(1.0)
    sc.check("…after which alice's changes no longer notify it", len(notifies(watcher, l2.cid)) == count, len(notifies(watcher, l2.cid)))
    s6.again(0)

    o = alice.request("MESSAGE", bob_aor, body="hi", content_type="text/plain")
    r = alice.final(call_id=o["call_id"])
    sc.check("a MESSAGE → 405", r is not None and r.code == 405, r)
