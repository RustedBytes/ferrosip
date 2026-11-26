//! Notifier side of SIP-specific event notification (RFC 6665): accepting
//! SUBSCRIBEs (new / refresh / unsubscribe) and sending NOTIFYs in the
//! subscription dialog through tm's UAC API. Shared by presence, sca and rls.

use crate::{aor, header};
use mod_txn::{Tm, UacRequest};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Ctx, Dest, Outbound, ShardedMap, fx_hash};
use sip_parser::uri::{name_addr, param, split_list};
use sip_parser::{HdrFlags, HdrKind};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Debug)]
pub struct Sub {
    pub id: u64,
    /// Event package (with its `;id=` if any).
    pub event: String,
    /// The resource: `sip:user@host`.
    pub pres_uri: String,
    pub watcher_uri: String,
    pub callid: String,
    pub from_tag: String,
    pub to_tag: String,
    pub contact: String,
    /// Route set towards the watcher (its Record-Route, in order).
    pub route: Vec<String>,
    pub src: Dest,
    pub expires_at: u64,
    pub local_cseq: u32,
    pub remote_cseq: u32,
    /// NOTIFY counter (dialog-info `version`).
    pub version: u32,
    pub extra: HashMap<String, String>,
}

pub type SubRef = Arc<Mutex<Sub>>;

/// Result of handling a SUBSCRIBE.
pub enum Outcome {
    /// A new subscription (already answered 200/202).
    New(SubRef),
    Refreshed(SubRef),
    /// Expires: 0 — answered; send the final NOTIFY (terminated).
    Ended(SubRef),
}

pub struct Notifier {
    subs: ShardedMap<(String, String), SubRef>,
    next: AtomicU64,
    pub min_expires: AtomicU64,
    pub max_expires: AtomicU64,
    pub default_expires: AtomicU64,
    tm: OnceLock<Arc<Tm>>,
    net: OnceLock<Arc<dyn Outbound>>,
}

impl Default for Notifier {
    fn default() -> Self {
        Self {
            subs: ShardedMap::new(64),
            next: AtomicU64::new(1),
            min_expires: AtomicU64::new(0),
            max_expires: AtomicU64::new(3600),
            default_expires: AtomicU64::new(3600),
            tm: OnceLock::new(),
            net: OnceLock::new(),
        }
    }
}

impl Notifier {
    pub fn set_tm(&self, tm: Arc<Tm>) {
        let _ = self.tm.set(tm);
    }
    pub fn set_net(&self, net: Arc<dyn Outbound>) {
        let _ = self.net.set(net);
    }
    pub fn tm(&self) -> Option<&Arc<Tm>> {
        self.tm.get()
    }
    pub fn net(&self) -> Option<&Arc<dyn Outbound>> {
        self.net.get()
    }

    /// Our Contact for replies/NOTIFYs towards `dst`.
    pub fn contact(&self, dst: &Dest) -> String {
        let addr = self.net.get().and_then(|n| n.advertise(dst.proto)).unwrap_or(dst.addr);
        let t = match dst.proto {
            sip_core::Proto::Udp => "",
            sip_core::Proto::Tcp => ";transport=tcp",
            sip_core::Proto::Tls => ";transport=tls",
            sip_core::Proto::Ws => ";transport=ws",
            sip_core::Proto::Wss => ";transport=wss",
        };
        format!("sip:{addr}{t}")
    }

    pub fn all(&self) -> Vec<SubRef> {
        let mut v = Vec::new();
        self.subs.for_each_mut(|_, s| v.push(s.clone()));
        v
    }

    /// Unexpired subscriptions to `pres_uri` for `event` (exact, without `;id`).
    pub fn watchers(&self, pres_uri: &str, event: &str) -> Vec<SubRef> {
        let t = unix_secs();
        self.all()
            .into_iter()
            .filter(|s| {
                let g = lock(s);
                g.expires_at > t && g.pres_uri == pres_uri && g.event.split(';').next() == Some(event)
            })
            .collect()
    }

    /// An in-dialog SUBSCRIBE (To tag) for one of our subscriptions.
    pub fn owns(&self, ctx: &mut Ctx<'_, '_>) -> bool {
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return false;
        }
        let m = &*ctx.msg;
        let (Some(to), Some(cid)) = (m.get(HdrKind::To), m.get(HdrKind::CallId)) else { return false };
        let Some(tt) = param(name_addr(to.body).1, b"tag") else { return false };
        let k = (String::from_utf8_lossy(cid.body).into_owned(), String::from_utf8_lossy(tt).into_owned());
        self.subs.get_cloned(&k).is_some()
    }

    pub fn remove(&self, s: &SubRef) {
        let k = {
            let g = lock(s);
            (g.callid.clone(), g.to_tag.clone())
        };
        self.subs.remove(&k);
    }

    /// Handle a SUBSCRIBE for one of `events`; answers it. `pres_uri`
    /// overrides the resource (default: the R-URI's AoR). `pending` → 202.
    pub fn subscribe(&self, ctx: &mut Ctx<'_, '_>, events: &[&str], pres_uri: Option<String>, pending: bool) -> Result<Outcome, i32> {
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            let _ = ctx.reply(400, "Bad Request");
            return Err(-1);
        }
        let event = header(ctx, "Event").or_else(|| header(ctx, "o")).unwrap_or_default();
        let pkg = event.split(';').next().unwrap_or("").trim().to_string();
        if !events.contains(&pkg.as_str()) {
            let allow = events.join(", ");
            let _ = ctx.reply_with(489, "Bad Event", format!("Allow-Events: {allow}\r\n").as_bytes());
            return Err(-1);
        }
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let m = &*ctx.msg;
        let (Some(from), Some(to), Some(cid), Some(cseq)) = (m.get(HdrKind::From), m.get(HdrKind::To), m.get(HdrKind::CallId), m.get(HdrKind::CSeq)) else {
            let _ = ctx.reply(400, "Missing headers");
            return Err(-1);
        };
        let callid = s(cid.body);
        let (furi, fparams) = name_addr(from.body);
        let from_tag = param(fparams, b"tag").map(s).unwrap_or_default();
        let to_tag = param(name_addr(to.body).1, b"tag").map(s);
        let watcher_uri = s(furi);
        let remote_cseq = std::str::from_utf8(cseq.body).ok().and_then(|c| c.split_whitespace().next()?.parse().ok()).unwrap_or(0);
        let contact = m.get(HdrKind::Contact).and_then(|h| split_list(h.body).first().map(|c| s(name_addr(c).0)));
        let route: Vec<String> =
            m.headers.iter().filter(|h| h.kind == HdrKind::RecordRoute).flat_map(|h| split_list(h.body)).map(|x| s(x).trim().to_string()).collect();
        // An empty Expires means the default; one that isn't a number is
        // refused, as Kamailio's presence does when parse_expires fails.
        let exp_hdr = m.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"expires")).map(|h| String::from_utf8_lossy(h.body).trim().to_string());
        let expires = match exp_hdr.as_deref() {
            None | Some("") => self.default_expires.load(Ordering::Relaxed),
            Some(v) => match v.parse::<u64>() {
                Ok(e) => e,
                Err(_) => {
                    let _ = ctx.reply(400, "Bad Expires");
                    return Err(-1);
                }
            },
        };
        let min = self.min_expires.load(Ordering::Relaxed);
        if expires != 0 && expires < min {
            let _ = ctx.reply_with(423, "Interval Too Brief", format!("Min-Expires: {min}\r\n").as_bytes());
            return Err(-1);
        }
        let expires = expires.min(self.max_expires.load(Ordering::Relaxed));
        let src = ctx.src;
        let our_contact = self.contact(&src);

        if let Some(tt) = to_tag {
            // Refresh or unsubscribe in an existing dialog.
            let Some(sub) = self.subs.get_cloned(&(callid.clone(), tt.clone())) else {
                let _ = ctx.reply(481, "Subscription does not exist");
                return Err(-1);
            };
            {
                let mut g = lock(&sub);
                g.remote_cseq = g.remote_cseq.max(remote_cseq);
                g.expires_at = unix_secs().saturating_add(expires);
                g.src = src;
                if let Some(c) = contact {
                    g.contact = c;
                }
            }
            let _ = ctx.reply_with(200, "OK", format!("Expires: {expires}\r\nContact: <{our_contact}>\r\n").as_bytes());
            if expires == 0 {
                self.remove(&sub);
                return Ok(Outcome::Ended(sub));
            }
            return Ok(Outcome::Refreshed(sub));
        }
        let Some(contact) = contact else {
            let _ = ctx.reply(400, "Missing Contact");
            return Err(-1);
        };
        let pres_uri = match pres_uri.or_else(|| aor(ctx.ruri())) {
            Some(p) => p,
            None => {
                let _ = ctx.reply(400, "Bad Request-URI");
                return Err(-1);
            }
        };
        // Same tag as the stateless reply generator would put on the 200.
        let to_tag = format!("{:016x}", fx_hash(callid.as_bytes()));
        let sub = Arc::new(Mutex::new(Sub {
            id: self.next.fetch_add(1, Ordering::Relaxed),
            event: event.trim().to_string(),
            pres_uri,
            watcher_uri,
            callid: callid.clone(),
            from_tag,
            to_tag: to_tag.clone(),
            contact,
            route,
            src,
            expires_at: unix_secs().saturating_add(expires),
            local_cseq: 0,
            remote_cseq,
            version: 0,
            extra: HashMap::new(),
        }));
        let (code, reason) = if pending { (202, "Accepted") } else { (200, "OK") };
        let _ = ctx.reply_with(code, reason, format!("Expires: {expires}\r\nContact: <{our_contact}>\r\n").as_bytes());
        if expires == 0 {
            // A fetch: one NOTIFY, no subscription kept.
            return Ok(Outcome::Ended(sub));
        }
        self.subs.insert((callid, to_tag), sub.clone());
        Ok(Outcome::New(sub))
    }

    /// Send a NOTIFY in the subscription dialog. `state` is "active",
    /// "pending" or "terminated;reason=…"; `headers` extra lines (CRLF).
    pub fn notify(self: &Arc<Self>, sub: &SubRef, state: &str, ctype: Option<&str>, body: &[u8], headers: &str) -> bool {
        let Some(tm) = self.tm.get() else { return false };
        let req = {
            let mut g = lock(sub);
            g.local_cseq = g.local_cseq.saturating_add(1);
            g.version = g.version.saturating_add(1);
            let left = g.expires_at.saturating_sub(unix_secs());
            let ss = if state.starts_with("terminated") { state.to_string() } else { format!("{state};expires={left}") };
            let mut h = format!(
                "From: <{}>;tag={}\r\nTo: <{}>;tag={}\r\nEvent: {}\r\nSubscription-State: {ss}\r\nContact: <{}>\r\n",
                g.pres_uri,
                g.to_tag,
                g.watcher_uri,
                g.from_tag,
                g.event,
                self.contact(&g.src)
            );
            if !g.route.is_empty() {
                h.push_str(&format!("Route: {}\r\n", g.route.join(",")));
            }
            if let Some(ct) = ctype.filter(|_| !body.is_empty()) {
                h.push_str(&format!("Content-Type: {ct}\r\n"));
            }
            h.push_str(headers);
            let dst = match g.route.first() {
                Some(r) => sip_core::pvcore::dest_from_uri(name_addr(r.as_bytes()).0),
                None => Some(g.src),
            };
            UacRequest {
                method: "NOTIFY".into(),
                ruri: g.contact.clone(),
                dst,
                call_id: Some(g.callid.clone()),
                cseq: g.local_cseq,
                headers: h,
                body: body.to_vec(),
                ..Default::default()
            }
        };
        let key = {
            let g = lock(sub);
            (g.callid.clone(), g.to_tag.clone())
        };
        // A 481 (or 408) to a NOTIFY ends the subscription.
        let me = self.clone();
        tm.t_uac(
            req,
            Some(Box::new(move |code, _| {
                if code == 481 || code == 408 {
                    me.remove_key(&key);
                }
            })),
        )
        .is_ok()
    }

    /// Expired subscriptions (removed from the table).
    pub fn take_expired(&self) -> Vec<SubRef> {
        let t = unix_secs();
        let mut gone = Vec::new();
        self.subs.retain(|_, s| {
            let keep = lock(s).expires_at > t;
            if !keep {
                gone.push(s.clone());
            }
            keep
        });
        gone
    }

    pub fn remove_key(&self, k: &(String, String)) {
        self.subs.remove(k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{hdr, reply, request, with_msg};

    /// SUBSCRIBE to sip:pres@ex.com with `extra` header lines; the outcome
    /// kind, the reply code and the reply.
    fn sub(n: &Notifier, to_tag: Option<&str>, extra: &str) -> (&'static str, u16, String) {
        with_msg(&request("SUBSCRIBE", "sip:pres@ex.com", to_tag, extra, ""), |ctx| {
            let kind = match n.subscribe(ctx, &["presence", "dialog"], None, false) {
                Ok(Outcome::New(_)) => "new",
                Ok(Outcome::Refreshed(_)) => "refreshed",
                Ok(Outcome::Ended(_)) => "ended",
                Err(_) => "error",
            };
            let (code, r) = reply(ctx);
            (kind, code, r)
        })
    }

    #[test]
    fn new_subscriptions_are_answered_and_kept() {
        let n = Notifier::default();
        let (kind, code, r) = sub(&n, None, "Event: presence\nExpires: 600\n");
        assert_eq!((kind, code), ("new", 200), "{r}");
        assert_eq!(hdr(&r, "Expires").as_deref(), Some("600"));
        assert_eq!(hdr(&r, "Contact").as_deref(), Some("<sip:192.0.2.9:5060>"));
        let w = n.watchers("sip:pres@ex.com", "presence");
        assert_eq!(w.len(), 1);
        let g = lock(&w[0]).clone();
        assert_eq!((g.watcher_uri.as_str(), g.from_tag.as_str(), g.contact.as_str(), g.remote_cseq), ("sip:watcher@ex.com", "ft", "sip:watcher@192.0.2.9", 2));
        assert_eq!(g.to_tag, format!("{:016x}", fx_hash(b"cid-1")));
        // The reply's To tag is the subscription's.
        assert!(r.contains(&format!("tag={}", g.to_tag)), "{r}");
        assert!(n.watchers("sip:pres@ex.com", "dialog").is_empty());
        assert!(n.watchers("sip:other@ex.com", "presence").is_empty());
    }

    #[test]
    fn expires_default_cap_and_minimum() {
        let n = Notifier::default();
        n.default_expires.store(120, Ordering::Relaxed);
        n.max_expires.store(300, Ordering::Relaxed);
        n.min_expires.store(60, Ordering::Relaxed);
        // (Expires header line, outcome, code, Expires answered)
        let cases = [
            ("", "new", 200, Some("120")),
            ("Expires: 9999\n", "new", 200, Some("300")),
            ("Expires: 60\n", "new", 200, Some("60")),
            ("Expires: 59\n", "error", 423, None),
            ("Expires: 0\n", "ended", 200, Some("0")),
            ("Expires: junk\n", "error", 400, None),
            ("Expires: 99999999999999999999999\n", "error", 400, None),
            ("Expires: \n", "new", 200, Some("120")),
        ];
        for (line, kind, code, exp) in cases {
            let (k, c, r) = sub(&n, None, &format!("Event: presence\n{line}"));
            assert_eq!((k, c), (kind, code), "{line:?}: {r}");
            assert_eq!(hdr(&r, "Expires").as_deref(), exp, "{line:?}");
            if c == 423 {
                assert_eq!(hdr(&r, "Min-Expires").as_deref(), Some("60"));
            }
        }
    }

    #[test]
    fn a_fetch_is_not_kept() {
        let n = Notifier::default();
        assert_eq!(sub(&n, None, "Event: presence\nExpires: 0\n").0, "ended");
        assert!(n.all().is_empty());
    }

    #[test]
    fn unknown_events_get_489_with_allow_events() {
        let n = Notifier::default();
        for line in ["Event: message-summary\n", ""] {
            let (k, c, r) = sub(&n, None, line);
            assert_eq!((k, c), ("error", 489), "{line:?}");
            assert_eq!(hdr(&r, "Allow-Events").as_deref(), Some("presence, dialog"));
        }
        // The compact form and parameters are understood.
        assert_eq!(sub(&n, None, "o: dialog;id=7\n").0, "new");
        let w = n.watchers("sip:pres@ex.com", "dialog");
        assert_eq!(lock(&w[0]).event, "dialog;id=7");
    }

    #[test]
    fn refresh_unsubscribe_and_unknown_dialogs() {
        let n = Notifier::default();
        sub(&n, None, "Event: presence\nExpires: 100\n");
        let tag = format!("{:016x}", fx_hash(b"cid-1"));
        let (k, c, r) = sub(&n, Some(&tag), "Event: presence\nExpires: 200\n");
        assert_eq!((k, c, hdr(&r, "Expires").as_deref()), ("refreshed", 200, Some("200")));
        let w = n.watchers("sip:pres@ex.com", "presence");
        assert!(lock(&w[0]).expires_at >= unix_secs() + 199);
        assert_eq!(sub(&n, Some("nope"), "Event: presence\n").1, 481);
        assert!(with_msg(&request("SUBSCRIBE", "sip:x@ex.com", Some(&tag), "", ""), |ctx| n.owns(ctx)));
        assert!(!with_msg(&request("SUBSCRIBE", "sip:x@ex.com", Some("other"), "", ""), |ctx| n.owns(ctx)));
        assert!(!with_msg(&request("SUBSCRIBE", "sip:x@ex.com", None, "", ""), |ctx| n.owns(ctx)));
        let (k, c, _) = sub(&n, Some(&tag), "Event: presence\nExpires: 0\n");
        assert_eq!((k, c), ("ended", 200));
        assert!(n.all().is_empty(), "unsubscribed");
    }

    #[test]
    fn new_subscriptions_need_a_contact_and_a_user() {
        let n = Notifier::default();
        let no_contact = request("SUBSCRIBE", "sip:pres@ex.com", None, "Event: presence\n", "").replace("Contact: <sip:watcher@192.0.2.9>\n", "");
        assert_eq!(with_msg(&no_contact, |ctx| (n.subscribe(ctx, &["presence"], None, false).is_err(), reply(ctx).0)), (true, 400));
        let no_user = request("SUBSCRIBE", "sip:ex.com", None, "Event: presence\n", "");
        assert_eq!(with_msg(&no_user, |ctx| (n.subscribe(ctx, &["presence"], None, false).is_err(), reply(ctx).0)), (true, 400));
        // pending → 202; the resource can be given.
        let ok = request("SUBSCRIBE", "sip:ex.com", None, "Event: presence\n", "");
        assert_eq!(with_msg(&ok, |ctx| (n.subscribe(ctx, &["presence"], Some("sip:list@ex.com".into()), true).is_ok(), reply(ctx).0)), (true, 202));
        assert_eq!(n.watchers("sip:list@ex.com", "presence").len(), 1);
    }

    #[test]
    fn record_route_becomes_the_route_set() {
        let n = Notifier::default();
        sub(&n, None, "Event: presence\nRecord-Route: <sip:p1;lr>, <sip:p2;lr>\nRecord-Route: <sip:p3;lr>\n");
        let w = n.watchers("sip:pres@ex.com", "presence");
        assert_eq!(lock(&w[0]).route, ["<sip:p1;lr>", "<sip:p2;lr>", "<sip:p3;lr>"]);
    }

    #[test]
    fn expired_subscriptions_are_taken_once() {
        let n = Notifier::default();
        sub(&n, None, "Event: presence\n");
        let w = n.watchers("sip:pres@ex.com", "presence");
        lock(&w[0]).expires_at = unix_secs().saturating_sub(1);
        assert!(n.watchers("sip:pres@ex.com", "presence").is_empty(), "expired ones are no watchers");
        assert_eq!(n.take_expired().len(), 1);
        assert!(n.take_expired().is_empty() && n.all().is_empty());
    }

    #[test]
    fn our_contact_names_the_transport() {
        let n = Notifier::default();
        let at = |p| n.contact(&Dest::new(p, "192.0.2.1:5061".parse().unwrap()));
        assert_eq!(at(sip_core::Proto::Udp), "sip:192.0.2.1:5061");
        assert_eq!(at(sip_core::Proto::Tcp), "sip:192.0.2.1:5061;transport=tcp");
        assert_eq!(at(sip_core::Proto::Tls), "sip:192.0.2.1:5061;transport=tls");
        assert_eq!(at(sip_core::Proto::Wss), "sip:192.0.2.1:5061;transport=wss");
    }
}
