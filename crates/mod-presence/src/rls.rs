//! `rls` — resource list server (RFC 4662): one SUBSCRIBE to a list URI
//! gets NOTIFYs carrying the state of every member, as `multipart/related`
//! with an RLMI document (`application/rlmi+xml`) plus one part per member
//! that has state.
//!
//! Lists come from the `xcap` table like Kamailio (`doc_type` 6,
//! rls-services documents: `<service uri="sip:friends@x"><list><entry
//! uri="sip:a@x"/>…`). Members' state is read from the local `presence`
//! module (`rls` must be loaded after it) and every change of a member's
//! presentity re-notifies the list's subscribers.
//!
//! `rls_handle_subscribe([watcher])`: 1 if the R-URI is a list (handled and
//! answered — 421 without `Supported: eventlist`), -1 otherwise, so the
//! script falls back to `handle_subscribe()`. RPC: `rls.reload`, `rls.lists`.

use crate::notifier::{Notifier, Outcome, SubRef};
use crate::presence::Presence;
use crate::{aor, header, xml};
use mod_txn::Tm;
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::serde_json::json;
use sip_core::sync::{lock, read, write};
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Registry};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

#[derive(Default)]
pub struct Rls {
    db_url: Mutex<Option<String>>,
    table: Mutex<Option<String>>,
    lists: RwLock<HashMap<String, Vec<String>>>,
    notifier: Arc<Notifier>,
    pres: OnceLock<Arc<Presence>>,
}

/// rls-services document → (service uri → member uris).
fn parse_services(doc: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for svc in xml::all(doc, "service") {
        let Some(uri) = xml::attr(&svc, "service", "uri") else { continue };
        let mut members = Vec::new();
        let mut i = 0;
        while let Some((s, e)) = xml::element(&svc, "entry", i) {
            if let Some(u) = svc.get(s..e).and_then(|entry| xml::attr(entry, "entry", "uri")) {
                members.push(u);
            }
            i = e;
        }
        out.push((uri, members));
    }
    out
}

impl Rls {
    fn reload(&self) -> Result<usize, String> {
        let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("rls"));
        let db = sip_db::connect(&url)?;
        let table = lock(&self.table).clone().unwrap_or_else(|| "xcap".into());
        let rows = db.query(&table, &["doc", "doc_type"], &[])?;
        let mut lists = HashMap::new();
        for r in rows.rows {
            if r.get(1).and_then(sip_db::DbVal::int) != Some(6) {
                continue;
            }
            for (uri, members) in parse_services(&r.first().map(sip_db::DbVal::text).unwrap_or_default()) {
                let key = aor(uri.as_bytes()).unwrap_or(uri);
                lists.insert(key, members.iter().map(|m| aor(m.as_bytes()).unwrap_or_else(|| m.clone())).collect());
            }
        }
        let n = lists.len();
        *write(&self.lists) = lists;
        Ok(n)
    }

    /// The full-state multipart body for a list.
    fn body(&self, list: &str, event: &str, version: u32) -> (String, Vec<u8>) {
        let members = read(&self.lists).get(list).cloned().unwrap_or_default();
        let boundary = format!("rls{:x}", sip_core::fx_hash(list.as_bytes()));
        let mut rlmi = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<list xmlns=\"urn:ietf:params:xml:ns:rlmi\" uri=\"{}\" version=\"{version}\" fullState=\"true\">",
            xml::escape(list)
        );
        let mut parts = Vec::new();
        for (i, m) in members.iter().enumerate() {
            let state = self.pres.get().and_then(|p| p.state(m, event)).filter(|(_, b)| !b.is_empty());
            rlmi.push_str(&format!("<resource uri=\"{}\">", xml::escape(m)));
            if let Some((ct, b)) = state {
                let cid = format!("{i}.{boundary}@ferrosip");
                rlmi.push_str(&format!("<instance id=\"{i}\" state=\"active\" cid=\"{cid}\"/>"));
                parts.push((cid, ct, b));
            }
            rlmi.push_str("</resource>");
        }
        rlmi.push_str("</list>");
        let start = format!("rlmi.{boundary}@ferrosip");
        let mut body = format!("--{boundary}\r\nContent-Transfer-Encoding: binary\r\nContent-ID: <{start}>\r\nContent-Type: application/rlmi+xml;charset=\"UTF-8\"\r\n\r\n{rlmi}\r\n").into_bytes();
        for (cid, ct, b) in parts {
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Transfer-Encoding: binary\r\nContent-ID: <{cid}>\r\nContent-Type: {ct}\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(&b);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (format!("multipart/related;type=\"application/rlmi+xml\";start=\"<{start}>\";boundary=\"{boundary}\""), body)
    }

    fn notify(&self, s: &SubRef, state: &str) {
        let (list, event, version) = {
            let g = lock(s);
            (g.pres_uri.clone(), g.event.split(';').next().unwrap_or("presence").to_string(), g.version.saturating_add(1))
        };
        let (ct, body) = self.body(&list, &event, version);
        self.notifier.notify(s, state, Some(&ct), &body, "Require: eventlist\r\n");
    }

    fn handle_subscribe(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        // A refresh or unsubscribe of a list subscription: its R-URI is our
        // Contact, not the list (Kamailio's rls matches the dialog first).
        if self.notifier.owns(ctx) {
            match self.notifier.subscribe(ctx, &["presence", "dialog"], None, false) {
                Ok(Outcome::New(s)) | Ok(Outcome::Refreshed(s)) => self.notify(&s, "active"),
                Ok(Outcome::Ended(s)) => self.notify(&s, "terminated;reason=timeout"),
                Err(_) => {}
            }
            return 1;
        }
        let Some(list) = aor(ctx.ruri()) else { return -1 };
        if !read(&self.lists).contains_key(&list) {
            return -1;
        }
        let supported = header(ctx, "Supported").or_else(|| header(ctx, "k")).is_some_and(|s| s.split(',').any(|x| x.trim().eq_ignore_ascii_case("eventlist")));
        if !supported {
            let _ = ctx.reply_with(421, "Extension Required", b"Require: eventlist\r\n");
            return 1;
        }
        match self.notifier.subscribe(ctx, &["presence", "dialog"], Some(list), false) {
            Ok(Outcome::New(s)) | Ok(Outcome::Refreshed(s)) => self.notify(&s, "active"),
            Ok(Outcome::Ended(s)) => self.notify(&s, "terminated;reason=timeout"),
            // Already answered (4xx/5xx) by the notifier.
            Err(_) => sip_core::log::log(sip_core::log::L_WARN, "rls: SUBSCRIBE refused"),
        }
        1
    }

    /// A presentity changed: re-notify the lists it's a member of.
    fn member_changed(&self, pres_uri: &str, event: &str) {
        let lists: Vec<String> = read(&self.lists).iter().filter(|(_, m)| m.iter().any(|x| x == pres_uri)).map(|(l, _)| l.clone()).collect();
        for l in lists {
            for s in self.notifier.watchers(&l, event) {
                self.notify(&s, "active");
            }
        }
    }
}

impl Module for Rls {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the xcap table (default: the module's default database)"),
            p("xcap_table", Ty::Str, "xcap", "Table with the rls-services documents"),
        ])
    }

    fn name(&self) -> &'static str {
        "rls"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{Ret, ctx, sig};
        Some(vec![
            sig(
                "rls_handle_subscribe",
                "handle_subscribe",
                &[],
                Ret::Bool,
                "Handle and answer a SUBSCRIBE to a resource list; false: not a list (leave it to presence)",
            )
            .allowed(ctx::REQUEST),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" | "xcap_db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "xcap_table" => *lock(&self.table) = Some(v.str()?.into()),
            "server_address"
            | "rlsubs_table"
            | "rlpres_table"
            | "integrated_xcap_server"
            | "to_presence_code"
            | "rls_event"
            | "outbound_proxy"
            | "max_expires"
            | "waitn_time"
            | "clean_period"
            | "max_notify_body_length"
            | "db_mode"
            | "hash_size"
            | "rls_db_url"
            | "rlmi_db_url" => {}
            _ => return Err(format!("rls: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        self.reload()?;
        let pres = reg.api::<Presence>().ok_or("rls needs presence loaded first")?;
        let me = self.clone();
        pres.on_change(Arc::new(move |u, e| me.member_changed(u, e)));
        let _ = self.pres.set(pres);
        self.notifier.set_tm(reg.api::<Tm>().ok_or("rls needs tm loaded first")?);
        let me = self.clone();
        reg.export(
            "rls",
            "rls_handle_subscribe",
            |a: &[Arg]| if a.len() > 1 { Err("expected [watcher_uri]".to_string()) } else { Ok(()) },
            move |ctx: &mut Ctx, _: &()| me.handle_subscribe(ctx),
        );
        let me = self.clone();
        reg.rpc.add("rls.reload", "Reload the resource lists", move |_| me.reload().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("rls.lists", "Resource lists and their members", move |_| Ok(json!(*read(&me.lists))));
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        self.notifier.set_net(net);
        std::thread::Builder::new()
            .name("rls-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    for s in self.notifier.take_expired() {
                        self.notify(&s, "terminated;reason=timeout");
                    }
                    let _ = unix_secs();
                }
            })
            .map_err(|e| format!("cannot start the rls timer thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::{EventPkg, merge_pidf};

    #[test]
    fn services_edges() {
        let d = r#"<rls-services><service uri="sip:a@x"><list><entry uri="sip:1@x"/><list name="sub"><entry uri="sip:2@x"/></list><entry-ref ref="r"/><external anchor="x"/></list></service><service><list><entry uri="sip:3@x"/></list></service><service uri='sip:empty@x'/></rls-services>"#;
        assert_eq!(parse_services(d), vec![("sip:a@x".to_string(), vec!["sip:1@x".to_string(), "sip:2@x".to_string()]), ("sip:empty@x".to_string(), vec![])]);
        assert!(parse_services("").is_empty());
    }

    #[test]
    fn list_body_is_multipart_with_rlmi_and_member_states() {
        // Only a@x has state.
        let doc = r#"<presence entity="sip:a@x"><tuple id="t"><status><basic>open</basic></status></tuple></presence>"#;
        let pres = Arc::new(Presence::default());
        pres.add_event(EventPkg {
            name: "presence".into(),
            ctype: "application/pidf+xml".into(),
            aggregate: Arc::new(merge_pidf),
            empty: Some(Arc::new(move |u: &str| (u == "sip:a@x").then(|| doc.as_bytes().to_vec()))),
            per_sub: None,
        });
        let rls = Rls::default();
        let _ = rls.pres.set(pres);
        write(&rls.lists).insert("sip:l@x".into(), vec!["sip:a@x".into(), "sip:b@x".into()]);
        let (ct, body) = rls.body("sip:l@x", "presence", 3);
        let body = String::from_utf8(body).unwrap();
        let boundary = format!("rls{:x}", sip_core::fx_hash(b"sip:l@x"));
        assert_eq!(ct, format!("multipart/related;type=\"application/rlmi+xml\";start=\"<rlmi.{boundary}@ferrosip>\";boundary=\"{boundary}\""));
        let parts: Vec<&str> = body.split(&format!("--{boundary}")).collect();
        // "", rlmi, a@x, "--\r\n"
        assert_eq!(parts.len(), 4, "{body}");
        assert_eq!(parts[3], "--\r\n");
        let rlmi = parts[1];
        assert!(rlmi.contains("Content-Type: application/rlmi+xml;charset=\"UTF-8\"\r\n\r\n"));
        assert_eq!(xml::attr(rlmi, "list", "version").as_deref(), Some("3"));
        assert_eq!(xml::attr(rlmi, "list", "fullState").as_deref(), Some("true"));
        let res = xml::all(rlmi, "resource");
        assert_eq!(res.len(), 2);
        assert_eq!(xml::attr(&res[0], "instance", "cid").as_deref(), Some(format!("0.{boundary}@ferrosip").as_str()));
        assert!(xml::element(&res[1], "instance", 0).is_none(), "b@x has no state");
        assert!(parts[2].contains(&format!("Content-ID: <0.{boundary}@ferrosip>\r\nContent-Type: application/pidf+xml\r\n\r\n{doc}\r\n")), "{}", parts[2]);
        // An unknown list: just the empty RLMI.
        let (_, empty) = rls.body("sip:none@x", "presence", 1);
        assert_eq!(String::from_utf8(empty).unwrap().matches("Content-ID").count(), 1);
    }

    #[test]
    fn subscribes_to_lists_need_eventlist_support() {
        let rls = Rls::default();
        write(&rls.lists).insert("sip:l@ex.com".into(), vec!["sip:a@ex.com".into()]);
        let run = |ruri: &str, extra: &str| {
            crate::testutil::with_msg(&crate::testutil::request("SUBSCRIBE", ruri, None, extra, ""), |ctx| {
                (rls.handle_subscribe(ctx), crate::testutil::reply(ctx))
            })
        };
        assert_eq!(run("sip:other@ex.com", "Event: presence\n").0, -1, "not a list: left to presence");
        let (r, (code, out)) = run("sip:l@ex.com", "Event: presence\n");
        assert_eq!((r, code), (1, 421));
        assert_eq!(crate::testutil::hdr(&out, "Require").as_deref(), Some("eventlist"));
        let (r, (code, _)) = run("sip:l@EX.com:5060", "Event: presence\nSupported: timer, eventlist\n");
        assert_eq!((r, code), (1, 200));
        assert_eq!(rls.notifier.watchers("sip:l@ex.com", "presence").len(), 1);
        assert_eq!(run("sip:l@ex.com", "Event: presence\nk: EventList\n").1.0, 200, "compact Supported");
    }

    #[test]
    fn services() {
        let d = r#"<rls-services xmlns="urn:ietf:params:xml:ns:rls-services"><service uri="sip:friends@x"><list name="f"><entry uri="sip:a@x"/><entry uri="sip:b@x"><display-name>B</display-name></entry></list><packages><package>presence</package></packages></service></rls-services>"#;
        assert_eq!(super::parse_services(d), vec![("sip:friends@x".to_string(), vec!["sip:a@x".to_string(), "sip:b@x".to_string()])]);
    }
}
