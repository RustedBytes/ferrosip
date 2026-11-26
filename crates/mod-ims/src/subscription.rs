//! The IMS subscription document an HSS returns in Cx `User-Data`
//! (3GPP TS 29.228 Annex E): public identities (the implicit registration
//! set) and initial filter criteria (iFC) with their trigger points.

use regex::Regex;

#[derive(Clone, Debug)]
pub enum SptKind {
    Method(String),
    RequestUri(Regex),
    Header {
        name: String,
        content: Option<Regex>,
    },
    /// 0 originating, 1 terminating registered, 2 terminating unregistered, 3 originating unregistered.
    SessionCase(u8),
    SessionDescription {
        line: String,
        content: Option<Regex>,
    },
}

#[derive(Clone, Debug)]
pub struct Spt {
    pub group: i32,
    pub negated: bool,
    pub kind: SptKind,
}

#[derive(Clone, Debug)]
pub struct Ifc {
    pub priority: i32,
    /// Conjunctive normal form (AND of ORed groups); else DNF.
    pub cnf: bool,
    pub spts: Vec<Spt>,
    pub server: String,
    /// 0 continue, 1 terminate the session when the AS can't be reached.
    pub default_handling: u8,
}

#[derive(Clone, Debug, Default)]
pub struct Subscription {
    pub private_id: String,
    pub public_ids: Vec<String>,
    pub ifcs: Vec<Ifc>,
}

/// Text of the first `<tag>…</tag>` (no namespaces in these documents).
fn inner<'a>(doc: &'a str, tag: &str) -> Option<&'a str> {
    let (_, rest) = doc.split_once(&format!("<{tag}>"))?;
    rest.split_once(&format!("</{tag}>")).map(|(v, _)| v)
}

fn all<'a>(doc: &'a str, tag: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut v = Vec::new();
    let mut rest = doc;
    while let Some((_, after)) = rest.split_once(&open) {
        let Some((item, tail)) = after.split_once(&close) else { break };
        v.push(item);
        rest = tail;
    }
    v
}

fn text(doc: &str, tag: &str) -> Option<String> {
    inner(doc, tag).map(|s| s.trim().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&"))
}

pub fn parse(xml: &str) -> Result<Subscription, String> {
    let mut sub = Subscription { private_id: text(xml, "PrivateID").unwrap_or_default(), ..Default::default() };
    for sp in all(xml, "ServiceProfile") {
        for pi in all(sp, "PublicIdentity") {
            if text(pi, "BarringIndication").as_deref() == Some("1") {
                continue;
            }
            if let Some(id) = text(pi, "Identity") {
                sub.public_ids.push(id);
            }
        }
        for f in all(sp, "InitialFilterCriteria") {
            let priority = text(f, "Priority").and_then(|p| p.parse().ok()).unwrap_or(0);
            let server = all(f, "ApplicationServer").first().and_then(|a| text(a, "ServerName")).ok_or("iFC without ApplicationServer/ServerName")?;
            let default_handling = all(f, "ApplicationServer").first().and_then(|a| text(a, "DefaultHandling")).and_then(|d| d.parse().ok()).unwrap_or(0);
            let tp = inner(f, "TriggerPoint").unwrap_or("");
            let cnf = text(tp, "ConditionTypeCNF").as_deref() == Some("1");
            let mut spts = Vec::new();
            for s in all(tp, "SPT") {
                let negated = text(s, "ConditionNegated").as_deref() == Some("1");
                let group = text(s, "Group").and_then(|g| g.parse().ok()).unwrap_or(0);
                let re = |p: &str| Regex::new(p).map_err(|e| format!("iFC regex {p:?}: {e}"));
                let kind = if let Some(m) = text(s, "Method") {
                    SptKind::Method(m)
                } else if let Some(r) = text(s, "RequestURI") {
                    SptKind::RequestUri(re(&r)?)
                } else if let Some(h) = inner(s, "SIPHeader") {
                    SptKind::Header { name: text(h, "Header").unwrap_or_default(), content: text(h, "Content").map(|c| re(&c)).transpose()? }
                } else if let Some(c) = text(s, "SessionCase") {
                    SptKind::SessionCase(c.parse().map_err(|_| format!("bad SessionCase {c:?}"))?)
                } else if let Some(d) = inner(s, "SessionDescription") {
                    SptKind::SessionDescription { line: text(d, "Line").unwrap_or_default(), content: text(d, "Content").map(|c| re(&c)).transpose()? }
                } else {
                    continue;
                };
                spts.push(Spt { group, negated, kind });
            }
            sub.ifcs.push(Ifc { priority, cnf, spts, server, default_handling });
        }
    }
    sub.ifcs.sort_by_key(|f| f.priority);
    Ok(sub)
}

/// What a trigger point is evaluated against.
pub struct Request<'a> {
    pub method: &'a str,
    pub ruri: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a str,
    pub session_case: u8,
}

impl Spt {
    fn eval(&self, r: &Request<'_>) -> bool {
        let v = match &self.kind {
            SptKind::Method(m) => m.eq_ignore_ascii_case(r.method),
            SptKind::RequestUri(re) => re.is_match(r.ruri),
            SptKind::Header { name, content } => r.headers.iter().any(|(n, v)| n.eq_ignore_ascii_case(name) && content.as_ref().is_none_or(|c| c.is_match(v))),
            SptKind::SessionCase(c) => *c == r.session_case,
            SptKind::SessionDescription { line, content } => r
                .body
                .lines()
                .filter_map(|l| l.split_once('='))
                .any(|(k, v)| k.trim().eq_ignore_ascii_case(line) && content.as_ref().is_none_or(|c| c.is_match(v.trim()))),
        };
        v != self.negated
    }
}

impl Ifc {
    /// Does the trigger point match (no trigger point = always)?
    pub fn matches(&self, r: &Request<'_>) -> bool {
        if self.spts.is_empty() {
            return true;
        }
        let mut groups: Vec<i32> = self.spts.iter().map(|s| s.group).collect();
        groups.sort_unstable();
        groups.dedup();
        let group = |g: i32| self.spts.iter().filter(move |s| s.group == g);
        if self.cnf { groups.iter().all(|&g| group(g).any(|s| s.eval(r))) } else { groups.iter().any(|&g| group(g).all(|s| s.eval(r))) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const DOC: &str = r#"<?xml version="1.0"?><IMSSubscription><PrivateID>alice@ims.test</PrivateID><ServiceProfile>
<PublicIdentity><Identity>sip:alice@ims.test</Identity></PublicIdentity><PublicIdentity><Identity>tel:+4930111</Identity></PublicIdentity>
<InitialFilterCriteria><Priority>1</Priority><TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF>
<SPT><ConditionNegated>0</ConditionNegated><Group>0</Group><Method>INVITE</Method></SPT>
<SPT><ConditionNegated>0</ConditionNegated><Group>1</Group><SessionCase>0</SessionCase></SPT>
</TriggerPoint><ApplicationServer><ServerName>sip:as.ims.test:6599</ServerName><DefaultHandling>0</DefaultHandling></ApplicationServer></InitialFilterCriteria>
</ServiceProfile></IMSSubscription>"#;

    /// An iFC document with one filter per (priority, trigger point XML).
    fn doc(ifcs: &[(i32, &str)]) -> String {
        let f: String = ifcs
            .iter()
            .map(|(p, tp)| {
                format!("<InitialFilterCriteria><Priority>{p}</Priority><TriggerPoint>{tp}</TriggerPoint><ApplicationServer><ServerName>sip:as{p}@x</ServerName><DefaultHandling>1</DefaultHandling></ApplicationServer></InitialFilterCriteria>")
            })
            .collect();
        format!(
            "<IMSSubscription><PrivateID> bob@x </PrivateID><ServiceProfile><PublicIdentity><Identity>sip:bob@x</Identity></PublicIdentity>{f}</ServiceProfile></IMSSubscription>"
        )
    }

    fn spt(group: i32, negated: bool, body: &str) -> String {
        format!("<SPT><ConditionNegated>{}</ConditionNegated><Group>{group}</Group>{body}</SPT>", u8::from(negated))
    }

    fn req<'a>(method: &'a str, ruri: &'a str, headers: &'a [(String, String)], body: &'a str, case: u8) -> Request<'a> {
        Request { method, ruri, headers, body, session_case: case }
    }

    #[test]
    fn identities_skip_barred_ones_and_unescape() {
        let x = "<IMSSubscription><PrivateID>a@x</PrivateID>\
                 <ServiceProfile><PublicIdentity><BarringIndication>1</BarringIndication><Identity>sip:barred@x</Identity></PublicIdentity>\
                 <PublicIdentity><BarringIndication>0</BarringIndication><Identity>sip:a&amp;b@x</Identity></PublicIdentity></ServiceProfile>\
                 <ServiceProfile><PublicIdentity><Identity> tel:+1 </Identity></PublicIdentity></ServiceProfile></IMSSubscription>";
        let s = parse(x).unwrap();
        assert_eq!(s.private_id, "a@x");
        assert_eq!(s.public_ids, ["sip:a&b@x", "tel:+1"]);
        assert!(s.ifcs.is_empty());
        assert_eq!(parse(&doc(&[])).unwrap().private_id, "bob@x");
        assert!(parse("").unwrap().public_ids.is_empty());
    }

    #[test]
    fn filters_sorted_by_priority_with_defaults() {
        let s = parse(&doc(&[(5, ""), (-1, ""), (2, "")])).unwrap();
        assert_eq!(s.ifcs.iter().map(|f| f.priority).collect::<Vec<_>>(), [-1, 2, 5]);
        assert_eq!(s.ifcs[0].server, "sip:as-1@x");
        assert_eq!(s.ifcs[0].default_handling, 1);
        // No trigger point: always.
        assert!(s.ifcs[0].matches(&req("BYE", "sip:x", &[], "", 0)));
        let no_as = "<ServiceProfile><InitialFilterCriteria><Priority>1</Priority></InitialFilterCriteria></ServiceProfile>";
        assert!(parse(no_as).unwrap_err().contains("ServerName"));
        let bad_re = doc(&[(1, &spt(0, false, "<RequestURI>(</RequestURI>"))]);
        assert!(parse(&bad_re).unwrap_err().contains("regex"));
        let bad_case = doc(&[(1, &spt(0, false, "<SessionCase>x</SessionCase>"))]);
        assert!(parse(&bad_case).unwrap_err().contains("SessionCase"));
        // An SPT of an unknown kind is skipped.
        let unknown = parse(&doc(&[(1, &spt(0, false, "<Unknown>1</Unknown>"))])).unwrap();
        assert!(unknown.ifcs[0].spts.is_empty());
    }

    #[test]
    fn service_point_triggers_of_each_kind() {
        let headers = vec![("P-Asserted-Identity".to_string(), "<sip:alice@x>".to_string()), ("Accept-Contact".to_string(), "*;+g.3gpp.icsi".to_string())];
        let sdp = "v=0\r\nm=audio 4000 RTP/AVP 0\r\nm= video 5000 RTP/AVP 96\r\n";
        // (SPT body, negated, matches the request)
        let cases = [
            ("<Method>invite</Method>", false, true),
            ("<Method>MESSAGE</Method>", false, false),
            ("<Method>MESSAGE</Method>", true, true),
            ("<RequestURI>^sip:bob@</RequestURI>", false, true),
            ("<RequestURI>carol</RequestURI>", false, false),
            ("<SIPHeader><Header>accept-contact</Header></SIPHeader>", false, true),
            ("<SIPHeader><Header>Accept-Contact</Header><Content>g\\.3gpp\\.icsi</Content></SIPHeader>", false, true),
            ("<SIPHeader><Header>Accept-Contact</Header><Content>mmtel</Content></SIPHeader>", false, false),
            ("<SIPHeader><Header>Subject</Header></SIPHeader>", false, false),
            ("<SIPHeader><Header>Subject</Header></SIPHeader>", true, true),
            ("<SessionCase>1</SessionCase>", false, true),
            ("<SessionCase>0</SessionCase>", false, false),
            ("<SessionDescription><Line>m</Line><Content>^video</Content></SessionDescription>", false, true),
            ("<SessionDescription><Line>m</Line><Content>^text</Content></SessionDescription>", false, false),
            ("<SessionDescription><Line>v</Line></SessionDescription>", false, true),
            ("<SessionDescription><Line>b</Line></SessionDescription>", false, false),
        ];
        for (body, neg, want) in cases {
            let s = parse(&doc(&[(1, &spt(0, neg, body))])).unwrap();
            assert_eq!(s.ifcs[0].matches(&req("INVITE", "sip:bob@x", &headers, sdp, 1)), want, "{body} negated={neg}");
        }
    }

    #[test]
    fn cnf_and_dnf_groups() {
        // Group 0: INVITE or MESSAGE; group 1: terminating (case 1).
        let spts =
            [spt(0, false, "<Method>INVITE</Method>"), spt(0, false, "<Method>MESSAGE</Method>"), spt(1, false, "<SessionCase>1</SessionCase>")].concat();
        let cnf = parse(&doc(&[(1, &format!("<ConditionTypeCNF>1</ConditionTypeCNF>{spts}"))])).unwrap();
        let dnf = parse(&doc(&[(1, &format!("<ConditionTypeCNF>0</ConditionTypeCNF>{spts}"))])).unwrap();
        // (method, session case, CNF: (INVITE or MESSAGE) and term, DNF: (INVITE and MESSAGE) or term)
        let cases = [("INVITE", 1, true, true), ("MESSAGE", 1, true, true), ("INVITE", 0, false, false), ("BYE", 1, false, true), ("BYE", 0, false, false)];
        for (m, case, want_cnf, want_dnf) in cases {
            let r = req(m, "sip:x", &[], "", case);
            assert_eq!(cnf.ifcs[0].matches(&r), want_cnf, "CNF {m} {case}");
            assert_eq!(dnf.ifcs[0].matches(&r), want_dnf, "DNF {m} {case}");
        }
        assert!(cnf.ifcs[0].cnf && !dnf.ifcs[0].cnf);
    }

    #[test]
    fn ifc() {
        let s = parse(DOC).unwrap();
        assert_eq!(s.public_ids, vec!["sip:alice@ims.test", "tel:+4930111"]);
        assert_eq!(s.ifcs.len(), 1);
        fn req(m: &str, c: u8) -> Request<'_> {
            Request { method: m, ruri: "sip:bob@ims.test", headers: &[], body: "", session_case: c }
        }
        assert!(s.ifcs[0].matches(&req("INVITE", 0)));
        assert!(!s.ifcs[0].matches(&req("MESSAGE", 0)));
        assert!(!s.ifcs[0].matches(&req("INVITE", 1)));
    }

    #[test]
    fn a_public_identity_without_identity_is_skipped() {
        let s = parse("<ServiceProfile><PublicIdentity><BarringIndication>0</BarringIndication></PublicIdentity><PublicIdentity><Identity>sip:a@x</Identity></PublicIdentity></ServiceProfile>").unwrap();
        assert_eq!(s.public_ids, ["sip:a@x"]);
    }
}
