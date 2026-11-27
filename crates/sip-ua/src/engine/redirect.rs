//! RFC 3261 §8.1.3.4 redirection of the initial INVITE.
//!
//! With `max_redirects` > 0 the engine follows a 3xx itself: the Contact
//! URIs in q order (highest first, ties in received order), skipping any
//! URI this call already tried (loop protection), at most `max_redirects`
//! times. Each retry is a new transaction (new branch, CSeq + 1, same
//! Call-ID and From tag) to the new Request-URI, resolved afresh. Without
//! it — or when nothing is left to try — the 3xx ends the leg and its
//! contacts travel in the failure cause, for the application to decide.

use super::*;
use crate::msg::StartLine;
use sip_parser::uri::parse_contact;

#[derive(Debug, Default)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub(super) struct Redirects {
    /// Request-URIs this call has tried (lower-cased).
    visited: Vec<String>,
    followed: u8,
}

/// The SIP/SIPS Contact URIs of a 3xx, best q first.
pub(super) fn redirect_contacts(resp: &SipMessage) -> Vec<String> {
    let mut v: Vec<(u16, usize, String)> = resp
        .values("Contact")
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let spec = parse_contact(c.as_bytes());
            let uri = String::from_utf8_lossy(spec.uri).trim().to_string();
            let ok = !spec.star && parse_uri(uri.as_bytes()).is_some_and(|u| u.scheme.eq_ignore_ascii_case(b"sip") || u.is_sips()) && is_safe_value(&uri);
            ok.then(|| (spec.q.unwrap_or(1_000), i, uri))
        })
        .collect();
    v.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    v.into_iter().map(|(_, _, u)| u).collect()
}

impl UaEngine {
    /// Follow a 3xx to our INVITE; false when we don't (or can't).
    pub(super) fn follow_redirect(&mut self, leg: &mut Leg, resp: &SipMessage, now: u64) -> bool {
        if self.cfg.max_redirects == 0 || leg.cancel != CancelState::None || leg.ext.redir.followed >= self.cfg.max_redirects {
            return false;
        }
        let Some(mut req) = leg.invite_template.clone() else { return false };
        if leg.ext.redir.visited.is_empty() {
            leg.ext.redir.visited.push(req.uri().unwrap_or_default().to_ascii_lowercase());
        }
        let visited = &leg.ext.redir.visited;
        let Some(target) = redirect_contacts(resp).into_iter().find(|u| !visited.contains(&u.to_ascii_lowercase())) else { return false };
        let Some(cseq) = leg.local_cseq.checked_add(1).filter(|c| *c < 1 << 31) else { return false };
        leg.ext.redir.visited.push(target.to_ascii_lowercase());
        leg.ext.redir.followed = leg.ext.redir.followed.saturating_add(1);
        leg.local_cseq = cseq;
        req.start = StartLine::Request { method: Method::Invite, uri: target.clone() };
        req.set_header("CSeq", format!("{cseq} INVITE"));
        // Credentials were for the old target's realm.
        req.remove_header("Authorization");
        req.remove_header("Proxy-Authorization");
        if leg.ext.fo.contact_generated {
            // The new target may need another transport: let dispatch pick the Contact.
            req.remove_header("Contact");
            leg.local_contact.clear();
        }
        leg.invite_template = Some(req.clone());
        leg.remote_target = target;
        leg.ext.fo = Failover { contact_generated: leg.ext.fo.contact_generated, ..Failover::default() };
        leg.auth_attempts = 0;
        for t in std::mem::take(&mut leg.early) {
            self.unregister_dialog(leg, &t.tag);
        }
        leg.set_phase(Phase::Calling);
        leg.invite_txn = None;
        leg.invite_dest = None;
        let id = leg.id;
        self.dispatch_leg_request(leg, req, Purpose::Invite(id), None, now).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contacts_in_q_order() {
        let mut r = SipMessage::response(302, "Moved");
        r.push_header("Contact", "<sip:a@1.1.1.1>;q=0.5, <sip:b@2.2.2.2>;q=0.9");
        r.push_header("Contact", "<sip:c@3.3.3.3>, <mailto:x@y>, <sip:d@4.4.4.4>;q=0.9");
        assert_eq!(redirect_contacts(&r), vec!["sip:c@3.3.3.3", "sip:b@2.2.2.2", "sip:d@4.4.4.4", "sip:a@1.1.1.1"]);
    }
}
