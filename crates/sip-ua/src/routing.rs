//! Where outbound legs go: adapters from ferrosip's registrar (usrloc)
//! and a trunk table to the fields of an [`OriginateRequest`].
//!
//! The engine never decides routing; the softswitch asks a
//! [`ContactLookup`] (registered users) or a [`TrunkRouter`] (carriers)
//! for ordered [`Target`]s and originates to them (sequentially or in
//! parallel — its policy).

use crate::api::OriginateRequest;
use crate::auth::Credentials;
use crate::msg::is_safe_value;
use sip_core::Dest;

/// One place to send an INVITE.
#[derive(Clone, Debug, Default)]
pub struct Target {
    pub request_uri: String,
    /// Send here (e.g. the address and connection a registration came
    /// from: NAT-safe, and the RFC 5626 flow for TCP/TLS/WS clients).
    pub next_hop: Option<Dest>,
    /// Pre-loaded route set (RFC 3327 Path of a registration).
    pub route_set: Vec<String>,
    pub credentials: Option<Credentials>,
}

impl Target {
    /// Fill the routing fields of `o`.
    pub fn apply_to(&self, o: &mut OriginateRequest) {
        o.request_uri = self.request_uri.clone();
        o.next_hop = self.next_hop;
        o.route_set = self.route_set.clone();
        if self.credentials.is_some() {
            o.credentials = self.credentials.clone();
        }
    }
}

/// Registered contacts of an address-of-record, best first.
pub trait ContactLookup: Send + Sync {
    fn lookup(&self, aor: &str) -> Vec<Target>;
}

/// Carrier routes for a dialled number, in the order to try them.
pub trait TrunkRouter: Send + Sync {
    fn route(&self, number: &str) -> Vec<Target>;
}

/// A carrier trunk.
#[derive(Clone, Debug)]
pub struct Trunk {
    pub name: String,
    /// `host[:port][;transport=…]` of the gateway.
    pub gateway: String,
    pub next_hop: Option<Dest>,
    pub credentials: Option<Credentials>,
    /// Digits removed from the front of the number…
    pub strip: usize,
    /// …and the prefix put in their place.
    pub prefix: String,
}

impl Trunk {
    fn target(&self, number: &str) -> Option<Target> {
        let rest = number.get(self.strip..)?;
        let user = format!("{}{rest}", self.prefix);
        let uri = format!("sip:{user}@{}", self.gateway);
        is_safe_value(&uri).then(|| Target { request_uri: uri, next_hop: self.next_hop, route_set: Vec::new(), credentials: self.credentials.clone() })
    }
}

/// Longest-prefix routing to trunks; every trunk with the longest matching
/// prefix is returned, in the order they were added (failover order).
#[derive(Clone, Debug, Default)]
pub struct PrefixTrunks {
    routes: Vec<(String, Trunk)>,
}

impl PrefixTrunks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Route numbers starting with `prefix` (`""` matches everything).
    pub fn add(&mut self, prefix: impl Into<String>, trunk: Trunk) -> &mut Self {
        self.routes.push((prefix.into(), trunk));
        self
    }
}

impl TrunkRouter for PrefixTrunks {
    fn route(&self, number: &str) -> Vec<Target> {
        // Only digits, *, # and a leading + are dialable here.
        let ok = !number.is_empty() && number.char_indices().all(|(i, c)| c.is_ascii_digit() || c == '*' || c == '#' || (c == '+' && i == 0));
        if !ok {
            return Vec::new();
        }
        let best = self.routes.iter().filter(|(p, _)| number.starts_with(p.as_str())).map(|(p, _)| p.len()).max();
        let Some(best) = best else { return Vec::new() };
        self.routes.iter().filter(|(p, _)| p.len() == best && number.starts_with(p.as_str())).filter_map(|(_, t)| t.target(number)).collect()
    }
}

/// ferrosip's registrar store (`mod-location`): contacts of an AoR, by
/// q (highest first), then most recently refreshed.
#[cfg(feature = "location")]
pub struct UsrlocContacts(pub std::sync::Arc<mod_location::store::Usrloc>);

#[cfg(feature = "location")]
impl ContactLookup for UsrlocContacts {
    fn lookup(&self, aor: &str) -> Vec<Target> {
        let addr = crate::msg::uri_of(aor);
        let (user, host) = match sip_parser::parse_uri(addr.as_bytes()) {
            Some(u) => (u.user.unwrap_or_default().to_vec(), u.host.to_vec()),
            None => (addr.as_bytes().to_vec(), Vec::new()),
        };
        let key = self.0.aor(&user, &host);
        let mut contacts = self.0.lookup(&key);
        contacts.sort_by(|a, b| b.q.unwrap_or(1_000).cmp(&a.q.unwrap_or(1_000)).then(b.last_modified.cmp(&a.last_modified)));
        contacts
            .into_iter()
            .filter_map(|c| {
                let uri = String::from_utf8(c.uri).ok().filter(|u| is_safe_value(u))?;
                let route_set = c.path.and_then(|p| String::from_utf8(p).ok()).map(|p| crate::msg::split_values(&p)).unwrap_or_default();
                Some(Target { request_uri: uri, next_hop: Some(c.received), route_set, credentials: None })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trunk(name: &str, gw: &str, strip: usize, prefix: &str) -> Trunk {
        Trunk { name: name.into(), gateway: gw.into(), next_hop: None, credentials: None, strip, prefix: prefix.into() }
    }

    #[test]
    fn longest_prefix_with_failover_order() {
        let mut t = PrefixTrunks::new();
        t.add("", trunk("default", "gw0.example", 0, ""))
            .add("+49", trunk("de-1", "gw1.example;transport=tcp", 3, "0049"))
            .add("+49", trunk("de-2", "gw2.example", 1, "00"))
            .add("+4930", trunk("berlin", "gw3.example:5070", 0, ""));
        let r: Vec<String> = t.route("+49891234").into_iter().map(|t| t.request_uri).collect();
        assert_eq!(r, vec!["sip:0049891234@gw1.example;transport=tcp", "sip:0049891234@gw2.example"]);
        assert_eq!(t.route("+4930123")[0].request_uri, "sip:+4930123@gw3.example:5070");
        assert_eq!(t.route("1800")[0].request_uri, "sip:1800@gw0.example");
        assert!(t.route("bob").is_empty() && t.route("1+2").is_empty());
        let mut o = OriginateRequest::default();
        t.route("1800")[0].apply_to(&mut o);
        assert_eq!(o.request_uri, "sip:1800@gw0.example");
    }
}
