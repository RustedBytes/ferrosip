//! Shared-state and security modules (Kamailio names, one `loadmodule`
//! each): `htable`, `pike`, `ratelimit`, `pipelimit`, `secfilter`,
//! `userblocklist`.

use sip_core::Module;
use std::sync::Arc;

mod filters;
mod htable;
mod limits;
#[cfg(test)]
mod testutil;

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &["htable", "pike", "ratelimit", "pipelimit", "secfilter", "userblocklist"];

/// The module called `name`, if it lives in this crate.
pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "htable" => Arc::new(htable::Htable::default()),
        "pike" => Arc::new(limits::Pike::default()),
        "ratelimit" => Arc::new(limits::RateLimit::default()),
        "pipelimit" => Arc::new(limits::PipeLimit::default()),
        "secfilter" => Arc::new(filters::SecFilter::default()),
        "userblocklist" => Arc::new(filters::UserBlocklist::default()),
        _ => return None,
    })
}

/// `k=v;k2=v2` → pairs.
pub(crate) fn kv_list(s: &str) -> Vec<(String, String)> {
    s.split(';')
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (k.trim().to_string(), v.trim().to_string())
        })
        .collect()
}

/// Exactly `N` arguments, as an array to destructure.
pub(crate) fn fixed_args<const N: usize>(a: &[sip_core::Arg]) -> Result<&[sip_core::Arg; N], String> {
    a.try_into().map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}
