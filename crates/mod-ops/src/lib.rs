//! Operations modules: `keepalive` (OPTIONS health checks of arbitrary
//! destinations), `sipdump` (every SIP message in and out to text and pcap
//! files) and `evapi` (event API: push data to external applications over
//! TCP and take their answers, e.g. to resume suspended transactions).

mod evapi;
mod keepalive;
mod sipdump;

use sip_core::Module;
use std::sync::Arc;

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &["keepalive", "sipdump", "evapi"];

pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "keepalive" => Arc::new(keepalive::Keepalive::default()),
        "sipdump" => Arc::new(sipdump::SipDump::default()),
        "evapi" => Arc::new(evapi::Evapi::default()),
        _ => return None,
    })
}

/// Exactly `N` arguments, as an array to destructure.
fn fixed_args<const N: usize>(a: &[sip_core::module::Arg]) -> Result<&[sip_core::module::Arg; N], String> {
    a.try_into().map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}
