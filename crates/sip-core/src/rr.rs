//! Record-Route / Path insertion requested by the script (`record_route()`,
//! `record_route_preset()`, `add_path()`), rendered when the outgoing
//! transport is known — per branch, by tm — so double Record-Route (one
//! entry per interface when the transport/address changes, `;r2=on`) is
//! correct (Kamailio rr `enable_double_rr`).

use crate::module::Ctx;
use crate::net::{Dest, Proto};
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub enum RrKind {
    /// Our own address(es), with `;lr` and params.
    Auto { double: bool },
    /// Explicit values (`record_route_preset`): one or two.
    Preset(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct RrEntry {
    /// "Record-Route" or "Path".
    pub header: &'static str,
    pub kind: RrKind,
    /// Extra URI params (`;ftag=…;foo=bar`), without the leading `;`.
    pub params: Vec<String>,
    /// `lr=on` instead of `lr` (rr `enable_full_lr`).
    pub full_lr: bool,
    /// User part of our URI (`add_path("user")`, `record_route` user).
    pub user: Option<String>,
}

/// Entries requested for the current message.
#[derive(Clone, Debug, Default)]
pub struct RecordRoute(pub Vec<RrEntry>);

/// `;params` added before `record_route()` (rr `add_rr_param()`, the
/// dialog's `did`): the next Record-Route entry takes them.
#[derive(Clone, Debug, Default)]
pub struct PendingParams(pub Vec<String>);

/// Add `;params` (without the `;`) to the Record-Route of this request:
/// to the entries requested so far, else to the next `record_route()`
/// (Kamailio rr `add_rr_param`).
pub fn add_params(ctx: &mut Ctx<'_, '_>, ps: Vec<String>) {
    match ctx.ext_get_mut::<RecordRoute>() {
        Some(rr) if !rr.0.is_empty() => rr.0.iter_mut().for_each(|e| e.params.extend(ps.iter().cloned())),
        _ => ctx.ext_mut::<PendingParams>().0.extend(ps),
    }
}

fn transport_param(p: Proto) -> &'static str {
    match p {
        Proto::Udp => "",
        Proto::Tcp => ";transport=tcp",
        Proto::Tls => ";transport=tls",
        Proto::Ws => ";transport=ws",
        Proto::Wss => ";transport=wss",
    }
}

fn uri(e: &RrEntry, addr: SocketAddr, proto: Proto, r2: bool, lr: &str) -> String {
    let params = &e.params;
    let user = e.user.as_deref().map(|u| format!("{u}@")).unwrap_or_default();
    let mut s = format!("sip:{user}{addr}{}", transport_param(proto));
    if r2 {
        s.push_str(";r2=on");
    }
    s.push(';');
    s.push_str(lr);
    for p in params {
        s.push(';');
        s.push_str(p);
    }
    s
}

/// Header lines to insert for a request leaving towards `dst`.
pub fn branch_lines(ctx: &Ctx<'_, '_>, dst: &Dest) -> Vec<u8> {
    let Some(rr) = ctx.ext::<RecordRoute>() else { return Vec::new() };
    let mut out = String::new();
    let inb = ctx.advertise(ctx.src.proto);
    let outb = ctx.advertise(dst.proto);
    for e in &rr.0 {
        let lr = if e.full_lr { "lr=on" } else { "lr" };
        match &e.kind {
            RrKind::Preset(values) => {
                for v in values {
                    let v = v.trim_start_matches('<').trim_end_matches('>');
                    let v = if v.starts_with("sip:") || v.starts_with("sips:") { v.to_string() } else { format!("sip:{v}") };
                    let lrp = if v.contains(";lr") { String::new() } else { format!(";{lr}") };
                    let params: String = e.params.iter().map(|p| format!(";{p}")).collect();
                    out.push_str(&format!("{}: <{v}{lrp}{params}>\r\n", e.header));
                }
            }
            // Path always names the interface facing the registrar.
            RrKind::Auto { .. } if e.header == "Path" => {
                out.push_str(&format!("Path: <{}>\r\n", uri(e, outb, dst.proto, false, lr)));
            }
            RrKind::Auto { double } if *double && (inb != outb || ctx.src.proto != dst.proto) => {
                // Top entry faces the next hop, the second the previous hop.
                out.push_str(&format!("{}: <{}>\r\n", e.header, uri(e, outb, dst.proto, true, lr)));
                out.push_str(&format!("{}: <{}>\r\n", e.header, uri(e, inb, ctx.src.proto, true, lr)));
            }
            RrKind::Auto { .. } => {
                out.push_str(&format!("{}: <{}>\r\n", e.header, uri(e, inb, ctx.src.proto, false, lr)));
            }
        }
    }
    out.into_bytes()
}
