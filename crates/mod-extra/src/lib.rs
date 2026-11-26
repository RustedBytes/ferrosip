//! The remaining modules of value (Kamailio names, one `loadmodule` each):
//! `siptrace`, `cnxcc`, `tmx`, `uac_redirect`, `avpops`, `sqlops`,
//! `mtree`, `prefix_route`, `speeddial`, `enum`, `outbound`, `tsilo`,
//! `rtimer`, `xhttp`, `xhttp_prom`, `ndb_redis`.

use sip_core::pv::PvRef;
use sip_core::{Arg, Ctx, Module};
use std::sync::Arc;

mod cnxcc;
mod data;
mod dns;
mod http;
mod misc;
mod redis;
mod tmx;
mod trace;

#[cfg(test)]
mod testutil;

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &[
    "siptrace",
    "cnxcc",
    "tmx",
    "uac_redirect",
    "avpops",
    "sqlops",
    "mtree",
    "prefix_route",
    "speeddial",
    "enum",
    "outbound",
    "tsilo",
    "rtimer",
    "xhttp",
    "xhttp_prom",
    "ndb_redis",
];

/// The module called `name`, if it lives in this crate.
pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "siptrace" => Arc::new(trace::SipTrace::default()),
        "cnxcc" => Arc::new(cnxcc::Cnxcc::default()),
        "tmx" => Arc::new(tmx::Tmx::default()),
        "uac_redirect" => Arc::new(tmx::UacRedirect::default()),
        "avpops" => Arc::new(data::AvpOps::default()),
        "sqlops" => Arc::new(data::SqlOps::default()),
        "mtree" => Arc::new(data::MTree::default()),
        "prefix_route" => Arc::new(data::PrefixRoute::default()),
        "speeddial" => Arc::new(data::SpeedDial::default()),
        "enum" => Arc::new(dns::Enum::default()),
        "outbound" => Arc::new(misc::Outbound::default()),
        "tsilo" => Arc::new(misc::Tsilo::default()),
        "rtimer" => Arc::new(misc::Rtimer::default()),
        "xhttp" => Arc::new(http::Xhttp::default()),
        "xhttp_prom" => Arc::new(http::XhttpProm::default()),
        "ndb_redis" => Arc::new(redis::NdbRedis::default()),
        _ => return None,
    })
}

/// An argument that must be a single variable (outputs).
pub(crate) fn pv_arg(a: &Arg) -> Result<PvRef, String> {
    match a {
        Arg::Fmt(f) => f.single_pv().cloned().ok_or_else(|| "expected a single variable".into()),
        _ => Err("expected a variable like $var(x)".into()),
    }
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

/// R-URI user (or "").
pub(crate) fn ruri_user(ctx: &Ctx<'_, '_>) -> String {
    sip_parser::parse_uri(ctx.ruri()).and_then(|u| u.user).map(|u| String::from_utf8_lossy(u).into_owned()).unwrap_or_default()
}

/// Exactly `N` arguments, as an array to destructure.
pub(crate) fn fixed_args<const N: usize>(a: &[Arg]) -> Result<&[Arg; N], String> {
    a.try_into().map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_list_splits_and_trims_pairs() {
        let cases: &[(&str, &[(&str, &str)])] = &[
            ("", &[]),
            (";;", &[]),
            ("name=srv1;addr=127.0.0.1;port=6379", &[("name", "srv1"), ("addr", "127.0.0.1"), ("port", "6379")]),
            (" a = 1 ; b ;c=", &[("a", "1"), ("b", ""), ("c", "")]),
            ("url=a=b", &[("url", "a=b")]),
        ];
        for &(s, want) in cases {
            let got = kv_list(s);
            let got: Vec<(&str, &str)> = got.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            assert_eq!(got, want, "{s:?}");
        }
    }

    #[test]
    fn every_name_has_a_module_with_that_name() {
        for &n in NAMES {
            let m = module(n).unwrap_or_else(|| panic!("{n}"));
            assert_eq!(m.name(), n);
        }
        assert!(module("nope").is_none());
    }

    #[test]
    fn fixed_args_checks_the_count() {
        let a = [Arg::Int(1), Arg::Int(2)];
        assert!(fixed_args::<2>(&a).is_ok());
        assert_eq!(fixed_args::<1>(&a).err().as_deref(), Some("expected 1 argument(s), got 2"));
    }
}
