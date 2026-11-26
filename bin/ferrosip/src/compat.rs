//! Running unmodified Kamailio configs.
//!
//! - **Built-in shims**: Kamailio modules whose job ferrosip does natively
//!   (the control socket, database drivers chosen by URL, the TLS and
//!   WebSocket transports) load as no-op modules, so `loadmodule` lines
//!   don't have to be removed. Their parameters are accepted with a notice;
//!   the TLS ones are mapped to ferrosip's TLS settings.
//! - **Parameters without effect**: Kamailio module parameters that tune
//!   behaviour ferrosip fixes are listed in [`NO_EFFECT`]. They load with a
//!   one-time notice instead of failing. Only listed names: an unknown
//!   parameter is still an error, which is what catches typos.

use sip_core::{Arg, Ctx, Module, Registry, want_args};
use std::sync::Arc;

/// A Kamailio module that is built into ferrosip.
struct Shim {
    name: &'static str,
    /// Where the functionality lives in ferrosip (shown once at startup).
    instead: &'static str,
}

impl Module for Shim {
    fn name(&self) -> &'static str {
        self.name
    }

    fn set_param(&self, name: &str, _v: &Arg) -> Result<(), String> {
        // tls params are applied by `tls_settings` before modules load.
        if self.name != "tls" || !matches!(name, "config" | "private_key" | "certificate" | "ca_list" | "verify_certificate" | "require_certificate") {
            sip_core::module::param_no_effect(self.name, name);
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        sip_core::elog!("ferrosip: note: loadmodule \"{}\": built in ({})", self.name, self.instead);
        if self.name == "websocket" {
            // In Kamailio the xhttp event route upgrades a plain TCP connection.
            // In ferrosip ws:/wss: listeners do the upgrade before any route
            // runs, so here there is nothing to upgrade: the call fails and the
            // usual `if (ws_handle_handshake()) exit;` falls through.
            reg.export("websocket", "ws_handle_handshake", |a: &[Arg]| want_args(a, 0), |_: &mut Ctx, _: &()| -1);
            reg.export(
                "websocket",
                "ws_close",
                |a: &[Arg]| {
                    if a.len() > 3 {
                        return Err("ws_close([status[, reason[, connection_id]]])".into());
                    }
                    Ok(())
                },
                |_: &mut Ctx, _: &()| -1,
            );
        }
        Ok(())
    }
}

/// Kamailio modules provided natively by ferrosip.
pub fn builtin_module(name: &str) -> Option<Arc<dyn Module>> {
    let instead = match name {
        "ctl" | "cfg_rpc" | "xmlrpc" | "mi_fifo" | "mi_rpc" | "fifo" => "control interface: the JSON-RPC socket (--rpc-socket, ferroctl)",
        "db_mysql" | "mysql" | "db_postgres" | "postgres" | "db_sqlite" | "db_text" | "dbtext" | "db_flatstore" => {
            "database driver: chosen by each module's db_url scheme"
        }
        "tls" => "TLS transport: tls: listeners; tls params map to --tls-* settings",
        "websocket" => "WebSocket transport: ws:/wss: listeners do the upgrade",
        "kemix" => "no KEMI engine besides app_lua",
        "debugger" => "logging: --debug and the log level RPCs",
        _ => return None,
    };
    let name: &'static str = Box::leak(name.to_string().into_boxed_str());
    Some(Arc::new(Shim { name, instead }))
}

/// `modparam("tls", …)` → ferrosip's TLS settings (command-line values win).
pub fn tls_settings(params: &[(String, String)], tls: &mut sip_transport::TlsFiles) {
    for (name, v) in params {
        match name.as_str() {
            // Kamailio's tls.cfg is the syntax --tls-profile reads.
            "config" if tls.profile.is_none() => tls.profile = Some(v.into()),
            "private_key" if tls.key.is_none() => tls.key = Some(v.into()),
            "certificate" if tls.cert.is_none() => tls.cert = Some(v.into()),
            "ca_list" if tls.ca.is_none() => tls.ca = Some(v.into()),
            "verify_certificate" | "require_certificate" if v.trim() == "1" => tls.verify_client = true,
            _ => {}
        }
    }
}

/// Kamailio module parameters ferrosip accepts without changing anything:
/// the behaviour they tune is fixed (or configured another way) here.
pub const NO_EFFECT: &[(&str, &str)] = &[
    ("acc", "report_ack"),
    ("acc", "report_cancels"),
    ("acc", "detect_direction"),
    ("jsonrpcs", "pretty_format"),
    ("tm", "restart_fr_on_each_reply"),
    ("tm", "cancel_b_method"),
    ("tm", "reparse_on_dns_failover"),
    ("tm", "e2e_cancel_reason"),
    ("registrar", "method_filtering"),
    ("registrar", "nat_flag"),
    ("registrar", "save_nat_flag"),
    ("registrar", "load_nat_flag"),
    ("registrar", "received_avp"),
    ("registrar", "xavp_cfg"),
    ("registrar", "xavp_rcd"),
    ("registrar", "gruu_enabled_unused"),
    ("rr", "custom_user_avp"),
    ("rr", "cookie_secret"),
    ("rr", "cookie_filter"),
    ("rr", "add_username"),
    ("rr", "force_send_socket"),
    ("rr", "append_fromtag"),
    ("rr", "enable_double_rr"),
    ("rr", "enable_full_lr"),
    ("rls", "xcap_root"),
    ("rls", "reduce_xcap_needs"),
    ("rls", "min_expiration"),
    ("rls", "max_expiration"),
    ("rls", "default_expiration"),
    ("rls", "auth"),
    ("msilo", "registrar"),
    ("domain", "load_domain_attrs"),
    ("domain", "db_mode"),
    ("dispatcher", "xavp_dst_mode"),
    ("dispatcher", "xavp_ctx_mode"),
    ("dispatcher", "sock_avp"),
    ("dispatcher", "grp_avp"),
    ("dispatcher", "dst_avp"),
    ("dispatcher", "cnt_avp"),
    ("dispatcher", "attrs_avp"),
    ("corex", "alias_subdomains"),
    ("auth", "force_stateless_reply"),
    ("auth", "use_next_nonce"),
    ("auth", "auth_checks_register"),
    ("auth", "auth_checks_no_dlg"),
    ("auth", "auth_checks_in_dlg"),
    ("auth_db", "plain_password_column"),
    ("nathelper", "rtpproxy_sock"),
    ("nathelper", "natping_stateful"),
    ("nathelper", "natping_method"),
    ("nathelper", "natping_crlf"),
    ("ims_registrar_scscf", "user_data_always"),
    ("ims_registrar_scscf", "use_path"),
    ("ims_registrar_scscf", "subscription_min_expires"),
    ("ims_registrar_scscf", "subscription_max_expires"),
    ("ims_registrar_scscf", "max_contacts"),
    ("sl", "bind_tm"),
    ("usrloc", "timer_procs"),
    ("usrloc", "timer_interval"),
    ("usrloc", "use_domain"),
    ("usrloc", "nat_bflag"),
    ("usrloc", "handle_lost_tcp"),
    ("usrloc", "close_expired_tcp"),
    ("xlog", "buf_size"),
    ("xlog", "prefix"),
    ("debugger", "cfgtrace"),
];

/// Is this parameter in [`NO_EFFECT`]?
pub fn no_effect(module: &str, name: &str) -> bool {
    NO_EFFECT.iter().any(|&(m, n)| m == module && n == name)
}
