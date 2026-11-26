//! Cx requests that don't block a worker (Kamailio's async ims_* calls).
//!
//! The SIP transaction is suspended while the HSS answers, so tm absorbs
//! the request's retransmissions meanwhile, and the worker goes on with
//! other messages. When the answer (or the cdp timeout) comes, a small pool
//! (`ims-cx-N`) resumes the transaction: `apply` turns the answer into
//! AVPs or a reply on the resumed request, then the script continues: in
//! the reply route named in a Kamailio-style call when the script has it,
//! else right after the call (`.fsr` `await`, or a `.cfg` without that
//! route).

use mod_txn::{Tm, TxnId};
use sip_core::sync::lock;
use sip_core::{AsyncPending, Continuation, Ctx, RouteHub};
use sip_diameter::{AnswerFn, DiameterError, Msg};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};

type Job = Box<dyn FnOnce() + Send>;

/// Threads that resume transactions (never the Diameter reader).
fn pool() -> &'static Mutex<Sender<Job>> {
    static P: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();
    P.get_or_init(|| {
        let (tx, rx) = channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..4 {
            let rx = rx.clone();
            // Without any thread, the receiver is gone and sends fail (logged).
            let spawned = std::thread::Builder::new().name(format!("ims-cx-{i}")).spawn(move || {
                loop {
                    let job = lock(&rx).recv();
                    let Ok(job) = job else { return };
                    if sip_core::panic::catch(job).is_err() {
                        sip_core::elog!("ims: panic while resuming after a Cx answer");
                    }
                }
            });
            if let Err(e) = spawned {
                sip_core::log::log(sip_core::log::L_ERR, &format!("ims: cannot start Cx resume thread {i}: {e}"));
            }
        }
        Mutex::new(tx)
    })
}

/// What the module applies to the resumed request: the answer (or why
/// there is none) → AVPs, or a reply sent with `ctx.reply_with`.
pub(crate) type Apply = Box<dyn FnOnce(Result<Msg, DiameterError>, &mut Ctx<'_, '_>) + Send>;

/// Suspend the request and run `send` (which sends the Cx request with the
/// given completion); `apply` runs on the resumed request. `timeout` is
/// the cdp timeout: tm keeps the suspended transaction a little longer, so
/// the Cx error, not "Suspended Too Long", decides.
///
/// Returns the function's result code: 0 (the script stops here and
/// continues on resume), or None when the request can't be suspended (a
/// failure or branch route, a transaction that already exists): the
/// caller then does the exchange synchronously.
pub(crate) fn run(
    tm: &Arc<Tm>,
    hub: &RouteHub,
    ctx: &mut Ctx<'_, '_>,
    reply_route: &str,
    timeout: std::time::Duration,
    send: impl FnOnce(AnswerFn) + Send + 'static,
    apply: Apply,
) -> Option<i32> {
    // A reply (an onreply route) has no transaction of its own to suspend.
    if !ctx.msg.is_request() {
        return None;
    }
    let route = (!reply_route.is_empty()).then(|| hub.runner().and_then(|r| r.route_index(reply_route))).flatten();
    let id = match tm.suspend_for(ctx, u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX).saturating_add(1000)) {
        Ok(id) => id,
        // A retransmission of the request being held: absorbed.
        Err(0) => return Some(0),
        Err(_) => return None,
    };
    let tm = tm.clone();
    match route {
        // Kamailio style: continue in the named reply route.
        Some(idx) => send(completion(tm, id, Continuation::route(idx), apply)),
        // Continue right after the call, once the script has unwound.
        None => ctx.ext.push(Box::new(AsyncPending(Box::new(move |cont| send(completion(tm, id, cont, apply)))))),
    }
    Some(0)
}

/// The Diameter completion: hand the answer to the pool, which resumes.
fn completion(tm: Arc<Tm>, id: TxnId, cont: Continuation, apply: Apply) -> AnswerFn {
    Box::new(move |res| {
        let job: Job = Box::new(move || {
            tm.resume(&id, |runner, c| {
                apply(res, c);
                runner.resume(&cont, c);
            });
        });
        if lock(pool()).send(job).is_err() {
            sip_core::elog!("ims: Cx resume pool is gone");
        }
    })
}

/// For the functions a `.cfg` uses as a check (`if (!Rx_AAR("R", …))`):
/// asynchronous when called from `.fsr` (no route name) or when the script
/// has the named reply route (Kamailio's form); otherwise the caller stays
/// synchronous so the check keeps its meaning.
pub(crate) fn wanted(hub: &RouteHub, reply_route: &str) -> bool {
    reply_route.is_empty() || hub.runner().and_then(|r| r.route_index(reply_route)).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{registry, reply_msg, request, script, with_msg};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// `run` with a send that records it ran (and never answers).
    fn run_on(tm: &Arc<Tm>, hub: &RouteHub, raw: &str, route: &str) -> (Option<i32>, bool, bool) {
        let sent = Arc::new(AtomicBool::new(false));
        let s2 = sent.clone();
        with_msg(raw, |ctx| {
            let rc = run(tm, hub, ctx, route, Duration::from_secs(1), move |_done| s2.store(true, Ordering::Relaxed), Box::new(|_, _| {}));
            (rc, sent.load(Ordering::Relaxed), ctx.ext::<AsyncPending>().is_some())
        })
    }

    #[test]
    fn only_new_requests_are_suspended() {
        let reg = registry(true);
        let tm = reg.api::<Tm>().unwrap();
        let hub = reg.hub.clone();
        // A reply has no transaction of its own; ACK and CANCEL can't be suspended.
        assert_eq!(run_on(&tm, &hub, &reply_msg(183, "", ""), ""), (None, false, false));
        assert_eq!(run_on(&tm, &hub, &request("ACK", "sip:bob@ims.test", "sip:bob@ims.test", "", ""), ""), (None, false, false));
        // A request: sent once the script has unwound (no reply route).
        let req = |branch: &str| request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", "").replace("z9hG4bK1", branch);
        assert_eq!(run_on(&tm, &hub, &req("z9hG4bKa"), ""), (Some(0), false, true));
        // A reply route the script doesn't have is the same.
        assert_eq!(run_on(&tm, &hub, &req("z9hG4bKb"), "CX_REPLY"), (Some(0), false, true));
        // With that route, the Cx request goes out at once.
        script(&hub, &[], &["CX_REPLY"], Box::new(|_, _| true));
        assert_eq!(run_on(&tm, &hub, &req("z9hG4bKc"), "CX_REPLY"), (Some(0), true, false));
    }

    #[test]
    fn asynchronous_when_fsr_or_the_reply_route_exists() {
        let hub = RouteHub::default();
        assert!(wanted(&hub, ""), ".fsr: no route name");
        assert!(!wanted(&hub, "R"), "no script");
        script(&hub, &[], &["R"], Box::new(|_, _| true));
        assert!(wanted(&hub, "R"));
        assert!(!wanted(&hub, "OTHER"));
    }
}
