//! Panic policy: recover where a panic only spoils one unit of work, fail
//! fast everywhere else.
//!
//! Kamailio isolates failures by running each worker in its own process.
//! ferrosip uses threads, so it decides explicitly:
//! - [`catch`] runs one message, RPC call, route callback or job. A panic
//!   there is logged, counted (`core:panics`) and turned into `Err(Panicked)`, and
//!   the thread carries on.
//! - A thread that serves one connection calls [`expendable`] first. A panic
//!   ends that thread, the same as losing that connection.
//! - Any other panic happens in a long-lived service thread (tm timer, TCP
//!   reader, module timers). Unhandled, it would leave the server running
//!   without that thread: transactions never timing out, connections never
//!   served.
//!   With [`install_hook`] (called by `main`), the process aborts instead, so
//!   a supervisor restarts it cleanly.

use std::cell::Cell;
use std::panic::{self, AssertUnwindSafe};
use std::sync::OnceLock;
use std::sync::atomic::AtomicI64;

thread_local! {
    static RECOVERABLE: Cell<u32> = const { Cell::new(0) };
    static EXPENDABLE: Cell<bool> = const { Cell::new(false) };
}

fn panics() -> &'static AtomicI64 {
    static C: OnceLock<&'static AtomicI64> = OnceLock::new();
    C.get_or_init(|| crate::stats::counter("core", "panics"))
}

/// A unit of work panicked (the panic was already printed by the hook).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Panicked;

impl std::fmt::Display for Panicked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("panicked")
    }
}

impl std::error::Error for Panicked {}

/// Run `f`; a panic inside it is caught (and logged by the hook) instead of
/// ending the thread.
pub fn catch<R>(f: impl FnOnce() -> R) -> Result<R, Panicked> {
    RECOVERABLE.with(|d| d.set(d.get().saturating_add(1)));
    let r = panic::catch_unwind(AssertUnwindSafe(f));
    RECOVERABLE.with(|d| d.set(d.get().saturating_sub(1)));
    r.map_err(|_| Panicked)
}

/// The current thread serves a single connection or request: if it panics,
/// only it ends.
pub fn expendable() {
    EXPENDABLE.with(|e| e.set(true));
}

/// What the hook does with a panic on this thread.
fn fatal_here() -> bool {
    RECOVERABLE.with(Cell::get) == 0 && !EXPENDABLE.with(Cell::get)
}

/// Install the process-wide policy (once, from `main`): every panic is
/// counted and printed with its thread name; panics outside [`catch`] on
/// threads that aren't [`expendable`] abort the process.
pub fn install_hook() {
    let default = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        crate::stats::inc(panics());
        default(info);
        if fatal_here() {
            let t = std::thread::current();
            crate::elog!(
                "ferrosip: fatal: thread {:?} panicked outside a recoverable section; aborting so a supervisor can restart the server",
                t.name().unwrap_or("?")
            );
            std::process::abort();
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catch_recovers_and_reports() {
        let before = panics().load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(catch(|| 7), Ok(7));
        // The hook is process-wide and other tests panic on purpose in
        // parallel: count only this thread's panics, or the total is off.
        let me = std::thread::current().id();
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |_| {
            if std::thread::current().id() == me {
                crate::stats::inc(panics());
            }
        }));
        assert!(catch(|| panic!("boom")).is_err());
        panic::set_hook(prev);
        assert_eq!(panics().load(std::sync::atomic::Ordering::Relaxed), before + 1);
        assert!(fatal_here(), "outside catch again");
    }

    #[test]
    fn nesting_and_expendable() {
        catch(|| {
            assert!(!fatal_here());
            assert!(catch(|| assert!(!fatal_here())).is_ok());
            assert!(!fatal_here());
        })
        .unwrap();
        std::thread::spawn(|| {
            expendable();
            assert!(!fatal_here());
        })
        .join()
        .unwrap();
    }
}
