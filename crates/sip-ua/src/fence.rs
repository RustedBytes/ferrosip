//! Egress fencing: the last check before a message leaves the process.
//!
//! Every [`Transmit`](crate::Transmit) carries the epoch of the owner that
//! produced it. An [`EgressFence`] holds the newest epoch the ownership
//! authority has granted; a driver sends a transmit only when
//! [`EgressFence::admits`] it. A takeover raises the fence (through
//! whatever channel the deployment has to the egress point: a shared
//! process, a lease watcher, an SBC), so a stale owner that is still
//! running cannot put another message on the wire through that egress.
//!
//! The fence is one of three enforcement points; see `docs/sip-ua-recovery.md`
//! (the store refuses stale commits, restore refuses stale takeovers). It
//! cannot recall a message already handed to the network.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// The newest owner epoch; cheap to clone and share between threads.
#[derive(Clone, Debug, Default)]
pub struct EgressFence(Arc<AtomicU64>);

impl EgressFence {
    #[must_use]
    pub fn new(epoch: u64) -> Self {
        Self(Arc::new(AtomicU64::new(epoch)))
    }

    /// A newer owner exists: refuse transmits of older epochs from now on.
    /// Never lowers the fence.
    pub fn raise(&self, epoch: u64) {
        self.0.fetch_max(epoch, Ordering::SeqCst);
    }

    #[must_use]
    pub fn current(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    /// May a transmit of `epoch` leave?
    #[must_use]
    pub fn admits(&self, epoch: u64) -> bool {
        epoch >= self.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fence_only_rises() {
        let f = EgressFence::new(1);
        assert!(f.admits(1) && f.admits(2) && !f.admits(0));
        f.raise(3);
        f.raise(2);
        assert_eq!(f.current(), 3);
        assert!(!f.admits(2) && f.admits(3));
        let g = f.clone();
        g.raise(4);
        assert!(!f.admits(3), "clones share the fence");
    }
}
