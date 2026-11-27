//! Identifiers. Each is a distinct type so a SIP Call-ID can never be
//! confused with a leg, an operation or (in the softswitch) a media id.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! id_type {
    ($(#[$m:meta])* $name:ident, $prefix:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u64);

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "-{}"), self.0)
            }
        }
    };
}

id_type!(
    /// One UA leg: an inbound INVITE we terminate or an outbound INVITE we
    /// originate. A leg owns at most one confirmed dialog.
    UaLegId,
    "leg"
);
id_type!(
    /// One accepted command; events that complete it carry it back.
    OperationId,
    "op"
);
id_type!(
    /// Offer/answer revision of a leg. It increases with every offer (in
    /// either direction); media operations are correlated with it.
    Generation,
    "gen"
);
id_type!(
    /// A transaction inside the engine.
    TxnId,
    "txn"
);

/// RFC 3261 §12 dialog identity, from the local point of view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SipDialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

/// Allocates leg and operation ids. Shared between an engine and the
/// handles that submit commands to it from other threads, so a handle can
/// name a leg or operation before the engine has seen the command.
#[derive(Clone, Debug, Default)]
pub struct IdAllocator(Arc<AtomicU64>);

impl IdAllocator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next(&self) -> u64 {
        // Wrapping after 2^64 allocations is not a practical concern.
        self.0.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }

    pub fn leg(&self) -> UaLegId {
        UaLegId(self.next())
    }

    pub fn op(&self) -> OperationId {
        OperationId(self.next())
    }
}

/// Source of randomness for tags, branches and Call-IDs.
pub trait Entropy: Send {
    fn next_u64(&mut self) -> u64;
}

/// Cryptographically random (RFC 3261 §19.3 asks for unguessable tags).
pub struct SystemEntropy {
    rng: ring::rand::SystemRandom,
    fallback: u64,
}

impl Default for SystemEntropy {
    fn default() -> Self {
        Self { rng: ring::rand::SystemRandom::new(), fallback: 0 }
    }
}

impl Entropy for SystemEntropy {
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        match ring::rand::SecureRandom::fill(&self.rng, &mut b) {
            Ok(()) => u64::from_le_bytes(b),
            // The OS generator failing is not recoverable for security; keep
            // ids unique at least.
            Err(_) => {
                let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
                self.fallback = splitmix(self.fallback ^ u64::from(nanos));
                self.fallback
            }
        }
    }
}

/// Deterministic (tests, simulations).
pub struct SeededEntropy(u64);

impl SeededEntropy {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl Entropy for SeededEntropy {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        splitmix(self.0)
    }
}

fn splitmix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_is_shared_and_unique() {
        let a = IdAllocator::new();
        let b = a.clone();
        let x = a.leg();
        let y = b.op();
        assert_ne!(x.0, y.0);
        assert_eq!(x.to_string(), "leg-1");
    }

    #[test]
    fn seeded_entropy_is_deterministic() {
        let mut a = SeededEntropy::new(7);
        let mut b = SeededEntropy::new(7);
        assert_eq!(a.next_u64(), b.next_u64());
        let mut s = SystemEntropy::default();
        assert_ne!(s.next_u64(), s.next_u64());
    }
}
