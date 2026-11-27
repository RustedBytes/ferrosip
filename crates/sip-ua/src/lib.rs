//! `sip-ua`: a reusable, sans-IO SIP user agent engine (UAC and UAS) for
//! building B2BUAs and softswitches on top of ferrosip.
//!
//! The engine owns SIP correctness: transactions (RFC 3261 §17 with the
//! RFC 6026 corrections), dialogs, CANCEL, forked 2xx handling, digest
//! authentication, offer/answer sequencing (RFC 3264) and timers. The
//! application owns call policy and media: it talks to the engine through
//! [`UaCommand`]s and [`EventEnvelope`]s, and SDP bodies stay opaque.
//!
//! The engine does no I/O and never blocks. A driver feeds it received
//! messages, the clock and DNS results, and sends what it emits; see
//! [`runtime`] for a ready-made UDP driver on std threads.

pub mod api;
pub mod auth;
pub mod cause;
pub mod dtmf;
pub mod engine;
pub mod identity;
pub mod ids;
pub mod msg;
pub mod refer;
pub mod routing;
pub mod runtime;
pub mod sdp;
pub mod txn;

pub use api::*;
pub use auth::Credentials;
pub use cause::{Cause, CauseKind, SipStatus};
pub use dtmf::Dtmf;
pub use engine::{LegSnapshot, OfferState, Phase, ResolveRequest, Role, Transmit, UaConfig, UaEngine, UaStats};
pub use identity::TrustPolicy;
pub use ids::{Entropy, Generation, IdAllocator, OperationId, SeededEntropy, SipDialogId, SystemEntropy, TxnId, UaLegId};
pub use msg::{Header, Limits, Method, SipMessage};
pub use refer::Replaces;
pub use sip_core::{Dest, Proto};
pub use txn::TimerConfig;
