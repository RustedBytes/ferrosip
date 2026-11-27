//! The command / event contract between the engine and the application
//! (the softswitch). See the crate README for the responsibilities each
//! command and event carries.
//!
//! Everything here is owned: commands and events cross worker boundaries
//! and never borrow a receive buffer.

use crate::auth::Credentials;
use crate::cause::{Cause, SipStatus};
use crate::ids::{Generation, OperationId, SipDialogId, UaLegId};
use crate::msg::Header;
use sip_core::Dest;

/// Create an outbound leg: send an INVITE.
#[derive(Clone, Debug, Default)]
pub struct OriginateRequest {
    /// Leg id to use (pre-allocated from the shared `IdAllocator`); None:
    /// the engine allocates one and returns it.
    pub leg: Option<UaLegId>,
    pub request_uri: String,
    /// From header value without tag (`"Alice" <sip:alice@example.com>`).
    pub from: String,
    /// To header value; default: `<request_uri>`.
    pub to: Option<String>,
    /// Send here instead of resolving the first Route / Request-URI.
    pub next_hop: Option<Dest>,
    /// Pre-loaded Route set (URIs or name-addrs), in order.
    pub route_set: Vec<String>,
    /// Contact URI; default: built from the advertised address.
    pub contact: Option<String>,
    /// Extra headers (validated: token names, no line breaks; the
    /// dialog-defining headers cannot be overridden).
    pub headers: Vec<Header>,
    /// SDP offer; None: delayed offer (the 2xx will carry the offer).
    pub sdp: Option<Vec<u8>>,
    pub credentials: Option<Credentials>,
    /// Cancel if not answered within this; default from the config.
    pub no_answer_timeout_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ProvisionalRequest {
    pub leg: UaLegId,
    /// 101..=199 (100 is sent by the engine itself).
    pub code: u16,
    pub reason: Option<String>,
    /// Early media: the answer to the INVITE's offer.
    pub sdp: Option<Vec<u8>>,
    pub headers: Vec<Header>,
}

#[derive(Clone, Debug)]
pub struct AcceptRequest {
    pub leg: UaLegId,
    /// Answer to the INVITE's offer, or our offer when the INVITE had none.
    /// May be omitted only when an early answer was already sent.
    pub sdp: Option<Vec<u8>>,
    pub headers: Vec<Header>,
}

#[derive(Clone, Debug)]
pub struct RejectRequest {
    pub leg: UaLegId,
    /// 300..=699.
    pub code: u16,
    pub reason: Option<String>,
    pub headers: Vec<Header>,
}

#[derive(Clone, Debug)]
pub struct CancelRequest {
    pub leg: UaLegId,
    /// `Reason` header value for the CANCEL (RFC 3326), e.g. `Q.850;cause=16`.
    pub reason: Option<String>,
}

/// Tear the leg down in whatever way its state requires: CANCEL (outbound,
/// not answered), a final error (inbound, not answered) or BYE.
#[derive(Clone, Debug)]
pub struct HangupRequest {
    pub leg: UaLegId,
    /// `Reason` header value (RFC 3326).
    pub reason: Option<String>,
    /// Final status for an unanswered inbound leg; default 480.
    pub code: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiateMethod {
    ReInvite,
    Update,
}

/// Send a new local offer in a confirmed dialog.
#[derive(Clone, Debug)]
pub struct NegotiateRequest {
    pub leg: UaLegId,
    pub method: NegotiateMethod,
    pub sdp: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct InfoRequest {
    pub leg: UaLegId,
    pub content_type: String,
    pub body: Vec<u8>,
    pub headers: Vec<Header>,
}

/// Answer the outstanding remote offer (or supply the offer a body-less
/// re-INVITE asked for). `sdp: None` rejects it (488) and rolls back.
#[derive(Clone, Debug)]
pub struct OfferResponse {
    pub leg: UaLegId,
    /// Must equal the generation of the `RemoteOffer` event being answered.
    pub generation: Generation,
    pub sdp: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub enum UaCommand {
    Originate(Box<OriginateRequest>),
    Provisional(ProvisionalRequest),
    Accept(AcceptRequest),
    Reject(RejectRequest),
    Cancel(CancelRequest),
    Hangup(HangupRequest),
    Negotiate(NegotiateRequest),
    SendInfo(InfoRequest),
    RespondToOffer(OfferResponse),
}

impl UaCommand {
    /// The leg a command addresses (None for `Originate` without an id).
    pub fn leg(&self) -> Option<UaLegId> {
        match self {
            Self::Originate(o) => o.leg,
            Self::Provisional(r) => Some(r.leg),
            Self::Accept(r) => Some(r.leg),
            Self::Reject(r) => Some(r.leg),
            Self::Cancel(r) => Some(r.leg),
            Self::Hangup(r) => Some(r.leg),
            Self::Negotiate(r) => Some(r.leg),
            Self::SendInfo(r) => Some(r.leg),
            Self::RespondToOffer(r) => Some(r.leg),
        }
    }
}

/// A command was accepted: its effects will follow as events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub op: OperationId,
    pub leg: UaLegId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandError {
    UnknownLeg,
    /// The leg is not in a state where this command is valid.
    InvalidState(&'static str),
    /// Another offer/answer exchange is in progress (RFC 3264 §4).
    OfferPending,
    /// `RespondToOffer` for a generation that is not the outstanding one.
    StaleGeneration,
    InvalidArgument(String),
    /// Leg limit reached or the command queue is full.
    Overloaded,
    /// Graceful drain: no new legs.
    Draining,
    /// No advertised address for the transport.
    NoLocalAddress,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CommandError {}

/// A new inbound INVITE (a new UAS leg).
#[derive(Clone, Debug)]
pub struct InboundInvite {
    pub request_uri: String,
    pub from: String,
    pub to: String,
    pub call_id: String,
    pub source: Dest,
    /// Every header of the INVITE, for the application's policy (trusted
    /// identity headers are only trustworthy from trusted sources).
    pub headers: Vec<Header>,
    /// The offer; None: delayed offer, `Accept` must carry an offer.
    pub sdp: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ProvisionalEvent {
    pub status: SipStatus,
    /// The early dialog's remote tag (forked early dialogs differ).
    pub remote_tag: Option<String>,
    /// Early SDP (the answer to our offer).
    pub sdp: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct AcceptedEvent {
    pub status: SipStatus,
    /// Answer to our offer, or the remote offer (then `RemoteOffer` follows).
    pub sdp: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct AckEvent {
    /// The answer, when our 2xx carried an offer.
    pub sdp: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferKind {
    /// Offer in a 2xx to our body-less INVITE: the answer goes in the ACK.
    InviteResponse,
    ReInvite,
    Update,
}

#[derive(Clone, Debug)]
pub struct RemoteOfferEvent {
    pub kind: OfferKind,
    /// None: a body-less re-INVITE; respond with an offer.
    pub sdp: Option<Vec<u8>>,
    /// Answer before this (engine clock, ms) or the engine applies its
    /// safe failure strategy.
    pub deadline: u64,
}

#[derive(Clone, Debug)]
pub struct ByeEvent {
    pub reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct InfoEvent {
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub headers: Vec<Header>,
}

/// An operation (Negotiate, SendInfo) finished.
#[derive(Clone, Debug)]
pub struct CompletedEvent {
    pub status: SipStatus,
    /// The answer to our offer (Negotiate).
    pub sdp: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct FailureEvent {
    pub cause: Cause,
    /// The leg is being torn down (a `Terminated` follows) or only the
    /// operation failed (e.g. a re-INVITE got 488; the session continues).
    pub leg_failed: bool,
    /// RFC 3261 §14.1 glare: retry after this many ms (491 only).
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct TerminationEvent {
    pub cause: Cause,
}

#[derive(Clone, Debug)]
pub enum UaEvent {
    IncomingInvite(InboundInvite),
    Provisional(ProvisionalEvent),
    Accepted(AcceptedEvent),
    Ack(AckEvent),
    /// The peer cancelled the unanswered inbound INVITE.
    Cancelled,
    RemoteOffer(RemoteOfferEvent),
    RemoteBye(ByeEvent),
    Info(InfoEvent),
    Completed(CompletedEvent),
    Failed(FailureEvent),
    /// The leg is gone; always the last event of a leg, emitted exactly once.
    Terminated(TerminationEvent),
    /// A command submitted through a non-blocking handle was refused.
    CommandRejected(CommandError),
}

impl UaEvent {
    /// Events that must reach the application even under overload.
    pub fn is_critical(&self) -> bool {
        matches!(self, Self::Terminated(_) | Self::Failed(_) | Self::CommandRejected(_))
    }
}

/// An event with its correlation data.
#[derive(Clone, Debug)]
pub struct EventEnvelope {
    pub leg: UaLegId,
    /// Monotonic per leg, starting at 1; a gap means events were missed
    /// (reconcile with `UaEngine::snapshot`).
    pub seq: u64,
    pub generation: Generation,
    /// The operation this event completes or answers, if any.
    pub op: Option<OperationId>,
    pub dialog: Option<SipDialogId>,
    pub event: UaEvent,
}
