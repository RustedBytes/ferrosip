//! The command / event contract between the engine and the application
//! (the softswitch). See the crate README for the responsibilities each
//! command and event carries.
//!
//! Everything here is owned: commands and events cross worker boundaries
//! and never borrow a receive buffer.

use crate::auth::Credentials;
use crate::cause::{Cause, SipStatus};
use crate::dtmf::Dtmf;
use crate::ids::{Generation, OperationId, SipDialogId, UaLegId};
use crate::msg::Header;
use crate::refer::Replaces;
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
    /// RFC 3891: replace this dialog at the target (attended transfer,
    /// call pickup); sent as `Replaces` with `Require: replaces`.
    pub replaces: Option<Replaces>,
    /// RFC 3325 P-Asserted-Identity values; sent only when the next hop is
    /// in `UaConfig::trust`, removed otherwise.
    pub asserted_identity: Vec<String>,
    /// RFC 3323 Privacy values (`id`, `header`, `session`, `user`, `none`, `critical`).
    pub privacy: Vec<String>,
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

/// Send a key press as INFO `application/dtmf-relay`.
#[derive(Clone, Copy, Debug)]
pub struct DtmfRequest {
    pub leg: UaLegId,
    pub dtmf: Dtmf,
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

/// Send a REFER (RFC 3515) in a confirmed dialog: ask the peer to call
/// `refer_to` (blind transfer), or to replace a dialog there (attended:
/// build `refer_to` with `refer::refer_to_with_replaces`).
#[derive(Clone, Debug)]
pub struct ReferRequest {
    pub leg: UaLegId,
    /// Refer-To value (URI or name-addr).
    pub refer_to: String,
    /// Referred-By value.
    pub referred_by: Option<String>,
    pub headers: Vec<Header>,
}

/// Accept (202 + NOTIFY "100 Trying") or decline (603) the peer's REFER.
#[derive(Clone, Debug)]
pub struct ReferResponse {
    pub leg: UaLegId,
    pub accept: bool,
}

/// Report progress of an accepted REFER to its sender (a NOTIFY with a
/// `message/sipfrag` status line). `last` ends the implicit subscription.
#[derive(Clone, Debug)]
pub struct ReferNotify {
    pub leg: UaLegId,
    pub code: u16,
    pub reason: Option<String>,
    pub last: bool,
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
    SendDtmf(DtmfRequest),
    RespondToOffer(OfferResponse),
    Refer(ReferRequest),
    RespondToRefer(ReferResponse),
    NotifyRefer(ReferNotify),
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
            Self::SendDtmf(r) => Some(r.leg),
            Self::RespondToOffer(r) => Some(r.leg),
            Self::Refer(r) => Some(r.leg),
            Self::RespondToRefer(r) => Some(r.leg),
            Self::NotifyRefer(r) => Some(r.leg),
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
    /// RFC 3891: the INVITE replaces this leg's dialog (validated by the
    /// engine). Accepting it and ending the replaced leg is the
    /// application's decision.
    pub replaces: Option<UaLegId>,
    /// The source is in `UaConfig::trust`.
    pub trusted_source: bool,
    /// RFC 3325 P-Asserted-Identity values, only from a trusted source
    /// (empty otherwise, whatever the request carried).
    pub asserted_identity: Vec<String>,
    /// RFC 3323 Privacy values the caller asked for.
    pub privacy: Vec<String>,
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
    /// Offer in a reliable provisional to our body-less INVITE: the answer
    /// goes in the PRACK (RFC 3262).
    ReliableProvisional,
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
    /// The key press, when the body is `application/dtmf-relay` or `application/dtmf`.
    pub dtmf: Option<Dtmf>,
    /// The peer's latest SDP offered RFC 4733 telephone-event: the same
    /// digit may also arrive in RTP; act on one source only.
    pub rtp_dtmf_negotiated: bool,
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

/// The peer asks us to call someone (RFC 3515). Answer with `RespondToRefer`.
#[derive(Clone, Debug)]
pub struct ReferEvent {
    /// The Refer-To value as received.
    pub refer_to: String,
    /// The target URI (URI headers removed).
    pub target: String,
    /// An embedded `Replaces` (attended transfer): pass it to `Originate`.
    pub replaces: Option<Replaces>,
    pub referred_by: Option<String>,
    pub headers: Vec<Header>,
    /// Answer before this (engine clock, ms), else 603.
    pub deadline: u64,
}

/// Progress of our REFER, from the peer's NOTIFY.
#[derive(Clone, Debug)]
pub struct ReferProgressEvent {
    /// The status line of the `message/sipfrag` body.
    pub status: SipStatus,
    /// The implicit subscription ended: no more progress will come.
    pub last: bool,
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
    ReferRequested(ReferEvent),
    ReferProgress(ReferProgressEvent),
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
