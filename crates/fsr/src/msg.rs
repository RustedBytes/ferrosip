//! The typed message object: `msg.<field>` → the pseudo-variable it is
//! read and written through.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldTy {
    Str,
    Int,
    Method,
    Transport,
}

pub struct Field {
    pub path: &'static str,
    pub pv: &'static str,
    pub ty: FieldTy,
    pub settable: bool,
    /// Present on requests / on replies.
    pub request: bool,
    pub reply: bool,
}

const fn f(path: &'static str, pv: &'static str, ty: FieldTy, settable: bool, request: bool, reply: bool) -> Field {
    Field { path, pv, ty, settable, request, reply }
}

use FieldTy::*;

pub const FIELDS: &[Field] = &[
    f("ruri", "$ru", Str, true, true, false),
    f("ruri.user", "$rU", Str, true, true, false),
    f("ruri.host", "$rd", Str, true, true, false),
    f("ruri.port", "$rp", Int, true, true, false),
    f("dst_uri", "$du", Str, true, true, false),
    f("from.uri", "$fu", Str, false, true, true),
    f("from.user", "$fU", Str, false, true, true),
    f("from.host", "$fd", Str, false, true, true),
    f("from.tag", "$ft", Str, false, true, true),
    f("from.display", "$fn", Str, false, true, true),
    f("to.uri", "$tu", Str, false, true, true),
    f("to.user", "$tU", Str, false, true, true),
    f("to.host", "$td", Str, false, true, true),
    f("to.tag", "$tt", Str, false, true, true),
    f("method", "$rm", Method, false, true, true),
    f("call_id", "$ci", Str, false, true, true),
    f("cseq", "$cs", Int, false, true, true),
    f("src.ip", "$si", Str, false, true, true),
    f("src.port", "$sp", Int, false, true, true),
    f("src.transport", "$pr", Transport, false, true, true),
    f("user_agent", "$ua", Str, false, true, true),
    f("body", "$rb", Str, false, true, true),
    f("code", "$rs", Int, false, false, true),
    f("reason", "$rr", Str, false, false, true),
];

pub fn field(path: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|f| f.path == path)
}

/// Request methods `msg.method` compares with.
pub const METHODS: &[&str] =
    &["INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "MESSAGE", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "PRACK", "UPDATE", "REFER"];

/// Transports (`msg.src.transport`), and how `$pr` spells them.
pub const TRANSPORTS: &[(&str, &str)] = &[("UDP", "udp"), ("TCP", "tcp"), ("TLS", "tls"), ("WS", "ws"), ("WSS", "wss")];

/// SIP response codes by name (the IANA registry's reason phrases in
/// PascalCase): `reply(NotFound)`, `r.code == BusyHere`. 606 is
/// `GlobalNotAcceptable` (406 is `NotAcceptable`).
pub const STATUS_CODES: &[(&str, i64)] = &[
    ("Trying", 100),
    ("Ringing", 180),
    ("CallIsBeingForwarded", 181),
    ("Queued", 182),
    ("SessionProgress", 183),
    ("EarlyDialogTerminated", 199),
    ("OK", 200),
    ("Accepted", 202),
    ("NoNotification", 204),
    ("MultipleChoices", 300),
    ("MovedPermanently", 301),
    ("MovedTemporarily", 302),
    ("UseProxy", 305),
    ("AlternativeService", 380),
    ("BadRequest", 400),
    ("Unauthorized", 401),
    ("PaymentRequired", 402),
    ("Forbidden", 403),
    ("NotFound", 404),
    ("MethodNotAllowed", 405),
    ("NotAcceptable", 406),
    ("ProxyAuthenticationRequired", 407),
    ("RequestTimeout", 408),
    ("Conflict", 409),
    ("Gone", 410),
    ("LengthRequired", 411),
    ("ConditionalRequestFailed", 412),
    ("RequestEntityTooLarge", 413),
    ("RequestUriTooLong", 414),
    ("UnsupportedMediaType", 415),
    ("UnsupportedUriScheme", 416),
    ("UnknownResourcePriority", 417),
    ("BadExtension", 420),
    ("ExtensionRequired", 421),
    ("SessionIntervalTooSmall", 422),
    ("IntervalTooBrief", 423),
    ("BadLocationInformation", 424),
    ("BadAlertMessage", 425),
    ("UseIdentityHeader", 428),
    ("ProvideReferrerIdentity", 429),
    ("FlowFailed", 430),
    ("AnonymityDisallowed", 433),
    ("BadIdentityInfo", 436),
    ("UnsupportedCertificate", 437),
    ("InvalidIdentityHeader", 438),
    ("FirstHopLacksOutboundSupport", 439),
    ("MaxBreadthExceeded", 440),
    ("BadInfoPackage", 469),
    ("ConsentNeeded", 470),
    ("TemporarilyUnavailable", 480),
    ("CallDoesNotExist", 481),
    ("LoopDetected", 482),
    ("TooManyHops", 483),
    ("AddressIncomplete", 484),
    ("Ambiguous", 485),
    ("BusyHere", 486),
    ("RequestTerminated", 487),
    ("NotAcceptableHere", 488),
    ("BadEvent", 489),
    ("RequestPending", 491),
    ("Undecipherable", 493),
    ("SecurityAgreementRequired", 494),
    ("ServerInternalError", 500),
    ("NotImplemented", 501),
    ("BadGateway", 502),
    ("ServiceUnavailable", 503),
    ("ServerTimeout", 504),
    ("VersionNotSupported", 505),
    ("MessageTooLarge", 513),
    ("PushNotificationServiceNotSupported", 555),
    ("PreconditionFailure", 580),
    ("BusyEverywhere", 600),
    ("Decline", 603),
    ("DoesNotExistAnywhere", 604),
    ("GlobalNotAcceptable", 606),
    ("Unwanted", 607),
    ("Rejected", 608),
];

/// The code a status name stands for.
pub fn status_code(name: &str) -> Option<i64> {
    STATUS_CODES.iter().find(|(n, _)| *n == name).map(|&(_, c)| c)
}

/// The name a status code has, if any (`404` → `NotFound`).
pub fn status_name(code: i64) -> Option<&'static str> {
    STATUS_CODES.iter().find(|&&(_, c)| c == code).map(|&(n, _)| n)
}

/// Reason phrases for `reply(code)` without one.
pub fn reason(code: i64) -> &'static str {
    match code {
        100 => "Trying",
        180 => "Ringing",
        181 => "Call Is Being Forwarded",
        182 => "Queued",
        183 => "Session Progress",
        199 => "Early Dialog Terminated",
        200 => "OK",
        202 => "Accepted",
        204 => "No Notification",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        305 => "Use Proxy",
        380 => "Alternative Service",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Conditional Request Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Unsupported URI Scheme",
        417 => "Unknown Resource-Priority",
        420 => "Bad Extension",
        421 => "Extension Required",
        422 => "Session Interval Too Small",
        423 => "Interval Too Brief",
        424 => "Bad Location Information",
        425 => "Bad Alert Message",
        428 => "Use Identity Header",
        429 => "Provide Referrer Identity",
        430 => "Flow Failed",
        433 => "Anonymity Disallowed",
        436 => "Bad Identity-Info",
        437 => "Unsupported Certificate",
        438 => "Invalid Identity Header",
        439 => "First Hop Lacks Outbound Support",
        440 => "Max-Breadth Exceeded",
        469 => "Bad Info Package",
        470 => "Consent Needed",
        480 => "Temporarily Unavailable",
        481 => "Call/Transaction Does Not Exist",
        482 => "Loop Detected",
        483 => "Too Many Hops",
        484 => "Address Incomplete",
        485 => "Ambiguous",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        489 => "Bad Event",
        491 => "Request Pending",
        493 => "Undecipherable",
        494 => "Security Agreement Required",
        500 => "Server Internal Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Server Time-out",
        505 => "Version Not Supported",
        513 => "Message Too Large",
        555 => "Push Notification Service Not Supported",
        580 => "Precondition Failure",
        600 => "Busy Everywhere",
        603 => "Decline",
        604 => "Does Not Exist Anywhere",
        606 => "Not Acceptable",
        607 => "Unwanted",
        608 => "Rejected",
        _ => "Unknown",
    }
}
