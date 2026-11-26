//! Kamailio's internal error codes (core error.h) and the replies built from
//! them (core error.c `err2reason_phrase()`): a SIP code and the text
//! `"<text> (<errno>/<signature>)"`. tm answers a failed relay with them
//! (t_funcs.c `kill_transaction()`, tm.c `ki_t_reply_error()`, signature
//! "TM"), so ferrosip's tm errors carry the same code and reason.

/// `E_UNSPEC`.
pub const E_UNSPEC: i32 = -1;
/// `E_OUT_OF_MEM`.
pub const E_OUT_OF_MEM: i32 = -2;
/// `E_EXEC`.
pub const E_EXEC: i32 = -11;
/// `E_TOO_MANY_BRANCHES`.
pub const E_TOO_MANY_BRANCHES: i32 = -12;
/// `E_UNEXPECTED_STATE`.
pub const E_UNEXPECTED_STATE: i32 = -20;
/// `E_BAD_REQ`.
pub const E_BAD_REQ: i32 = -400;
/// `E_SEND`.
pub const E_SEND: i32 = -477;
/// `E_BAD_ADDRESS`.
pub const E_BAD_ADDRESS: i32 = -478;
/// `E_BAD_URI`.
pub const E_BAD_URI: i32 = -479;
/// `E_CANCELED`.
pub const E_CANCELED: i32 = -487;
/// `E_BAD_SERVER`.
pub const E_BAD_SERVER: i32 = -500;

/// Kamailio core error.c `err2reason_phrase()`: the SIP code and the text
/// (without the `" (N/SIG)"` suffix) for an internal error.
pub fn err2reason(err: i32) -> (u16, &'static str) {
    let neg = |e: i32| u16::try_from(e.unsigned_abs()).unwrap_or(500);
    match err {
        E_SEND => (neg(err), "Unfortunately error on sending to next hop occurred"),
        E_BAD_ADDRESS => (neg(err), "Unresolvable destination"),
        E_BAD_REQ => (neg(err), "Bad Request"),
        E_BAD_URI => (neg(err), "Regretfully, we were not able to process the URI"),
        -9 => (neg(E_BAD_REQ), "Transaction tuple incomplete"),
        -13 => (neg(E_BAD_REQ), "Bad To"),
        E_EXEC => (neg(E_BAD_SERVER), "Error in external logic"),
        E_TOO_MANY_BRANCHES => (neg(E_BAD_SERVER), "Forking capacity exceeded"),
        -15 => (neg(E_BAD_REQ), "Invalid character in q parameter"),
        -16 => (neg(E_BAD_REQ), "Empty q parameter"),
        -17 => (neg(E_BAD_REQ), "Q parameter too big"),
        -18 => (neg(E_BAD_REQ), "Decimal part missing in q"),
        E_CANCELED => (neg(err), "Transaction canceled"),
        E_OUT_OF_MEM => (500, "Message processing error"),
        E_UNEXPECTED_STATE => (500, "Internal processing error"),
        0 => (500, "No error"),
        _ => (500, "I'm terribly sorry, server error occurred"),
    }
}

/// `err2reason_phrase()` in full: the code and `"<text> (<errno>/<sig>)"`.
pub fn err2reason_phrase(err: i32, sig: &str) -> (u16, String) {
    let (code, text) = err2reason(err);
    (code, format!("{text} ({}/{sig})", err.saturating_neg()))
}

/// An error reply as a constant: `reply!(code, "text", errno, "SIG")` is
/// `(code, "text (errno/SIG)")`, what `err2reason_phrase(-errno, "SIG")`
/// gives.
macro_rules! reply {
    ($code:literal, $text:literal, $errno:literal, $sig:literal) => {
        ($code, concat!($text, " (", $errno, "/", $sig, ")"))
    };
}
macro_rules! tm_error {
    ($code:literal, $text:literal, $errno:literal) => {
        reply!($code, $text, $errno, "TM")
    };
}

/// tm's reply for `E_UNSPEC` (also a failure route that dropped the replies
/// and left no relay error, t_reply.c `kill_transaction_unsafe()`).
pub const TM_E_UNSPEC: (u16, &str) = tm_error!(500, "I'm terribly sorry, server error occurred", 1);
/// tm's reply for `E_TOO_MANY_BRANCHES` (t_fwd.c `add_uac()`: no branch left).
pub const TM_E_TOO_MANY_BRANCHES: (u16, &str) = tm_error!(500, "Forking capacity exceeded", 12);
/// tm's reply for `E_SEND` (t_fwd.c `t_forward_nonack()`: no branch could be
/// sent, the next hops blocklisted included).
pub const TM_E_SEND: (u16, &str) = tm_error!(477, "Unfortunately error on sending to next hop occurred", 477);
/// tm's reply for `E_BAD_ADDRESS` (t_fwd.c `add_uac()`: `uri2dst2()` failed).
pub const TM_E_BAD_ADDRESS: (u16, &str) = tm_error!(478, "Unresolvable destination", 478);
/// sl's reply (`sl_reply_error()`, sl_funcs.c) for `E_TOO_MANY_BRANCHES`:
/// `append_branch()` found the destination set full (core dset.c).
pub const SL_E_TOO_MANY_BRANCHES: (u16, &str) = reply!(500, "Forking capacity exceeded", 12, "SL");

/// The reply for the last error, as `sig`'s module words it: tm's
/// `t_reply_error()` (tm.c:1661-1684) and sl's `sl_reply_error()`
/// (sl_funcs.c:437-445) both send `err2reason_phrase(prev_ser_error, …,
/// "TM" / "SL")`. The error is kept as its reply (`Ctx::last_error`), with
/// the signature of the module that failed: that becomes `sig`. No error:
/// E_UNSPEC.
pub fn reply_error(last: Option<(u16, &'static str)>, sig: &str) -> (u16, std::borrow::Cow<'static, str>) {
    let Some((code, reason)) = last else {
        let (code, text) = err2reason_phrase(E_UNSPEC, sig);
        return (code, text.into());
    };
    if let Some(head) = reason.strip_suffix(")")
        && let Some((before, tail)) = head.rsplit_once(" (")
        && let Some((errno, old)) = tail.split_once('/')
        && !errno.is_empty()
        && errno.bytes().all(|b| b.is_ascii_digit())
        && old != sig
        && old.bytes().all(|b| b.is_ascii_uppercase())
    {
        return (code, format!("{before} ({errno}/{sig})").into());
    }
    (code, reason.into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn reply_error_signature() {
        assert_eq!(reply_error(None, "TM"), (500, "I'm terribly sorry, server error occurred (1/TM)".into()));
        assert_eq!(reply_error(None, "SL"), (500, "I'm terribly sorry, server error occurred (1/SL)".into()));
        assert_eq!(reply_error(Some(SL_E_TOO_MANY_BRANCHES), "TM"), (500, "Forking capacity exceeded (12/TM)".into()));
        assert_eq!(reply_error(Some(TM_E_SEND), "TM"), (TM_E_SEND.0, TM_E_SEND.1.into()));
        assert_eq!(reply_error(Some(TM_E_SEND), "SL"), (477, "Unfortunately error on sending to next hop occurred (477/SL)".into()));
        assert_eq!(reply_error(Some((400, "Bad Via")), "SL"), (400, "Bad Via".into()));
        assert_eq!(reply_error(Some((500, "Not here (x/TM)")), "SL"), (500, "Not here (x/TM)".into()));
    }

    use super::*;

    #[test]
    fn tm_constants_match_err2reason_phrase() {
        for (err, c) in [(E_UNSPEC, TM_E_UNSPEC), (E_TOO_MANY_BRANCHES, TM_E_TOO_MANY_BRANCHES), (E_SEND, TM_E_SEND), (E_BAD_ADDRESS, TM_E_BAD_ADDRESS)] {
            let (code, text) = err2reason_phrase(err, "TM");
            assert_eq!((code, text.as_str()), c);
        }
        // Codes: -errno for the SIP-shaped errors, else 400 / 500.
        let (code, text) = err2reason_phrase(E_TOO_MANY_BRANCHES, "SL");
        assert_eq!((code, text.as_str()), SL_E_TOO_MANY_BRANCHES);
        assert_eq!(err2reason_phrase(E_SEND, "SL"), (477, "Unfortunately error on sending to next hop occurred (477/SL)".into()));
        assert_eq!(err2reason(-520).0, 500); // E_BLOCKLISTED: the default text
        assert_eq!(err2reason(-15).0, 400);
        assert_eq!(err2reason(E_CANCELED), (487, "Transaction canceled"));
    }

    #[test]
    fn err2reason_table() {
        let cases: &[(i32, u16, &str)] = &[
            (E_SEND, 477, "Unfortunately error on sending to next hop occurred"),
            (E_BAD_ADDRESS, 478, "Unresolvable destination"),
            (E_BAD_REQ, 400, "Bad Request"),
            (E_BAD_URI, 479, "Regretfully, we were not able to process the URI"),
            (-9, 400, "Transaction tuple incomplete"),
            (-13, 400, "Bad To"),
            (E_EXEC, 500, "Error in external logic"),
            (E_TOO_MANY_BRANCHES, 500, "Forking capacity exceeded"),
            (-16, 400, "Empty q parameter"),
            (-17, 400, "Q parameter too big"),
            (-18, 400, "Decimal part missing in q"),
            (E_CANCELED, 487, "Transaction canceled"),
            (E_OUT_OF_MEM, 500, "Message processing error"),
            (E_UNEXPECTED_STATE, 500, "Internal processing error"),
            (0, 500, "No error"),
            (E_UNSPEC, 500, "I'm terribly sorry, server error occurred"),
            (E_BAD_SERVER, 500, "I'm terribly sorry, server error occurred"),
            (5, 500, "I'm terribly sorry, server error occurred"),
            (i32::MIN, 500, "I'm terribly sorry, server error occurred"),
        ];
        for (err, code, text) in cases {
            assert_eq!(err2reason(*err), (*code, *text), "{err}");
        }
        assert_eq!(err2reason_phrase(0, "SL").1, "No error (0/SL)");
        assert_eq!(err2reason_phrase(i32::MIN, "X").1, format!("I'm terribly sorry, server error occurred ({}/X)", i32::MAX));
    }

    #[test]
    fn reply_error_only_resigns_well_formed_suffixes() {
        let cases: &[((u16, &'static str), &str, &str)] = &[
            ((500, "Forking capacity exceeded (12/SL)"), "SL", "Forking capacity exceeded (12/SL)"),
            ((500, "Text (12/tm)"), "SL", "Text (12/tm)"),
            ((500, "Text (/TM)"), "SL", "Text (/TM)"),
            ((500, "Text (1a/TM)"), "SL", "Text (1a/TM)"),
            ((500, "Text (12/TM) tail"), "SL", "Text (12/TM) tail"),
            ((500, "A (b) (3/TM)"), "SL", "A (b) (3/SL)"),
            ((500, "(3/TM)"), "SL", "(3/TM)"),
        ];
        for ((code, reason), sig, want) in cases {
            assert_eq!(reply_error(Some((*code, reason)), sig), (*code, std::borrow::Cow::Borrowed(*want)), "{reason} as {sig}");
        }
    }
}
