//! DTMF in SIP INFO (the de-facto `application/dtmf-relay` and
//! `application/dtmf` bodies), and detecting RFC 4733 `telephone-event` in
//! SDP so digits that also travel in RTP are not acted on twice.

/// One key press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "recovery", derive(serde::Serialize, serde::Deserialize))]
pub struct Dtmf {
    /// `0`–`9`, `*`, `#`, `A`–`D`.
    pub digit: char,
    pub duration_ms: Option<u32>,
}

pub fn is_digit(c: char) -> bool {
    c.is_ascii_digit() || matches!(c.to_ascii_uppercase(), '*' | '#' | 'A' | 'B' | 'C' | 'D')
}

/// RFC 4733 event code (0–15) → digit.
fn from_event(code: u8) -> Option<char> {
    match code {
        0..=9 => char::from_digit(u32::from(code), 10),
        10 => Some('*'),
        11 => Some('#'),
        12..=15 => char::from_u32(u32::from(b'A').saturating_add(u32::from(code).saturating_sub(12))),
        _ => None,
    }
}

fn digit_of(v: &str) -> Option<char> {
    let v = v.trim();
    let mut chars = v.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if is_digit(c) => Some(c.to_ascii_uppercase()),
        // Some send the event code ("10" for *).
        _ => v.parse::<u8>().ok().and_then(from_event),
    }
}

/// The DTMF an INFO body carries, if it is one of the known formats.
pub fn parse_info(content_type: Option<&str>, body: &[u8]) -> Option<Dtmf> {
    let mime = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    let text = std::str::from_utf8(body).ok()?;
    match mime.as_str() {
        "application/dtmf-relay" => {
            let mut digit = None;
            let mut duration_ms = None;
            for line in text.lines() {
                let Some((k, v)) = line.split_once('=') else { continue };
                match k.trim().to_ascii_lowercase().as_str() {
                    "signal" => digit = digit_of(v),
                    "duration" => duration_ms = v.trim().parse().ok(),
                    _ => {}
                }
            }
            Some(Dtmf { digit: digit?, duration_ms })
        }
        "application/dtmf" => Some(Dtmf { digit: digit_of(text.lines().next()?)?, duration_ms: None }),
        _ => None,
    }
}

/// `application/dtmf-relay` body for `d`.
pub fn relay_body(d: &Dtmf) -> Vec<u8> {
    format!("Signal={}\r\nDuration={}\r\n", d.digit, d.duration_ms.unwrap_or(160)).into_bytes()
}

/// The SDP offers or accepts RFC 4733 telephone-event.
pub fn sdp_has_telephone_event(sdp: &[u8]) -> bool {
    String::from_utf8_lossy(sdp).lines().any(|l| l.starts_with("a=rtpmap:") && l.to_ascii_lowercase().contains("telephone-event/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(parse_info(Some("application/dtmf-relay"), b"Signal=5\r\nDuration=160\r\n"), Some(Dtmf { digit: '5', duration_ms: Some(160) }));
        assert_eq!(parse_info(Some("Application/DTMF-Relay"), b"Signal= 11\r\n"), Some(Dtmf { digit: '#', duration_ms: None }));
        assert_eq!(parse_info(Some("application/dtmf"), b"*"), Some(Dtmf { digit: '*', duration_ms: None }));
        assert_eq!(parse_info(Some("application/dtmf"), b"14"), Some(Dtmf { digit: 'C', duration_ms: None }));
        assert_eq!(parse_info(Some("text/plain"), b"5"), None);
        assert_eq!(parse_info(Some("application/dtmf-relay"), b"Signal=x"), None);
        assert_eq!(relay_body(&Dtmf { digit: '#', duration_ms: None }), b"Signal=#\r\nDuration=160\r\n");
        assert!(sdp_has_telephone_event(b"v=0\r\nm=audio 1 RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\n"));
        assert!(!sdp_has_telephone_event(b"v=0\r\nm=audio 1 RTP/AVP 0\r\n"));
    }
}
