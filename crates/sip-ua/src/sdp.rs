//! The little SDP the UA must understand. SDP bodies are opaque to the
//! engine: it checks only that a body is plausibly SDP and, when RFC 3261
//! §13.2.2.4 forces it to answer an offer the application cannot answer in
//! time, builds an answer that rejects every stream (port 0).

/// Plausible SDP: UTF-8, starts with `v=0`, has an `o=` and an `m=` or `c=`.
pub fn is_valid(body: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(body) else { return false };
    let mut lines = s.lines().map(str::trim).filter(|l| !l.is_empty());
    lines.next() == Some("v=0") && s.lines().any(|l| l.starts_with("o="))
}

/// An answer rejecting every m-line of `offer` (RFC 3264 §6: port 0, same
/// number of m-lines, at least one format each).
pub fn reject_all(offer: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(offer);
    let mut out = String::from("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n");
    for l in s.lines().map(str::trim).filter(|l| l.starts_with("m=")) {
        let mut parts = l.get(2..).unwrap_or_default().split_ascii_whitespace();
        let media = parts.next().unwrap_or("audio");
        let _port = parts.next();
        let proto = parts.next().unwrap_or("RTP/AVP");
        let fmt = parts.next().unwrap_or("0");
        out.push_str(&format!("m={media} 0 {proto} {fmt}\r\n"));
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_and_rejection() {
        let offer = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0 8\r\nm=video 4002 RTP/AVP 96\r\n";
        assert!(is_valid(offer));
        assert!(!is_valid(b"hello"));
        let a = String::from_utf8(reject_all(offer)).unwrap();
        assert!(a.contains("m=audio 0 RTP/AVP 0\r\n") && a.contains("m=video 0 RTP/AVP 96\r\n"));
        assert!(is_valid(a.as_bytes()));
    }
}
