//! The SDP offer/answer (RFC 3264) for one audio stream.

use crate::audio::Codec;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, PartialEq, Eq)]
pub struct Offer {
    /// Where the caller wants our RTP.
    pub addr: SocketAddr,
    /// Payload types in the caller's order of preference.
    pub codecs: Vec<Codec>,
    /// RTP/SAVP and friends: we don't do SRTP.
    pub secure: bool,
}

/// The first audio stream of an offer.
pub fn parse_offer(body: &str) -> Result<Offer, &'static str> {
    let mut session_c: Option<IpAddr> = None;
    let mut media: Option<(u16, Vec<String>, bool)> = None;
    let mut media_c: Option<IpAddr> = None;
    let mut rtpmap: Vec<(String, String)> = Vec::new();
    let mut in_audio = false;
    let mut seen_media = false;
    for line in body.lines() {
        let line = line.trim_end();
        let Some((k, v)) = line.split_once('=') else { continue };
        match k {
            "c" => {
                let ip = v.split_whitespace().nth(2).and_then(|a| a.split('/').next()).and_then(|a| a.parse().ok());
                if !seen_media {
                    session_c = ip;
                } else if in_audio {
                    media_c = ip;
                }
            }
            "m" => {
                seen_media = true;
                in_audio = false;
                if media.is_some() {
                    continue;
                }
                let mut f = v.split_whitespace();
                let (kind, port, proto) = (f.next(), f.next(), f.next().unwrap_or(""));
                if kind == Some("audio") {
                    let port: u16 = port.and_then(|p| p.split('/').next()).and_then(|p| p.parse().ok()).ok_or("bad m=audio port")?;
                    if port == 0 {
                        continue;
                    }
                    in_audio = true;
                    let secure = proto.contains("SAVP") || proto.contains("TLS");
                    media = Some((port, f.map(str::to_string).collect(), secure));
                }
            }
            "a" if in_audio => {
                if let Some(m) = v.strip_prefix("rtpmap:") {
                    let mut f = m.split_whitespace();
                    if let (Some(pt), Some(enc)) = (f.next(), f.next()) {
                        rtpmap.push((pt.to_string(), enc.to_ascii_uppercase()));
                    }
                }
            }
            _ => {}
        }
    }
    let (port, pts, secure) = media.ok_or("no audio stream")?;
    let ip = media_c.or(session_c).ok_or("no connection address")?;
    let codecs = pts
        .iter()
        .filter_map(|pt| {
            let enc = rtpmap.iter().find(|(p, _)| p == pt).map(|(_, e)| e.as_str());
            match (pt.as_str(), enc) {
                (_, Some("PCMU/8000" | "PCMU/8000/1")) | ("0", None) => Some(Codec::Pcmu),
                (_, Some("PCMA/8000" | "PCMA/8000/1")) | ("8", None) => Some(Codec::Pcma),
                _ => None,
            }
        })
        .collect();
    Ok(Offer { addr: SocketAddr::new(ip, port), codecs, secure })
}

/// Our answer: one codec, 20 ms packets.
pub fn answer(ip: IpAddr, port: u16, codec: Codec, session: u64, version: u64) -> String {
    let fam = if ip.is_ipv4() { "IP4" } else { "IP6" };
    format!(
        "v=0\r\no=ferrosip {session} {version} IN {fam} {ip}\r\ns=ferrosip\r\nc=IN {fam} {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {pt}\r\na=rtpmap:{pt} {name}/8000\r\na=ptime:20\r\na=sendrecv\r\n",
        pt = codec.pt(),
        name = codec.name()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offers() {
        let o = parse_offer(
            "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 9 8 0 101\r\na=rtpmap:101 telephone-event/8000\r\n",
        )
        .unwrap();
        assert_eq!(o.addr, "10.0.0.1:4000".parse().unwrap());
        assert_eq!(o.codecs, vec![Codec::Pcma, Codec::Pcmu]);
        assert!(!o.secure);
        // Media-level c= wins; dynamic PT mapped to PCMU; video ignored.
        let o = parse_offer("v=0\nc=IN IP4 1.1.1.1\nm=video 5000 RTP/AVP 96\nc=IN IP4 9.9.9.9\nm=audio 4002 RTP/AVP 96\nc=IN IP6 ::1\na=rtpmap:96 pcmu/8000\n")
            .unwrap();
        assert_eq!(o.addr, "[::1]:4002".parse().unwrap());
        assert_eq!(o.codecs, vec![Codec::Pcmu]);
        assert!(parse_offer("v=0\nc=IN IP4 1.1.1.1\nm=audio 4000 RTP/SAVP 0\n").unwrap().secure);
        assert!(parse_offer("v=0\nc=IN IP4 1.1.1.1\nm=audio 4000 RTP/AVP 9\n").unwrap().codecs.is_empty());
        assert!(parse_offer("v=0\nm=audio 4000 RTP/AVP 0\n").is_err());
        assert!(parse_offer("v=0\nc=IN IP4 1.1.1.1\n").is_err());
        let a = answer("192.0.2.1".parse().unwrap(), 30000, Codec::Pcmu, 7, 1);
        assert!(a.contains("m=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"));
        assert!(a.contains("c=IN IP4 192.0.2.1\r\n"));
    }

    #[test]
    fn offer_cases() {
        let v4 = |s: &str| -> SocketAddr { s.parse().unwrap() };
        // (SDP, expected (address, codecs, secure) or error)
        type Want = Result<(SocketAddr, Vec<Codec>, bool), &'static str>;
        let cases: Vec<(&str, Want)> = vec![
            ("c=IN IP4 1.2.3.4\r\nm=audio 4000 RTP/AVP 0 8\r\n", Ok((v4("1.2.3.4:4000"), vec![Codec::Pcmu, Codec::Pcma], false))),
            ("c=IN IP4 1.2.3.4\r\nm=audio 4000 RTP/AVP 8 0\r\n", Ok((v4("1.2.3.4:4000"), vec![Codec::Pcma, Codec::Pcmu], false))),
            ("c=IN IP4 224.2.1.1/127\nm=audio 4000/2 RTP/AVP 0\n", Ok((v4("224.2.1.1:4000"), vec![Codec::Pcmu], false))),
            ("c=IN IP4 1.2.3.4\nm=audio 4000 RTP/AVP 97 0\na=rtpmap:97 PCMA/8000/1\n", Ok((v4("1.2.3.4:4000"), vec![Codec::Pcma, Codec::Pcmu], false))),
            ("c=IN IP4 1.2.3.4\nm=audio 4000 RTP/AVP 97\na=rtpmap:97 PCMU/16000\n", Ok((v4("1.2.3.4:4000"), vec![], false))),
            ("c=IN IP4 1.2.3.4\nm=audio 4000 RTP/AVP 0\na=rtpmap:0 opus/48000/2\n", Ok((v4("1.2.3.4:4000"), vec![], false))),
            ("c=IN IP4 1.2.3.4\nm=audio 4000 UDP/TLS/RTP/SAVPF 0\n", Ok((v4("1.2.3.4:4000"), vec![Codec::Pcmu], true))),
            ("c=IN IP4 1.2.3.4\nm=audio 4000 RTP/SAVP 0\n", Ok((v4("1.2.3.4:4000"), vec![Codec::Pcmu], true))),
            // A disabled stream is skipped for the next audio stream, with its own c=.
            (
                "c=IN IP4 1.1.1.1\nm=audio 0 RTP/AVP 0\nc=IN IP4 2.2.2.2\nm=audio 5000 RTP/AVP 8\nc=IN IP4 3.3.3.3\n",
                Ok((v4("3.3.3.3:5000"), vec![Codec::Pcma], false)),
            ),
            // Only the first audio stream; a later one's attributes don't leak in.
            (
                "c=IN IP4 1.1.1.1\nm=audio 5000 RTP/AVP 96\nm=audio 6000 RTP/AVP 96\nc=IN IP4 9.9.9.9\na=rtpmap:96 PCMU/8000\n",
                Ok((v4("1.1.1.1:5000"), vec![], false)),
            ),
            ("c=IN IP4 1.1.1.1\nm=audio 0 RTP/AVP 0\n", Err("no audio stream")),
            ("c=IN IP4 1.1.1.1\nm=audio x RTP/AVP 0\n", Err("bad m=audio port")),
            ("c=IN IP4 1.1.1.1\nm=audio 70000 RTP/AVP 0\n", Err("bad m=audio port")),
            ("c=IN IP4 nonsense\nm=audio 4000 RTP/AVP 0\n", Err("no connection address")),
            ("", Err("no audio stream")),
        ];
        for (sdp, want) in cases {
            let got = parse_offer(sdp).map(|o| (o.addr, o.codecs, o.secure));
            assert_eq!(got, want, "{sdp:?}");
        }
    }

    #[test]
    fn answers_are_exact() {
        assert_eq!(
            answer("192.0.2.1".parse().unwrap(), 30000, Codec::Pcma, 1_700_000_000, 2),
            "v=0\r\no=ferrosip 1700000000 2 IN IP4 192.0.2.1\r\ns=ferrosip\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n\
             m=audio 30000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=ptime:20\r\na=sendrecv\r\n"
        );
        let a = answer("2001:db8::1".parse().unwrap(), 30002, Codec::Pcmu, 1, 1);
        assert!(a.contains("o=ferrosip 1 1 IN IP6 2001:db8::1\r\n") && a.contains("c=IN IP6 2001:db8::1\r\n"), "{a}");
        assert!(a.contains("m=audio 30002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=ptime:20\r\n"), "{a}");
        // Our answer parses as an offer with the same address and codec.
        let o = parse_offer(&a).unwrap();
        assert_eq!((o.addr, o.codecs, o.secure), ("[2001:db8::1]:30002".parse().unwrap(), vec![Codec::Pcmu], false));
    }
}
