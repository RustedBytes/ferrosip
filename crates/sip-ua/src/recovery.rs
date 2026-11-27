//! Recoverable engine state (feature `recovery`).
//!
//! See `docs/sip-ua-recovery.md` for the design (ADR), the durability
//! contract and the supported scope. In short:
//!
//! - [`StateRecord`] is a versioned, owned snapshot of an engine (legs,
//!   transactions, pending effects, operation outcomes, leg tombstones),
//!   encoded as JSON. It is not a memory dump: every field is named, byte
//!   buffers are base64, deadlines are relative to the record's own clock
//!   anchors, credentials are references (no password), connection ids are
//!   dropped.
//! - In durable mode ([`crate::UaConfig::durable`]) every input's effects
//!   come out as a [`Transition`]: the state delta of the legs and
//!   transactions it touched, plus the transmits and events it produced.
//!   The driver persists the delta, then dispatches the effects. Nothing is
//!   sent before its commit; after a commit, effects are at least once
//!   (re-sent on restore if their dispatch wasn't recorded).
//! - [`RecoveryState`] folds a checkpoint and its journal of transitions,
//!   and `UaEngine::restore` rebuilds an engine from it.

pub use crate::engine::recovery::{
    ClockAnchor, CredentialProvider, Effects, FORMAT_VERSION, FileJournal, JournalError, MIN_FORMAT_VERSION, MemoryJournal, RecoveryState, RestoreError,
    RestoreOptions, RestoreReport, RestoredLeg, StateRecord, Transition, TransitionRecord,
};
pub use crate::engine::{KeyedAccepted, LegOutcome, OpRecord, OpStatus, Tombstone};

/// Base64 (standard alphabet, padded) for byte buffers in records.
pub(crate) mod b64 {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(b: &[u8]) -> String {
        let mut out = String::with_capacity(b.len().div_ceil(3).saturating_mul(4));
        for c in b.chunks(3) {
            let n = c
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, &x)| acc | (u32::from(x) << (16u32.saturating_sub(8u32.saturating_mul(u32::try_from(i).unwrap_or(0))))));
            for i in 0..4usize {
                if i <= c.len() {
                    let idx = (n >> (18u32.saturating_sub(6u32.saturating_mul(u32::try_from(i).unwrap_or(0))))) & 63;
                    out.push(char::from(T.get(usize::try_from(idx).unwrap_or(0)).copied().unwrap_or(b'A')));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(s.len().saturating_mul(3) / 4);
        let (mut acc, mut bits) = (0u32, 0u32);
        for c in s.bytes() {
            if c == b'=' {
                break;
            }
            let v = u32::try_from(T.iter().position(|&t| t == c)?).ok()?;
            acc = (acc << 6) | v;
            bits = bits.saturating_add(6);
            if bits >= 8 {
                bits = bits.saturating_sub(8);
                out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            }
        }
        Some(out)
    }
}

/// `sip_core::Dest` as a record. The connection id is never restored: a
/// connection does not survive the process (see the transport policy).
pub mod dest_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use sip_core::{Dest, Proto};

    #[derive(Serialize, Deserialize)]
    pub(crate) struct DestRecord {
        pub proto: String,
        pub addr: String,
        /// Was bound to a connection (informational; not restored).
        #[serde(default)]
        pub had_conn: bool,
    }

    pub(crate) fn to_record(d: &Dest) -> DestRecord {
        DestRecord { proto: d.proto.via_name().to_ascii_lowercase(), addr: d.addr.to_string(), had_conn: d.conn.is_some() }
    }

    pub(crate) fn from_record(r: &DestRecord) -> Option<Dest> {
        let proto = Proto::ALL.into_iter().find(|p| p.via_name().eq_ignore_ascii_case(&r.proto))?;
        Some(Dest::new(proto, r.addr.parse().ok()?))
    }

    pub fn serialize<S: Serializer>(d: &Dest, s: S) -> Result<S::Ok, S::Error> {
        to_record(d).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Dest, D::Error> {
        let r = DestRecord::deserialize(d)?;
        from_record(&r).ok_or_else(|| serde::de::Error::custom(format!("bad destination {}:{}", r.proto, r.addr)))
    }

    pub mod opt {
        use super::*;
        pub fn serialize<S: Serializer>(d: &Option<Dest>, s: S) -> Result<S::Ok, S::Error> {
            d.as_ref().map(to_record).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Dest>, D::Error> {
            match Option::<DestRecord>::deserialize(d)? {
                None => Ok(None),
                Some(r) => from_record(&r).map(Some).ok_or_else(|| serde::de::Error::custom("bad destination")),
            }
        }
    }

    pub mod vec {
        use super::*;
        pub fn serialize<S: Serializer>(d: &[Dest], s: S) -> Result<S::Ok, S::Error> {
            d.iter().map(to_record).collect::<Vec<_>>().serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Dest>, D::Error> {
            Vec::<DestRecord>::deserialize(d)?.iter().map(|r| from_record(r).ok_or_else(|| serde::de::Error::custom("bad destination"))).collect()
        }
    }
}

/// Byte buffers as base64 strings.
pub mod bytes_serde {
    use super::b64;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::sync::Arc;

    /// Bytes as a JSON string: the text itself when it is UTF-8 (SIP
    /// messages, SDP: no base64 overhead), else `b64:` and base64.
    pub fn encode(b: &[u8]) -> String {
        match std::str::from_utf8(b) {
            Ok(t) if !t.starts_with("b64:") => t.to_owned(),
            _ => format!("b64:{}", b64::encode(b)),
        }
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        match s.strip_prefix("b64:") {
            Some(b) => b64::decode(b),
            None => Some(s.as_bytes().to_vec()),
        }
    }

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        decode(&s).ok_or_else(|| serde::de::Error::custom("bad base64"))
    }

    pub mod arc {
        use super::*;
        pub fn serialize<S: Serializer>(b: &Arc<[u8]>, s: S) -> Result<S::Ok, S::Error> {
            super::serialize(b, s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Arc<[u8]>, D::Error> {
            super::deserialize(d).map(Arc::from)
        }
    }

    pub mod opt_arc {
        use super::*;
        use serde::Serialize;
        pub fn serialize<S: Serializer>(b: &Option<Arc<[u8]>>, s: S) -> Result<S::Ok, S::Error> {
            b.as_ref().map(|b| encode(b)).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Arc<[u8]>>, D::Error> {
            match Option::<String>::deserialize(d)? {
                None => Ok(None),
                Some(s) => decode(&s).map(|v| Some(Arc::from(v))).ok_or_else(|| serde::de::Error::custom("bad base64")),
            }
        }
    }

    pub mod opt_vec {
        use super::*;
        use serde::Serialize;
        pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            b.as_ref().map(|b| encode(b)).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            match Option::<String>::deserialize(d)? {
                None => Ok(None),
                Some(s) => decode(&s).map(Some).ok_or_else(|| serde::de::Error::custom("bad base64")),
            }
        }
    }
}

/// A SIP message as its wire form (one string), parsed back on load.
pub mod msg_wire {
    use crate::msg::{Limits, SipMessage};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(m: &SipMessage, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::bytes_serde::encode(&m.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SipMessage, D::Error> {
        let s = String::deserialize(d)?;
        let b = super::bytes_serde::decode(&s).ok_or_else(|| serde::de::Error::custom("bad base64"))?;
        // Our own message: no tighter limits than its size.
        let limits = Limits { max_message: b.len().max(Limits::default().max_message), max_body: b.len().max(Limits::default().max_body), ..Limits::default() };
        SipMessage::parse(&b, &limits).map_err(|e| serde::de::Error::custom(format!("unparsable SIP message: {e:?}")))
    }
}

/// Credentials as a reference: username and realm only. The password is
/// never written; `RestoreOptions::credentials` supplies it again.
pub mod creds_serde {
    use crate::auth::Credentials;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct CredRef {
        username: String,
        realm: Option<String>,
    }

    pub fn serialize<S: Serializer>(c: &Option<Credentials>, s: S) -> Result<S::Ok, S::Error> {
        c.as_ref().map(|c| CredRef { username: c.username.clone(), realm: c.realm.clone() }).serialize(s)
    }

    /// The password comes back empty, to be filled by the provider.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Credentials>, D::Error> {
        Ok(Option::<CredRef>::deserialize(d)?.map(|r| Credentials { username: r.username, password: String::new(), realm: r.realm }))
    }
}

#[cfg(test)]
mod tests {
    use super::b64;

    #[test]
    fn base64_round_trip() {
        for s in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", &[0u8, 255, 128, 7]] {
            let e = b64::encode(s);
            assert_eq!(b64::decode(&e).as_deref(), Some(s), "{e}");
        }
        assert_eq!(b64::encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64::encode(b"fo"), "Zm8=");
        assert!(b64::decode("@@").is_none());
    }
}
