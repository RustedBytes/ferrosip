//! Sharding by Call-ID: several engines (each its own thread, ordering
//! domain and, in durable mode, journal) behind one address.
//!
//! Every message of a dialog carries its Call-ID, so the shard is a pure
//! function of it ([`shard_of_call_id`]): requests, responses, ACK and
//! CANCEL of one call reach the same engine without shared state. A shard
//! only generates Call-IDs that map to itself (`UaConfig::shard`), so the
//! responses to its own requests come back to it. An INVITE with
//! `Replaces` is routed by its own Call-ID too (the dialog it creates must
//! live where its later requests arrive); the replaced dialog may be on
//! another shard, found through the shared [`DialogDirectory`]. Leg ids are
//! striped per shard ([`crate::IdAllocator::striped`]), so commands are
//! routed by leg id.
//!
//! The function depends on the shard count: changing the count of a
//! running (or durable) deployment moves calls between shards. Restore
//! each shard's journal with the same count.

use crate::engine::{Phase, Role};
use crate::ids::UaLegId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};

/// A leg's role and phase, readable from other shards.
#[derive(Debug, Default)]
pub struct LegStatus(AtomicU8);

impl LegStatus {
    pub(crate) fn new(role: Role, phase: Phase) -> Self {
        let s = Self::default();
        s.set(role, phase);
        s
    }

    pub(crate) fn set(&self, role: Role, phase: Phase) {
        let r = u8::from(role == Role::Uas);
        let p = match phase {
            Phase::Calling => 0,
            Phase::Early => 1,
            Phase::Confirmed => 2,
            Phase::Terminating => 3,
            Phase::Terminated => 4,
        };
        self.0.store(r << 4 | p, Ordering::Release);
    }

    pub(crate) fn get(&self) -> (Role, Phase) {
        let v = self.0.load(Ordering::Acquire);
        let role = if v >> 4 == 1 { Role::Uas } else { Role::Uac };
        let phase = match v & 0xf {
            0 => Phase::Calling,
            1 => Phase::Early,
            2 => Phase::Confirmed,
            3 => Phase::Terminating,
            _ => Phase::Terminated,
        };
        (role, phase)
    }
}

/// The dialogs of every shard of a runtime, for RFC 3891 `Replaces`
/// across shards: (Call-ID, local tag, remote tag) → shard, leg, status.
/// Written at dialog creation and removal only.
/// (Call-ID, local tag, remote tag).
type DialogKey = (String, String, String);
/// Shard, leg, status.
type Listed = (u32, UaLegId, Arc<LegStatus>);

#[derive(Debug, Default)]
pub struct DialogDirectory {
    map: RwLock<HashMap<DialogKey, Listed>>,
}

impl DialogDirectory {
    pub(crate) fn insert(&self, key: DialogKey, shard: u32, leg: UaLegId, status: Arc<LegStatus>) {
        if let Ok(mut m) = self.map.write() {
            m.insert(key, (shard, leg, status));
        }
    }

    pub(crate) fn remove(&self, key: &DialogKey) {
        if let Ok(mut m) = self.map.write() {
            m.remove(key);
        }
    }

    pub(crate) fn get(&self, key: &DialogKey) -> Option<Listed> {
        self.map.read().ok()?.get(key).cloned()
    }

    /// Dialogs listed (all shards).
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.read().map_or(0, |m| m.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// This engine is shard `index` of `count`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shard {
    pub index: u32,
    pub count: u32,
}

/// FNV-1a: stable across processes and versions (unlike `DefaultHasher`).
fn fnv(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &x in b {
        h ^= u64::from(x);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[must_use]
pub fn shard_of_call_id(call_id: &str, count: u32) -> u32 {
    let n = u64::from(count.max(1));
    u32::try_from(fnv(call_id.trim().as_bytes()).checked_rem(n).unwrap_or(0)).unwrap_or(0)
}

#[must_use]
pub fn shard_of_leg(leg: UaLegId, count: u32) -> u32 {
    let n = u64::from(count.max(1));
    u32::try_from(leg.0.saturating_sub(1).checked_rem(n).unwrap_or(0)).unwrap_or(0)
}

/// The value of the first header `name` (or its compact form) of a raw
/// message, without parsing the rest.
fn header<'a>(data: &'a [u8], name: &str, compact: Option<&str>) -> Option<&'a str> {
    let head = data.windows(4).position(|w| w == b"\r\n\r\n").map_or(data, |e| data.get(..e).unwrap_or(data));
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        let n = n.trim();
        (n.eq_ignore_ascii_case(name) || compact.is_some_and(|c| n.eq_ignore_ascii_case(c))).then(|| v.trim())
    })
}

/// The shard a received message belongs to: its Call-ID's. Unparseable:
/// shard 0 (which answers or drops it like any engine).
#[must_use]
pub fn shard_for_message(data: &[u8], count: u32) -> u32 {
    if count <= 1 {
        return 0;
    }
    header(data, "Call-ID", Some("i")).map_or(0, |c| shard_of_call_id(c, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing() {
        let inv = b"INVITE sip:a@x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\ni: abc@h\r\nCSeq: 1 INVITE\r\n\r\n";
        let resp = b"SIP/2.0 200 OK\r\nCall-ID: abc@h\r\nReplaces: zzz\r\n\r\n";
        assert_eq!(shard_for_message(inv, 7), shard_of_call_id("abc@h", 7));
        assert_eq!(shard_for_message(resp, 7), shard_of_call_id("abc@h", 7), "a response is routed by its Call-ID");
        let rep = b"INVITE sip:a@x SIP/2.0\r\nCall-ID: new@h\r\nReplaces: old@h;to-tag=1;from-tag=2\r\n\r\n";
        assert_eq!(shard_for_message(rep, 7), shard_of_call_id("new@h", 7), "the new dialog lives on its own Call-ID's shard");
        for (r, p) in [(Role::Uac, Phase::Early), (Role::Uas, Phase::Confirmed), (Role::Uas, Phase::Terminated)] {
            assert_eq!(LegStatus::new(r, p).get(), (r, p));
        }
        assert_eq!(shard_for_message(b"garbage", 7), 0);
        assert_eq!(shard_for_message(inv, 1), 0);
        let a = crate::IdAllocator::striped(2, 5);
        for _ in 0..10 {
            assert_eq!(shard_of_leg(a.leg(), 5), 2);
        }
    }
}
