//! Tombstones of ended legs, kept FIFO up to a bound.
//!
//! Tens of thousands live at once. Kept as many small heap allocations
//! (strings per tombstone) they cost about 10 % of the engine's call rate
//! in the in-process benchmark — not in the bookkeeping itself, but
//! through allocator fragmentation felt by everything else. So the records
//! sit in one ring (`VecDeque<Grave>`) and their text in another
//! (`VecDeque<u8>`): two contiguous buffers, reused as old entries leave.

use super::Tombstone;
use crate::cause::{Cause, CauseKind, SipStatus};
use crate::ids::{SipDialogId, UaLegId};
use std::collections::{HashMap, VecDeque};

#[derive(Debug)]
struct Grave {
    leg: UaLegId,
    /// Absolute offset of its text in the text ring.
    at: u64,
    /// Lengths of Call-ID, local tag, remote tag, SIP reason, detail.
    lens: [u32; 5],
    kind: CauseKind,
    /// 0: no SIP status.
    code: u16,
    q850: u16,
    has_remote: bool,
    has_detail: bool,
    last_seq: u64,
}

#[derive(Debug, Default)]
pub(crate) struct Graves {
    order: VecDeque<Grave>,
    /// Absolute index of `order[0]`.
    order_base: u64,
    /// Leg → absolute index in `order`.
    index: HashMap<UaLegId, u64>,
    text: VecDeque<u8>,
    /// Absolute offset of `text[0]`.
    text_base: u64,
}

fn clamp(s: &str) -> &str {
    // A length must fit in u32 (it always does for SIP header values).
    match u32::try_from(s.len()) {
        Ok(_) => s,
        Err(_) => "",
    }
}

impl Graves {
    /// Bury `leg` (its cause and last event sequence), evicting the oldest
    /// while there are `max` or more. Returns the evicted legs.
    pub(crate) fn push(&mut self, leg: UaLegId, ids: (&str, &str, Option<&str>), cause: &Cause, last_seq: u64, max: usize) -> Vec<UaLegId> {
        let mut evicted = Vec::new();
        while self.order.len() >= max.max(1) {
            match self.pop() {
                Some(l) => evicted.push(l),
                None => break,
            }
        }
        let (call_id, local_tag, remote_tag) = ids;
        let reason = cause.sip.as_ref().map_or("", |s| s.reason.as_str());
        let detail = cause.detail.as_deref().unwrap_or("");
        let parts = [clamp(call_id), clamp(local_tag), clamp(remote_tag.unwrap_or("")), clamp(reason), clamp(detail)];
        let at = self.text_base.saturating_add(self.text.len() as u64);
        let mut lens = [0u32; 5];
        for (l, p) in lens.iter_mut().zip(parts) {
            *l = u32::try_from(p.len()).unwrap_or(0);
            self.text.extend(p.as_bytes());
        }
        let g = Grave {
            leg,
            at,
            lens,
            kind: cause.kind,
            code: cause.sip.as_ref().map_or(0, |s| s.code),
            q850: cause.q850,
            has_remote: remote_tag.is_some(),
            has_detail: cause.detail.is_some(),
            last_seq,
        };
        let pos = self.order_base.saturating_add(self.order.len() as u64);
        self.order.push_back(g);
        self.index.insert(leg, pos);
        evicted
    }

    fn pop(&mut self) -> Option<UaLegId> {
        let g = self.order.pop_front()?;
        let pos = self.order_base;
        self.order_base = self.order_base.saturating_add(1);
        if self.index.get(&g.leg) == Some(&pos) {
            self.index.remove(&g.leg);
        }
        // Its text is the oldest in the ring.
        let len: u64 = g.lens.iter().map(|&l| u64::from(l)).sum();
        let end = g.at.saturating_add(len);
        let drop_n = usize::try_from(end.saturating_sub(self.text_base)).unwrap_or(usize::MAX).min(self.text.len());
        self.text.drain(..drop_n);
        self.text_base = self.text_base.saturating_add(drop_n as u64);
        Some(g.leg)
    }

    pub(crate) fn get(&self, leg: UaLegId) -> Option<Tombstone> {
        let pos = *self.index.get(&leg)?;
        let g = self.order.get(usize::try_from(pos.checked_sub(self.order_base)?).ok()?)?;
        Some(self.tombstone(g))
    }

    /// All, oldest first.
    #[cfg(any(feature = "recovery", test))]
    pub(crate) fn all(&self) -> Vec<Tombstone> {
        self.order.iter().map(|g| self.tombstone(g)).collect()
    }

    fn tombstone(&self, g: &Grave) -> Tombstone {
        let mut off = usize::try_from(g.at.saturating_sub(self.text_base)).unwrap_or(usize::MAX);
        let mut part = |len: u32| {
            let n = usize::try_from(len).unwrap_or(0);
            let bytes: Vec<u8> = self.text.range(off.min(self.text.len())..off.saturating_add(n).min(self.text.len())).copied().collect();
            off = off.saturating_add(n);
            String::from_utf8(bytes).unwrap_or_default()
        };
        let [a, b, c, d, e] = g.lens;
        let (call_id, local_tag, remote_tag, reason, detail) = (part(a), part(b), part(c), part(d), part(e));
        let dialog = g.has_remote.then(|| SipDialogId { call_id: call_id.clone(), local_tag, remote_tag });
        let mut cause = Cause::new(g.kind);
        cause.q850 = g.q850;
        cause.sip = (g.code != 0).then_some(SipStatus { code: g.code, reason });
        cause.detail = g.has_detail.then_some(detail);
        Tombstone { leg: g.leg, call_id, dialog, cause, last_seq: g.last_seq }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation, clippy::arithmetic_side_effects, reason = "test")]
mod tests {
    use super::*;

    fn cause(code: u16) -> Cause {
        let mut c = Cause::new(CauseKind::SipResponse);
        c.sip = Some(SipStatus { code, reason: format!("R{code}") });
        c.detail = Some("d".into());
        c
    }

    #[test]
    fn fifo_with_bound_and_round_trip() {
        let mut g = Graves::default();
        for i in 0..10u64 {
            let remote = (i % 2 == 0).then(|| format!("rt{i}"));
            let ev = g.push(UaLegId(i), (&format!("cid{i}"), &format!("lt{i}"), remote.as_deref()), &cause(400 + i as u16), i * 3, 4);
            assert_eq!(ev, if i >= 4 { vec![UaLegId(i - 4)] } else { vec![] });
        }
        assert_eq!(g.order.len(), 4);
        assert!(g.get(UaLegId(5)).is_none());
        let t = g.get(UaLegId(8)).unwrap();
        assert_eq!((t.call_id.as_str(), t.last_seq, t.cause.sip.as_ref().map(|s| (s.code, s.reason.as_str()))), ("cid8", 24, Some((408, "R408"))));
        assert_eq!(t.dialog.as_ref().map(|d| (d.local_tag.as_str(), d.remote_tag.as_str())), Some(("lt8", "rt8")));
        assert_eq!(t.cause.detail.as_deref(), Some("d"));
        assert!(g.get(UaLegId(9)).unwrap().dialog.is_none());
        assert_eq!(g.all().iter().map(|t| t.leg.0).collect::<Vec<_>>(), vec![6, 7, 8, 9]);
        // The text ring holds only the live entries.
        let live: usize = g.all().iter().map(|t| t.call_id.len() + t.dialog.as_ref().map_or(3, |d| d.local_tag.len() + d.remote_tag.len()) + 4 + 1).sum();
        assert_eq!(g.text.len(), live);
    }
}
