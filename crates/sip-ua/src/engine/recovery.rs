//! Recoverable state: records, durable transitions, restore, journals.
//! See `crate::recovery` and `docs/sip-ua-recovery.md`.

use super::*;
use crate::recovery::b64;
use crate::recovery::dest_serde::{DestRecord, from_record, to_record};
use serde::{Deserialize, Serialize};
use sip_core::serde_json::{self, Value};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Record format version written by this build.
pub const FORMAT_VERSION: u32 = 1;
/// Oldest record format this build reads (upcast on load).
pub const MIN_FORMAT_VERSION: u32 = 1;

/// The engine's monotonic clock and the wall clock (Unix ms) at the same
/// instant. Deadlines in a record are relative to its anchor; on restore
/// the wall-clock difference is taken as downtime (negative: clock moved
/// back, taken as zero and reported).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockAnchor {
    pub engine_ms: u64,
    pub wall_ms: u64,
}

// `Leg::ack` and `Leg::killed` hold (…, bytes, Dest) tuples.
pub(super) mod ack_serde {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct AckRec {
        cseq: u32,
        bytes: String,
        dest: DestRecord,
    }

    pub fn serialize<S: serde::Serializer>(v: &Option<AckCache>, s: S) -> Result<S::Ok, S::Error> {
        v.as_ref().map(|(c, b, d)| AckRec { cseq: *c, bytes: b64::encode(b), dest: to_record(d) }).serialize(s)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<AckCache>, D::Error> {
        let Some(r) = Option::<AckRec>::deserialize(d)? else { return Ok(None) };
        let bytes = b64::decode(&r.bytes).ok_or_else(|| serde::de::Error::custom("bad base64"))?;
        let dest = from_record(&r.dest).ok_or_else(|| serde::de::Error::custom("bad destination"))?;
        Ok(Some((r.cseq, Arc::from(bytes), dest)))
    }
}

pub(super) mod killed_serde {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct KilledRec {
        tag: String,
        bytes: String,
        dest: DestRecord,
    }

    pub fn serialize<S: serde::Serializer>(v: &[KilledFork], s: S) -> Result<S::Ok, S::Error> {
        v.iter().map(|(t, b, d)| KilledRec { tag: t.clone(), bytes: b64::encode(b), dest: to_record(d) }).collect::<Vec<_>>().serialize(s)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<KilledFork>, D::Error> {
        Vec::<KilledRec>::deserialize(d)?
            .into_iter()
            .map(|r| {
                let bytes = b64::decode(&r.bytes).ok_or_else(|| serde::de::Error::custom("bad base64"))?;
                let dest = from_record(&r.dest).ok_or_else(|| serde::de::Error::custom("bad destination"))?;
                Ok((r.tag, Arc::from(bytes), dest))
            })
            .collect()
    }
}

/// Engine counters a restore must continue from.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
struct Scalars {
    next_txn: u64,
    next_resolve: u64,
    /// Highest leg/operation id handed out.
    id_high: u64,
    event_seq: u64,
    draining: bool,
}

/// One durable transition: the state delta of what an input touched, and
/// the effects it produced (dispatch only after the delta is committed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransitionRecord {
    pub format: u32,
    /// Consecutive per engine (journal position).
    pub seq: u64,
    /// The owner epoch that produced it.
    pub epoch: u64,
    pub anchor: ClockAnchor,
    scalars: Scalars,
    /// `{"anchor":…, "leg":…}` per touched leg (timers relative to anchor).
    legs: Vec<(UaLegId, Value)>,
    legs_removed: Vec<UaLegId>,
    txns: Vec<(TxnId, Value)>,
    txns_removed: Vec<TxnId>,
    /// The whole set of pending DNS resolutions (usually empty).
    resolves: Value,
    ops: Vec<OpRecord>,
    ops_removed: Vec<String>,
    tombstones: Vec<Tombstone>,
    tombstones_removed: Vec<UaLegId>,
    pub transmits: Vec<Transmit>,
    pub events: Vec<EventEnvelope>,
}

impl TransitionRecord {
    pub fn to_json(&self) -> Result<String, JournalError> {
        serde_json::to_string(self).map_err(|e| JournalError::Corrupt(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self, JournalError> {
        let v: Value = serde_json::from_str(s).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        let v = upcast(v)?;
        serde_json::from_value(v).map_err(|e| JournalError::Corrupt(e.to_string()))
    }

    /// Changes no persistent state (only stateless replies and
    /// retransmissions of transactions that are never persisted).
    pub fn is_stateless(&self) -> bool {
        self.legs.is_empty()
            && self.legs_removed.is_empty()
            && self.txns.is_empty()
            && self.txns_removed.is_empty()
            && self.ops.is_empty()
            && self.ops_removed.is_empty()
            && self.tombstones.is_empty()
            && self.tombstones_removed.is_empty()
            && self.events.is_empty()
    }
}

/// What `take_transition` hands the driver.
#[derive(Clone, Debug)]
pub struct Transition {
    pub record: TransitionRecord,
    /// Persist `record` before dispatching its transmits and events. False:
    /// nothing persistent changed (stateless replies), dispatch at once.
    pub needs_commit: bool,
}

/// Effects of a committed transition not yet known to be dispatched.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Effects {
    pub seq: u64,
    pub transmits: Vec<Transmit>,
    pub events: Vec<EventEnvelope>,
}

/// The durable state of an engine: a checkpoint folded with its journal.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StateRecord {
    pub format: u32,
    pub epoch: u64,
    pub anchor: ClockAnchor,
    /// Last transition folded in.
    pub last_seq: u64,
    scalars: Scalars,
    legs: BTreeMap<u64, Value>,
    txns: BTreeMap<u64, Value>,
    resolves: Value,
    ops: BTreeMap<String, OpRecord>,
    /// Oldest first.
    tombstones: Vec<Tombstone>,
    /// Committed effects whose dispatch wasn't recorded.
    pub undispatched: Vec<Effects>,
}

/// The state folded from a checkpoint and its journal.
pub type RecoveryState = StateRecord;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalError {
    Io(String),
    /// A record from an owner older than the fence: it lost ownership.
    StaleEpoch {
        fence: u64,
        got: u64,
    },
    /// Transitions must be appended in order.
    Gap {
        expected: u64,
        got: u64,
    },
    Incompatible {
        found: u32,
        supported: u32,
    },
    Corrupt(String),
    /// The requested events are no longer retained: query outcomes instead.
    ReconciliationRequired {
        oldest_retained: u64,
    },
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for JournalError {}

/// Bring an older record up to the current format (none exist yet: v1).
fn upcast(v: Value) -> Result<Value, JournalError> {
    let found = v.get("format").and_then(Value::as_u64).and_then(|f| u32::try_from(f).ok()).ok_or_else(|| JournalError::Corrupt("no format".into()))?;
    if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&found) {
        return Err(JournalError::Incompatible { found, supported: FORMAT_VERSION });
    }
    Ok(v)
}

impl StateRecord {
    pub fn new() -> Self {
        Self { format: FORMAT_VERSION, resolves: Value::Array(Vec::new()), ..Self::default() }
    }

    /// Fold one committed transition in.
    pub fn apply(&mut self, t: &TransitionRecord) -> Result<(), JournalError> {
        if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&t.format) {
            return Err(JournalError::Incompatible { found: t.format, supported: FORMAT_VERSION });
        }
        if t.epoch < self.epoch {
            return Err(JournalError::StaleEpoch { fence: self.epoch, got: t.epoch });
        }
        let expected = self.last_seq.saturating_add(1);
        if t.seq != expected {
            return Err(JournalError::Gap { expected, got: t.seq });
        }
        for (id, v) in &t.legs {
            self.legs.insert(id.0, v.clone());
        }
        for id in &t.legs_removed {
            self.legs.remove(&id.0);
        }
        for (id, v) in &t.txns {
            self.txns.insert(id.0, v.clone());
        }
        for id in &t.txns_removed {
            self.txns.remove(&id.0);
        }
        self.resolves = t.resolves.clone();
        for o in &t.ops {
            self.ops.insert(o.key.clone(), o.clone());
        }
        for k in &t.ops_removed {
            self.ops.remove(k);
        }
        if !t.tombstones_removed.is_empty() || !t.tombstones.is_empty() {
            // One pass (up to `max_tombstones` entries): drop the removed and
            // the replaced, then append the new ones in order.
            let gone: std::collections::HashSet<UaLegId> = t.tombstones_removed.iter().copied().chain(t.tombstones.iter().map(|x| x.leg)).collect();
            self.tombstones.retain(|x| !gone.contains(&x.leg));
            self.tombstones.extend(t.tombstones.iter().cloned());
        }
        if !t.transmits.is_empty() || !t.events.is_empty() {
            self.undispatched.push(Effects { seq: t.seq, transmits: t.transmits.clone(), events: t.events.clone() });
        }
        self.scalars = t.scalars;
        self.epoch = t.epoch;
        self.anchor = t.anchor;
        self.last_seq = t.seq;
        Ok(())
    }

    /// The effects of every transition up to `seq` went out.
    pub fn dispatched(&mut self, seq: u64) {
        self.undispatched.retain(|e| e.seq > seq);
    }

    pub fn leg_count(&self) -> usize {
        self.legs.len()
    }

    pub fn transaction_count(&self) -> usize {
        self.txns.len()
    }

    pub fn to_json(&self) -> Result<String, JournalError> {
        serde_json::to_string(self).map_err(|e| JournalError::Corrupt(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self, JournalError> {
        let v: Value = serde_json::from_str(s).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        let v = upcast(v)?;
        serde_json::from_value(v).map_err(|e| JournalError::Corrupt(e.to_string()))
    }
}

/// Supplies the password of a restored leg's credentials (records keep
/// only username and realm).
pub type CredentialProvider = dyn Fn(&str, Option<&str>) -> Option<String>;

#[derive(Default)]
pub struct RestoreOptions<'a> {
    /// Owner epoch of the restoring engine (from the external authority).
    pub epoch: u64,
    /// Refuse a state written under this epoch or a newer one (takeover
    /// must come with a newer epoch).
    pub require_newer_epoch: bool,
    pub credentials: Option<&'a CredentialProvider>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoredLeg {
    /// Back in service; `overdue` timers fire on the first `handle_timeout`.
    Restored { leg: UaLegId, overdue: Vec<String> },
    /// Not restored: outside the supported recovery scope (reason given).
    Unsupported { leg: UaLegId, reason: String },
    /// Not restored: clashes with another restored leg.
    Conflicted { leg: UaLegId, reason: String },
    /// Not restored: the record can't be read.
    Corrupt { leg: u64, reason: String },
}

#[derive(Clone, Debug, Default)]
pub struct RestoreReport {
    pub legs: Vec<RestoredLeg>,
    pub transactions_restored: usize,
    pub transactions_dropped: Vec<(TxnId, String)>,
    /// Committed effects whose dispatch wasn't recorded: dispatch them now
    /// (stamped with the new epoch), then record `replay_up_to` dispatched.
    pub replay_transmits: Vec<Transmit>,
    pub replay_events: Vec<EventEnvelope>,
    pub replay_up_to: u64,
    /// Largest time applied between a record's anchor and now (wall
    /// clock): the downtime plus how long the record had been unchanged.
    pub downtime_ms: u64,
    /// A record's wall clock was ahead of now: downtime taken as zero.
    pub clock_skew: bool,
    pub notes: Vec<String>,
}

impl RestoreReport {
    pub fn restored(&self) -> Vec<UaLegId> {
        self.legs.iter().filter_map(|l| if let RestoredLeg::Restored { leg, .. } = l { Some(*leg) } else { None }).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreError {
    Incompatible {
        found: u32,
        supported: u32,
    },
    /// The state is from this epoch or a newer one: we are not the newer owner.
    StaleEpoch {
        state: u64,
        offered: u64,
    },
}

/// Timers relative to `now` in the record (`[kind, at]` pairs).
fn rel_timers(v: &mut Value, now: u64) {
    if let Some(a) = v.as_array_mut() {
        for t in a {
            if let Some(at) = t.get(1).and_then(Value::as_u64)
                && let Some(slot) = t.get_mut(1)
            {
                *slot = Value::from(at.saturating_sub(now));
            }
        }
    }
}

/// Back to absolute engine time: `now + remaining − downtime` (at least now).
/// Returns how many were already due.
fn abs_timers(v: &mut Value, now: u64, downtime: u64, overdue: &mut Vec<String>) {
    if let Some(a) = v.as_array_mut() {
        for t in a {
            let name = t.get(0).map(|k| k.to_string().trim_matches('"').to_string()).unwrap_or_default();
            if let Some(rem) = t.get(1).and_then(Value::as_u64)
                && let Some(slot) = t.get_mut(1)
            {
                if rem <= downtime {
                    overdue.push(name);
                }
                *slot = Value::from(now.saturating_add(rem.saturating_sub(downtime)));
            }
        }
    }
}

fn downtime(anchor: ClockAnchor, wall_ms: u64, report: &mut RestoreReport) -> u64 {
    match wall_ms.checked_sub(anchor.wall_ms) {
        Some(d) => {
            report.downtime_ms = report.downtime_ms.max(d);
            d
        }
        None => {
            report.clock_skew = true;
            0
        }
    }
}

impl UaEngine {
    fn leg_value(leg: &Leg, anchor: ClockAnchor) -> Option<Value> {
        let mut v = serde_json::to_value(leg).ok()?;
        if let Some(t) = v.get_mut("timers") {
            rel_timers(t, anchor.engine_ms);
        }
        Some(serde_json::json!({ "anchor": anchor, "leg": v }))
    }

    fn txn_value(e: &TxnEntry, anchor: ClockAnchor) -> Option<Value> {
        let mut v = serde_json::to_value(e).ok()?;
        if let Some(t) = v.get_mut("txn") {
            if let Some(a) = t.get_mut("armed") {
                rel_timers(a, anchor.engine_ms);
            }
            if let Some(c) = t.get_mut("created")
                && let Some(n) = c.as_u64()
            {
                *c = Value::from(anchor.engine_ms.saturating_sub(n));
            }
        }
        Some(serde_json::json!({ "anchor": anchor, "entry": v }))
    }

    /// A server transaction answering a request outside any leg (481, 405,
    /// OPTIONS, 503…) or a request whose effect is the leg's own state
    /// (BYE): never persisted.
    fn ephemeral(e: &TxnEntry) -> bool {
        matches!(e.txn.kind, crate::txn::Kind::InviteServer | crate::txn::Kind::NonInviteServer) && e.purpose == Purpose::Detached
    }

    /// Durable mode: the delta and effects of everything since the last
    /// transition. `now` is the engine clock, `wall_ms` the wall clock.
    pub fn take_transition(&mut self, now: u64, wall_ms: u64) -> Option<Transition> {
        if !self.cfg.durable || self.lease_lapsed(now) {
            return None;
        }
        let jr = std::mem::take(&mut self.jr.legs);
        let txs = std::mem::take(&mut self.jr.txns);
        let txs_removed = std::mem::take(&mut self.jr.txns_removed);
        let ops = std::mem::take(&mut self.jr.ops);
        let ops_removed = std::mem::take(&mut self.jr.ops_removed);
        let tombs = std::mem::take(&mut self.jr.tombstones);
        let tombs_removed = std::mem::take(&mut self.jr.tombstones_removed);
        let anchor = ClockAnchor { engine_ms: now, wall_ms };
        let mut legs = Vec::new();
        let mut legs_removed = Vec::new();
        for id in jr {
            match self.legs.get(&id) {
                Some(l) => {
                    if let Some(v) = Self::leg_value(l, anchor) {
                        legs.push((id, v));
                    }
                }
                None => legs_removed.push(id),
            }
        }
        let mut txns = Vec::new();
        let mut txns_removed: Vec<TxnId> = txs_removed.into_iter().collect();
        for id in txs {
            match self.txns.get(&id) {
                Some(e) if !Self::ephemeral(e) => {
                    if let Some(v) = Self::txn_value(e, anchor) {
                        txns.push((id, v));
                    }
                }
                Some(_) => {}
                None => txns_removed.push(id),
            }
        }
        let mut resolves: Vec<(&u64, &PendingResolve)> = self.pending_resolve.iter().collect();
        resolves.sort_by_key(|(k, _)| **k);
        let resolves = serde_json::to_value(&resolves).unwrap_or(Value::Array(Vec::new()));
        let ops: Vec<OpRecord> = ops.iter().filter_map(|k| self.ops.get(k).cloned()).collect();
        let tombstones: Vec<Tombstone> = tombs.iter().filter_map(|l| self.tombstones.get(*l)).collect();
        let transmits: Vec<Transmit> = self.transmits.drain(..).collect();
        let events: Vec<EventEnvelope> = self.events.drain(..).collect();
        let next = self.jr.seq.saturating_add(1);
        let record = TransitionRecord {
            format: FORMAT_VERSION,
            seq: next,
            epoch: self.epoch,
            anchor,
            scalars: Scalars {
                next_txn: self.next_txn,
                next_resolve: self.next_resolve,
                id_high: self.ids.high_water(),
                event_seq: self.event_seq,
                draining: self.draining,
            },
            legs,
            legs_removed,
            txns,
            txns_removed,
            resolves,
            ops,
            ops_removed: ops_removed.into_iter().collect(),
            tombstones,
            tombstones_removed: tombs_removed.into_iter().collect(),
            transmits,
            events,
        };
        let stateless = record.is_stateless();
        if stateless && record.transmits.is_empty() {
            return None;
        }
        if stateless {
            // Not part of the journal: no sequence number is used up.
            return Some(Transition { record: TransitionRecord { seq: 0, ..record }, needs_commit: false });
        }
        self.jr.seq = next;
        Some(Transition { record, needs_commit: true })
    }

    /// The last transition position (journal sequence) handed out.
    pub fn journal_seq(&self) -> u64 {
        self.jr.seq
    }

    /// A full record of the engine (a checkpoint), consistent with the
    /// transitions taken so far. In durable mode take the pending
    /// transition first: uncommitted effects are not part of a checkpoint.
    pub fn export_state(&self, now: u64, wall_ms: u64) -> StateRecord {
        let anchor = ClockAnchor { engine_ms: now, wall_ms };
        let mut s = StateRecord::new();
        s.epoch = self.epoch;
        s.anchor = anchor;
        s.last_seq = self.jr.seq;
        s.scalars = Scalars {
            next_txn: self.next_txn,
            next_resolve: self.next_resolve,
            id_high: self.ids.high_water(),
            event_seq: self.event_seq,
            draining: self.draining,
        };
        for (id, l) in &self.legs {
            if let Some(v) = Self::leg_value(l, anchor) {
                s.legs.insert(id.0, v);
            }
        }
        for (id, e) in &self.txns {
            if !Self::ephemeral(e)
                && let Some(v) = Self::txn_value(e, anchor)
            {
                s.txns.insert(id.0, v);
            }
        }
        let mut resolves: Vec<(&u64, &PendingResolve)> = self.pending_resolve.iter().collect();
        resolves.sort_by_key(|(k, _)| **k);
        s.resolves = serde_json::to_value(&resolves).unwrap_or(Value::Array(Vec::new()));
        s.ops = self.ops.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        s.tombstones = self.tombstones.all();
        if !self.transmits.is_empty() || !self.events.is_empty() {
            s.undispatched.push(Effects {
                seq: self.jr.seq,
                transmits: self.transmits.iter().cloned().collect(),
                events: self.events.iter().cloned().collect(),
            });
        }
        s
    }

    /// Rebuild an engine from recovered state. Every reference is checked
    /// and every index and timer rebuilt before the engine is returned;
    /// nothing is sent. `now` is the new engine clock, `wall_ms` the wall
    /// clock now. Dispatch `report.replay_*` before admitting traffic.
    pub fn restore(
        cfg: UaConfig,
        entropy: Box<dyn Entropy>,
        ids: IdAllocator,
        state: &StateRecord,
        opts: &RestoreOptions<'_>,
        now: u64,
        wall_ms: u64,
    ) -> Result<(Self, RestoreReport), RestoreError> {
        if !(MIN_FORMAT_VERSION..=FORMAT_VERSION).contains(&state.format) {
            return Err(RestoreError::Incompatible { found: state.format, supported: FORMAT_VERSION });
        }
        if opts.epoch < state.epoch || (opts.require_newer_epoch && opts.epoch <= state.epoch) {
            return Err(RestoreError::StaleEpoch { state: state.epoch, offered: opts.epoch });
        }
        let mut e = UaEngine::with_entropy(cfg, entropy, ids);
        e.epoch = opts.epoch;
        e.jr.seq = state.last_seq;
        let mut rep = RestoreReport { replay_up_to: state.last_seq, ..RestoreReport::default() };
        let mut max_id = state.scalars.id_high;
        // Legs present in the state that could not be restored: their
        // transactions go too, and the journal is told they are gone.
        let mut lost: std::collections::BTreeSet<UaLegId> = std::collections::BTreeSet::new();

        // Legs.
        for (raw_id, v) in &state.legs {
            let anchor = v.get("anchor").cloned().and_then(|a| serde_json::from_value::<ClockAnchor>(a).ok()).unwrap_or_default();
            let down = downtime(anchor, wall_ms, &mut rep);
            let mut lv = v.get("leg").cloned().unwrap_or(Value::Null);
            let mut overdue = Vec::new();
            if let Some(t) = lv.get_mut("timers") {
                abs_timers(t, now, down, &mut overdue);
            }
            let mut leg: Leg = match serde_json::from_value(lv) {
                Ok(l) => l,
                Err(err) => {
                    rep.legs.push(RestoredLeg::Corrupt { leg: *raw_id, reason: err.to_string() });
                    lost.insert(UaLegId(*raw_id));
                    continue;
                }
            };
            if leg.id.0 != *raw_id {
                lost.insert(UaLegId(*raw_id));
                rep.legs.push(RestoredLeg::Corrupt { leg: *raw_id, reason: format!("record holds {}", leg.id) });
                continue;
            }
            // Transport policy: a connection does not survive the process.
            if let Some(f) = leg.flow
                && f.proto.is_stream()
                && leg.role == Role::Uas
            {
                lost.insert(leg.id);
                rep.legs.push(RestoredLeg::Unsupported {
                    leg: leg.id,
                    reason: format!("dialog bound to an inbound {} connection, which can't be re-established (the peer must reconnect)", f.proto.via_name()),
                });
                continue;
            }
            let clash = leg.dialog_tags.iter().any(|t| e.dialogs.contains_key(&(leg.call_id.clone(), leg.local_tag.clone(), t.clone())))
                || leg.merged_key.as_ref().is_some_and(|k| e.merged.contains_key(k));
            if clash {
                lost.insert(leg.id);
                rep.legs.push(RestoredLeg::Conflicted { leg: leg.id, reason: "dialog identity already restored for another leg".into() });
                continue;
            }
            if let Some(c) = &mut leg.creds {
                match opts.credentials.and_then(|p| p(&c.username, c.realm.as_deref())) {
                    Some(pw) => c.password = pw,
                    None => {
                        rep.notes.push(format!("{}: credentials for {} not supplied; authentication retries disabled", leg.id, c.username));
                        leg.creds = None;
                    }
                }
            }
            max_id = max_id.max(leg.id.0).max(leg.origin_op.map_or(0, |o| o.0));
            for t in leg.dialog_tags.clone() {
                e.dialogs.insert((leg.call_id.clone(), leg.local_tag.clone(), t), leg.id);
            }
            if let Some(k) = leg.merged_key.clone() {
                e.merged.insert(k, leg.id);
            }
            for (t, at) in leg.timers.clone() {
                e.schedule(at, TimerRef::Leg(leg.id, t));
            }
            rep.legs.push(RestoredLeg::Restored { leg: leg.id, overdue });
            e.legs.insert(leg.id, leg);
        }

        // Transactions.
        let mut max_txn = state.scalars.next_txn;
        for (raw_id, v) in &state.txns {
            let anchor = v.get("anchor").cloned().and_then(|a| serde_json::from_value::<ClockAnchor>(a).ok()).unwrap_or_default();
            let down = downtime(anchor, wall_ms, &mut rep);
            let mut ev = v.get("entry").cloned().unwrap_or(Value::Null);
            let mut overdue = Vec::new();
            if let Some(t) = ev.get_mut("txn") {
                if let Some(a) = t.get_mut("armed") {
                    abs_timers(a, now, down, &mut overdue);
                }
                if let Some(c) = t.get_mut("created")
                    && let Some(age) = c.as_u64()
                {
                    *c = Value::from(now.saturating_sub(age.saturating_add(down)));
                }
            }
            let mut entry: TxnEntry = match serde_json::from_value(ev) {
                Ok(x) => x,
                Err(err) => {
                    rep.transactions_dropped.push((TxnId(*raw_id), format!("unreadable: {err}")));
                    continue;
                }
            };
            entry.txn.restored();
            let owner = match entry.purpose {
                Purpose::Invite(l)
                | Purpose::ReInvite(l, _)
                | Purpose::Update(l, _)
                | Purpose::Bye(l)
                | Purpose::Cancel(l)
                | Purpose::Info(l, _)
                | Purpose::Refresh(l)
                | Purpose::Refer(l, _) => Some(l),
                Purpose::Detached => None,
            };
            // A transaction may outlive its leg (a BYE absorbing
            // retransmissions): keep it unless its leg failed to restore.
            if owner.is_some_and(|l| lost.contains(&l)) {
                rep.transactions_dropped.push((TxnId(*raw_id), "its leg was not restored".into()));
                continue;
            }
            let server = matches!(entry.txn.kind, crate::txn::Kind::InviteServer | crate::txn::Kind::NonInviteServer);
            if server && entry.txn.dest.proto.is_stream() {
                rep.transactions_dropped.push((TxnId(*raw_id), "server transaction on a lost connection".into()));
                continue;
            }
            let clash = match &entry.key {
                TxnKey::Client(k) => e.client_keys.contains_key(k),
                TxnKey::Server(k) => e.server_keys.contains_key(k),
            };
            if clash || entry.txn.id.0 != *raw_id || e.txns.contains_key(&entry.txn.id) {
                rep.transactions_dropped.push((TxnId(*raw_id), "transaction identity clash".into()));
                continue;
            }
            match &entry.key {
                TxnKey::Client(k) => {
                    e.client_keys.insert(k.clone(), entry.txn.id);
                }
                TxnKey::Server(k) => {
                    e.server_keys.insert(k.clone(), entry.txn.id);
                }
            }
            for (k, at) in entry.txn.armed_timers() {
                e.schedule(at, TimerRef::Txn(entry.txn.id, k));
            }
            max_txn = max_txn.max(*raw_id);
            rep.transactions_restored = rep.transactions_restored.saturating_add(1);
            e.txns.insert(entry.txn.id, entry);
        }

        // Pending DNS resolutions: ask again.
        if let Ok(rs) = serde_json::from_value::<Vec<(u64, PendingResolve)>>(state.resolves.clone()) {
            for (id, p) in rs {
                if !e.legs.contains_key(&p.leg) {
                    continue;
                }
                let flow = e.legs.get(&p.leg).and_then(|l| l.flow);
                if let Some(Target::Resolve(host, port, proto, secure)) = e.target_for(&p.req, flow) {
                    e.resolves.push_back(ResolveRequest { id, host, port, proto, secure });
                    e.next_resolve = e.next_resolve.max(id);
                    e.pending_resolve.insert(id, p);
                }
            }
        }

        // Keyed operations and tombstones.
        for (k, r) in &state.ops {
            max_id = max_id.max(r.op.0).max(r.leg.0);
            e.op_keys.insert(r.op, k.clone());
            e.ops.insert(k.clone(), r.clone());
        }
        for t in &state.tombstones {
            max_id = max_id.max(t.leg.0);
            let ids = (t.call_id.as_str(), t.dialog.as_ref().map_or("", |d| d.local_tag.as_str()), t.dialog.as_ref().map(|d| d.remote_tag.as_str()));
            let max = e.cfg.max_tombstones;
            e.tombstones.push(t.leg, ids, &t.cause, t.last_seq, max);
        }

        // The journal must forget what was not restored.
        for (t, _) in &rep.transactions_dropped {
            e.jr.txns_removed.insert(*t);
        }
        for l in lost {
            e.jr.legs.insert(l);
        }
        e.next_txn = max_txn;
        e.next_resolve = e.next_resolve.max(state.scalars.next_resolve);
        e.event_seq = state.scalars.event_seq;
        e.draining = state.scalars.draining;
        e.ids.advance_to(max_id);

        // Committed effects whose dispatch wasn't recorded.
        for fx in &state.undispatched {
            rep.replay_transmits.extend(fx.transmits.iter().cloned().map(|mut t| {
                t.epoch = opts.epoch;
                t.txn = t.txn.filter(|id| e.txns.contains_key(id));
                t
            }));
            rep.replay_events.extend(fx.events.iter().cloned());
        }
        Ok((e, rep))
    }
}

/// An in-memory journal: the deterministic durable driver for tests, with
/// failpoints, an ownership fence and a bounded event log for replay.
pub struct MemoryJournal {
    state: StateRecord,
    events: std::collections::VecDeque<EventEnvelope>,
    event_retention: usize,
    fail_appends: u32,
    fence: u64,
    pub appends: u64,
}

impl MemoryJournal {
    pub fn new(event_retention: usize) -> Self {
        Self { state: StateRecord::new(), events: std::collections::VecDeque::new(), event_retention, fail_appends: 0, fence: 0, appends: 0 }
    }

    /// Persist a transition (through its JSON encoding, as a real store).
    pub fn append(&mut self, t: &TransitionRecord) -> Result<(), JournalError> {
        if self.fail_appends > 0 {
            self.fail_appends = self.fail_appends.saturating_sub(1);
            return Err(JournalError::Io("failpoint: append failed".into()));
        }
        if t.epoch < self.fence {
            return Err(JournalError::StaleEpoch { fence: self.fence, got: t.epoch });
        }
        let t = TransitionRecord::from_json(&t.to_json()?)?;
        self.state.apply(&t)?;
        for ev in &t.events {
            self.events.push_back(ev.clone());
            if self.events.len() > self.event_retention {
                self.events.pop_front();
            }
        }
        self.appends = self.appends.saturating_add(1);
        Ok(())
    }

    pub fn dispatched(&mut self, seq: u64) {
        self.state.dispatched(seq);
    }

    /// A new owner raises the fence: older epochs can no longer append.
    pub fn fence(&mut self, epoch: u64) {
        self.fence = self.fence.max(epoch);
    }

    /// May an owner of `epoch` still act? A driver checks this before it
    /// dispatches a transition that needed no commit (stateless replies),
    /// so a stale owner sends nothing at all, not even a 481.
    pub fn admit(&self, epoch: u64) -> Result<(), JournalError> {
        if epoch < self.fence {
            return Err(JournalError::StaleEpoch { fence: self.fence, got: epoch });
        }
        Ok(())
    }

    /// Make the next `n` appends fail.
    pub fn fail_next_appends(&mut self, n: u32) {
        self.fail_appends = n;
    }

    /// The recovered state, as a restarting process would read it.
    pub fn state(&self) -> Result<StateRecord, JournalError> {
        StateRecord::from_json(&self.state.to_json()?)
    }

    /// Committed events after `log_seq`, or `ReconciliationRequired` when
    /// some are no longer retained.
    pub fn events_after(&self, log_seq: u64) -> Result<Vec<EventEnvelope>, JournalError> {
        if let Some(first) = self.events.front()
            && first.log_seq > log_seq.saturating_add(1)
        {
            return Err(JournalError::ReconciliationRequired { oldest_retained: first.log_seq });
        }
        Ok(self.events.iter().filter(|e| e.log_seq > log_seq).cloned().collect())
    }
}

/// A file-backed journal: `state.json` (checkpoint) plus `journal.log`
/// (one JSON transition per line), each append fsynced before it returns.
///
/// Ownership: `fence` holds the newest owner epoch; `owner.lock` (an
/// advisory file lock) makes "check the fence, then write" atomic between
/// processes sharing the directory. A newer owner opens with
/// [`FileJournal::open_as`], which raises the fence before it loads the
/// state, so every later append, dispatch record or checkpoint of an older
/// owner is refused (`StaleEpoch`). One host (or a shared filesystem with
/// working `flock`); a distributed deployment uses a store with
/// conditional writes instead.
pub struct FileJournal {
    dir: PathBuf,
    log: std::fs::File,
    lock: std::fs::File,
    state: StateRecord,
    owner: u64,
}

fn read_fence(dir: &Path) -> Result<u64, JournalError> {
    match std::fs::read_to_string(dir.join("fence")) {
        Ok(s) => s.trim().parse().map_err(|_| JournalError::Io("fence: not a number".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(JournalError::Io(e.to_string())),
    }
}

fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join(name))?;
    std::fs::File::open(dir)?.sync_all()
}

impl FileJournal {
    /// Open (creating) and load as the current owner (the fence's epoch).
    pub fn open(dir: &Path) -> Result<Self, JournalError> {
        Self::open_as(dir, None)
    }

    /// Open as the owner of `epoch`: refused when the fence is newer;
    /// raises the fence to `epoch` (fencing every older owner) before it
    /// loads the checkpoint folded with every complete journal line. A torn
    /// last line (crash mid-write) is ignored.
    pub fn open_as(dir: &Path, epoch: Option<u64>) -> Result<Self, JournalError> {
        let io = |e: std::io::Error| JournalError::Io(e.to_string());
        std::fs::create_dir_all(dir).map_err(io)?;
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("owner.lock")).map_err(io)?;
        lock.lock().map_err(io)?;
        let r = Self::load(dir, epoch, &lock);
        let _ = lock.unlock();
        r
    }

    fn load(dir: &Path, epoch: Option<u64>, lock: &std::fs::File) -> Result<Self, JournalError> {
        let io = |e: std::io::Error| JournalError::Io(e.to_string());
        let fence = read_fence(dir)?;
        let owner = match epoch {
            Some(e) if e < fence => return Err(JournalError::StaleEpoch { fence, got: e }),
            Some(e) => {
                if e > fence {
                    write_atomic(dir, "fence", e.to_string().as_bytes()).map_err(io)?;
                }
                e
            }
            None => fence,
        };
        let mut state = match std::fs::read_to_string(dir.join("state.json")) {
            Ok(s) => StateRecord::from_json(&s)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StateRecord::new(),
            Err(e) => return Err(io(e)),
        };
        let log_path = dir.join("journal.log");
        if let Ok(text) = std::fs::read_to_string(&log_path) {
            for line in text.split_inclusive('\n') {
                if !line.ends_with('\n') {
                    break; // torn write
                }
                let line = line.trim();
                if let Some(seq) = line.strip_prefix("dispatched ") {
                    if let Ok(n) = seq.parse() {
                        state.dispatched(n);
                    }
                    continue;
                }
                if line.is_empty() {
                    continue;
                }
                let t = TransitionRecord::from_json(line)?;
                if t.seq <= state.last_seq {
                    continue; // already in the checkpoint
                }
                state.apply(&t)?;
            }
        }
        let log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).map_err(io)?;
        Ok(Self { dir: dir.to_path_buf(), log, lock: lock.try_clone().map_err(io)?, state, owner })
    }

    /// The owner epoch this journal was opened as.
    pub fn owner(&self) -> u64 {
        self.owner
    }

    /// The newest owner epoch (the fence file).
    pub fn fence_epoch(&self) -> Result<u64, JournalError> {
        read_fence(&self.dir)
    }

    /// May an owner of `epoch` still act (see [`MemoryJournal::admit`])?
    pub fn admit(&self, epoch: u64) -> Result<(), JournalError> {
        let fence = read_fence(&self.dir)?;
        if epoch < fence {
            return Err(JournalError::StaleEpoch { fence, got: epoch });
        }
        Ok(())
    }

    /// Run `f` holding the ownership lock, if `epoch` is not fenced.
    fn guarded<T>(&mut self, epoch: u64, f: impl FnOnce(&mut Self) -> Result<T, JournalError>) -> Result<T, JournalError> {
        self.lock.lock().map_err(|e| JournalError::Io(e.to_string()))?;
        let r = self.admit(epoch).and_then(|()| f(self));
        let _ = self.lock.unlock();
        r
    }

    pub fn state(&self) -> &StateRecord {
        &self.state
    }

    pub fn append(&mut self, t: &TransitionRecord) -> Result<(), JournalError> {
        self.guarded(t.epoch, |j| {
            let mut next = j.state.clone();
            next.apply(t)?;
            let mut line = t.to_json()?;
            line.push('\n');
            j.log.write_all(line.as_bytes()).map_err(|e| JournalError::Io(e.to_string()))?;
            j.log.sync_data().map_err(|e| JournalError::Io(e.to_string()))?;
            j.state = next;
            Ok(())
        })
    }

    pub fn dispatched(&mut self, seq: u64) -> Result<(), JournalError> {
        let owner = self.owner.max(self.state.epoch);
        self.guarded(owner, |j| {
            j.log.write_all(format!("dispatched {seq}\n").as_bytes()).map_err(|e| JournalError::Io(e.to_string()))?;
            j.state.dispatched(seq);
            Ok(())
        })
    }

    /// Write a checkpoint atomically (temp file, fsync, rename) and start
    /// an empty journal.
    pub fn checkpoint(&mut self) -> Result<(), JournalError> {
        let owner = self.owner.max(self.state.epoch);
        self.guarded(owner, Self::checkpoint_locked)
    }

    fn checkpoint_locked(&mut self) -> Result<(), JournalError> {
        let io = |e: std::io::Error| JournalError::Io(e.to_string());
        let tmp = self.dir.join("state.json.tmp");
        let mut f = std::fs::File::create(&tmp).map_err(io)?;
        f.write_all(self.state.to_json()?.as_bytes()).map_err(io)?;
        f.sync_all().map_err(io)?;
        std::fs::rename(&tmp, self.dir.join("state.json")).map_err(io)?;
        let log = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(self.dir.join("journal.log")).map_err(io)?;
        log.sync_all().map_err(io)?;
        self.log = std::fs::OpenOptions::new().append(true).open(self.dir.join("journal.log")).map_err(io)?;
        Ok(())
    }
}
