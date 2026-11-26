//! Timer wheel: O(1) schedule, O(entries-in-slot) per tick.
//! Kamailio's timer.c uses a hierarchical wheel driven by a dedicated timer
//! process; modules (tm) hang retransmission/final-response timers on it.

pub struct TimerWheel<T> {
    slots: Vec<Vec<(u64, T)>>,
    now: u64,
    mask: u64,
}

impl<T> TimerWheel<T> {
    pub fn new(slots: usize) -> Self {
        let n = slots.next_power_of_two();
        Self { slots: (0..n).map(|_| Vec::new()).collect(), now: 0, mask: (n as u64).saturating_sub(1) }
    }

    #[inline]
    pub fn now(&self) -> u64 {
        self.now
    }

    /// The slot of tick `at`.
    fn slot(&mut self, at: u64) -> &mut Vec<(u64, T)> {
        let i = usize::try_from(at & self.mask).unwrap_or_default();
        #[allow(clippy::indexing_slicing, reason = "i is masked below slots.len(), a power of two")]
        &mut self.slots[i]
    }

    /// Schedule `item` `delay_ticks` from now (at least one tick); a delay
    /// past the end of time never fires.
    pub fn schedule(&mut self, delay_ticks: u64, item: T) {
        let at = self.now.saturating_add(delay_ticks.max(1));
        self.slot(at).push((at, item));
    }

    /// Advance one tick and move every expired item into `out`.
    /// Items more than one revolution away stay in their slot.
    pub fn advance(&mut self, out: &mut Vec<T>) {
        self.now = self.now.saturating_add(1);
        let now = self.now;
        let slot = self.slot(now);
        out.extend(slot.extract_if(.., |(at, _)| *at <= now).map(|(_, item)| item));
        // A drained slot is not visited again for a whole revolution: give
        // its buffer back instead of keeping every slot sized to its busiest
        // tick (8192 slots × peak load stayed resident before).
        if slot.is_empty() && slot.capacity() > 0 {
            *slot = Vec::new();
        }
    }

    /// Item buffers currently held by the slots (for tests and stats).
    pub fn capacity(&self) -> usize {
        self.slots.iter().map(Vec::capacity).sum()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn wheel() {
        let mut w = super::TimerWheel::new(4);
        w.schedule(2, 'a');
        w.schedule(6, 'b'); // wraps around the 4-slot wheel
        let mut out = vec![];
        for _ in 0..2 {
            w.advance(&mut out);
        }
        assert_eq!(out, ['a']);
        for _ in 0..4 {
            w.advance(&mut out);
        }
        assert_eq!(out, ['a', 'b']);
    }

    #[test]
    fn drained_slots_free_their_buffers() {
        let mut w = super::TimerWheel::new(64);
        for t in 1..=64 {
            for i in 0..100 {
                w.schedule(t, i);
            }
        }
        assert!(w.capacity() >= 6400);
        let mut out = vec![];
        for _ in 0..64 {
            w.advance(&mut out);
        }
        assert_eq!(out.len(), 6400);
        assert_eq!(w.capacity(), 0);
    }

    fn run(w: &mut super::TimerWheel<u32>, ticks: u64) -> Vec<(u64, u32)> {
        let mut fired = vec![];
        for _ in 0..ticks {
            let mut out = vec![];
            w.advance(&mut out);
            fired.extend(out.into_iter().map(|i| (w.now(), i)));
        }
        fired
    }

    #[test]
    fn fires_at_the_scheduled_tick() {
        let mut w = super::TimerWheel::new(8);
        // (delay, item): 0 counts as 1; 8 and 16 land in the same slot as 0.
        for (delay, item) in [(0, 0), (1, 1), (3, 3), (8, 8), (16, 16), (7, 7), (3, 33)] {
            w.schedule(delay, item);
        }
        let fired = run(&mut w, 20);
        assert_eq!(fired, [(1, 0), (1, 1), (3, 3), (3, 33), (7, 7), (8, 8), (16, 16)]);
    }

    #[test]
    fn slot_counts_round_up_to_a_power_of_two() {
        for (slots, revolution) in [(0, 1), (1, 1), (5, 8), (8, 8), (9, 16)] {
            let mut w = super::TimerWheel::new(slots);
            w.schedule(revolution, 1);
            w.schedule(revolution + 1, 2);
            assert_eq!(run(&mut w, revolution + 1), [(revolution, 1), (revolution + 1, 2)], "{slots} slots");
        }
    }

    #[test]
    fn schedule_is_relative_to_now() {
        let mut w = super::TimerWheel::new(4);
        assert_eq!(run(&mut w, 5), []);
        assert_eq!(w.now(), 5);
        w.schedule(2, 9);
        assert_eq!(run(&mut w, 3), [(7, 9)]);
    }

    #[test]
    fn a_delay_past_the_end_of_time_does_not_fire() {
        let mut w = super::TimerWheel::new(4);
        w.schedule(u64::MAX, 1);
        w.schedule(u64::MAX - 1, 2);
        assert_eq!(run(&mut w, 64), []);
    }
}
