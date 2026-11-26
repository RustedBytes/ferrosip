//! The device watchdog of one connection (RFC 3539 §3.4.1), as a state
//! machine without a clock: the reader reports traffic with
//! [`Watchdog::received`], the watchdog thread calls [`Watchdog::tick`]
//! every second and does what it answers.
//!
//! - OKAY: after `Tw` without traffic a DWR is sent; if `Tw` passes again
//!   with no answer (nor anything else), the peer becomes SUSPECT.
//! - SUSPECT: requests are routed elsewhere; any traffic makes it OKAY
//!   again, another `Tw` of silence closes the connection.

use std::time::{Duration, Instant};

/// RFC 3539 §3.4.1: Tw is at least 6 seconds.
pub const MIN_TW: Duration = Duration::from_secs(6);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Healthy; `pending` while a DWR is unanswered.
    Okay { pending: bool },
    /// Not used for new requests; closed after another `Tw` of silence.
    Suspect,
}

/// What the watchdog thread must do now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Nothing,
    SendDwr,
    /// The peer went SUSPECT (requests go elsewhere).
    Suspect,
    /// The peer is DOWN: close the connection.
    Close,
}

#[derive(Debug)]
pub struct Watchdog {
    tw: Duration,
    state: State,
    /// When the timer next fires; never for a `Tw` beyond the clock.
    due: Option<Instant>,
}

impl Watchdog {
    /// A connection opened at `now`, with the configured `tw` (raised to
    /// [`MIN_TW`]).
    pub fn new(tw: Duration, now: Instant) -> Self {
        let tw = tw.max(MIN_TW);
        Self { tw, state: State::Okay { pending: false }, due: now.checked_add(tw) }
    }

    #[cfg(test)]
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether requests may be routed to this connection.
    pub fn usable(&self) -> bool {
        self.state != State::Suspect
    }

    /// Anything arrived from the peer at `now` (a DWA or any other message).
    pub fn received(&mut self, now: Instant) {
        self.state = State::Okay { pending: false };
        self.due = now.checked_add(self.tw);
    }

    /// The timer check at `now`.
    pub fn tick(&mut self, now: Instant) -> Action {
        if self.due.is_none_or(|due| now < due) {
            return Action::Nothing;
        }
        self.due = now.checked_add(self.tw);
        let (state, action) = match self.state {
            State::Okay { pending: false } => (State::Okay { pending: true }, Action::SendDwr),
            State::Okay { pending: true } => (State::Suspect, Action::Suspect),
            State::Suspect => (State::Suspect, Action::Close),
        };
        self.state = state;
        action
    }

    /// The longest silence before [`Action::Close`]: the reader's own read
    /// timeout, should the watchdog thread fall behind.
    pub fn silence_limit(&self) -> Duration {
        self.tw.saturating_mul(3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TW: Duration = Duration::from_secs(10);

    fn at(t0: Instant, s: u64) -> Instant {
        t0.checked_add(Duration::from_secs(s)).unwrap()
    }

    #[test]
    fn silence_goes_dwr_then_suspect_then_down() {
        let t0 = Instant::now();
        let mut w = Watchdog::new(TW, t0);
        // (second, action, state after)
        let steps = [
            (1, Action::Nothing, State::Okay { pending: false }),
            (9, Action::Nothing, State::Okay { pending: false }),
            (10, Action::SendDwr, State::Okay { pending: true }),
            (11, Action::Nothing, State::Okay { pending: true }),
            (19, Action::Nothing, State::Okay { pending: true }),
            (20, Action::Suspect, State::Suspect),
            (29, Action::Nothing, State::Suspect),
            (30, Action::Close, State::Suspect),
        ];
        for (s, action, state) in steps {
            assert_eq!(w.tick(at(t0, s)), action, "at {s}s");
            assert_eq!(w.state(), state, "at {s}s");
            assert_eq!(w.usable(), state != State::Suspect, "at {s}s");
        }
        assert_eq!(w.silence_limit(), Duration::from_secs(30), "the reader times out when the watchdog closes");
    }

    #[test]
    fn traffic_resets_the_timer_in_every_state() {
        let t0 = Instant::now();
        let mut w = Watchdog::new(TW, t0);
        // Steady traffic: never a DWR.
        for s in (5..100).step_by(5) {
            w.received(at(t0, s));
            assert_eq!(w.tick(at(t0, s.saturating_add(1))), Action::Nothing);
        }
        // The DWA answers a pending DWR: OKAY again, next DWR Tw later.
        let mut w = Watchdog::new(TW, t0);
        assert_eq!(w.tick(at(t0, 10)), Action::SendDwr);
        w.received(at(t0, 12));
        assert_eq!(w.state(), State::Okay { pending: false });
        assert_eq!(w.tick(at(t0, 21)), Action::Nothing);
        assert_eq!(w.tick(at(t0, 22)), Action::SendDwr);
        // SUSPECT: anything received makes the peer usable again.
        let mut w = Watchdog::new(TW, t0);
        assert_eq!(w.tick(at(t0, 10)), Action::SendDwr);
        assert_eq!(w.tick(at(t0, 20)), Action::Suspect);
        assert!(!w.usable());
        w.received(at(t0, 25));
        assert!(w.usable());
        assert_eq!(w.tick(at(t0, 35)), Action::SendDwr, "starts over from OKAY");
    }

    #[test]
    fn a_late_tick_fires_once_and_re_arms_from_then() {
        let t0 = Instant::now();
        let mut w = Watchdog::new(TW, t0);
        // The watchdog thread was held up for a minute: one step, not six.
        assert_eq!(w.tick(at(t0, 60)), Action::SendDwr);
        assert_eq!(w.tick(at(t0, 61)), Action::Nothing);
        assert_eq!(w.tick(at(t0, 70)), Action::Suspect);
    }

    #[test]
    fn tw_is_at_least_six_seconds() {
        let t0 = Instant::now();
        for tw in [0, 1, 5] {
            let mut w = Watchdog::new(Duration::from_secs(tw), t0);
            assert_eq!(w.tick(at(t0, 5)), Action::Nothing, "tw {tw}");
            assert_eq!(w.tick(at(t0, 6)), Action::SendDwr, "tw {tw}");
            assert_eq!(w.silence_limit(), Duration::from_secs(18));
        }
        let mut w = Watchdog::new(Duration::from_secs(7), t0);
        assert_eq!(w.tick(at(t0, 6)), Action::Nothing);
        assert_eq!(w.tick(at(t0, 7)), Action::SendDwr);
    }

    #[test]
    fn a_tw_beyond_the_clock_never_fires() {
        let t0 = Instant::now();
        let mut w = Watchdog::new(Duration::MAX, t0);
        assert_eq!(w.tick(at(t0, 1_000_000)), Action::Nothing);
        assert_eq!(w.silence_limit(), Duration::MAX);
    }
}
