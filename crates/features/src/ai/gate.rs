/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Who may call a model right now, on this node (AI-10, AI-11, AI-24). A
//! call that can't start isn't queued: the caller carries on without the
//! model, so a slow model never backs up mail.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

/// Consecutive failures that pause a model (AI-11).
pub const FAILURES_TO_PAUSE: u32 = 5;

/// Why a call didn't start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Every slot is in use (AI-10).
    Busy,
    /// The model is paused after repeated failures (AI-11).
    Paused,
    /// The account has used its calls for the hour (AI-24).
    HourlyLimit,
    /// The account already has a call in flight (AI-24).
    OneAtATime,
}

/// What happened to a model's state, for the caller to log once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Paused,
    Resumed,
}

#[derive(Default)]
struct ModelState {
    failures: u32,
    paused_until: Option<Instant>,
    probing: bool,
}

struct AccountState {
    window_start: Instant,
    calls: u32,
    busy: bool,
}

#[derive(Default)]
struct State {
    in_flight: usize,
    models: HashMap<u64, ModelState>,
    accounts: HashMap<u32, AccountState>,
    /// Administrators asking for explanations, counted apart from their own
    /// scripts' calls (EX-15).
    explainers: HashMap<u32, AccountState>,
}

/// The node's gate.
#[derive(Default)]
pub struct Gate {
    state: Mutex<State>,
}

/// A call in flight. Dropping it frees its slot; `finish` records how it
/// went.
pub struct Permit<'x> {
    gate: &'x Gate,
    model_id: u64,
    account_id: Option<u32>,
    explain: bool,
    done: bool,
}

/// The limits the gate applies.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_concurrent: usize,
    pub backoff: Duration,
    pub account_calls_per_hour: u32,
}

impl Gate {
    /// The one gate for this process.
    pub fn global() -> &'static Gate {
        static GATE: OnceLock<Gate> = OnceLock::new();
        GATE.get_or_init(Gate::default)
    }

    /// Starts a call to `model_id`, for an account's own script when
    /// `account_id` is set.
    pub fn try_start(
        &self,
        model_id: u64,
        account_id: Option<u32>,
        limits: Limits,
    ) -> Result<Permit<'_>, Refused> {
        self.start(model_id, account_id, limits, None)
    }

    /// Starts an explanation for administrator `account_id` ("Explain
    /// this", EX-14 to EX-16). Mail comes first: it takes a slot only when
    /// one would stay free for the spam classifier, or when nothing else is
    /// in flight. It counts toward `calls_per_hour`, apart from the
    /// administrator's own scripts.
    pub fn try_start_explain(
        &self,
        model_id: u64,
        account_id: u32,
        limits: Limits,
        calls_per_hour: u32,
    ) -> Result<Permit<'_>, Refused> {
        self.start(model_id, Some(account_id), limits, Some(calls_per_hour))
    }

    fn start(
        &self,
        model_id: u64,
        account_id: Option<u32>,
        limits: Limits,
        explain_per_hour: Option<u32>,
    ) -> Result<Permit<'_>, Refused> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let model = state.models.entry(model_id).or_default();
        if let Some(until) = model.paused_until {
            if now < until || model.probing {
                return Err(Refused::Paused);
            }
            // The pause is over: one request probes the model (AI-11)
            model.probing = true;
        }
        let probing = model.probing;
        let refuse = |state: &mut State, why| {
            if probing {
                state.models.entry(model_id).or_default().probing = false;
            }
            Err(why)
        };
        let max = limits.max_concurrent.max(1);
        let full = match explain_per_hour {
            // EX-14: leave a slot for mail, unless the node is idle
            Some(_) => state.in_flight > 0 && state.in_flight + 1 >= max,
            None => state.in_flight >= max,
        };
        if full {
            return refuse(&mut state, Refused::Busy);
        }
        if let Some(account_id) = account_id {
            let (accounts, per_hour) = match explain_per_hour {
                Some(per_hour) => (&mut state.explainers, per_hour),
                None => (&mut state.accounts, limits.account_calls_per_hour),
            };
            let account = accounts.entry(account_id).or_insert(AccountState {
                window_start: now,
                calls: 0,
                busy: false,
            });
            if now.duration_since(account.window_start) >= Duration::from_secs(3600) {
                account.window_start = now;
                account.calls = 0;
            }
            if account.busy {
                return refuse(&mut state, Refused::OneAtATime);
            }
            if account.calls >= per_hour {
                return refuse(&mut state, Refused::HourlyLimit);
            }
            account.calls += 1;
            account.busy = true;
        }
        state.in_flight += 1;
        Ok(Permit {
            gate: self,
            model_id,
            account_id,
            explain: explain_per_hour.is_some(),
            done: false,
        })
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.state.lock().unwrap().in_flight
    }
}

impl Permit<'_> {
    /// Records the call's outcome. Returns a pause or resume to log once.
    pub fn finish(mut self, ok: bool, backoff: Duration) -> Option<Transition> {
        self.done = true;
        let mut state = self.gate.state.lock().unwrap();
        let model = state.models.entry(self.model_id).or_default();
        let was_paused = model.paused_until.is_some();
        model.probing = false;
        let transition = if ok {
            model.failures = 0;
            model.paused_until = None;
            was_paused.then_some(Transition::Resumed)
        } else {
            model.failures += 1;
            if was_paused || model.failures >= FAILURES_TO_PAUSE {
                model.paused_until = Some(Instant::now() + backoff);
            }
            (!was_paused && model.paused_until.is_some()).then_some(Transition::Paused)
        };
        Self::release(&mut state, self.account_id, self.explain);
        transition
    }

    fn release(state: &mut State, account_id: Option<u32>, explain: bool) {
        state.in_flight = state.in_flight.saturating_sub(1);
        let accounts = if explain {
            &mut state.explainers
        } else {
            &mut state.accounts
        };
        if let Some(account_id) = account_id
            && let Some(account) = accounts.get_mut(&account_id)
        {
            account.busy = false;
        }
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if !self.done {
            let mut state = self.gate.state.lock().unwrap();
            if let Some(model) = state.models.get_mut(&self.model_id) {
                model.probing = false;
            }
            Self::release(&mut state, self.account_id, self.explain);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits {
        max_concurrent: 1,
        backoff: Duration::from_millis(50),
        account_calls_per_hour: 2,
    };

    #[test]
    fn one_slot_no_queue() {
        let gate = Gate::default();
        let permit = gate.try_start(1, None, LIMITS).unwrap();
        assert_eq!(gate.try_start(1, None, LIMITS).err(), Some(Refused::Busy));
        drop(permit);
        assert_eq!(gate.in_flight(), 0);
        assert!(gate.try_start(1, None, LIMITS).is_ok());
    }

    #[test]
    fn pauses_after_failures_then_probes() {
        let gate = Gate::default();
        for n in 1..=FAILURES_TO_PAUSE {
            let t = gate.try_start(7, None, LIMITS).unwrap().finish(false, LIMITS.backoff);
            assert_eq!(t, (n == FAILURES_TO_PAUSE).then_some(Transition::Paused));
        }
        assert_eq!(gate.try_start(7, None, LIMITS).err(), Some(Refused::Paused));
        std::thread::sleep(Duration::from_millis(60));
        // One probe, and nobody else while it's out
        let probe = gate.try_start(7, None, Limits { max_concurrent: 4, ..LIMITS }).unwrap();
        assert_eq!(
            gate.try_start(7, None, Limits { max_concurrent: 4, ..LIMITS }).err(),
            Some(Refused::Paused)
        );
        assert_eq!(probe.finish(true, LIMITS.backoff), Some(Transition::Resumed));
        assert!(gate.try_start(7, None, LIMITS).is_ok());
    }

    #[test]
    fn account_limits() {
        let gate = Gate::default();
        let limits = Limits { max_concurrent: 4, ..LIMITS };
        let first = gate.try_start(1, Some(9), limits).unwrap();
        assert_eq!(gate.try_start(1, Some(9), limits).err(), Some(Refused::OneAtATime));
        first.finish(true, limits.backoff);
        gate.try_start(1, Some(9), limits).unwrap().finish(true, limits.backoff);
        assert_eq!(gate.try_start(1, Some(9), limits).err(), Some(Refused::HourlyLimit));
        // Other accounts and trusted scripts aren't affected
        assert!(gate.try_start(1, Some(10), limits).is_ok());
        assert!(gate.try_start(1, None, limits).is_ok());
    }

    #[test]
    fn explanations_leave_a_slot_for_mail() {
        let gate = Gate::default();
        let limits = Limits { max_concurrent: 2, ..LIMITS };
        // Idle: an explanation may start
        let explain = gate.try_start_explain(1, 9, limits, 30).unwrap();
        // Mail still gets the last slot
        let mail = gate.try_start(1, None, limits).unwrap();
        drop(explain);
        // One classification in flight, two slots: explaining would use the last
        assert_eq!(gate.try_start_explain(1, 9, limits, 30).err(), Some(Refused::Busy));
        drop(mail);
        // With one slot, an explanation runs only when the node is idle
        let one = Limits { max_concurrent: 1, ..LIMITS };
        let e = gate.try_start_explain(1, 9, one, 30).unwrap();
        assert_eq!(gate.try_start(1, None, one).err(), Some(Refused::Busy));
        drop(e);
    }

    #[test]
    fn explanations_counted_apart() {
        let gate = Gate::default();
        let limits = Limits { max_concurrent: 8, account_calls_per_hour: 1, ..LIMITS };
        for _ in 0..2 {
            gate.try_start_explain(1, 9, limits, 2).unwrap().finish(true, limits.backoff);
        }
        assert_eq!(gate.try_start_explain(1, 9, limits, 2).err(), Some(Refused::HourlyLimit));
        // The same administrator's scripts have their own count
        let script = gate.try_start(1, Some(9), limits).unwrap();
        assert_eq!(gate.in_flight(), 1);
        drop(script);
    }
}
