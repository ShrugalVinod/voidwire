//! Iron Dome deterministic finite state machine (see ARCHITECTURE.md §2).

use serde::{Deserialize, Serialize};

use crate::error::{Result, VwError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DomeState {
    Disarmed,
    ArmingBootLock,
    Handshaking,
    CanaryAuditing,
    TunnelActive,
    KeyRotating,
    FailsafeLockdown,
    Disarming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DomeEvent {
    Arm,
    LockEngaged,
    HandshakeComplete,
    HandshakeFailed,
    CanaryPassed,
    CanaryFailed,
    RotationDue,
    Panic,
    RotationComplete,
    RotationFailed,
    Fault,
    LinkLost,
    Retry,
    DownKeepLockdown,
    Disarm,
    LockReleased,
}

impl DomeState {
    /// User traffic may flow through the tunnel.
    pub const fn traffic_allowed(self) -> bool {
        matches!(self, DomeState::TunnelActive | DomeState::KeyRotating)
    }

    /// The host firewall must be in lockdown (everything but `Disarmed`).
    pub const fn firewall_locked(self) -> bool {
        !matches!(self, DomeState::Disarmed)
    }

    /// Pure transition function. Invalid pairs are rejected without side effects.
    pub fn next(self, event: DomeEvent) -> Result<DomeState> {
        use DomeEvent as E;
        use DomeState as S;
        let to = match (self, event) {
            (S::Disarmed, E::Arm) => S::ArmingBootLock,
            (S::ArmingBootLock, E::LockEngaged) => S::Handshaking,
            (S::Handshaking, E::HandshakeComplete) => S::CanaryAuditing,
            (S::CanaryAuditing, E::CanaryPassed) => S::TunnelActive,
            (S::TunnelActive, E::RotationDue | E::Panic) => S::KeyRotating,
            (S::KeyRotating, E::RotationComplete) => S::TunnelActive,
            (S::Handshaking, E::HandshakeFailed | E::Fault | E::LinkLost) => S::FailsafeLockdown,
            (S::CanaryAuditing, E::CanaryFailed | E::Fault | E::LinkLost) => S::FailsafeLockdown,
            (S::TunnelActive, E::Fault | E::LinkLost | E::DownKeepLockdown) => S::FailsafeLockdown,
            (S::KeyRotating, E::RotationFailed | E::Fault | E::LinkLost | E::DownKeepLockdown) => {
                S::FailsafeLockdown
            }
            (S::ArmingBootLock, E::Fault) => S::FailsafeLockdown,
            (S::FailsafeLockdown, E::Retry) => S::Handshaking,
            (S::FailsafeLockdown, E::Panic) => S::Handshaking,
            (
                S::ArmingBootLock
                | S::Handshaking
                | S::CanaryAuditing
                | S::TunnelActive
                | S::KeyRotating
                | S::FailsafeLockdown,
                E::Disarm,
            ) => S::Disarming,
            (S::Disarming, E::LockReleased) => S::Disarmed,
            // Faults while already locked down or idle are absorbed.
            (S::FailsafeLockdown, E::Fault | E::LinkLost) => S::FailsafeLockdown,
            (S::Disarmed, E::Fault | E::LinkLost) => S::Disarmed,
            (from, event) => return Err(VwError::InvalidTransition { from, event }),
        };
        Ok(to)
    }
}

/// A state machine instance with an audit trail kept in RAM only.
#[derive(Debug, Clone)]
pub struct IronDome {
    state: DomeState,
    history: Vec<(DomeState, DomeEvent, DomeState)>,
}

impl Default for IronDome {
    fn default() -> Self {
        Self::new()
    }
}

impl IronDome {
    const HISTORY_CAP: usize = 256;

    pub fn new() -> Self {
        Self {
            state: DomeState::Disarmed,
            history: Vec::new(),
        }
    }

    pub fn state(&self) -> DomeState {
        self.state
    }

    pub fn fire(&mut self, ev: DomeEvent) -> Result<DomeState> {
        let to = self.state.next(ev)?;
        if self.history.len() == Self::HISTORY_CAP {
            self.history.remove(0);
        }
        self.history.push((self.state, ev, to));
        self.state = to;
        Ok(to)
    }

    pub fn history(&self) -> &[(DomeState, DomeEvent, DomeState)] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use DomeEvent as E;
    use DomeState as S;

    const ALL_STATES: [S; 8] = [
        S::Disarmed,
        S::ArmingBootLock,
        S::Handshaking,
        S::CanaryAuditing,
        S::TunnelActive,
        S::KeyRotating,
        S::FailsafeLockdown,
        S::Disarming,
    ];
    const ALL_EVENTS: [E; 16] = [
        E::Arm,
        E::LockEngaged,
        E::HandshakeComplete,
        E::HandshakeFailed,
        E::CanaryPassed,
        E::CanaryFailed,
        E::RotationDue,
        E::Panic,
        E::RotationComplete,
        E::RotationFailed,
        E::Fault,
        E::LinkLost,
        E::Retry,
        E::DownKeepLockdown,
        E::Disarm,
        E::LockReleased,
    ];

    #[test]
    fn happy_path() {
        let mut d = IronDome::new();
        for e in [
            E::Arm,
            E::LockEngaged,
            E::HandshakeComplete,
            E::CanaryPassed,
        ] {
            d.fire(e).unwrap();
        }
        assert_eq!(d.state(), S::TunnelActive);
        assert!(d.state().traffic_allowed());
        d.fire(E::RotationDue).unwrap();
        d.fire(E::RotationComplete).unwrap();
        d.fire(E::Disarm).unwrap();
        d.fire(E::LockReleased).unwrap();
        assert_eq!(d.state(), S::Disarmed);
    }

    #[test]
    fn no_traffic_before_canary() {
        let mut d = IronDome::new();
        d.fire(E::Arm).unwrap();
        d.fire(E::LockEngaged).unwrap();
        d.fire(E::HandshakeComplete).unwrap();
        assert!(!d.state().traffic_allowed());
        assert!(d.fire(E::RotationDue).is_err());
        d.fire(E::CanaryFailed).unwrap();
        assert_eq!(d.state(), S::FailsafeLockdown);
        assert!(d.state().firewall_locked());
    }

    /// Exhaustive property: the only way to reach `Disarmed` from any locked
    /// state is via Disarm → LockReleased, and traffic is never allowed unless
    /// the previous state was CanaryAuditing, TunnelActive or KeyRotating.
    #[test]
    fn exhaustive_safety() {
        for s in ALL_STATES {
            for e in ALL_EVENTS {
                if let Ok(to) = s.next(e) {
                    if s != S::Disarmed && to == S::Disarmed {
                        assert_eq!((s, e), (S::Disarming, E::LockReleased));
                    }
                    if to.traffic_allowed() {
                        assert!(
                            matches!(s, S::CanaryAuditing | S::TunnelActive | S::KeyRotating),
                            "{s:?} --{e:?}--> {to:?}"
                        );
                    }
                    if to == S::TunnelActive && s == S::CanaryAuditing {
                        assert_eq!(e, E::CanaryPassed);
                    }
                }
            }
        }
    }

    #[test]
    fn invalid_transition_keeps_state() {
        let mut d = IronDome::new();
        assert!(d.fire(E::CanaryPassed).is_err());
        assert_eq!(d.state(), S::Disarmed);
        assert!(d.history().is_empty());
    }
}
