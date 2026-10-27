//! Explicit controlled-test router contract, shared by the two consumers.
//! No loader, live publication, signal installation or hash authority is granted.
use std::ffi::OsString;

pub(crate) const PROFILE: &str = "linux-x86-64-private-altstack-v1";
const ARGUMENT: &str = "--entry-router=linux-x86-64-private-altstack-v1";
// Literal planner legacy-64 ISA envelope; D4/D5 are deliberately excluded.
const ILLEGAL: [u8; 14] = [
    0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouterMode {
    Absent,
    PrivateAltstack,
}
impl RouterMode {
    pub(crate) fn arguments(args: &mut Vec<OsString>) -> Self {
        if args.last().is_some_and(|s| s == ARGUMENT) {
            args.pop();
            Self::PrivateAltstack
        } else {
            Self::Absent
        }
    }
    pub(crate) fn enabled(self) -> bool {
        self == Self::PrivateAltstack
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Route {
    pub pc: u64,
    pub target: u64,
    pub source_start: u64,
    pub source_end: u64,
    pub fetch: Vec<u8>,
}
impl Route {
    pub(crate) fn check(&self) {
        assert!(self.source_start <= self.pc && self.pc < self.source_end);
        assert!(self.target != 0 && self.pc != self.target);
        assert!(!self.fetch.is_empty());
        if self.fetch[0] == 0x62 {
            // Same complete instruction-fetch envelope as quiescent B1. This
            // is invalid EVEX P1, not an assumption that every 62 is illegal.
            assert_eq!(self.fetch.len(), 15);
            assert!(self.pc % 4096 <= 4096 - 15);
            assert!(self.pc.checked_add(15).unwrap() <= self.source_end);
            assert_eq!(self.fetch[2] & 4, 0);
        } else {
            assert_eq!(self.fetch.len(), 1);
            assert!(ILLEGAL.contains(&self.fetch[0]));
        }
    }
}

pub(crate) fn check_routes(routes: &[Route]) {
    assert!(routes.len() <= 87);
    for route in routes {
        route.check();
    }
    assert!(routes.windows(2).all(|w| w[0].pc < w[1].pc));
}

#[cfg(test)]
mod tests {
    use super::*;
    fn route() -> Route {
        Route {
            pc: 0x401104,
            target: 0x501000,
            source_start: 0x401100,
            source_end: 0x401140,
            fetch: vec![0x06],
        }
    }
    #[test]
    fn exact_legacy_and_invalid_evex_markers() {
        for byte in ILLEGAL {
            let mut r = route();
            r.fetch = vec![byte];
            r.check();
        }
        let mut r = route();
        r.fetch = vec![0; 15];
        r.fetch[0] = 0x62;
        r.check();
        for byte in [0x90, 0xc3, 0xd4, 0xd5, 0xe9] {
            let mut bad = route();
            bad.fetch = vec![byte];
            assert!(std::panic::catch_unwind(|| bad.check()).is_err());
        }
        let mut bad = r.clone();
        bad.fetch[2] = 4;
        assert!(std::panic::catch_unwind(|| bad.check()).is_err());
        let mut bad = r.clone();
        bad.fetch.pop();
        assert!(std::panic::catch_unwind(|| bad.check()).is_err());
        let mut bad = r.clone();
        bad.source_end = bad.pc + 14;
        assert!(std::panic::catch_unwind(|| bad.check()).is_err());
        let mut bad = r;
        bad.pc = 0x401fff;
        bad.source_end = 0x402100;
        assert!(std::panic::catch_unwind(|| bad.check()).is_err());
    }
    #[test]
    fn route_identity_and_explicit_opt_in() {
        let r = route();
        check_routes(std::slice::from_ref(&r));
        assert!(std::panic::catch_unwind(|| check_routes(&[r.clone(), r.clone()])).is_err());
        let mut bad = r;
        bad.target = bad.pc;
        assert!(std::panic::catch_unwind(|| bad.check()).is_err());
        let mut args = vec![OsString::from("driver")];
        assert_eq!(RouterMode::arguments(&mut args), RouterMode::Absent);
        args.push(ARGUMENT.into());
        assert_eq!(
            RouterMode::arguments(&mut args),
            RouterMode::PrivateAltstack
        );
        assert_eq!(args.len(), 1);
        args.push("--entry-router=unknown".into());
        assert_eq!(RouterMode::arguments(&mut args), RouterMode::Absent);
        assert_eq!(args.len(), 2); // Existing caller arity refuses this argument.
    }
}
