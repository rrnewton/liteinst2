//! Exact caller opt-in shared by structural and native core consumers.
//! This module grants no product, owner, router or execution authority.
use std::ffi::OsString;

pub(crate) const MARKER: &str = "planning-profile.tsv";
pub(crate) const MARKER_BYTES: &[u8] =
    b"LI2PLANNING\t1\nprofile\towned-foreign-neighbors-v1\nqualification_complete\tfalse\n";
const ARGUMENT: &str = "--planning-profile=owned-foreign-neighbors-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlanningProfile {
    Legacy,
    OwnedForeignNeighbors,
}
impl PlanningProfile {
    /// Consume only the new final argument. Old arity/coordinate checks remain
    /// in each caller; an unexpected extra argument cannot select a profile.
    pub(crate) fn arguments(args: &mut Vec<OsString>, legacy_len: usize) -> Self {
        if args.len() == legacy_len + 1 {
            assert_eq!(args.pop().unwrap(), ARGUMENT);
            Self::OwnedForeignNeighbors
        } else {
            Self::Legacy
        }
    }
    pub(crate) fn marker(self, actual: Option<&[u8]>) {
        match self {
            Self::Legacy => assert!(actual.is_none(), "legacy marker must be absent"),
            Self::OwnedForeignNeighbors => assert_eq!(actual, Some(MARKER_BYTES)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_caller_profile_and_whole_marker_must_agree() {
        let mut legacy = vec![OsString::from("program"); 7];
        assert_eq!(
            PlanningProfile::arguments(&mut legacy, 7),
            PlanningProfile::Legacy
        );
        PlanningProfile::Legacy.marker(None);
        legacy.push(ARGUMENT.into());
        assert_eq!(
            PlanningProfile::arguments(&mut legacy, 7),
            PlanningProfile::OwnedForeignNeighbors
        );
        assert_eq!(legacy.len(), 7);
        PlanningProfile::OwnedForeignNeighbors.marker(Some(MARKER_BYTES));
        assert!(
            std::panic::catch_unwind(|| PlanningProfile::Legacy.marker(Some(MARKER_BYTES)))
                .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| PlanningProfile::OwnedForeignNeighbors.marker(None))
                .is_err()
        );
        for bytes in [
            b"".as_slice(),
            &MARKER_BYTES[..MARKER_BYTES.len() - 1],
            b"LI2PLANNING\t2\nprofile\towned-foreign-neighbors-v1\nqualification_complete\tfalse\n",
            b"LI2PLANNING\t1\nprofile\towned-foreign-neighbors-v1\nqualification_complete\ttrue\n",
        ] {
            assert!(
                std::panic::catch_unwind(
                    || PlanningProfile::OwnedForeignNeighbors.marker(Some(bytes))
                )
                .is_err()
            );
        }
        let mut bad = vec![OsString::from("program"); 7];
        bad.push("--planning-profile=unknown".into());
        assert!(std::panic::catch_unwind(move || PlanningProfile::arguments(&mut bad, 7)).is_err());
    }
}
