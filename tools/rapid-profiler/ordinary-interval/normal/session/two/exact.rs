//! Two closed consumer subjects; this is not another SDK or executable profile.
//! Exact37 work truth is independent of the installed scanner/maps. Raw callback
//! endpoints remain uncalibrated observations, not instruction costs or duration truth.
use super::{Command, LABEL, protocol};
use crate::exact::truth;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Subject {
    Strnlen41,
    Exact37,
}
impl Subject {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Strnlen41 => LABEL,
            Self::Exact37 => "normal-exact-37-v1",
        }
    }
    pub(super) fn accept(self, ids: &mut protocol::Ids, request: &Command) -> Result<(), String> {
        // Domain refusal precedes the existing ID mutation and ledger reservation.
        if self == Self::Exact37 {
            command(request).map_err(str::to_string)?;
        }
        ids.accept(request).map_err(str::to_string)
    }
    pub(super) fn output_bound(self, calls: usize, flushes: usize, arms: u32) -> usize {
        // Keep every old capacity/overflow guard and the old proof unchanged.
        let old = super::output_bound(calls, flushes, arms);
        match self {
            Self::Strnlen41 => old,
            // Only RESULT.value changes: <=4096's4 decimal digits to u64's20.
            // RESULT211 + SAMPLE136; the new READY is shorter than the old one.
            Self::Exact37 => old.checked_add(16 * calls).unwrap(),
        }
    }
}
pub(super) fn extent(length: u64) {
    assert_eq!(length, 37, "exact37 extent, not arbitrary discovery");
}
pub(super) fn geometry(
    entry: u64,
    range: (u64, u64),
    code: &[u8],
    heads: &[u64],
    actual_returns: &BTreeSet<u64>,
) {
    truth::check_bytes(code).unwrap();
    assert_eq!(range, (entry, entry.checked_add(37).unwrap()));
    let expected = truth::HEADS.map(|offset| entry.checked_add(u64::from(offset)).unwrap());
    assert_eq!(heads, expected.as_slice());
    returns(entry, actual_returns);
}
pub(super) fn returns(entry: u64, actual: &BTreeSet<u64>) {
    assert_eq!(actual, &BTreeSet::from([entry.checked_add(36).unwrap()]));
}
pub(super) fn return_pc(entry: u64, actual: u64) {
    assert_eq!(actual, entry.checked_add(36).unwrap());
}
pub(super) fn request(bytes: &[u8], bound: usize) -> Result<(), &'static str> {
    if !matches!(bytes.len(), 1 | 64) || bound != bytes.len() {
        return Err("exact37 requires bound=length and length1or64");
    }
    Ok(())
}
pub(super) fn command(command: &Command) -> Result<(), &'static str> {
    if let Command::Call { bound, bytes, .. } = command {
        request(bytes, *bound)?;
    }
    Ok(())
}
pub(super) fn value(actual: u64, bytes: &[u8], bound: usize) {
    request(bytes, bound).unwrap();
    assert_eq!(actual, truth::checksum(bytes).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    fn refused(f: impl FnOnce()) {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err());
    }
    fn heads(entry: u64) -> Vec<u64> {
        truth::HEADS.iter().map(|&n| entry + u64::from(n)).collect()
    }
    #[test]
    fn exact_subject_authenticates_every_byte_head_extent_and_return() {
        let entry = 0x1000;
        let expected_heads = heads(entry);
        let expected_returns = BTreeSet::from([entry + 36]);
        geometry(
            entry,
            (entry, entry + 37),
            &truth::BYTES,
            &expected_heads,
            &expected_returns,
        );
        for i in 0..truth::BYTES.len() {
            for bit in 0..8 {
                let mut code = truth::BYTES;
                code[i] ^= 1 << bit;
                refused(|| {
                    geometry(
                        entry,
                        (entry, entry + 37),
                        &code,
                        &expected_heads,
                        &expected_returns,
                    )
                });
            }
        }
        refused(|| {
            geometry(
                entry,
                (entry, entry + 37),
                &truth::BYTES[..36],
                &expected_heads,
                &expected_returns,
            )
        });
        for range in [
            (entry + 1, entry + 37),
            (entry, entry + 36),
            (entry, entry + 38),
        ] {
            refused(|| {
                geometry(
                    entry,
                    range,
                    &truth::BYTES,
                    &expected_heads,
                    &expected_returns,
                )
            });
        }
        for i in 0..expected_heads.len() {
            let mut wrong = expected_heads.clone();
            wrong[i] += 1;
            refused(|| {
                geometry(
                    entry,
                    (entry, entry + 37),
                    &truth::BYTES,
                    &wrong,
                    &expected_returns,
                )
            });
        }
        let mut reversed = expected_heads.clone();
        reversed.swap(1, 2);
        refused(|| {
            geometry(
                entry,
                (entry, entry + 37),
                &truth::BYTES,
                &reversed,
                &expected_returns,
            )
        });
        refused(|| {
            geometry(
                entry,
                (entry, entry + 37),
                &truth::BYTES,
                &expected_heads[..10],
                &expected_returns,
            )
        });
        for wrong in [
            BTreeSet::new(),
            BTreeSet::from([entry + 34, entry + 40]),
            BTreeSet::from([entry + 36, entry + 40]),
        ] {
            refused(|| {
                geometry(
                    entry,
                    (entry, entry + 37),
                    &truth::BYTES,
                    &expected_heads,
                    &wrong,
                )
            });
        }
    }
    #[test]
    fn exact_domain_refusal_precedes_actual_shared_id_acceptance() {
        let id = u64::MAX;
        let mut ids = protocol::Ids::default();
        for (length, bound) in [(0, 0), (2, 2), (63, 63), (65, 65), (64, 1), (1, 0), (1, 2)] {
            let bad = Command::Call {
                id,
                bound,
                bytes: vec![0; length],
            };
            assert!(Subject::Exact37.accept(&mut ids, &bad).is_err());
            assert_eq!(ids.len(), 0);
        }
        let good = protocol::parse(b"CALL 18446744073709551615 1 ff").unwrap();
        Subject::Exact37.accept(&mut ids, &good).unwrap();
        assert_eq!(ids.len(), 1);
        assert!(
            Subject::Exact37
                .accept(&mut ids, &Command::Flush { id })
                .is_err()
        );
        Subject::Exact37
            .accept(&mut ids, &Command::Flush { id: 7 })
            .unwrap();
        Subject::Exact37.accept(&mut ids, &Command::Stop).unwrap();
        assert_eq!(ids.len(), 2);
        let mut old = protocol::Ids::default();
        for (id, text) in [b"CALL 1 0 -".as_slice(), b"CALL 2 1 0000", b"CALL 3 0 ff"]
            .into_iter()
            .enumerate()
        {
            Subject::Strnlen41
                .accept(&mut old, &protocol::parse(text).unwrap())
                .unwrap();
            assert_eq!(old.len(), id + 1);
        }
    }
    #[test]
    fn exact_value_validator_checks_the_complete_input_and_full_u64_result() {
        // Independent fixed scalar constants, not values produced by the helper under test.
        for (bytes, expected) in [
            (vec![0], 0x9e37_79b9_7f4a_7c4f),
            (vec![0xff], 0x9e37_79b9_7f4a_7cb0),
            (vec![0; 64], 0x9e37_79b9_7f4a_6a95),
        ] {
            value(expected, &bytes, bytes.len());
            assert_eq!(expected.to_string().len(), 20);
            refused(|| value(expected ^ 1, &bytes, bytes.len()));
            let mut changed = bytes.clone();
            changed[0] ^= 1;
            refused(|| value(expected, &changed, changed.len()));
            refused(|| value(expected, &bytes, bytes.len() - 1));
        }
        refused(|| value(0, &[], 0));
        refused(|| value(0, &[0; 2], 2));
        refused(|| value(0, &[0; 65], 65));
    }
    #[test]
    fn exact_return_validator_refuses_other_exits_and_address_overflow() {
        for entry in [0, 0x1000, u64::MAX - 36] {
            returns(entry, &BTreeSet::from([entry + 36]));
            return_pc(entry, entry + 36);
            for offset in [0, 34, 35] {
                refused(|| return_pc(entry, entry + offset));
                refused(|| returns(entry, &BTreeSet::from([entry + offset])));
            }
        }
        for wrong in [0x1022, 0x1028, 0x1025] {
            refused(|| return_pc(0x1000, wrong));
        }
        refused(|| return_pc(u64::MAX - 35, 0));
        refused(|| returns(u64::MAX - 35, &BTreeSet::from([0])));
    }
    #[test]
    fn exact_metadata_keeps_fixed_selection_labels_and_extents_distinct() {
        assert_eq!(Subject::Strnlen41.label(), "freebsd-strnlen-14.1-v1");
        assert_eq!(Subject::Exact37.label(), "normal-exact-37-v1");
        assert_ne!(Subject::Strnlen41, Subject::Exact37);
        extent(37);
        for wrong in [0, 1, 36, 38, 41, 80, u64::MAX] {
            refused(|| extent(wrong));
        }
    }
    #[test]
    fn exact_output_envelope_preserves_legacy_and_all_capacity_refusals() {
        assert_eq!(Subject::Strnlen41.output_bound(4096, 0, 4096), 1_749_369);
        let maximum = Subject::Exact37.output_bound(4096, 0, 4096);
        assert_eq!(maximum, 1_814_905);
        assert!(maximum < 4 * 1024 * 1024);
        for calls in 0..=4096 {
            let flushes = 4096 - calls;
            assert!(Subject::Exact37.output_bound(calls, flushes, 4096) <= 1_814_905);
            assert_eq!(
                Subject::Strnlen41.output_bound(calls, flushes, 4096),
                super::super::output_bound(calls, flushes, 4096)
            );
        }
        for subject in [Subject::Strnlen41, Subject::Exact37] {
            for (calls, flushes, arms) in [
                (4096, 1, 4096),
                (0, 4097, 1),
                (0, 0, 4097),
                (usize::MAX, 1, 1),
            ] {
                refused(|| {
                    subject.output_bound(calls, flushes, arms);
                });
            }
        }
    }
}
