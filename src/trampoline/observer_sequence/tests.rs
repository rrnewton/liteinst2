use super::*;
use crate::scanner::InstructionScanner;
use crate::trampoline::{HookContext, TrampolinePlan};
use std::cell::Cell;

unsafe extern "C" fn observer(_: *mut HookContext) {}

fn plan() -> TrampolinePlan {
    let scan = InstructionScanner::default()
        .scan(&[0x90; 5], 0x4000)
        .unwrap();
    TrampolinePlan::from_scan(&scan, 0x4000, observer).unwrap()
}

#[test]
fn instrumentation_refusal_precedes_restore_coordinate() {
    let plan = plan();
    let state = SavedExtendedStateLayout::UNAVAILABLE;
    for recording in [false, true] {
        let visited = Cell::new(false);
        let result = encode(
            &state,
            ObservationStackProfile::Legacy128,
            recording,
            |frames| {
                plan.encode_instrumentation(0, &state, 0x4000, (Some(observer), None), None, frames)
            },
            |_| {
                visited.set(true);
                Err(TrampolineError::AddressNotRepresentable { address: u64::MAX })
            },
        );
        assert!(matches!(
            result,
            Err(TrampolineError::InvalidExtendedStateLayout {
                message: "saved-state format is unavailable",
            })
        ));
        assert!(!visited.get());
    }
}

#[test]
fn successful_instrumentation_preserves_later_coordinate_refusal() {
    let plan = plan();
    let state = SavedExtendedStateLayout::describe_target_fxsave64();
    for recording in [false, true] {
        let encoded_len = Cell::new(None);
        let visited = Cell::new(false);
        let result = encode(
            &state,
            ObservationStackProfile::Legacy128,
            recording,
            |frames| {
                let emitted = plan.encode_instrumentation(
                    0,
                    &state,
                    0x4000,
                    (Some(observer), None),
                    None,
                    frames,
                )?;
                assert!(!emitted.bytes.is_empty());
                assert!(emitted.fields.is_empty());
                encoded_len.set(Some(emitted.bytes.len()));
                Ok(emitted)
            },
            |len| {
                assert_eq!(encoded_len.get(), Some(len));
                visited.set(true);
                u64::MAX
                    .checked_add(len as u64)
                    .ok_or(TrampolineError::AddressNotRepresentable { address: u64::MAX })
            },
        );
        assert!(visited.get());
        assert!(matches!(
            result,
            Err(TrampolineError::AddressNotRepresentable { address: u64::MAX })
        ));
    }
}
