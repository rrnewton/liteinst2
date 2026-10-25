use super::*;

fn state() -> State {
    State {
        phase: Phase::Prepared,
        mutated: false,
        synchronizations: 0,
        held: true,
        members: 2,
        failure: None,
    }
}

fn denied() -> SyncPatchError {
    SyncPatchError::Synchronize(SyncCoreError::SystemCall {
        operation: crate::sync_core::SyncCoreOperation::Synchronize,
        errno: libc::EPERM,
    })
}

struct Model {
    bytes: [[u8; 16]; 2],
    original: [[u8; 16]; 2],
    split: bool,
    verifies: usize,
    barriers: usize,
    fail_verify: Option<usize>,
    fail_barrier: Option<usize>,
    panic_first_guard: bool,
    events: Vec<&'static str>,
    held: bool,
}

impl Model {
    fn new(split: bool) -> Self {
        let original =
            core::array::from_fn(|member| core::array::from_fn(|byte| (member * 32 + byte) as u8));
        Self {
            bytes: original,
            original,
            split,
            verifies: 0,
            barriers: 0,
            fail_verify: None,
            fail_barrier: None,
            panic_first_guard: false,
            events: Vec::new(),
            held: true,
        }
    }
    fn final_bytes(&self) -> [[u8; 16]; 2] {
        let mut out = self.original;
        for bytes in &mut out {
            let start = if self.split { 6 } else { 0 };
            bytes[start..start + 5].copy_from_slice(&[0xe9, 0x11, 0x22, 0x33, 0x44]);
        }
        out
    }
    fn observed(&self, phase: Phase) -> [[u8; 16]; 2] {
        let mut out = self.original;
        if self.split
            && matches!(
                phase,
                Phase::GuardsPublished
                    | Phase::GuardsSynchronized
                    | Phase::BacksPublished
                    | Phase::BacksSynchronized
            )
        {
            for bytes in &mut out {
                bytes[6..8].fill(0xcc);
            }
        }
        if self.split && matches!(phase, Phase::BacksPublished | Phase::BacksSynchronized) {
            for bytes in &mut out {
                bytes[8..11].copy_from_slice(&[0x22, 0x33, 0x44]);
            }
        }
        if matches!(phase, Phase::FrontsPublished | Phase::Complete) {
            out = self.final_bytes();
        }
        out
    }
}

impl Work for Model {
    fn verify(&mut self) -> Result<(), SyncPatchError> {
        self.verifies += 1;
        if self.fail_verify == Some(self.verifies) {
            return Err(PatchError::SignalHandlerInstall { errno: libc::EPERM }.into());
        }
        Ok(())
    }
    fn has_split(&self) -> bool {
        self.split
    }
    fn guards(&mut self) {
        self.events.push("all guards");
        if self.split {
            for index in 0..2 {
                self.bytes[index][6..8].fill(0xcc);
                assert!(
                    !(self.panic_first_guard && index == 0),
                    "forced unwind after first guard"
                );
            }
        }
    }
    fn backs(&mut self) {
        self.events.push("all backs");
        if self.split {
            for bytes in &mut self.bytes {
                bytes[8..11].copy_from_slice(&[0x22, 0x33, 0x44]);
            }
        }
    }
    fn fronts(&mut self) {
        self.events.push("all fronts");
        self.bytes = self.final_bytes();
    }
    fn synchronize(&mut self) -> Result<(), SyncPatchError> {
        self.events.push("sync");
        self.barriers += 1;
        if self.fail_barrier == Some(self.barriers) {
            Err(denied())
        } else {
            Ok(())
        }
    }
    fn release(&mut self, committed: bool) {
        assert!(self.held, "no double release");
        self.held = false;
        self.events.push(if committed { "commit" } else { "abort" });
    }
}

fn first_failure(state: &mut State, work: &mut Model) -> Failure {
    for _ in 0..6 {
        if let Err(failure) = state.advance(work) {
            return failure;
        }
    }
    panic!("required failure did not occur in the six publication phases");
}

#[test]
fn split_words_preserve_all_padding_and_authenticate_every_byte() {
    let old = [0x0f, 0x1f, 0x44, 0, 0, 0xb8, 42, 0];
    let new = [0xe9, 0x10, 0x20, 0x30, 0x40, 0xb8, 42, 0];
    let mut checked = 0;
    for front in 1..8 {
        let start = 8 - front;
        let mut original = [0xa5; 16];
        original[start..start + 8].copy_from_slice(&old);
        let words = [
            original[..8].try_into().unwrap(),
            original[8..].try_into().unwrap(),
        ];
        let result = split_words(front, old, new, words, words).unwrap();
        let mut final_expected = original;
        final_expected[start..start + 8].copy_from_slice(&new);
        assert_eq!([result.front, result.back].concat(), final_expected);
        let mut guard_expected = original;
        guard_expected[start..8].fill(0xcc);
        assert_eq!([result.guard, words[1]].concat(), guard_expected);
        for byte in 0..16 {
            let mut changed = words;
            changed[byte / 8][byte % 8] ^= 1;
            assert!(matches!(
                split_words(front, old, new, words, changed),
                Err(SyncPatchError::Patch(PatchError::ExpectedBytesMismatch))
            ));
            checked += 1;
        }
    }
    assert_eq!(checked, 112);
}

#[test]
fn two_member_phases_have_exact_bytes_and_only_three_shared_barriers() {
    let mut state = state();
    let mut work = Model::new(true);
    let phases = [
        Phase::GuardsPublished,
        Phase::GuardsSynchronized,
        Phase::BacksPublished,
        Phase::BacksSynchronized,
        Phase::FrontsPublished,
        Phase::Complete,
    ];
    for (index, phase) in phases.into_iter().enumerate() {
        let receipt = state.advance(&mut work).unwrap();
        assert_eq!(receipt.phase, phase);
        assert_eq!(receipt.members, 2);
        assert_eq!(receipt.synchronizations, index.div_ceil(2));
        assert_eq!(receipt.failure, None);
        assert!(receipt.mutated);
        assert_eq!(receipt.writer_ownership_retained, phase != Phase::Complete);
        assert_eq!(work.bytes, work.observed(phase));
    }
    assert_eq!(
        work.events,
        [
            "all guards",
            "sync",
            "all backs",
            "sync",
            "all fronts",
            "sync",
            "commit"
        ]
    );
    let events = work.events.clone();
    assert_eq!(state.advance(&mut work).unwrap().phase, Phase::Complete);
    state.abandon(&mut work);
    assert_eq!(work.events, events);
}

#[test]
fn every_barrier_failure_is_terminal_and_retains_exact_incomplete_bytes() {
    for (barrier, phase) in [
        (1, Phase::GuardsPublished),
        (2, Phase::BacksPublished),
        (3, Phase::FrontsPublished),
    ] {
        let mut state = state();
        let mut work = Model::new(true);
        work.fail_barrier = Some(barrier);
        let failure = first_failure(&mut state, &mut work);
        assert_eq!(failure.error, denied());
        assert_eq!(failure.receipt.phase, phase);
        assert_eq!(failure.receipt.failure, Some(denied()));
        assert_eq!(failure.receipt.synchronizations, barrier - 1);
        assert!(failure.receipt.writer_ownership_retained && failure.receipt.mutated);
        assert_eq!(work.bytes, work.observed(phase));
        let events = work.events.clone();
        let bytes = work.bytes;
        work.fail_barrier = None; // Removing the cause never authorizes implicit recovery.
        assert_eq!(state.advance(&mut work).unwrap_err(), failure);
        state.abandon(&mut work);
        assert!(work.held);
        assert_eq!(work.events, events);
        assert_eq!(work.bytes, bytes);
    }
}

#[test]
fn every_route_verification_failure_keeps_the_correct_store_boundary() {
    let phases = [
        Phase::Aborted,
        Phase::GuardsPublished,
        Phase::GuardsSynchronized,
        Phase::BacksPublished,
        Phase::BacksSynchronized,
        Phase::FrontsPublished,
    ];
    for (index, phase) in phases.into_iter().enumerate() {
        let mut state = state();
        let mut work = Model::new(true);
        work.fail_verify = Some(index + 1);
        let failure = first_failure(&mut state, &mut work);
        assert_eq!(failure.receipt.phase, phase);
        assert_eq!(failure.receipt.mutated, index != 0);
        assert_eq!(failure.receipt.writer_ownership_retained, index != 0);
        assert_eq!(work.held, index != 0);
        assert_eq!(work.bytes, work.observed(phase));
        let events = work.events.clone();
        work.fail_verify = None;
        assert_eq!(state.advance(&mut work).unwrap_err(), failure);
        state.abandon(&mut work);
        assert_eq!(work.events, events);
    }
}

#[test]
fn atomic_members_have_no_mutation_until_front_publication() {
    for barrier in 1..=3 {
        let mut state = state();
        let mut work = Model::new(false);
        work.fail_barrier = Some(barrier);
        let failure = first_failure(&mut state, &mut work);
        assert_eq!(failure.receipt.mutated, barrier == 3);
        assert_eq!(failure.receipt.writer_ownership_retained, barrier == 3);
        assert_eq!(
            failure.receipt.phase,
            if barrier == 3 {
                Phase::FrontsPublished
            } else {
                Phase::Aborted
            }
        );
        assert_eq!(
            work.bytes,
            if barrier == 3 {
                work.final_bytes()
            } else {
                work.original
            }
        );
        assert_eq!(
            work.events.iter().filter(|&&e| e == "abort").count(),
            usize::from(barrier != 3)
        );
    }
}

#[test]
fn dropping_at_every_incomplete_phase_never_unlocks_mutated_members() {
    for steps in 0..6 {
        let mut state = state();
        let mut work = Model::new(true);
        for _ in 0..steps {
            state.advance(&mut work).unwrap();
        }
        let bytes = work.bytes;
        state.abandon(&mut work);
        assert_eq!(work.held, steps != 0);
        assert_eq!(state.held, steps != 0);
        assert_eq!(work.bytes, bytes);
        assert_eq!(
            work.events.iter().filter(|&&e| e == "abort").count(),
            usize::from(steps == 0)
        );
    }
}

#[test]
fn unwind_after_first_store_keeps_all_leases_and_cannot_retry() {
    let mut state = state();
    let mut work = Model::new(true);
    work.panic_first_guard = true;
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.advance(&mut work)));
    assert!(result.is_err());
    assert!(state.mutated && state.held);
    assert_eq!(state.failure, Some(SyncPatchError::IncompleteOperation));
    assert_eq!(work.bytes[0][6..8], [0xcc, 0xcc]);
    assert_eq!(work.bytes[1], work.original[1]);
    let events = work.events.clone();
    state.abandon(&mut work);
    assert!(work.held);
    assert_eq!(
        state.advance(&mut work).unwrap_err().error,
        SyncPatchError::IncompleteOperation
    );
    assert_eq!(work.events, events);
}

#[test]
fn envelope_validation_rejects_duplicates_overlap_empty_and_wrapped_extents() {
    assert!(disjoint(&[(8, 16), (16, 24)]).is_ok());
    for ranges in [
        vec![(8, 16), (8, 16)],
        vec![(8, 24), (16, 32)],
        vec![(8, 8)],
        vec![(usize::MAX, 0)],
        vec![(16, 24), (8, 16)],
    ] {
        assert_eq!(disjoint(&ranges), Err(SyncPatchError::OverlappingMembers));
    }
}
