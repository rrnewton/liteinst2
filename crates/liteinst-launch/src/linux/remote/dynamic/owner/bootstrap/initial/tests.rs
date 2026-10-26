//! Pure synthetic geometry/storage controls only; no native bootstrap credit.
use super::*;

const ORIGINAL: &[u8] = b"00400000-00402000 r-xp 00001000 08:02 17    /fixture/a  b  \n00600000-00601000 rw-p 00000000 00:00 0\nffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n";
const FINAL: &[u8] = b"00400000-00402000 r--p 00001000 08:02 17    /fixture/a  b  \n00600000-00601000 rw-p 00000000 00:00 0\n00800000-00801000 r-xp 00000000 00:00 0\nffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n";

fn invalid<T>(result: Result<T, LaunchError>, reason: &'static str) {
    assert!(matches!(result, Err(LaunchError::Invalid(actual)) if actual == reason));
}
fn changed(source: &[u8], old: &str, new: &str) -> Vec<u8> {
    let source = std::str::from_utf8(source).unwrap();
    assert_eq!(source.matches(old).count(), 1);
    source.replace(old, new).into_bytes()
}

#[test]
fn initial_bootstrap_shape_retains_full_paths_and_exact_executable_profile() {
    let shape = InitialBootstrapShape::from_original(ORIGINAL).unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    let prepared = PreparedInitialBootstrap::allocate(shape.clone(), ORIGINAL, until).unwrap();
    assert_eq!(prepared.originals.len(), 1);
    assert_eq!(
        prepared.originals[0].pathname.as_deref(),
        Some("/fixture/a  b  ")
    );
    assert_eq!(prepared.mappings.len(), 3);
    assert_eq!(prepared.mappings[2].pathname.as_deref(), Some("[vsyscall]"));
    assert_eq!(prepared.until, until);
    assert!(prepared.allocated_bytes().unwrap() <= shape.reservation_bytes().unwrap());
    assert!(prepared.completed().is_none());
    prepared.validate_plan(ORIGINAL).unwrap();
    for permissions in ["rwxp", "r-xs"] {
        invalid(
            InitialBootstrapShape::from_original(&changed(ORIGINAL, "r-xp", permissions)),
            "bootstrap requires aligned private immutable executable mappings",
        );
    }
    assert!(
        InitialBootstrapShape::from_original(&changed(ORIGINAL, "00402000", "00402001")).is_err()
    );
    assert!(InitialBootstrapShape::from_original(&ORIGINAL[..ORIGINAL.len() - 1]).is_err());
    let boundary = b"00400000-04400000 r-xp 0 00:00 0\n";
    InitialBootstrapShape::from_original(boundary).unwrap();
    invalid(
        InitialBootstrapShape::from_original(&changed(boundary, "04400000", "04401000")),
        "bootstrap executable inventory exceeds bound",
    );
    let mut rows = String::new();
    for index in 0..64 {
        let start = 0x400000 + index * 2 * PAGE;
        rows.push_str(&format!(
            "{start:08x}-{:08x} r-xp 0 00:00 0\n",
            start + PAGE
        ));
    }
    InitialBootstrapShape::from_original(rows.as_bytes()).unwrap();
    rows.push_str("00800000-00801000 r-xp 0 00:00 0\n");
    invalid(
        InitialBootstrapShape::from_original(rows.as_bytes()),
        "bootstrap executable inventory exceeds bound",
    );
}

#[test]
fn initial_bootstrap_capacity_counts_six_max_states_three_maps_and_descriptors() {
    let shape = InitialBootstrapShape::from_original(ORIGINAL).unwrap();
    let descriptor_count = 1 + 3 + 1;
    let paths = 2 * "/fixture/a  b  ".len() + "[vsyscall]".len();
    assert_eq!(
        shape.reservation_bytes().unwrap(),
        size_of::<PreparedInitialBootstrap>()
            + 6 * MAX_XSTATE
            + 3 * MAP_BYTES
            + descriptor_count * (size_of::<MemoryMapping>() + 4)
            + paths
    );
    let bound = shape.reservation_bytes().unwrap();
    storage::require_capacity(bound, bound).unwrap();
    storage::require_capacity(bound - 1, bound).unwrap();
    invalid(
        storage::require_capacity(bound + 1, bound),
        "initial bootstrap allocation exceeds reservation",
    );
    assert!(storage::add(usize::MAX, 1).is_err());
    let prepared = PreparedInitialBootstrap::allocate(
        shape,
        ORIGINAL,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    for slot in &prepared.states {
        assert_eq!(slot.state.xstate.len(), MAX_XSTATE);
        assert!(slot.state.xstate.iter().all(|byte| *byte == 0));
    }
    assert_eq!(prepared.diagnostics().exit_maps.bytes(), []);
    assert_eq!(prepared.diagnostics().current_maps.bytes(), []);
}

#[test]
fn initial_bootstrap_effect_capacity_keeps_every_attempt_and_first_failure() {
    let mut progress = InitialBootstrapProgress {
        phase: InitialBootstrapPhase::Quarantine,
        ..InitialBootstrapProgress::default()
    };
    for index in 0..EFFECTS {
        let effect = InitialBootstrapEffect::Bootstrap(BootstrapEffect::Quarantine {
            start: (index * PAGE) as u64,
            length: PAGE,
        });
        progress.begin(effect).unwrap();
        assert!(!progress.effects()[index].unwrap().complete);
        progress.finish(effect, Some(index as u64)).unwrap();
    }
    let before = progress.effects().to_vec();
    invalid(
        progress.begin(InitialBootstrapEffect::OriginalExecResume),
        "initial bootstrap effect storage or ordering differs",
    );
    assert_eq!(progress.effects(), before);
    progress.exec_wait = Some((7, 0x857f));
    progress.fail(Some(&LaunchError::Timeout("original deadline")));
    let first = progress.first_failure;
    progress.fail(Some(&LaunchError::Invalid("later failure")));
    progress.fail(None);
    assert_eq!(progress.first_failure, first);
    assert_eq!(progress.exec_wait, Some((7, 0x857f)));
    assert_eq!(progress.effects(), before);
    assert_eq!(
        first.unwrap().kind,
        InitialBootstrapFailureKind::Timeout("original deadline")
    );
}

#[test]
fn initial_bootstrap_progress_never_completes_an_unattempted_or_failed_effect() {
    let effect = InitialBootstrapEffect::Bootstrap(BootstrapEffect::PatchEntry);
    let mut progress = InitialBootstrapProgress::default();
    invalid(
        progress.finish(effect, None),
        "initial bootstrap effect was not attempted",
    );
    progress.begin(effect).unwrap();
    invalid(
        progress.begin(InitialBootstrapEffect::OriginalExecResume),
        "initial bootstrap effect storage or ordering differs",
    );
    invalid(
        progress.finish(InitialBootstrapEffect::OriginalExecResume, None),
        "initial bootstrap effect completion differs",
    );
    progress.fail(None);
    invalid(
        progress.finish(effect, None),
        "initial bootstrap effect completion differs",
    );
    assert_eq!(progress.effects().len(), 1);
    assert!(!progress.effects()[0].unwrap().complete);
    assert_eq!(
        progress.first_failure.unwrap().kind,
        InitialBootstrapFailureKind::Unwound
    );
    let held = RawHeldFacts {
        stopped: true,
        owned: true,
        exact_status: true,
        live_pin: true,
        retired: false,
        lost_custody: false,
    };
    require_raw_held(held).unwrap();
    for changed in [
        RawHeldFacts {
            stopped: false,
            ..held
        },
        RawHeldFacts {
            owned: false,
            ..held
        },
        RawHeldFacts {
            exact_status: false,
            ..held
        },
        RawHeldFacts {
            live_pin: false,
            ..held
        },
        RawHeldFacts {
            retired: true,
            ..held
        },
        RawHeldFacts {
            lost_custody: true,
            ..held
        },
    ] {
        invalid(
            require_raw_held(changed),
            "initial bootstrap raw wait lacks pinned held custody",
        );
    }
    // A terminal raw observation is retained even though its retired numeric
    // TID cannot authorize any subsequent ptrace request.
    let mut previous = MemoryObservation::default();
    previous.bytes[..3].copy_from_slice(&[9, 8, 7]);
    previous.copied = 3;
    progress.retain_wait(WaitCapture::Runner, 7, 0x57f);
    progress.runner_queries_started = true;
    progress.retain_wait(WaitCapture::Runner, 7, 0);
    assert_eq!(progress.runner_wait, Some((7, 0)));
    assert!(!progress.runner_queries_started);
    assert_eq!(&previous.bytes[..previous.copied], &[9, 8, 7]);
    progress.exec_queries_started = true;
    progress.retain_wait(WaitCapture::ExecExit, 7, 0);
    progress.first_user_queries_started = true;
    progress.retain_wait(WaitCapture::FirstUser, 7, 0);
    assert_eq!(progress.exec_wait, Some((7, 0)));
    assert!(!progress.exec_queries_started && !progress.first_user_queries_started);
}

#[test]
fn initial_bootstrap_transfer_is_one_shot_and_preserves_failed_data() {
    let mut progress = InitialBootstrapProgress::default();
    let mut value = Some([1, 2, 3]);
    invalid(
        storage::transfer(&mut progress, &mut value),
        "initial bootstrap is not complete",
    );
    assert_eq!(value, Some([1, 2, 3]));
    progress.phase = InitialBootstrapPhase::Complete;
    progress.fail(Some(&LaunchError::Invalid("late failure")));
    invalid(
        storage::transfer(&mut progress, &mut value),
        "initial bootstrap is not complete",
    );
    assert_eq!(value, Some([1, 2, 3]));
    let mut progress = InitialBootstrapProgress {
        phase: InitialBootstrapPhase::Complete,
        ..InitialBootstrapProgress::default()
    };
    assert_eq!(
        storage::transfer(&mut progress, &mut value).unwrap(),
        [1, 2, 3]
    );
    assert_eq!(progress.phase, InitialBootstrapPhase::Transferred);
    assert_eq!(value, None);
    invalid(
        storage::transfer(&mut progress, &mut value),
        "initial bootstrap is not complete",
    );
}

#[test]
fn initial_bootstrap_final_inventory_requires_exact_identity_and_only_x_removal() {
    final_inventory(ORIGINAL, FINAL, &(0x800000..0x801000)).unwrap();
    for (old, new) in [
        ("08:02", "08:03"),
        ("17    ", "18    "),
        ("00001000", "00002000"),
        ("/fixture/a  b  ", "/fixture/a b  "),
        ("17    ", "17   "),
        ("r--p", "r-xp"),
        ("rw-p", "r--p"),
        ("--xp", "---p"),
        ("00402000", "00403000"),
    ] {
        assert!(
            final_inventory(ORIGINAL, &changed(FINAL, old, new), &(0x800000..0x801000)).is_err(),
            "{old} -> {new}"
        );
    }
    assert!(final_inventory(ORIGINAL, ORIGINAL, &(0x800000..0x801000)).is_err());
    for permissions in ["rw-p", "r-xs", "rwxp"] {
        assert!(
            final_inventory(
                ORIGINAL,
                &changed(FINAL, "r-xp", permissions),
                &(0x800000..0x801000)
            )
            .is_err()
        );
    }
    for suffix in [" 1", " 0 /unexpected"] {
        let changed = changed(
            FINAL,
            "r-xp 00000000 00:00 0",
            &format!("r-xp 00000000 00:00{suffix}"),
        );
        assert!(final_inventory(ORIGINAL, &changed, &(0x800000..0x801000)).is_err());
    }
}

#[test]
fn initial_bootstrap_range_checks_whole_interval_private_coverage_and_permissions() {
    let raw = b"00400000-00401000 r--p 0 00:00 0\n00401000-00402000 r--p 0 00:00 0\n00800000-00801000 r-xp 0 00:00 0\n";
    let island = 0x800000..0x801000;
    runner::private_range(raw, &island, 0x400000, 2 * PAGE, Some(libc::PROT_READ)).unwrap();
    assert!(runner::private_range(raw, &island, 0x400000, 0, None).is_err());
    assert!(runner::private_range(raw, &island, 0x400000, 3 * PAGE, None).is_err());
    assert!(
        runner::private_range(raw, &island, 0x400000, 2 * PAGE, Some(libc::PROT_EXEC)).is_err()
    );
    assert!(runner::private_range(raw, &island, 0x800000, PAGE, None).is_err());
    assert!(runner::private_range(raw, &island, u64::MAX - 1, PAGE, None).is_err());
    let shared = changed(raw, "00401000-00402000 r--p", "00401000-00402000 r--s");
    assert!(runner::private_range(&shared, &island, 0x400000, 2 * PAGE, None).is_err());
}

#[test]
fn initial_bootstrap_state_copy_preserves_full_payload_without_native_credit() {
    let mut source = StateSlot::allocate().unwrap();
    source.state.registers.eflags = 0x40202;
    source.state.registers.cs = 0x33;
    source.state.mask = 0x55;
    source.state.xstate[512] = 0xa5;
    source.state.xstate.truncate(1024);
    source.complete = true;
    let mut destination = StateSlot::allocate().unwrap();
    let capacity = destination.state.xstate.capacity();
    destination.copy_from(&source).unwrap();
    assert_eq!(destination.state, source.state);
    assert_eq!(destination.state.xstate.capacity(), capacity);
    assert_eq!(destination.registers_request, None);
    assert_eq!(destination.xstate_request, None);
    assert_eq!(destination.mask_request, None);
    source.complete = false;
    invalid(
        destination.copy_from(&source),
        "initial bootstrap copied incomplete state",
    );
}
