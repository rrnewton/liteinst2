//! Pure dispatch controls. Registry inputs and state bytes are synthetic; these
//! tests prove no native EXEC, source capture, physical pin or cleanup.
use super::tests::{PC, SESSION, SOURCE};
use super::*;
use crate::lifecycle::{HoldReason, LifecycleRegistry, Limits};

pub(in super::super) fn profile() -> DynamicExecProfile {
    DynamicExecProfile {
        max_capture_images: 2,
        max_capture_bytes: 4096,
        max_total_capture_bytes: 8192,
        max_argument_pointers: 32,
        max_string_bytes: 4096,
    }
}

pub(in super::super) fn identities() -> (DynamicTask, DynamicTask) {
    let mut registry = LifecycleRegistry::new(
        Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 2,
            obligations: 8,
        },
        101,
        PC,
    )
    .unwrap();
    let old = registry.root_task();
    let record = registry.task(old).unwrap();
    let before = DynamicTask {
        task: old,
        process: record.process,
        address_space: record.address_space,
        generation: 7,
    };
    registry.resume(old, 0).unwrap();
    registry
        .observe_stop(old, 1, PC + 2, HoldReason::SyscallEntry)
        .unwrap();
    let ticket = registry.prepare_exec(old).unwrap();
    registry.resume(old, 1).unwrap();
    let transition = registry
        .observe_exec_event(ticket, 2, 101, 101, SOURCE)
        .unwrap();
    let record = registry.task(transition.task).unwrap();
    assert_eq!(record.sequence, 0);
    let after = DynamicTask {
        task: transition.task,
        process: record.process,
        address_space: record.address_space,
        generation: 0,
    };
    (before, after)
}

pub(in super::super) fn state(task: DynamicTask) -> DynamicAdmissionState {
    let mut state = super::tests::state();
    state.task = task;
    state.registers.rax = libc::SYS_execve as u64;
    state.registers.rdi = 0x600000;
    state.registers.rsi = 0x601000;
    state.registers.rdx = 0x602000;
    state
}

pub(in super::super) fn request(
    expected: &PendingToken,
    replacement: DynamicTask,
    until: Instant,
) -> DynamicSourceRequest {
    let mut request = super::tests::request(expected, until);
    let stop = |sequence| DynamicStop {
        session: expected.stop.session,
        tid: expected.stop.tid,
        task: Some(replacement.task),
        sequence,
    };
    request.token.task = replacement;
    request.token.candidate_epoch = 0;
    request.token.capture_stop = stop(10);
    request.token.transition = SourceTransitionBinding::Exec(Arc::new(ExecSourceBinding {
        previous: expected.task,
        replacement,
        exec_stop: stop(0),
        exit_stop: stop(1),
        bootstrap_stop: stop(10),
        attempt: KernelAttemptId {
            session: expected.stop.session,
            invocation: expected.invocation,
        },
    }));
    let image = &mut Arc::get_mut(&mut request.images).unwrap()[0];
    image.original.pathname = Some("/runtime/main".into());
    image.quarantined.pathname = image.original.pathname.clone();
    request
}

fn refused<T>(result: Result<T, GateError>, reason: &'static str) {
    assert!(matches!(result, Err(GateError::Refused(actual)) if actual == reason));
}

#[test]
fn exec_profile_requires_singleton_and_checked_whole_vma_input_bounds() {
    let options = DynamicAdmissionOptions::default();
    let original = profile();
    original.validate(&options).unwrap();
    for row in 0..14 {
        let mut changed = original.clone();
        match row {
            0 => changed.max_capture_images = 0,
            1 => changed.max_capture_images = 65,
            2 => changed.max_capture_bytes = 0,
            3 => changed.max_capture_bytes = 65537,
            4 => changed.max_capture_bytes = 4095,
            5 => changed.max_total_capture_bytes = 4095,
            6 => changed.max_total_capture_bytes = 12288,
            7 => changed.max_argument_pointers = 1,
            8 => changed.max_argument_pointers = 4097,
            9 => changed.max_string_bytes = 0,
            10 => changed.max_string_bytes = 65537,
            11 => changed.max_capture_images = usize::MAX,
            12 => changed.max_total_capture_bytes = usize::MAX,
            13 => changed.max_capture_bytes = usize::MAX,
            _ => unreachable!(),
        }
        refused(
            changed.validate(&options),
            "invalid singleton exec source profile",
        );
    }
    let mut low = options.clone();
    low.limits.source_fact_bytes = 4096;
    refused(
        original.validate(&low),
        "invalid singleton exec source profile",
    );
    let mut threads = options.clone();
    threads.lifecycle.max_tasks = 2;
    refused(
        original.validate(&threads),
        "invalid singleton exec source profile",
    );
    let boundary = DynamicExecProfile {
        max_capture_images: 64,
        max_capture_bytes: 65536,
        max_total_capture_bytes: 64 * 65536,
        max_argument_pointers: 4096,
        max_string_bytes: 65536,
    };
    boundary.validate(&options).unwrap();
    assert_eq!(original, profile());
    assert_eq!(options.limits.source_fact_bytes, 64 * 1024 * 1024);
}

#[test]
fn exec_binding_retains_previous_mm_and_requires_exact_new_epoch_and_stop_chain() {
    let (before, after) = identities();
    let input = super::tests::pending(&state(before));
    let until = Instant::now() + Duration::from_secs(3);
    let capture = request(&input.token, after, until);
    capture
        .check_exec_binding(&input.token, &profile(), until)
        .unwrap();
    assert_eq!(capture.transition(), DynamicSourceTransition::Exec);
    assert_eq!(capture.previous_task(), before);
    assert_eq!(capture.task(), after);
    assert_eq!(
        (capture.previous_epoch(), capture.candidate_epoch()),
        (7, 0)
    );
    assert_eq!(
        capture.kernel_attempt(),
        KernelAttemptId {
            session: SESSION,
            invocation: 13
        }
    );
    assert_ne!(before.task, after.task);
    assert_ne!(before.address_space, after.address_space);
    assert_eq!(before.process, after.process);
    // Registry EXEC births a different TaskId at sequence zero. Chronology
    // across tasks is native event/attempt order, never numeric stop ordering.
    let SourceTransitionBinding::Exec(binding) = &capture.token.transition else {
        unreachable!()
    };
    let ExecSourceBinding {
        exec_stop,
        exit_stop,
        bootstrap_stop,
        ..
    } = binding.as_ref();
    assert_eq!(exec_stop.sequence, 0);
    assert!(input.token.stop.sequence > exec_stop.sequence);
    assert!(exit_stop.sequence > exec_stop.sequence);
    assert!(bootstrap_stop.sequence > exit_stop.sequence);
    for (birth, exit, bootstrap) in [
        (1, 2, 10),
        (u64::MAX, u64::MAX, u64::MAX),
        (0, 0, 10),
        (0, 8, 7),
        (0, 8, 8),
    ] {
        let mut changed = request(&input.token, after, until);
        let SourceTransitionBinding::Exec(binding) = &mut changed.token.transition else {
            unreachable!()
        };
        let ExecSourceBinding {
            exec_stop,
            exit_stop,
            bootstrap_stop,
            ..
        } = Arc::make_mut(binding);
        exec_stop.sequence = birth;
        exit_stop.sequence = exit;
        bootstrap_stop.sequence = bootstrap;
        // Preserve the capture equality so the intended wrong-birth or
        // same-task regression predicate, not a stale capture, must refuse.
        changed.token.capture_stop = bootstrap_stop.clone();
        let unchanged = changed.token.clone();
        refused(
            changed.check_exec_binding(&input.token, &profile(), until),
            "dynamic exec source request binding differs",
        );
        assert_eq!(changed.token, unchanged);
    }
    let token = capture.token.clone();
    let bytes = capture.images()[0].bytes().to_vec();
    for row in 0..24 {
        let mut changed = request(&input.token, after, until);
        match row {
            0 => changed.token.original.invocation += 1,
            1 => changed.token.until += Duration::from_nanos(1),
            2 => changed.token.id.session += 1,
            3 => changed.token.id.serial = 0,
            4 => changed.token.task = before,
            5 => changed.token.original.epoch += 1,
            6 => changed.token.original.stop.task = Some(after.task),
            7 => changed.token.candidate_epoch = 1,
            8 => changed.token.capture_stop.sequence += 1,
            9..=23 => {
                let SourceTransitionBinding::Exec(binding) = &mut changed.token.transition else {
                    unreachable!()
                };
                let ExecSourceBinding {
                    previous,
                    replacement,
                    exec_stop,
                    exit_stop,
                    bootstrap_stop,
                    attempt,
                } = Arc::make_mut(binding);
                match row {
                    9 => *previous = after,
                    10 => replacement.task = before.task,
                    11 => replacement.address_space = before.address_space,
                    12 => replacement.process = identities().0.process,
                    13 => replacement.generation = 1,
                    14 => exec_stop.sequence = input.token.stop.sequence,
                    15 => exit_stop.sequence = exec_stop.sequence,
                    16 => bootstrap_stop.sequence = exit_stop.sequence,
                    17 => exec_stop.tid += 1,
                    18 => exit_stop.task = Some(before.task),
                    19 => bootstrap_stop.session += 1,
                    20 => attempt.session += 1,
                    21 => attempt.invocation += 1,
                    22 => exec_stop.task = None,
                    23 => exit_stop.session += 1,
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
        let unchanged = changed.token.clone();
        refused(
            changed.check_exec_binding(&input.token, &profile(), until),
            "dynamic exec source request binding differs",
        );
        assert_eq!(changed.token, unchanged);
    }
    assert_eq!(capture.token, token);
    assert_eq!(capture.images()[0].bytes(), bytes);
}

#[test]
fn source_transition_tags_do_not_turn_mapping_authority_into_exec_or_the_reverse() {
    let mapping_state = super::tests::state();
    let old = super::tests::pending(&mapping_state);
    let until = Instant::now() + Duration::from_secs(3);
    let mapping = super::tests::request(&old.token, until);
    mapping
        .check_mapping_binding(&old.token, &super::tests::profile(), until)
        .unwrap();
    assert_eq!(mapping.transition(), DynamicSourceTransition::Mapping);
    assert_eq!(mapping.previous_task(), mapping.task());
    refused(
        mapping.check_exec_binding(&old.token, &profile(), until),
        "dynamic exec source request binding differs",
    );
    let (before, after) = identities();
    let input = super::tests::pending(&state(before));
    let exec = request(&input.token, after, until);
    refused(
        exec.check_mapping_binding(&input.token, &super::tests::profile(), until),
        "dynamic source request binding differs",
    );
    let mut wrong_tag = request(&input.token, after, until);
    wrong_tag.token.transition = SourceTransitionBinding::Mapping;
    refused(
        wrong_tag.check_exec_binding(&input.token, &profile(), until),
        "dynamic exec source request binding differs",
    );
}

#[test]
fn exec_capture_requires_complete_file_geometry_identity_and_total_payload() {
    let (before, after) = identities();
    let input = super::tests::pending(&state(before));
    let until = Instant::now() + Duration::from_secs(3);
    for row in 0..15 {
        let mut capture = request(&input.token, after, until);
        let image = &mut Arc::get_mut(&mut capture.images).unwrap()[0];
        match row {
            0 => image.id.index = 1,
            1 => image.id.request.serial += 1,
            2 => image.mapping_incarnation = 0,
            3 => image.original.start += 1,
            4 => image.original.end -= 1,
            5 => image.bytes = vec![0x90; 4095].into(),
            6 => image.original.permissions = "rwxp".into(),
            7 => image.original.file_offset = 1,
            8 => image.original.pathname = None,
            9 => image.original.pathname = Some(String::new()),
            10 => image.quarantined.pathname = Some("/another/main".into()),
            11 => image.quarantined.permissions = "r-xp".into(),
            12 => image.quarantined.file_offset = 4096,
            13 => image.quarantined.end += 4096,
            14 => {
                image.lower_neighbor = Some(MemoryMapping {
                    start: SOURCE - 4096,
                    end: SOURCE,
                    permissions: "r-xp".into(),
                    file_offset: 0,
                    pathname: None,
                })
            }
            _ => unreachable!(),
        }
        refused(
            capture.check_exec_binding(&input.token, &profile(), until),
            "dynamic exec source capture geometry differs",
        );
    }
    let mut batch = request(&input.token, after, until);
    // Build a second distinct whole file VMA from separate immutable model data.
    let one = request(&input.token, after, until);
    let two = DynamicSourceImage {
        id: DynamicSourceCaptureId {
            request: batch.id(),
            index: 1,
        },
        mapping_incarnation: 8,
        original: MemoryMapping {
            start: SOURCE + 8192,
            end: SOURCE + 12288,
            permissions: "r-xp".into(),
            file_offset: 4096,
            pathname: Some("/runtime/interpreter".into()),
        },
        quarantined: MemoryMapping {
            start: SOURCE + 8192,
            end: SOURCE + 12288,
            permissions: "r--p".into(),
            file_offset: 4096,
            pathname: Some("/runtime/interpreter".into()),
        },
        bytes: vec![0x90; 4096].into(),
        lower_neighbor: None,
        upper_neighbor: None,
    };
    let mut images = Vec::new();
    let image = &one.images[0];
    images.push(DynamicSourceImage {
        id: image.id,
        mapping_incarnation: image.mapping_incarnation,
        original: image.original.clone(),
        quarantined: image.quarantined.clone(),
        bytes: Arc::clone(&image.bytes),
        lower_neighbor: None,
        upper_neighbor: None,
    });
    images.push(two);
    batch.images = images.into();
    batch
        .check_exec_binding(&input.token, &profile(), until)
        .unwrap();
    let mut low = profile();
    low.max_total_capture_bytes = 4096;
    refused(
        batch.check_exec_binding(&input.token, &low, until),
        "dynamic exec source capture geometry differs",
    );
    low = profile();
    low.max_capture_images = 1;
    refused(
        batch.check_exec_binding(&input.token, &low, until),
        "exec source request image bound differs",
    );
    Arc::get_mut(&mut batch.images).unwrap()[1].mapping_incarnation = 7;
    refused(
        batch.check_exec_binding(&input.token, &profile(), until),
        "dynamic exec source capture geometry differs",
    );
    let second = &mut Arc::get_mut(&mut batch.images).unwrap()[1];
    second.mapping_incarnation = 8;
    second.original.start = SOURCE;
    second.original.end = SOURCE + 4096;
    second.quarantined.start = SOURCE;
    second.quarantined.end = SOURCE + 4096;
    refused(
        batch.check_exec_binding(&input.token, &profile(), until),
        "dynamic exec source capture geometry differs",
    );
    batch.images = Vec::<DynamicSourceImage>::new().into();
    refused(
        batch.check_exec_binding(&input.token, &profile(), until),
        "exec source request image bound differs",
    );
}

#[test]
fn exec_head_reply_retains_exact_capture_set_and_never_supplies_bytes() {
    let (before, after) = identities();
    let input = super::tests::pending(&state(before));
    let until = Instant::now() + Duration::from_secs(3);
    let capture = request(&input.token, after, until);
    let original = capture.images()[0].bytes().to_vec();
    let good = super::tests::facts(&capture);
    capture.check_facts(&good).unwrap();
    for row in 0..4 {
        let mut changed = good.clone();
        match row {
            0 => changed.images[0].capture.request.serial += 1,
            1 => changed.images.push(changed.images[0].clone()),
            2 => changed.images.clear(),
            3 => {
                changed.images[0].heads.insert(SOURCE + 4096);
            }
            _ => unreachable!(),
        }
        let reason = if row == 3 {
            "dynamic source reply head lies outside capture"
        } else {
            "dynamic source reply image set differs"
        };
        refused(capture.check_facts(&changed), reason);
        assert_eq!(capture.images()[0].bytes(), original);
    }
}
