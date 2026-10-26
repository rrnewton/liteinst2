//! Synthetic binding/calibration controls only. These objects do not establish
//! a native stop, mapping, anonymous provenance, source lease or cleanup.
use super::*;
use crate::lifecycle::{LifecycleRegistry, Limits};
use crate::selected::{SyscallAliases, decode};

pub(in super::super) const SOURCE: u64 = 0x800000;
pub(in super::super) const PC: u64 = 0x401000;
pub(in super::super) const SESSION: u64 = 41;

pub(in super::super) fn state() -> DynamicAdmissionState {
    let registry = LifecycleRegistry::new(
        Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 1,
            obligations: 8,
        },
        101,
        PC,
    )
    .unwrap();
    let task = registry.root_task();
    let record = registry.task(task).unwrap();
    // Integer-only initialized channel data, never a native observation.
    let mut raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    raw.rip = PC;
    raw.cs = 0x33;
    raw.eflags = 0x202;
    raw.rsp = 0x600000;
    raw.orig_rax = u64::MAX;
    raw.rax = libc::SYS_mprotect as u64;
    raw.rdi = SOURCE;
    raw.rsi = PAGE;
    raw.rdx = (libc::PROT_READ | libc::PROT_EXEC) as u64;
    DynamicAdmissionState {
        task: DynamicTask {
            task,
            process: record.process,
            address_space: record.address_space,
            generation: 0,
        },
        registers: raw.into(),
        xstate: vec![0x5a; 832],
        signal_mask: 0x200,
    }
}

pub(in super::super) fn pending(state: &DynamicAdmissionState) -> ProviderInput {
    ProviderInput {
        token: PendingToken {
            stop: DynamicStop {
                session: SESSION,
                sequence: 3,
                tid: 101,
                task: Some(state.task.task),
            },
            task: state.task,
            epoch: state.task.generation,
            plan: 11,
            invocation: 13,
        },
        input: SelectedInput::new(
            decode(PC, &[0x0f, 0x05], &SyscallAliases::default()).unwrap(),
            state.registers,
        )
        .unwrap(),
    }
}

pub(in super::super) fn profile() -> DynamicMappingProfile {
    DynamicMappingProfile {
        allowed_ranges: std::iter::once(SOURCE..SOURCE + 4 * PAGE).collect(),
        max_operations: 8,
        max_live_mappings: 1,
        max_source_requests: 2,
        max_capture_bytes: PAGE as usize,
    }
}

fn mapping(start: u64, end: u64, permissions: &str) -> MemoryMapping {
    MemoryMapping {
        start,
        end,
        permissions: permissions.into(),
        file_offset: 0,
        pathname: None,
    }
}

pub(in super::super) fn request(expected: &PendingToken, until: Instant) -> DynamicSourceRequest {
    let id = DynamicSourceRequestId {
        session: SESSION,
        serial: 1,
    };
    DynamicSourceRequest {
        token: PendingSourceToken {
            id,
            original: expected.clone(),
            transition: SourceTransitionBinding::Mapping,
            capture_stop: DynamicStop {
                sequence: 9,
                ..expected.stop.clone()
            },
            task: expected.task,
            candidate_epoch: expected.epoch + 1,
            until,
        },
        images: vec![DynamicSourceImage {
            id: DynamicSourceCaptureId {
                request: id,
                index: 0,
            },
            mapping_incarnation: 7,
            original: mapping(SOURCE, SOURCE + PAGE, "r-xp"),
            quarantined: mapping(SOURCE, SOURCE + PAGE, "r--p"),
            bytes: vec![0x90; PAGE as usize].into(),
            lower_neighbor: None,
            upper_neighbor: None,
        }]
        .into(),
    }
}

pub(in super::super) fn facts(request: &DynamicSourceRequest) -> DynamicSourceFacts {
    DynamicSourceFacts {
        images: vec![DynamicSourceHeads {
            capture: request.images()[0].id(),
            heads: [SOURCE, SOURCE + 2].into_iter().collect(),
        }],
    }
}

fn refused<T>(result: Result<T, GateError>, reason: &'static str) {
    assert!(matches!(result, Err(GateError::Refused(actual)) if actual == reason));
}

#[test]
fn mapping_profile_is_explicit_singleton_and_keeps_finite_bounds() {
    let original = profile();
    let options = DynamicAdmissionOptions::default();
    original.validate(&options, &[]).unwrap();
    assert!(original.contains_range(&(SOURCE..SOURCE + PAGE)));
    assert!(!original.contains_range(&(SOURCE..SOURCE + 2 * PAGE)));
    assert!(!original.contains_range(&(SOURCE + 1..SOURCE + PAGE)));
    assert!(!original.contains_range(&Range {
        start: SOURCE + PAGE,
        end: SOURCE
    }));
    for field in 0..8 {
        let mut changed = original.clone();
        match field {
            0 => changed.max_operations = 0,
            1 => changed.max_operations = 4097,
            2 => changed.max_live_mappings = 0,
            3 => changed.max_live_mappings = 65,
            4 => changed.max_source_requests = 0,
            5 => changed.max_source_requests = 9,
            6 => changed.max_capture_bytes = 65537,
            7 => changed.max_capture_bytes = 4095,
            _ => unreachable!(),
        }
        refused(
            changed.validate(&options, &[]),
            "invalid singleton anonymous mapping profile",
        );
    }
    let mut changed = options.clone();
    changed.lifecycle.max_tasks = 2;
    refused(
        original.validate(&changed, &[]),
        "invalid singleton anonymous mapping profile",
    );
    changed = options.clone();
    changed.limits.source_fact_bytes = 4095;
    refused(
        original.validate(&changed, &[]),
        "invalid singleton anonymous mapping profile",
    );
    assert_eq!(original, profile());
    assert_eq!(options.limits.source_fact_bytes, 64 * 1024 * 1024);
}

#[test]
fn address_envelopes_reject_overlap_wrap_and_initial_source_aliases() {
    let options = DynamicAdmissionOptions::default();
    for range in [0..PAGE, SOURCE..SOURCE, SOURCE + 1..SOURCE + PAGE] {
        let mut value = profile();
        value.allowed_ranges = vec![range];
        refused(
            value.validate(&options, &[]),
            "invalid anonymous mapping address envelope",
        );
    }
    let mut value = profile();
    value.allowed_ranges.push(SOURCE + PAGE..SOURCE + 2 * PAGE);
    refused(
        value.validate(&options, &[]),
        "invalid anonymous mapping address envelope",
    );
    value.allowed_ranges = std::iter::once(PAGE..PAGE + MAX_DOMAIN_BYTES + PAGE).collect();
    refused(
        value.validate(&options, &[]),
        "anonymous mapping address envelope exceeds page bound",
    );
    let initial = ImageFacts {
        start: SOURCE,
        bytes: vec![0x90; 2],
        heads: [SOURCE].into_iter().collect(),
    };
    refused(
        profile().validate(&options, &[initial]),
        "anonymous mapping envelope overlaps initial source",
    );
    let overflow = ImageFacts {
        start: u64::MAX,
        bytes: vec![0; 2],
        heads: BTreeSet::new(),
    };
    refused(
        profile().validate(&options, &[overflow]),
        "initial image range overflows",
    );
}

#[test]
fn capture_reports_exact_source_and_uncommitted_epoch_without_authority() {
    let pending = pending(&state());
    let until = Instant::now() + Duration::from_secs(3);
    let value = request(&pending.token, until);
    value
        .check_mapping_binding(&pending.token, &profile(), until)
        .unwrap();
    assert_eq!(value.id().session(), SESSION);
    assert_eq!(value.id().serial(), 1);
    assert_eq!(value.task(), pending.token.task);
    assert_eq!(value.previous_epoch(), 0);
    assert_eq!(value.candidate_epoch(), 1);
    assert_eq!(value.expires_at(), until);
    assert_eq!(
        value.kernel_attempt(),
        KernelAttemptId {
            session: SESSION,
            invocation: 13
        }
    );
    let image = &value.images()[0];
    assert_eq!(image.id().request(), value.id());
    assert_eq!(image.id().index(), 0);
    assert_eq!(image.mapping_incarnation(), 7);
    assert_eq!(image.range(), SOURCE..SOURCE + PAGE);
    assert_eq!(image.bytes(), vec![0x90; PAGE as usize]);
    assert_eq!(
        image.original_mapping(),
        &mapping(SOURCE, SOURCE + PAGE, "r-xp")
    );
    assert_eq!(
        image.quarantined_mapping(),
        &mapping(SOURCE, SOURCE + PAGE, "r--p")
    );
    assert!(image.lower_neighbor().is_none() && image.upper_neighbor().is_none());
    value.check_facts(&facts(&value)).unwrap();
}

#[test]
fn stale_foreign_and_late_capture_tokens_cannot_match_original_invocation() {
    let expected = pending(&state()).token;
    let until = Instant::now() + Duration::from_secs(3);
    for field in 0..12 {
        let mut value = request(&expected, until);
        match field {
            0 => value.token.original.invocation += 1,
            1 => value.token.original.plan += 1,
            2 => value.token.id.session += 1,
            3 => value.token.id.serial = 0,
            4 => value.token.until += Duration::from_nanos(1),
            5 => value.token.task.generation += 1,
            6 => value.token.capture_stop.session += 1,
            7 => value.token.capture_stop.tid += 1,
            8 => value.token.capture_stop.task = None,
            9 => value.token.capture_stop.sequence = expected.stop.sequence,
            10 => value.token.candidate_epoch = expected.epoch,
            11 => value.token.candidate_epoch = expected.epoch + 2,
            _ => unreachable!(),
        }
        let before = format!("{value:?}");
        refused(
            value.check_mapping_binding(&expected, &profile(), until),
            "dynamic source request binding differs",
        );
        assert_eq!(format!("{value:?}"), before);
    }
    let mut bad_epoch = expected.clone();
    bad_epoch.epoch = 1;
    let mut value = request(&expected, until);
    value.token.original = bad_epoch.clone();
    refused(
        value.check_mapping_binding(&bad_epoch, &profile(), until),
        "dynamic source request binding differs",
    );
}

#[test]
fn epoch_exhaustion_and_foreign_task_identity_do_not_alias_a_capture() {
    let expected = pending(&state()).token;
    let until = Instant::now() + Duration::from_secs(3);
    let other = state();
    let mut value = request(&expected, until);
    value.token.task = other.task;
    refused(
        value.check_mapping_binding(&expected, &profile(), until),
        "dynamic source request binding differs",
    );
    let mut exhausted = expected.clone();
    exhausted.epoch = u64::MAX;
    exhausted.task.generation = u64::MAX;
    let mut value = request(&expected, until);
    value.token.original = exhausted.clone();
    value.token.task = exhausted.task;
    value.token.candidate_epoch = 0;
    refused(
        value.check_mapping_binding(&exhausted, &profile(), until),
        "dynamic source request binding differs",
    );
}

#[test]
fn complete_vma_bytes_permissions_and_neighbors_are_required_exactly() {
    let expected = pending(&state()).token;
    let until = Instant::now() + Duration::from_secs(3);
    for field in 0..12 {
        let mut value = request(&expected, until);
        let image = &mut Arc::get_mut(&mut value.images).unwrap()[0];
        match field {
            0 => image.id.index = 1,
            1 => image.mapping_incarnation = 0,
            2 => image.bytes = vec![0x90; PAGE as usize - 1].into(),
            3 => image.original.permissions = "rwxp".into(),
            4 => image.original.file_offset = PAGE,
            5 => image.original.pathname = Some("[anonymous-looking]".into()),
            6 => image.quarantined.end += PAGE,
            7 => image.quarantined.permissions = "r-xp".into(),
            8 => image.lower_neighbor = Some(mapping(SOURCE - PAGE, SOURCE, "r-xp")),
            9 => image.upper_neighbor = Some(mapping(SOURCE + PAGE, SOURCE + 2 * PAGE, "r")),
            10 => image.lower_neighbor = Some(mapping(SOURCE - PAGE, SOURCE - 1, "rw-p")),
            11 => {
                image.upper_neighbor = Some(mapping(SOURCE + 2 * PAGE, SOURCE + 3 * PAGE, "r--p"))
            }
            _ => unreachable!(),
        }
        refused(
            value.check_mapping_binding(&expected, &profile(), until),
            "dynamic source capture geometry differs",
        );
    }
    let mut value = request(&expected, until);
    let image = &mut Arc::get_mut(&mut value.images).unwrap()[0];
    image.lower_neighbor = Some(mapping(SOURCE - PAGE, SOURCE, "rw-p"));
    image.upper_neighbor = Some(mapping(SOURCE + PAGE, SOURCE + 2 * PAGE, "---p"));
    value
        .check_mapping_binding(&expected, &profile(), until)
        .unwrap();
    value.images = Vec::<DynamicSourceImage>::new().into();
    refused(
        value.check_mapping_binding(&expected, &profile(), until),
        "mapping source request requires one complete VMA",
    );
}

#[test]
fn reply_cannot_substitute_missing_duplicate_or_foreign_capture_rows() {
    let expected = pending(&state()).token;
    let value = request(&expected, Instant::now() + Duration::from_secs(3));
    let original = facts(&value);
    let mut missing = original.clone();
    missing.images.clear();
    refused(
        value.check_facts(&missing),
        "dynamic source reply image set differs",
    );
    let mut duplicate = original.clone();
    duplicate.images.push(duplicate.images[0].clone());
    refused(
        value.check_facts(&duplicate),
        "dynamic source reply image set differs",
    );
    for field in 0..3 {
        let mut foreign = original.clone();
        match field {
            0 => foreign.images[0].capture.request.session += 1,
            1 => foreign.images[0].capture.request.serial += 1,
            2 => foreign.images[0].capture.index += 1,
            _ => unreachable!(),
        }
        refused(
            value.check_facts(&foreign),
            "dynamic source reply image set differs",
        );
    }
    assert_eq!(original, facts(&value));
}

#[test]
fn reply_checks_byte_extent_but_does_not_invent_head_completeness() {
    let expected = pending(&state()).token;
    let value = request(&expected, Instant::now() + Duration::from_secs(3));
    for address in [SOURCE - 1, SOURCE + PAGE, u64::MAX] {
        let mut reply = facts(&value);
        reply.images[0].heads.insert(address);
        refused(
            value.check_facts(&reply),
            "dynamic source reply head lies outside capture",
        );
    }
    let mut reply = facts(&value);
    reply.images[0].heads.clear();
    value.check_facts(&reply).unwrap(); // Structural match; owner route checks remain mandatory.
    reply.images[0].heads.extend(SOURCE..SOURCE + PAGE);
    value.check_facts(&reply).unwrap();
    assert_eq!(reply.images[0].heads.len(), PAGE as usize);
}
