//! Synthetic source/census models, not native replacement, source capture or
//! permission evidence. Native creation/EXIT/cleanup belongs to separate tests.
use super::*;
use crate::lifecycle::{LifecycleRegistry, Limits};
use crate::linux::remote::dynamic::admission::PendingSourceToken;
use liteinst_admission::entries::ResumeKind;

const BASE: u64 = 0x400000;
const TARGET: u64 = 0x800000;
const SESSION: u64 = 73;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn map(start: u64) -> MemoryMapping {
    MemoryMapping {
        start,
        end: start + PAGE,
        permissions: "r-xp".into(),
        file_offset: 0,
        pathname: None,
    }
}
fn domain(with_target: bool) -> Domain {
    let starts = if with_target {
        vec![BASE, TARGET]
    } else {
        vec![BASE]
    };
    Domain::new(
        starts
            .iter()
            .map(|&start| ImageFacts {
                start,
                bytes: vec![0x90; PAGE as usize],
                heads: BTreeSet::from([start]),
            })
            .collect(),
        starts.iter().map(|&start| map(start)).collect(),
        &DynamicAdmissionOptions::default(),
        deadline(),
        |start, len| {
            assert!(starts.contains(&start));
            assert_eq!(len, PAGE as usize);
            Ok(vec![0x90; len])
        },
    )
    .unwrap()
}
fn census(pc: u64) -> (ResumeCensus, ObservedStop) {
    let registry = LifecycleRegistry::new_after_exec_syscall_exit(
        Limits {
            tasks: 1,
            processes: 1,
            address_spaces: 1,
            obligations: 8,
        },
        101,
        pc,
    )
    .unwrap();
    let record = registry.task(registry.root_task()).unwrap();
    let mut raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    raw.rip = pc;
    raw.orig_rax = u64::MAX;
    raw.cs = 0x33;
    raw.ss = 0x2b;
    raw.eflags = 0x202;
    raw.rsp = 0x700000;
    let observed = ObservedStop {
        token: DynamicStop {
            session: SESSION,
            sequence: 9,
            tid: 101,
            task: Some(registry.root_task()),
        },
        task: DynamicTask {
            task: registry.root_task(),
            process: record.process,
            address_space: record.address_space,
            generation: 0,
        },
        logical_pc: pc,
        registers: raw.into(),
        xstate: vec![0x5a; 832],
        signal_mask: 0,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    };
    let mut census = ResumeCensus::new(
        SESSION,
        record.address_space,
        0,
        census::Limits {
            epochs: 16,
            source_fact_bytes: 64 * 1024 * 1024,
            reports: 256,
            origins: 32,
            witnesses: 256,
            plan_history: 256,
        },
    )
    .unwrap();
    let reservation = census
        .reserve(BudgetCharge {
            origins: 1,
            source_fact_bytes: 8192,
            ..BudgetCharge::default()
        })
        .unwrap();
    census
        .insert(reservation, OriginKind::CurrentHeldPc, pc, observed.clone())
        .unwrap();
    census.finish_reservation(reservation).unwrap();
    (census, observed)
}
fn capture(observed: &ObservedStop, until: Instant) -> (DynamicSourceRequest, DynamicSourceFacts) {
    let id = DynamicSourceRequestId {
        session: SESSION,
        serial: 1,
    };
    let capture = DynamicSourceCaptureId {
        request: id,
        index: 0,
    };
    let mut code = vec![0x90; PAGE as usize];
    code[..2].copy_from_slice(&[0x0f, 0xa2]);
    let request = DynamicSourceRequest {
        token: PendingSourceToken {
            id,
            original: PendingToken {
                stop: DynamicStop {
                    sequence: 3,
                    ..observed.token.clone()
                },
                task: observed.task,
                epoch: 0,
                plan: 1,
                invocation: 1,
            },
            capture_stop: observed.token.clone(),
            task: observed.task,
            candidate_epoch: 1,
            until,
        },
        images: vec![DynamicSourceImage {
            id: capture,
            mapping_incarnation: 2,
            original: map(TARGET),
            quarantined: MemoryMapping {
                permissions: "r--p".into(),
                ..map(TARGET)
            },
            bytes: code.into(),
            lower_neighbor: None,
            upper_neighbor: None,
        }]
        .into(),
    };
    let facts = DynamicSourceFacts {
        images: vec![
            crate::linux::remote::dynamic::admission::DynamicSourceHeads {
                capture,
                heads: BTreeSet::from([TARGET]),
            },
        ],
    };
    (request, facts)
}
fn refused<T>(result: Result<T, GateError>, expected: &'static str) {
    assert!(matches!(result, Err(GateError::Refused(actual)) if actual == expected));
}
fn unchanged(
    census: &ResumeCensus,
) -> (
    BudgetCharge,
    BudgetCharge,
    Vec<census::OriginRow>,
    Vec<census::HistoryRecord>,
) {
    (
        census.charged(),
        census.used(),
        census.rows().cloned().collect(),
        census.history().to_vec(),
    )
}

#[test]
fn no_capture_preserves_exact_failed_effect_source_and_removes_only_absent_target() {
    let domain = domain(true);
    let (census, _) = census(BASE);
    let before = unchanged(&census);
    let old = &domain.images[1];
    let preserved = stage_sources(
        &domain,
        &census,
        &(TARGET..TARGET + PAGE),
        None,
        domain.original_executables.clone(),
        deadline(),
    )
    .unwrap();
    assert_eq!(preserved.images().len(), 2);
    let retained = &preserved.images()[1];
    assert_eq!(retained.snapshot.bytes(), old.snapshot.bytes());
    assert_eq!(retained.snapshot.mapping, old.snapshot.mapping);
    assert_eq!(retained.core_identity.source, old.core_identity.source);
    assert_eq!(retained.entries.heads(), old.entries.heads());
    assert_eq!(retained.snapshot.generation, Generation(1));
    assert_eq!(retained.entries.version(), 1);
    let removed = stage_sources(
        &domain,
        &census,
        &(TARGET..TARGET + PAGE),
        None,
        vec![map(BASE)],
        deadline(),
    )
    .unwrap();
    assert_eq!(removed.images().len(), 1);
    assert_eq!(removed.mappings(), &[map(BASE)]);
    assert!(removed.pages().values().all(|executable| !executable));
    assert_eq!(domain.images.len(), 2);
    assert_eq!(domain.generation, 0);
    assert_eq!(domain.source_binding, preserved.identity().old_binding);
    assert_ne!(
        preserved.identity().new_binding,
        removed.identity().new_binding
    );
    assert_eq!(unchanged(&census), before);
}

#[test]
fn actual_capture_bytes_and_full_reply_get_fresh_identity_with_exact_current_projection() {
    let domain = domain(true);
    let (census, observed) = census(BASE);
    let before = unchanged(&census);
    let until = deadline();
    let (request, mut facts) = capture(&observed, until);
    // All offsets remain a permitted reply shape; no fixture-specific head cap.
    facts.images[0].heads = (TARGET..TARGET + PAGE).collect();
    let staged = stage_sources(
        &domain,
        &census,
        &(TARGET..TARGET + PAGE),
        Some((&request, &facts)),
        vec![map(BASE), map(TARGET)],
        until,
    )
    .unwrap();
    let fresh = &staged.images()[1];
    assert_eq!(fresh.snapshot.bytes(), request.images()[0].bytes());
    assert_eq!(fresh.entries.heads().len(), PAGE as usize);
    assert_ne!(fresh.snapshot.mapping, domain.images[1].snapshot.mapping);
    assert_ne!(
        fresh.core_identity.source,
        domain.images[1].core_identity.source
    );
    assert_eq!(
        staged.images()[0].snapshot.mapping,
        domain.images[0].snapshot.mapping
    );
    assert_eq!(
        staged.images()[0].entries.resumes(),
        &BTreeMap::from([(BASE, BTreeSet::from([ResumeKind::ParkedThread]))])
    );
    assert_eq!(staged.images()[0].entries.generation(), Generation(1));
    let metadata =
        super::super::super::transitions::mapping_request_storage_bytes(&request, false).unwrap();
    let with_payload =
        super::super::super::transitions::mapping_request_storage_bytes(&request, true).unwrap();
    assert_eq!(with_payload - metadata, request.images()[0].bytes().len());
    let reply_bytes =
        super::super::super::transitions::mapping_reply_storage_bytes(&facts).unwrap();
    assert!(reply_bytes >= PAGE as usize * 64);
    let staged_bytes =
        super::super::super::transitions::mapping_staged_storage_bytes(&staged).unwrap();
    assert!(staged_bytes >= staged.catalog_bytes() + 2 * PAGE as usize);
    assert_eq!(domain.images[1].snapshot.bytes()[0], 0x90);
    assert_eq!(unchanged(&census), before);
}

#[test]
fn incomplete_unrelated_inventory_and_any_removed_active_origin_refuse() {
    let domain = domain(true);
    let (census, _) = census(BASE);
    let before = unchanged(&census);
    for maps in [
        vec![map(TARGET)],
        vec![
            MemoryMapping {
                file_offset: PAGE,
                ..map(BASE)
            },
            map(TARGET),
        ],
    ] {
        refused(
            stage_sources(
                &domain,
                &census,
                &(TARGET..TARGET + PAGE),
                None,
                maps,
                deadline(),
            ),
            "mapping source replacement changes an unaffected descriptor",
        );
    }
    for maps in [
        vec![map(BASE), map(TARGET), map(0xa00000)],
        vec![
            map(BASE),
            MemoryMapping {
                end: TARGET + 2 * PAGE,
                ..map(TARGET)
            },
        ],
        vec![map(BASE), map(TARGET), map(TARGET + PAGE)],
    ] {
        refused(
            stage_sources(
                &domain,
                &census,
                &(TARGET..TARGET + PAGE),
                None,
                maps,
                deadline(),
            ),
            "mapping logical executable inventory differs",
        );
    }
    let missing = self::domain(false);
    refused(
        stage_sources(
            &missing,
            &census,
            &(TARGET..TARGET + PAGE),
            None,
            vec![map(BASE), map(TARGET)],
            deadline(),
        ),
        "mapping logical executable inventory differs",
    );
    let (target_census, _) = self::census(TARGET);
    let target_before = unchanged(&target_census);
    refused(
        stage_sources(
            &domain,
            &target_census,
            &(TARGET..TARGET + PAGE),
            None,
            vec![map(BASE)],
            deadline(),
        ),
        "dynamic continuation missing source image",
    );
    assert_eq!(unchanged(&target_census), target_before);
    assert_eq!(unchanged(&census), before);
    assert_eq!(domain.generation, 0);
}

#[test]
fn foreign_stale_and_malformed_capture_never_stage_or_mutate_the_old_domain() {
    let domain = domain(false);
    let (census, observed) = census(BASE);
    let before = unchanged(&census);
    for row in 0..10 {
        let until = deadline();
        let (mut request, mut facts) = capture(&observed, until);
        match row {
            0 => request.token.id.session += 1,
            1 => request.token.capture_stop.sequence += 1,
            2 => request.token.task.generation = 1,
            3 => request.token.candidate_epoch = 2,
            4 => request.token.until += Duration::from_secs(1),
            5 => {
                facts.images[0].heads.insert(TARGET + PAGE);
            }
            6 => {
                Arc::get_mut(&mut request.images).unwrap()[0]
                    .quarantined
                    .permissions = "r-xp".into();
            }
            7 => {
                Arc::get_mut(&mut request.images).unwrap()[0].lower_neighbor =
                    Some(map(TARGET - PAGE));
            }
            8 => {
                Arc::get_mut(&mut request.images).unwrap()[0].mapping_incarnation = 0;
            }
            9 => {
                Arc::get_mut(&mut request.images).unwrap()[0].bytes =
                    vec![0x90; PAGE as usize - 1].into();
            }
            _ => unreachable!(),
        };
        let expected = if row <= 4 {
            "mapping source capture differs from current census"
        } else if row == 5 {
            "dynamic source reply head lies outside capture"
        } else {
            "mapping source capture is not an isolated complete NX image"
        };
        refused(
            stage_sources(
                &domain,
                &census,
                &(TARGET..TARGET + PAGE),
                Some((&request, &facts)),
                vec![map(BASE), map(TARGET)],
                until,
            ),
            expected,
        );
        assert_eq!(unchanged(&census), before);
        assert_eq!(domain.images.len(), 1);
        assert_eq!(domain.generation, 0);
    }
}
