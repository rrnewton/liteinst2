//! Supplied bookkeeping only: no native stop, seal, completion or release.
use super::*;
use crate::lifecycle::{LifecycleRegistry, Limits as LifecycleLimits};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(super) const PANIC: u32 = 0x4445_5343;
#[derive(Clone, Copy)]
pub(super) struct Fault {
    pub(super) before: Option<usize>,
    pub(super) after: Option<usize>,
}
pub(super) fn before(fault: Option<Fault>, index: usize) -> Result<(), CensusConsumerError> {
    if fault.is_some_and(|v| v.before == Some(index)) {
        Err(CensusConsumerError::Allocation)
    } else {
        Ok(())
    }
}
pub(super) fn after(fault: Option<Fault>, index: usize) {
    if fault.is_some_and(|v| v.after == Some(index)) {
        std::panic::panic_any(PANIC);
    }
}

pub(super) fn seeded() -> ResumeCensus {
    let registry = LifecycleRegistry::new(LifecycleLimits::default(), 23, 0x401000).unwrap();
    let task = registry.root_task();
    let record = registry.task(task).unwrap();
    let registers = RegisterSnapshot {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        rbp: 11,
        rbx: 10,
        r11: 9,
        r10: 8,
        r9: 7,
        r8: 6,
        rax: 5,
        rcx: 4,
        rdx: 3,
        rsi: 2,
        rdi: 1,
        orig_rax: u64::MAX,
        rip: 0x401000,
        cs: 0x33,
        eflags: 0x202,
        rsp: 0x600000,
        ss: 0x2b,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    };
    let observed = ObservedStop {
        token: DynamicStop {
            session: 17,
            sequence: 1,
            tid: record.tid,
            task: Some(task),
        },
        task: DynamicTask {
            task,
            process: record.process,
            address_space: record.address_space,
            generation: 0,
        },
        logical_pc: registers.rip,
        registers,
        xstate: vec![0x5a; 832],
        signal_mask: 0x200,
        phase: StopPhase::UserCheckpoint,
        signal: None,
    };
    let mut census = ResumeCensus::new(
        17,
        record.address_space,
        0,
        Limits {
            epochs: 256,
            source_fact_bytes: 64 * 1024 * 1024,
            reports: 4096,
            origins: 4096,
            witnesses: 4096,
            plan_history: 4096,
        },
    )
    .unwrap();
    let token = census
        .reserve(BudgetCharge {
            origins: 1,
            source_fact_bytes: 16384,
            ..BudgetCharge::default()
        })
        .unwrap();
    census
        .insert(
            token,
            OriginKind::CurrentHeldPc,
            observed.logical_pc,
            observed,
        )
        .unwrap();
    census.finish_reservation(token).unwrap();
    census
}

fn planned() -> (ResumeCensus, PreparedConsumerDescriptors, Reservation) {
    let mut census = seeded();
    let mut out = PreparedConsumerDescriptors::empty();
    out.plan(
        &census,
        ConsumerDescriptorDemand {
            origins: 11,
            history: 83,
        },
    )
    .unwrap();
    let token = census
        .reserve(BudgetCharge {
            source_fact_bytes: out.reservation_bytes().unwrap(),
            ..BudgetCharge::default()
        })
        .unwrap();
    (census, out, token)
}
fn payloads(census: &ResumeCensus) -> [Identity; 2] {
    [
        Identity::of(&census.state.origins[0].row.initial.xstate),
        Identity::of(&census.state.origins[0].current.xstate),
    ]
}
fn settle(census: &mut ResumeCensus, out: &PreparedConsumerDescriptors, token: Reservation) {
    census
        .account_external(
            token,
            BudgetCharge {
                source_fact_bytes: out.allocated_bytes(Some(census)).unwrap(),
                ..BudgetCharge::default()
            },
        )
        .unwrap();
    census.finish_reservation(token).unwrap();
}

#[test]
fn consumer_descriptor_exact_preallocation_preserves_owned_prefix() {
    let (mut census, mut out, token) = planned();
    let initial = census.state.origins[0].row.clone();
    let current = census.state.origins[0].current.clone();
    let state = CensusStamp::of(&census);
    let payload = payloads(&census);
    let old = out.shape.unwrap().old;
    out.allocate_in_place(&mut census, token).unwrap();
    assert_eq!(census.state.origins[0].row, initial);
    assert_eq!(census.state.origins[0].current, current);
    assert_eq!(payloads(&census), payload);
    assert_eq!(census.state.charged, state.charged);
    assert_eq!(census.state.used, state.used);
    assert_eq!(census.state.reservation, state.reservation);
    assert_eq!(
        Identity::of(&out.origins),
        Identity {
            length: 0,
            ..old[0]
        }
    );
    assert_eq!(
        Identity::of(&out.history),
        Identity {
            length: 0,
            ..old[1]
        }
    );
    assert_eq!(census.state.origins.capacity(), 12);
    assert_eq!(census.state.history.capacity(), 83);
    assert_eq!(
        out.allocated_bytes(Some(&census)).unwrap(),
        out.reservation_bytes().unwrap()
    );
    out.require_complete(&census).unwrap();
    settle(&mut census, &out, token);
    let retained = out.retention_snapshot(Some(&census)).unwrap();
    out.mark_aborted();
    out.require_retention(Some(&census), &retained).unwrap();
    assert_eq!(
        out.allocate_in_place(&mut census, token),
        Err(CensusConsumerError::Reused)
    );
}

#[test]
fn consumer_descriptor_future_reserves_keep_exact_backings() {
    let (mut census, mut out, token) = planned();
    out.allocate_in_place(&mut census, token).unwrap();
    settle(&mut census, &out, token);
    let allocated = out.installed.unwrap();
    let original = census.state.origins[0].row.clone();
    let original_payload = payloads(&census);
    // These descriptive append rows exercise the real Vec/reserve mechanism;
    // they are not production commits or authentic seven-transition histories.
    for (origins, witnesses) in [
        (1, 7),
        (1, 8),
        (1, 7),
        (1, 7),
        (1, 7),
        (1, 7),
        (1, 7),
        (1, 7),
        (1, 8),
        (1, 7),
        (1, 7),
        (0, 4),
    ] {
        let token = census
            .reserve(BudgetCharge {
                origins,
                witnesses,
                ..BudgetCharge::default()
            })
            .unwrap();
        for _ in 0..origins {
            let mut row = original.clone();
            row.id.serial = census.state.next_serial;
            census.state.next_serial += 1;
            census.state.origins.push(StoredOrigin {
                current: row.initial.clone(),
                row,
                active: false,
                frame: None,
                runtime_kernel: None,
                ordinary_history: None,
            });
        }
        for _ in 0..witnesses {
            census.state.history.push(HistoryRecord::Refreshed {
                origin: original.id,
                before: original.initial.clone(),
                after: original.initial.clone(),
            });
        }
        census.finish_reservation(token).unwrap();
        out.require_complete(&census).unwrap();
        assert_eq!(census.state.origins.as_ptr() as usize, allocated[0].pointer);
        assert_eq!(census.state.history.as_ptr() as usize, allocated[1].pointer);
        assert_eq!(census.state.origins.capacity(), allocated[0].capacity);
        assert_eq!(census.state.history.capacity(), allocated[1].capacity);
        assert_eq!(payloads(&census), original_payload);
        assert_eq!(census.state.origins[0].row, original);
    }
    assert_eq!(
        (census.state.origins.len(), census.state.history.len()),
        (12, 83)
    );
    let retained = out.retention_snapshot(Some(&census)).unwrap();
    out.require_retention(Some(&census), &retained).unwrap();
    // Control: without preallocation, the same real reserve frontier grows.
    let mut baseline = seeded();
    let before = Identity::of(&baseline.state.history);
    let token = baseline
        .reserve(BudgetCharge {
            witnesses: 83,
            ..BudgetCharge::default()
        })
        .unwrap();
    assert_ne!(
        Identity::of(&baseline.state.history).capacity,
        before.capacity
    );
    baseline.finish_reservation(token).unwrap();
    let mut epoch = seeded();
    let token = epoch
        .reserve(BudgetCharge {
            witnesses: 7,
            epochs: 1,
            ..BudgetCharge::default()
        })
        .unwrap();
    assert_eq!(epoch.state.history.capacity(), 8);
    epoch.finish_reservation(token).unwrap();
}

#[test]
fn consumer_descriptor_wrong_identity_token_and_reuse_refuse() {
    for foreign_census in [false, true] {
        let (mut census, mut out, token) = planned();
        let mut other = seeded();
        let other_token = other
            .reserve(BudgetCharge {
                source_fact_bytes: out.reservation_bytes().unwrap(),
                ..BudgetCharge::default()
            })
            .unwrap();
        let before = CensusStamp::of(&census);
        let failed = if foreign_census {
            out.allocate_in_place(&mut other, token)
        } else {
            out.allocate_in_place(&mut census, other_token)
        };
        assert!(failed.is_err());
        assert_eq!(CensusStamp::of(&census), before);
        assert_eq!(out.origins.capacity(), 0);
        assert_eq!(out.history.capacity(), 0);
        assert!(out.progress.first_failure.is_some());
        assert_eq!(
            out.allocate_in_place(&mut census, token),
            Err(CensusConsumerError::Reused)
        );
        census.finish_reservation(token).unwrap();
        other.finish_reservation(other_token).unwrap();
    }
    let census = seeded();
    for demand in [
        ConsumerDescriptorDemand {
            origins: usize::MAX,
            history: 1,
        },
        ConsumerDescriptorDemand {
            origins: 1,
            history: usize::MAX,
        },
        ConsumerDescriptorDemand {
            origins: 0,
            history: 1,
        },
    ] {
        let mut out = PreparedConsumerDescriptors::empty();
        assert!(out.plan(&census, demand).is_err());
        assert!(out.plan(&census, demand).is_err());
        assert_eq!(out.origins.capacity(), 0);
    }
    let (mut census, mut out, token) = planned();
    census.finish_reservation(token).unwrap();
    let short = census
        .reserve(BudgetCharge {
            source_fact_bytes: out.reservation_bytes().unwrap() - 1,
            ..BudgetCharge::default()
        })
        .unwrap();
    assert_eq!(
        out.allocate_in_place(&mut census, short),
        Err(CensusConsumerError::Census(
            CensusError::ReservationExhausted
        ))
    );
    assert_eq!(out.progress.allocated, [false; 2]);
    census.finish_reservation(short).unwrap();
    assert!(out.allocated_bytes(None).is_err());
}

#[test]
fn consumer_descriptor_allocation_errors_retain_each_prefix() {
    for index in 0..2 {
        let (mut census, mut out, token) = planned();
        let before = CensusStamp::of(&census);
        let initial = census.state.origins[0].row.clone();
        let payload = payloads(&census);
        out.fault = Some(Fault {
            before: Some(index),
            after: None,
        });
        assert_eq!(
            out.allocate_in_place(&mut census, token),
            Err(CensusConsumerError::Allocation)
        );
        assert_eq!(out.progress.allocated, [index == 1, false]);
        assert_eq!(out.origins.capacity(), if index == 1 { 12 } else { 0 });
        assert_eq!(out.history.capacity(), 0);
        assert_eq!(CensusStamp::of(&census), before);
        assert_eq!(census.state.origins[0].row, initial);
        assert_eq!(payloads(&census), payload);
        let actual = out.allocated_bytes(Some(&census)).unwrap();
        assert_eq!(
            actual,
            size_of::<PreparedConsumerDescriptors>()
                + bytes(
                    before.descriptors[0].capacity + out.origins.capacity(),
                    before.descriptors[1].capacity
                )
                .unwrap()
        );
        out.mark_aborted();
        assert_eq!(
            out.progress.first_failure,
            Some(CensusConsumerError::Allocation)
        );
        settle(&mut census, &out, token);
        let prefix = out.retention_snapshot(Some(&census)).unwrap();
        out.require_retention(Some(&census), &prefix).unwrap();
        assert!(out.require_complete(&census).is_err());
    }
}

#[test]
fn consumer_descriptor_allocation_unwinds_retain_each_prefix() {
    for index in 0..2 {
        let (mut census, mut out, token) = planned();
        let before = CensusStamp::of(&census);
        let initial = census.state.origins[0].row.clone();
        out.fault = Some(Fault {
            before: None,
            after: Some(index),
        });
        let panic = catch_unwind(AssertUnwindSafe(|| {
            out.allocate_in_place(&mut census, token)
        }))
        .unwrap_err();
        assert_eq!(*panic.downcast::<u32>().unwrap(), PANIC);
        assert_eq!(out.progress.allocated, [true, index == 1]);
        assert_eq!(CensusStamp::of(&census), before);
        assert_eq!(census.state.origins[0].row, initial);
        assert_eq!(out.origins.capacity(), 12);
        assert_eq!(out.history.capacity(), if index == 1 { 83 } else { 0 });
        out.mark_aborted();
        let progress = out.progress;
        assert_eq!(progress.first_failure, Some(CensusConsumerError::Aborted));
        assert_eq!(
            out.allocate_in_place(&mut census, token),
            Err(CensusConsumerError::Reused)
        );
        assert_eq!(out.progress, progress);
        settle(&mut census, &out, token);
        let prefix = out.retention_snapshot(Some(&census)).unwrap();
        out.require_retention(Some(&census), &prefix).unwrap();
    }
}

#[test]
fn consumer_descriptor_retention_rejects_changed_headers_and_owners() {
    let (mut census, mut out, token) = planned();
    out.allocate_in_place(&mut census, token).unwrap();
    settle(&mut census, &out, token);
    let original = out.retention_snapshot(Some(&census)).unwrap();
    let changes: &[fn(&mut ConsumerDescriptorRetention)] = &[
        |v| v.census.as_mut().unwrap().identity.identity ^= 1,
        |v| v.census.as_mut().unwrap().identity.session ^= 1,
        |v| v.census.as_mut().unwrap().identity.generation ^= 1,
        |v| v.census.as_mut().unwrap().next_serial ^= 1,
        |v| v.census.as_mut().unwrap().descriptors[0].pointer ^= 1,
        |v| v.census.as_mut().unwrap().descriptors[0].length ^= 1,
        |v| v.census.as_mut().unwrap().descriptors[0].capacity ^= 1,
        |v| v.census.as_mut().unwrap().descriptors[1].pointer ^= 1,
        |v| v.census.as_mut().unwrap().descriptors[1].length ^= 1,
        |v| v.census.as_mut().unwrap().descriptors[1].capacity ^= 1,
        |v| v.owners[0].pointer ^= 1,
        |v| v.owners[1].capacity ^= 1,
        |v| v.progress.complete = false,
        |v| v.token.as_mut().unwrap().serial ^= 1,
        |v| v.installed.as_mut().unwrap()[0].pointer ^= 1,
        |v| v.shape.as_mut().unwrap().target[0] ^= 1,
    ];
    for change in changes {
        let mut altered = original;
        change(&mut altered);
        assert_eq!(
            out.require_retention(Some(&census), &altered),
            Err(CensusConsumerError::Mismatch)
        );
        out.require_retention(Some(&census), &original).unwrap();
    }
    for axis in 0..6 {
        for charged in [false, true] {
            let mut altered = original;
            let stamp = altered.census.as_mut().unwrap();
            let value = if charged {
                &mut stamp.charged
            } else {
                &mut stamp.used
            };
            match axis {
                0 => value.epochs += 1,
                1 => value.source_fact_bytes += 1,
                2 => value.reports += 1,
                3 => value.origins += 1,
                4 => value.witnesses += 1,
                _ => value.plan_history += 1,
            }
            assert_eq!(
                out.require_retention(Some(&census), &altered),
                Err(CensusConsumerError::Mismatch)
            );
        }
    }
    let mut replacement = exact_storage::empty_vec(census.state.origins.capacity()).unwrap();
    replacement.append(&mut census.state.origins);
    let original_allocation = std::mem::replace(&mut census.state.origins, replacement);
    assert!(out.require_complete(&census).is_err());
    let mut restored = original_allocation;
    restored.append(&mut census.state.origins);
    census.state.origins = restored;
    out.require_retention(Some(&census), &original).unwrap();
    assert!(out.require_retention(None, &original).is_err());
}
