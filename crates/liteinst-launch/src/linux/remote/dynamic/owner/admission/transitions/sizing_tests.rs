//! Pure sizing controls, not native extent certificates or execution evidence.
//! The old transitions/tests.rs remains unchanged. These cases retain every
//! metadata/count dimension and vary only a supplied logical XSTATE extent.
use super::*;

const BASE: u64 = 0x40_0000;

fn geometry(pages: usize) -> Domain {
    let mut bytes = vec![0x90; pages * PAGE as usize];
    let mut heads = BTreeSet::new();
    for page in 0..pages {
        let offset = page * PAGE as usize + 32;
        bytes[offset..offset + 2].copy_from_slice(&[0x0f, 0xa2]);
        heads.insert(BASE + offset as u64);
    }
    let mapping = MemoryMapping {
        start: BASE,
        end: BASE + bytes.len() as u64,
        permissions: "r-xp".into(),
        file_offset: 0,
        pathname: Some("retained-sizing-source".into()),
    };
    Domain::new(
        vec![ImageFacts {
            start: BASE,
            bytes: bytes.clone(),
            heads,
        }],
        vec![mapping],
        &DynamicAdmissionOptions::default(),
        Instant::now() + Duration::from_secs(3),
        |address, len| {
            assert_eq!((address, len), (BASE, bytes.len()));
            Ok(bytes.clone())
        },
    )
    .unwrap()
}

fn non_payload(charge: BudgetCharge) -> BudgetCharge {
    BudgetCharge {
        source_fact_bytes: 0,
        ..charge
    }
}

fn transaction(
    payload: StatePayload,
    domain: &Domain,
    frames: usize,
    successors: usize,
    rebind: bool,
    plans: usize,
) -> BudgetCharge {
    combine(
        combine(
            effect_charge_with_payload(payload, domain, 1 + frames, 1, successors, rebind, plans)
                .unwrap(),
            refresh_charge_with_payload(payload, 1).unwrap(),
        )
        .unwrap(),
        combine(
            frame_effect_charge_with_payload(payload, frames, 1, successors, rebind, plans)
                .unwrap(),
            frame_refresh_charge_with_payload(payload, frames, 1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

fn limits_for(charge: BudgetCharge) -> census::Limits {
    census::Limits {
        // The constructor's initial epoch is a real, separate lifetime debit.
        epochs: charge.epochs + 1,
        source_fact_bytes: charge.source_fact_bytes,
        reports: charge.reports,
        origins: charge.origins,
        witnesses: charge.witnesses,
        plan_history: charge.plan_history,
    }
}

fn census(limits: census::Limits) -> ResumeCensus {
    let registry = crate::lifecycle::LifecycleRegistry::new_after_exec_syscall_exit(
        crate::lifecycle::Limits {
            tasks: 1,
            processes: 1,
            address_spaces: 1,
            obligations: 8,
        },
        100,
        BASE,
    )
    .unwrap();
    let space = registry.task(registry.root_task()).unwrap().address_space;
    ResumeCensus::new(17, space, 0, limits).unwrap()
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
fn retained_extent_geometry_is_closed_and_does_not_certify_a_native_read() {
    for bytes in [512, 520, 1024, 4096, 11008, MAX_XSTATE - 8] {
        let payload = StatePayload::from_retained_extent(bytes).unwrap();
        assert_eq!(payload.xstate_bytes, bytes);
        assert_eq!(
            state_bound_with_payload(payload).unwrap(),
            size_of::<ObservedStop>() + bytes
        );
    }
    for bytes in [
        0,
        1,
        504,
        511,
        513,
        519,
        65535,
        MAX_XSTATE,
        MAX_XSTATE + 8,
        usize::MAX,
    ] {
        assert!(matches!(
            StatePayload::from_retained_extent(bytes),
            Err(GateError::Refused(
                "signal retained XSTATE extent geometry differs"
            ))
        ));
    }
    assert_eq!(StatePayload::maximum().xstate_bytes, 65536);
    assert_eq!(
        DynamicAdmissionLimits::default().source_fact_bytes,
        64 * 1024 * 1024
    );
}

#[test]
fn maximum_payload_preserves_all_legacy_helpers_and_full_metadata() {
    let payload = StatePayload::maximum();
    assert_eq!(state_bound().unwrap(), size_of::<ObservedStop>() + 65536);
    assert_eq!(
        origin_bound().unwrap(),
        2 * state_bound().unwrap()
            + size_of::<census::OriginRow>()
            + size_of::<ObservedStop>()
            + 64
    );
    assert_eq!(
        consume_bound().unwrap(),
        8 * state_bound().unwrap()
            + size_of::<OwnerConsumption>()
            + size_of::<census::HistoryRecord>()
            + 1024
    );
    for count in [0, 1, 2, 4, 8, 12] {
        assert_eq!(
            refresh_charge(count).unwrap(),
            BudgetCharge {
                source_fact_bytes: count
                    * (2 * state_bound().unwrap() + 65536 + size_of::<census::HistoryRecord>()),
                witnesses: count,
                ..BudgetCharge::default()
            }
        );
        assert_eq!(
            refresh_charge(count).unwrap(),
            refresh_charge_with_payload(payload, count).unwrap()
        );
    }
    for pages in [1, 5] {
        let domain = geometry(pages);
        for tasks in 1..=2 {
            assert_eq!(
                rebind_charge(&domain, 3, 1, tasks).unwrap(),
                rebind_charge_with_payload(payload, &domain, 3, 1, tasks).unwrap()
            );
            for successors in 0..=tasks {
                for rebind in [false, true] {
                    for plans in 0..=1 {
                        assert_eq!(
                            effect_charge(&domain, 3, tasks, successors, rebind, plans).unwrap(),
                            effect_charge_with_payload(
                                payload, &domain, 3, tasks, successors, rebind, plans
                            )
                            .unwrap()
                        );
                        for frames in 0..=2 {
                            assert_eq!(
                                frame_effect_charge(frames, tasks, successors, rebind, plans)
                                    .unwrap(),
                                frame_effect_charge_with_payload(
                                    payload, frames, tasks, successors, rebind, plans
                                )
                                .unwrap()
                            );
                            assert_eq!(
                                frame_refresh_charge(frames, 12).unwrap(),
                                frame_refresh_charge_with_payload(payload, frames, 12).unwrap()
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn exact_extent_delta_changes_only_state_payload_not_source_or_count_geometry() {
    for (low, high) in [(512, 520), (512, 11008), (11008, 65528)] {
        let small = StatePayload::from_retained_extent(low).unwrap();
        let large = StatePayload::from_retained_extent(high).unwrap();
        for pages in [1, 5] {
            let domain = geometry(pages);
            for tasks in 1..=2 {
                for successors in 0..=tasks {
                    for rebind in [false, true] {
                        for plans in 0..=1 {
                            let a = effect_charge_with_payload(
                                small, &domain, 3, tasks, successors, rebind, plans,
                            )
                            .unwrap();
                            let b = effect_charge_with_payload(
                                large, &domain, 3, tasks, successors, rebind, plans,
                            )
                            .unwrap();
                            // Independent expanded coefficient: origins/consumption=10s,
                            // external states=8, refresh+probe/copies=19t, settling=6t².
                            let coefficient = if successors == 0 {
                                1
                            } else {
                                10 * successors + 8 + 19 * tasks + 6 * tasks * tasks
                            } + 6 * tasks * (usize::from(rebind) + plans);
                            assert_eq!(
                                b.source_fact_bytes - a.source_fact_bytes,
                                coefficient * (high - low)
                            );
                            assert_eq!(non_payload(a), non_payload(b));
                            // The non-state remainder retains exact source/plan/metadata bytes.
                            assert_eq!(
                                a.source_fact_bytes - coefficient * low,
                                b.source_fact_bytes - coefficient * high
                            );
                        }
                    }
                }
                let a = rebind_charge_with_payload(small, &domain, 3, 1, tasks).unwrap();
                let b = rebind_charge_with_payload(large, &domain, 3, 1, tasks).unwrap();
                assert_eq!(
                    b.source_fact_bytes - a.source_fact_bytes,
                    6 * tasks * (high - low)
                );
                assert_eq!(non_payload(a), non_payload(b));
            }
        }
    }
}

#[test]
fn full_frame_payload_and_refresh_multiplicities_remain_maximum_sized() {
    for bytes in [512, 11008, MAX_XSTATE - 8] {
        let payload = StatePayload::from_retained_extent(bytes).unwrap();
        for frames in 0..=2 {
            for passes in [0, 1, 2, 6, 9, 10, 12] {
                let count = frames * passes;
                let actual = frame_refresh_charge_with_payload(payload, frames, passes).unwrap();
                assert_eq!(
                    actual,
                    BudgetCharge {
                        witnesses: count,
                        source_fact_bytes: count
                            * (3 * bytes
                                + 2 * size_of::<ObservedStop>()
                                + size_of::<census::HistoryRecord>()
                                + size_of::<census::FrameFacts>()
                                + 65536
                                + 4096
                                + 256),
                        ..BudgetCharge::default()
                    }
                );
            }
            for tasks in 1..=2 {
                for successors in 0..=tasks {
                    for rebind in [false, true] {
                        for plans in 0..=1 {
                            let passes = usize::from(successors != 0)
                                + 2 * usize::from(rebind)
                                + 2 * plans
                                + if successors == 0 { 0 } else { 4 + 2 * tasks };
                            assert_eq!(
                                frame_effect_charge_with_payload(
                                    payload, frames, tasks, successors, rebind, plans
                                )
                                .unwrap(),
                                frame_refresh_charge_with_payload(payload, frames, passes).unwrap()
                            );
                        }
                    }
                }
            }
        }
    }
}

fn trajectory(
    payload: StatePayload,
    domain: &Domain,
    altstack: bool,
    edited: bool,
) -> BudgetCharge {
    // ONLY the startup payload lower bound is used here. All transition/source
    // metadata is retained below; omitted startup metadata and kernel-attempt
    // prefixes are positive and cannot turn this into an acceptance certificate.
    let mut charge = BudgetCharge {
        source_fact_bytes: 224 * MAX_XSTATE,
        ..BudgetCharge::default()
    };
    for (n, successors, rebind, plans) in [
        (4, 1, true, 0),
        (3, 0, false, 1),
        (2, 0, false, 0),
        (2, 1, true, 1),
    ] {
        for _ in 0..n {
            charge = combine(
                charge,
                transaction(payload, domain, 0, successors, rebind, plans),
            )
            .unwrap();
        }
    }
    if altstack {
        for (successors, rebind, plans) in
            [(1, true, 0), (0, false, 1), (0, false, 0), (1, true, 1)]
        {
            charge = combine(
                charge,
                transaction(payload, domain, 0, successors, rebind, plans),
            )
            .unwrap();
        }
    }
    let frames = if edited { 2 } else { 1 };
    charge = combine(
        charge,
        signal_delivery_charge_with_payload(payload, domain, 1, frames).unwrap(),
    )
    .unwrap();
    for (n, successors, rebind, plans) in [
        (2, 0, false, 0),
        (1, 1, true, 1),
        (2, 1, true, 0),
        (2, 0, false, 1),
    ] {
        for _ in 0..n {
            charge = combine(
                charge,
                transaction(payload, domain, frames, successors, rebind, plans),
            )
            .unwrap();
        }
    }
    charge = combine(
        charge,
        signal_return_charge_with_payload(payload, domain, 1 + frames, frames).unwrap(),
    )
    .unwrap();
    if edited {
        for (n, successors, rebind, plans) in [
            (2, 1, true, 0),
            (1, 0, false, 1),
            (1, 0, false, 0),
            (1, 1, true, 1),
        ] {
            for _ in 0..n {
                charge = combine(
                    charge,
                    transaction(payload, domain, 0, successors, rebind, plans),
                )
                .unwrap();
            }
        }
    }
    charge
}

#[test]
fn four_trajectory_reservations_preserve_original_failure_floor_and_parametric_delta() {
    let domain = geometry(5);
    // The inherited-nonzero case has the same session path as ordinary; its
    // separately owned predecessor is not charged to the application census.
    for (name, altstack, edited, old_units, coefficient) in [
        ("ordinary", false, false, 1123, 840),
        ("altstack", true, false, 1247, 964),
        ("edited-altstack", true, true, 1649, 1310),
        ("inherited-nonzero", false, false, 1123, 840),
    ] {
        let old = trajectory(StatePayload::maximum(), &domain, altstack, edited);
        assert!(old.source_fact_bytes > old_units * MAX_XSTATE, "{name}");
        assert!(
            old.source_fact_bytes > DynamicAdmissionLimits::default().source_fact_bytes,
            "{name}"
        );
        for bytes in [512, 11008, MAX_XSTATE - 8] {
            let new = trajectory(
                StatePayload::from_retained_extent(bytes).unwrap(),
                &domain,
                altstack,
                edited,
            );
            assert_eq!(
                old.source_fact_bytes - new.source_fact_bytes,
                coefficient * (MAX_XSTATE - bytes),
                "{name}"
            );
            assert_eq!(non_payload(old), non_payload(new), "{name}");
        }
    }
}

#[test]
fn every_full_budget_dimension_refuses_one_short_before_mutation() {
    let domain = geometry(5);
    let charge = transaction(
        StatePayload::from_retained_extent(11008).unwrap(),
        &domain,
        2,
        1,
        true,
        1,
    );
    for dimension in 0..6 {
        let mut limits = limits_for(charge);
        match dimension {
            0 => limits.epochs -= 1,
            1 => limits.source_fact_bytes -= 1,
            2 => limits.reports -= 1,
            // Keep a positive limit by asking for two origins in this one case.
            3 => limits.origins = charge.origins,
            4 => limits.witnesses -= 1,
            5 => limits.plan_history = charge.plan_history,
            _ => unreachable!(),
        }
        let mut request = charge;
        if dimension == 3 {
            request.origins += 1;
        }
        if dimension == 5 {
            request.plan_history += 1;
        }
        let mut census = census(limits);
        let before = unchanged(&census);
        assert_eq!(census.reserve(request), Err(census::CensusError::Capacity));
        assert_eq!(unchanged(&census), before);
    }
}

#[test]
fn certified_payload_reservation_keeps_exact_remaining_check_and_no_refund() {
    let domain = geometry(5);
    let payload = StatePayload::from_retained_extent(11008).unwrap();
    let charge = transaction(payload, &domain, 2, 1, true, 1);
    let mut census = census(limits_for(charge));
    let before_used = census.used();
    let reservation = census.reserve(charge).unwrap();
    let before = unchanged(&census);
    let larger = transaction(
        StatePayload::from_retained_extent(11016).unwrap(),
        &domain,
        2,
        1,
        true,
        1,
    );
    assert_eq!(
        census.check_reserved(reservation, larger),
        Err(census::CensusError::ReservationExhausted)
    );
    assert_eq!(
        census.account_external(
            reservation,
            BudgetCharge {
                source_fact_bytes: charge.source_fact_bytes + 1,
                ..BudgetCharge::default()
            }
        ),
        Err(census::CensusError::ReservationExhausted)
    );
    assert_eq!(unchanged(&census), before);
    assert_eq!(census.check_reserved(reservation, charge), Ok(()));
    census.finish_reservation(reservation).unwrap();
    assert_eq!(unchanged(&census), before);
    assert_eq!(census.used(), before_used);
    assert_eq!(
        census.reserve(BudgetCharge {
            source_fact_bytes: 1,
            ..BudgetCharge::default()
        }),
        Err(census::CensusError::Capacity)
    );
    assert_eq!(unchanged(&census), before);
    assert_eq!(
        DynamicAdmissionLimits::default().source_fact_bytes,
        64 * 1024 * 1024
    );
}

#[test]
fn checked_arithmetic_refuses_unrepresentable_retained_shapes() {
    for payload in [
        StatePayload::maximum(),
        StatePayload::from_retained_extent(512).unwrap(),
    ] {
        for result in [
            refresh_charge_with_payload(payload, usize::MAX),
            frame_refresh_charge_with_payload(payload, usize::MAX, 2),
            frame_refresh_charge_with_payload(payload, 2, usize::MAX),
            frame_effect_charge_with_payload(payload, 2, 1, 1, true, usize::MAX),
        ] {
            assert!(matches!(
                result,
                Err(GateError::Refused(
                    "dynamic transition evidence size overflows"
                ))
            ));
        }
    }
}
