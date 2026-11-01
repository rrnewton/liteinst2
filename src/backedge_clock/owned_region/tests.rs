use super::*;
use crate::backedge_clock::{BackedgeClock, BackedgeClockRegion, CLOCK_PAGE_BYTES, ClockMode};
use crate::contracts::{CodeIdentity, SourceIdentity};
use crate::controls::{ControlIdentity, ControlWriter, ProbeControl};
use crate::trampoline::{HookContext, TrampolinePlan};
use std::sync::Arc;

const BASE: u64 = 0x100000;

unsafe extern "C" fn callback(_: *mut HookContext, _: ControlIdentity<'_>) {}
unsafe extern "C" fn ordinary(_: *mut HookContext) {}

fn clock() -> BackedgeClock {
    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            CLOCK_PAGE_BYTES,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    // Only a private data page is mapped. Authored source/image coordinates
    // below are encoder coordinates and are never executed by these controls.
    unsafe { BackedgeClock::from_owned_mapping(page as usize as u64, CLOCK_PAGE_BYTES) }.unwrap()
}

fn edge(bytes: &mut Vec<u8>, condition: Option<u8>, target: usize) -> usize {
    let site = bytes.len();
    if let Some(condition) = condition {
        bytes.extend([0x0f, 0x80 | condition]);
    } else {
        bytes.push(0xe9);
    }
    let displacement = i32::try_from(target as i64 - (bytes.len() + 4) as i64).unwrap();
    bytes.extend(displacement.to_le_bytes());
    site
}

fn two_edges(prefix: &[u8], conditions: [Option<u8>; 2]) -> (Vec<u8>, [usize; 2]) {
    let mut bytes = prefix.to_vec();
    let sites = conditions.map(|condition| {
        let target = bytes.len();
        bytes.extend([0x83, 0xc0, 1, 0x85, 0xc9]); // ADD EAX,1; TEST ECX,ECX
        bytes.extend([0x74, if condition.is_some() { 6 } else { 5 }]);
        edge(&mut bytes, condition, target)
    });
    bytes.push(0xc3);
    (bytes, sites)
}

// A distinct nested loop, not two independent single-site source plans.
fn nested() -> (Vec<u8>, [usize; 2]) {
    (
        vec![
            0x31, 0xc0, // XOR EAX,EAX
            0x41, 0xb8, 3, 0, 0, 0, // MOV R8D,3
            0xb9, 4, 0, 0, 0, // outer: MOV ECX,4
            0xff, 0xc0, 0xff, 0xc9, // inner: INC EAX; DEC ECX
            0x0f, 0x85, 0xf6, 0xff, 0xff, 0xff, // JNZ inner
            0x41, 0xff, 0xc8, // DEC R8D
            0x0f, 0x85, 0xe8, 0xff, 0xff, 0xff, // JNZ outer
            0xc3,
        ],
        [17, 26],
    )
}

fn admission(bytes: &[u8], sites: [usize; 2]) -> Result<[Option<u8>; 2], ClockError> {
    admit(bytes, BASE, sites.map(|offset| BASE + offset as u64)).map(|(_, kinds)| kinds)
}

fn identity(base: u64) -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([0x39; 32]),
        mapping: base,
        generation: 1,
    }
}

fn managed(base: u64, sites: [usize; 2]) -> [(u64, ProbeControl, ControlWriter); 2] {
    sites.map(|site| {
        let (control, writer) = ProbeControl::new_managed_bound(callback, true);
        (base + site as u64, control, writer)
    })
}

fn region(clock: &BackedgeClock, mode: ClockMode) -> BackedgeClockRegion {
    let (bytes, sites) = nested();
    let base = clock.address() + 0x10000;
    BackedgeClockRegion::new_owned_region(
        identity(base),
        base,
        &bytes,
        managed(base, sites),
        clock.clone(),
        mode,
    )
    .unwrap()
}

#[test]
fn owned_region_accepts_two_backedges_and_exact_scalar_forms() {
    for first in [Some(5), Some(15), Some(2), None] {
        for second in [Some(5), Some(15), Some(2), None] {
            let (bytes, sites) = two_edges(&[], [first, second]);
            assert_eq!(admission(&bytes, sites), Ok([first, second]));
        }
    }
    let scalars: &[&[u8]] = &[
        &[0xb0, 1],
        &[0xb4, 1],
        &[0xb8, 1, 0, 0, 0],
        &[0x48, 0xb8, 1, 0, 0, 0, 0, 0, 0, 0],
        &[0x45, 0x89, 0xd8],
        &[0x0f, 0xb6, 0xc8],
        &[0x31, 0xc0],
        &[0x83, 0xc0, 1],
        &[0x83, 0xd0, 1],
        &[0x83, 0xe8, 1],
        &[0x83, 0xe0, 1],
        &[0x83, 0xc8, 1],
        &[0x85, 0xc9],
        &[0x39, 0xc8],
        &[0xff, 0xc0],
        &[0x41, 0xff, 0xc8],
        &[0x90],
    ];
    for scalar in scalars {
        let (bytes, sites) = two_edges(scalar, [Some(5), Some(2)]);
        assert_eq!(
            admission(&bytes, sites),
            Ok([Some(5), Some(2)]),
            "{scalar:02x?}"
        );
    }
    let (bytes, sites) = nested();
    assert_eq!(admission(&bytes, sites), Ok([Some(5), Some(5)]));
    assert_eq!(
        crate::backedge_clock::owned_loop::admit(&bytes, BASE, BASE + sites[0] as u64),
        Err(ClockError::Source),
    );
}

#[test]
fn owned_region_size_and_forward_head_boundaries() {
    let (mut bytes, sites) = two_edges(&[], [Some(5), Some(15)]);
    bytes.pop();
    bytes.resize(79, 0x90);
    bytes.push(0xc3);
    assert_eq!(bytes.len(), 80);
    assert_eq!(admission(&bytes, sites), Ok([Some(5), Some(15)]));
    bytes.insert(bytes.len() - 1, 0x90);
    assert_eq!(admission(&bytes, sites), Err(ClockError::Source));
    for short in [&[][..], &[0x90, 0x90, 0x90, 0xc3][..]] {
        assert_eq!(admission(short, [0, 1]), Err(ClockError::Source));
    }
    let (bytes, _) = two_edges(&[], [Some(5), Some(15)]);
    for base in [0, u64::MAX - 10] {
        assert!(matches!(
            admit(&bytes, base, [1, 2]),
            Err(ClockError::Source)
        ));
    }
    for prefix in [
        &[0x74, 0][..],
        &[0xeb, 0],
        &[0x0f, 0x84, 0, 0, 0, 0],
        &[0xe9, 0, 0, 0, 0],
    ] {
        let (bytes, sites) = two_edges(prefix, [Some(5), Some(15)]);
        assert_eq!(admission(&bytes, sites), Ok([Some(5), Some(15)]));
    }
    for prefix in [&[0xeb, 1][..], &[0xeb, 0xfe], &[0x74, 0x7f]] {
        let (bytes, sites) = two_edges(prefix, [Some(5), Some(15)]);
        assert_eq!(admission(&bytes, sites), Err(ClockError::Source));
    }
}

#[test]
fn owned_region_requires_complete_two_site_roster() {
    let (bytes, sites) = two_edges(&[], [Some(5), Some(15)]);
    for supplied in [
        [sites[0], sites[0]],
        [sites[1], sites[0]],
        [sites[0] + 1, sites[1]],
        [sites[0], sites[1] + 1],
    ] {
        assert_eq!(admission(&bytes, supplied), Err(ClockError::Source));
    }
    let mut one = bytes.clone();
    one[sites[0]..sites[0] + 6].fill(0x90);
    assert_eq!(admission(&one, sites), Err(ClockError::Source));
    let mut three = bytes.clone();
    three.pop();
    let target = three.len();
    three.extend([0x90, 0x74, 6]);
    edge(&mut three, Some(2), target);
    three.push(0xc3);
    assert_eq!(admission(&three, sites), Err(ClockError::Source));
    let mut unsupported = bytes.clone();
    unsupported[sites[0] + 1] = 0x84;
    assert_eq!(admission(&unsupported, sites), Err(ClockError::Source));
    let mut short = bytes;
    short[sites[0]..sites[0] + 6].copy_from_slice(&[0x75, 0xf7, 0x90, 0x90, 0x90, 0x90]);
    assert_eq!(admission(&short, sites), Err(ClockError::Source));
}

#[test]
fn owned_region_rejects_non_scalar_operands_and_hidden_prefixes() {
    let forbidden: &[&[u8]] = &[
        &[0x8b, 0x00],
        &[0x89, 0x00],
        &[0x48, 0x8d, 0x00],
        &[0x48, 0x89, 0xe0],
        &[0x89, 0xe0],
        &[0x40, 0xb4, 1],
        &[0xbb, 1, 0, 0, 0],
        &[0x49, 0xbc, 1, 0, 0, 0, 0, 0, 0, 0],
        &[0x8b, 0x05, 0, 0, 0, 0],
        &[0x66, 0xb8, 1, 0],
        &[0x67, 0x8b, 0x00],
        &[0x64, 0x8b, 0x00],
        &[0x2e, 0x90],
        &[0x40, 0x48, 0x90],
        &[0xf0, 0x01, 0x00],
        &[0xf3, 0x90],
        &[0x0f, 0x57, 0xc0],
        &[0xd9, 0xe8],
        &[0x50],
        &[0x58],
        &[0x0f, 0x05],
        &[0xcc],
        &[0xe8, 0, 0, 0, 0],
        &[0xff, 0xd0],
        &[0xf4],
        &[0x0f, 0x1f, 0x00],
    ];
    for prefix in forbidden {
        let (bytes, sites) = two_edges(prefix, [Some(5), Some(15)]);
        assert_eq!(
            admission(&bytes, sites),
            Err(ClockError::Source),
            "{prefix:02x?}"
        );
    }
}

#[test]
fn owned_region_requires_all_heads_reachable_and_able_to_return() {
    let (bytes, sites) = two_edges(&[0xeb, 1, 0x90], [Some(5), Some(15)]);
    assert_eq!(admission(&bytes, sites), Err(ClockError::Source));
    // Every head is reachable, but heads 4 and 5 cannot reach the final RET.
    let no_exit = [
        0x85, 0xc9, 0x74, 6, 0x90, 0xe9, 0xfa, 0xff, 0xff, 0xff, 0x90, 0x0f, 0x85, 0xf9, 0xff,
        0xff, 0xff, 0xc3,
    ];
    assert_eq!(admission(&no_exit, [5, 11]), Err(ClockError::Source));
    let (early, sites) = two_edges(&[0xc3], [Some(5), Some(15)]);
    assert_eq!(admission(&early, sites), Err(ClockError::Source));
    let (mut missing, sites) = two_edges(&[], [Some(5), Some(15)]);
    *missing.last_mut().unwrap() = 0x90;
    assert_eq!(admission(&missing, sites), Err(ClockError::Source));
    let (mut prefixed, sites) = two_edges(&[], [Some(5), Some(15)]);
    prefixed.insert(prefixed.len() - 1, 0xf3);
    assert_eq!(admission(&prefixed, sites), Err(ClockError::Source));
}

#[test]
fn owned_region_sorts_exact_managed_associations() {
    let clock = clock();
    let before = unsafe { clock.snapshot_parked() };
    for mode in [ClockMode::Counter, ClockMode::Stop] {
        let (bytes, sites) = nested();
        let base = clock.address() + 0x10000;
        let [first, second] = managed(base, sites);
        let expected = [(first.0, first.1.clone()), (second.0, second.1.clone())];
        let region = BackedgeClockRegion::new_owned_region(
            identity(base),
            base,
            &bytes,
            [second, first],
            clock.clone(),
            mode,
        )
        .unwrap();
        assert_eq!(region.clock(), &clock);
        assert_eq!(
            region.controls(),
            [
                (expected[0].0, &expected[0].1),
                (expected[1].0, &expected[1].1)
            ]
        );
        for action in &region.actions {
            assert_eq!(action.identity, identity(base));
            assert_eq!(action.base, base);
            assert_eq!(action.source, bytes);
            assert_eq!(action.clock, clock);
            assert_eq!(action.mode, mode);
            assert_eq!(action.condition, Some(5));
            assert_eq!(
                action.control.try_set_enabled(false),
                Err(crate::controls::ManagedControl)
            );
            assert!(action.control.is_enabled());
        }
        let scan = InstructionScanner::default().scan(&bytes, base).unwrap();
        assert_eq!(region.validate_scan(&scan), Ok(()));
    }
    assert_eq!(unsafe { clock.snapshot_parked() }, before);
}

#[test]
fn owned_region_rejects_wrong_or_aliased_managed_bindings() {
    let clock = clock();
    let (bytes, sites) = nested();
    let base = clock.address() + 0x10000;
    let make = |managed| {
        BackedgeClockRegion::new_owned_region(
            identity(base),
            base,
            &bytes,
            managed,
            clock.clone(),
            ClockMode::Stop,
        )
    };
    let [(pc0, c0, w0), (pc1, c1, w1)] = managed(base, sites);
    assert_eq!(
        make([(pc0, c0, w1), (pc1, c1, w0)]),
        Err(ClockError::Source)
    );
    let [(pc0, c0, w0), (pc1, _, w1)] = managed(base, sites);
    assert_eq!(
        make([(pc0, c0.clone(), w0), (pc1, c0, w1)]),
        Err(ClockError::Source)
    );
    let [(pc0, _, _), second] = managed(base, sites);
    let (disabled, writer) = ProbeControl::new_managed_bound(callback, false);
    assert_eq!(
        make([(pc0, disabled, writer), second]),
        Err(ClockError::Source)
    );
    let [(pc0, _, _), second] = managed(base, sites);
    let (unbound, writer) = ProbeControl::new_managed(ordinary, true);
    assert_eq!(
        make([(pc0, unbound, writer), second]),
        Err(ClockError::Source)
    );
    let [(pc0, _, writer), second] = managed(base, sites);
    assert_eq!(
        make([(pc0, ProbeControl::new(ordinary, true), writer), second]),
        Err(ClockError::Source)
    );
}

#[test]
fn owned_region_revalidation_rejects_binding_and_scan_drift() {
    let clock = clock();
    let original = region(&clock, ClockMode::Stop);
    let first = &original.actions[0];
    let scan = InstructionScanner::default()
        .scan(&first.source, first.base)
        .unwrap();
    for mutation in 0..10 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.actions[1].identity.generation += 1,
            1 => changed.actions[1].base += 1,
            2 => changed.actions[1].source[0] ^= 1,
            3 => changed.actions[1].clock = self::clock(),
            4 => changed.actions[1].mode = ClockMode::Counter,
            5 => changed.actions[1].logical_pc = changed.actions[0].logical_pc,
            6 => changed.actions[1].condition = Some(2),
            7 => changed.actions[1].control = changed.actions[0].control.clone(),
            8 => changed
                .actions
                .iter_mut()
                .for_each(|a| a.identity.generation = 0),
            9 => changed
                .actions
                .iter_mut()
                .for_each(|a| a.identity.mapping += 1),
            _ => unreachable!(),
        }
        assert_eq!(
            changed.validate_scan(&scan),
            Err(ClockError::Source),
            "mutation {mutation}"
        );
    }
    let wrong_base = InstructionScanner::default()
        .scan(&first.source, first.base + 1)
        .unwrap();
    assert_eq!(original.validate_scan(&wrong_base), Err(ClockError::Source));
    let mut wrong_bytes = first.source.clone();
    wrong_bytes[1] = 0xc9;
    let wrong_source = InstructionScanner::default()
        .scan(&wrong_bytes, first.base)
        .unwrap();
    assert_eq!(
        original.validate_scan(&wrong_source),
        Err(ClockError::Source)
    );
    let (bytes, sites) = nested();
    for (id, base) in [
        (
            CodeIdentity {
                generation: 0,
                ..identity(first.base)
            },
            first.base,
        ),
        (identity(first.base + 1), first.base),
        (identity(clock.address()), clock.address()),
    ] {
        assert_eq!(
            BackedgeClockRegion::new_owned_region(
                id,
                base,
                &bytes,
                managed(base, sites),
                clock.clone(),
                ClockMode::Stop,
            ),
            Err(ClockError::Source)
        );
    }
}

#[test]
fn owned_region_image_retains_the_shared_clock_owner() {
    let clock = clock();
    let weak = Arc::downgrade(&clock.inner);
    let region = region(&clock, ClockMode::Stop);
    let first = &region.actions[0];
    let scan = InstructionScanner::default()
        .scan(&first.source, first.base)
        .unwrap();
    let plan = TrampolinePlan::from_owned_clock_region(&scan, &region).unwrap();
    let image = plan.emit_at(first.base + 0x10000).unwrap();
    assert_eq!(image.clock(), Some(&clock));
    drop(plan);
    drop(region);
    drop(clock);
    assert!(weak.upgrade().is_some());
    drop(image);
    assert!(weak.upgrade().is_none());
}
