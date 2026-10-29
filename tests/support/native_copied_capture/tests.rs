//! Pure helper controls; fabricated transport never grants ptrace/native credit.
use super::*;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn refuses(f: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
}
fn body() -> rust_invoke::Plan {
    rust_invoke::admit(&[
        0x53, 0x48, 0x89, 0xcb, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0xff, 0xd0,
        0x48, 0x89, 0x03, 0x5b, 0xc3,
    ])
    .unwrap()
}
fn fill(local: &[libc::iovec], salt: u8) {
    for (n, iov) in local.iter().enumerate() {
        // SAFETY: read_with supplies its fresh live, uniquely owned buffers.
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(iov.iov_base.cast::<u8>(), iov.iov_len) };
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = salt.wrapping_add((n * 17 + i * 31) as u8);
        }
    }
}
fn point(data: Vec<u8>, stack: Vec<u8>) -> Snapshot {
    Snapshot {
        logical_pc: 0x1234,
        // SAFETY: inert all-integer fixture, never installed in a tracee.
        registers: unsafe { core::mem::zeroed() },
        xstate: vec![0x5a; 24],
        data,
        application_stack: stack,
    }
}

#[test]
fn copied_dispatch_matches_direct_heads_calls_and_outer() {
    let plan = body();
    for base in [0x1000, 0x1000_0000, u64::MAX - 256] {
        let dispatch = Dispatch::new(&plan, base);
        for offset in 0..=plan.bytes().len() as u64 {
            let pc = base + offset;
            for _ in 0..3 {
                assert_eq!(
                    dispatch.is_head(pc),
                    plan.heads().iter().any(|&n| base + n == pc)
                );
                assert_eq!(
                    dispatch.call(pc),
                    plan.calls().iter().position(|&n| base + n == pc)
                );
            }
        }
        assert!(!dispatch.is_head(base - 1));
        assert_eq!(dispatch.call(base - 1), None);
        assert_eq!(dispatch.outer(), base + plan.outer_ret());
        assert_eq!(
            dispatch.call_step(),
            plan.steps()
                .iter()
                .find(|s| s.offset == plan.calls()[0])
                .unwrap()
        );
        let other = Dispatch::new(&plan, base - 0x100);
        assert!(!other.is_head(base));
    }
    refuses(|| {
        Dispatch::new(&plan, u64::MAX - 1);
    });
}

#[test]
fn copied_capture_bounds_aliases_overflow_and_exact_ranges() {
    let lengths: Vec<_> = [4096, 4096, 4096]
        .into_iter()
        .chain([8192; 10])
        .chain([4096, 400])
        .collect();
    let ranges: Vec<_> = lengths
        .iter()
        .enumerate()
        .map(|(i, &n)| (0x100000 + i as u64 * 0x10000, n))
        .collect();
    let plan = CapturePlan::new(&ranges);
    assert_eq!((plan.ranges.len(), plan.total), (15, 98_704));
    let captured = plan.read_with(|local, remote| {
        assert_eq!((local.len(), remote.len()), (15, 15));
        for (i, (l, r)) in local.iter().zip(remote).enumerate() {
            assert_eq!((r.iov_base as usize as u64, r.iov_len), ranges[i]);
            assert_eq!(l.iov_len, ranges[i].1);
        }
        fill(local, 3);
        98_704
    });
    for (n, bytes) in captured.iter().enumerate() {
        assert_eq!(bytes.len(), ranges[n].1);
        for (i, &byte) in bytes.iter().enumerate() {
            assert_eq!(byte, 3_u8.wrapping_add((n * 17 + i * 31) as u8));
        }
    }
    for bad in [
        vec![],
        vec![(1, 0)],
        vec![(u64::MAX, 1)],
        vec![(1, usize::MAX)],
        vec![(1, 4), (1, 4)],
        vec![(1, 4), (4, 1)],
        vec![(1, MAX_BYTES + 1)],
        (0..16).map(|n| (1 + n * 2, 1)).collect(),
    ] {
        refuses(|| {
            CapturePlan::new(&bad);
        });
    }
    assert_eq!(CapturePlan::new(&[(1, 4), (5, 2)]).total, 6);
    let mut excessive = ranges.clone();
    excessive[14].1 += 1;
    refuses(|| {
        CapturePlan::new(&excessive);
    });
}

#[test]
fn copied_capture_requires_one_exact_transfer_and_fresh_storage() {
    let plan = CapturePlan::new(&[(0x1000, 3), (0x8000, 5)]);
    let first = plan.read_with(|local, _| {
        fill(local, 1);
        8
    });
    let second = plan.read_with(|local, _| {
        fill(local, 2);
        8
    });
    assert_ne!(first, second);
    for a in &first {
        for b in &second {
            let (a0, b0) = (a.as_ptr() as usize, b.as_ptr() as usize);
            assert!(a0 + a.len() <= b0 || b0 + b.len() <= a0);
        }
    }
    for returned in [-1, 0, 1, 3, 7, 9, isize::MAX] {
        let attempts = Cell::new(0);
        refuses(|| {
            plan.read_with(|local, _| {
                attempts.set(attempts.get() + 1);
                fill(local, 9);
                returned
            });
        });
        assert_eq!(attempts.get(), 1);
    }
}

#[test]
fn copied_capture_corruptions_and_dual_fault_remain_refusals() {
    let caller = vec![(0x1000, vec![0x11; 3])];
    let images = vec![(0x8000, vec![0x22; 5]), (0xa000, vec![0x33; 7])];
    let expected: Vec<_> = caller
        .iter()
        .chain(&images)
        .map(|(_, b)| b.clone())
        .collect();
    compare_images(&expected, &caller, &images);
    for n in 0..expected.len() {
        for i in 0..expected[n].len() {
            let mut bad = expected.clone();
            bad[n][i] ^= 1;
            refuses(|| compare_images(&bad, &caller, &images));
        }
    }
    refuses(|| compare_images(&expected[..2], &caller, &images));
    let mut reordered = expected.clone();
    reordered.swap(0, 1);
    refuses(|| compare_images(&reordered, &caller, &images));
    let ranges: Vec<_> = caller
        .iter()
        .chain(&images)
        .map(|(a, b)| (*a, b.len()))
        .collect();
    let plan = CapturePlan::new(&ranges);
    let compared = Cell::new(false);
    let failure = catch_unwind(AssertUnwindSafe(|| {
        let captured = plan.read_with(|local, _| {
            fill(local, 0xff); // early image mismatch plus later transfer failure
            3
        });
        compared.set(true);
        compare_images(&captured, &caller, &images);
    }))
    .unwrap_err();
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .unwrap();
    assert!(message.contains("copied vector read incomplete"));
    assert!(!compared.get());
    refuses(|| {
        let captured = plan.read_with(|local, _| {
            fill(local, 0xff);
            15
        });
        compare_images(&captured, &caller, &images);
    });
    let baseline = point(vec![0x44; 32], vec![0x55; 24]);
    for area in 0..3 {
        let len = [
            baseline.xstate.len(),
            baseline.data.len(),
            baseline.application_stack.len(),
        ][area];
        for at in 0..len {
            let mut bad = point(baseline.data.clone(), baseline.application_stack.clone());
            match area {
                0 => bad.xstate[at] ^= 1,
                1 => bad.data[at] ^= 1,
                _ => bad.application_stack[at] ^= 1,
            }
            refuses(|| assert_state(&baseline, &bad));
        }
    }
    for field in 0..4 {
        let mut bad = point(baseline.data.clone(), baseline.application_stack.clone());
        match field {
            0 => bad.registers.rax ^= 1,
            1 => bad.registers.rsp ^= 8,
            2 => bad.registers.eflags ^= 1,
            _ => bad.logical_pc ^= 1,
        }
        refuses(|| assert_state(&baseline, &bad));
    }
}
