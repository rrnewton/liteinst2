//! Actual canonical-neighbor operations, separate from the old 35-cycle suite.
use super::*;
use liteinst2::patcher::synchronized::SyncPatchError;

fn call(address: usize) -> u64 {
    let result: u64;
    // SAFETY: authored no-stack, callee-saved-preserving code ends in RET.
    // Explicit seeds make direct B/ADD/RET entries independent of compiler state.
    unsafe {
        core::arch::asm!(
            "call {entry}",
            entry = in(reg) address,
            inlateout("rax") 40_u64 => result,
            in("rcx") 50_u64,
            clobber_abi("C"),
        );
    }
    result
}

fn jump(source: u64, target: u64) -> [u8; 5] {
    let mut out = [0; 5];
    out[0] = 0xe9;
    out[1..].copy_from_slice(
        &i32::try_from(i128::from(target) - i128::from(source) - 5)
            .unwrap()
            .to_le_bytes(),
    );
    out
}

pub fn run() {
    let capability = SyncCore::prepare().unwrap();
    let mut calls = 0;
    let mut phases = 0;
    let mut refusals = 0;
    for (order_index, order) in [[0, 1], [1, 0]].into_iter().enumerate() {
        // Separate permanent RX/RW aliases: writes must compose the neighbor's
        // live five-byte redirect, not overwrite it with a stale plan tail.
        let fd =
            unsafe { libc::memfd_create(c"word-canonical-neighbors".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        assert_eq!(unsafe { libc::ftruncate(fd, PAGE as libc::off_t) }, 0);
        let rw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        let rx = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(rw, libc::MAP_FAILED);
        assert_ne!(rx, libc::MAP_FAILED);
        assert_eq!(unsafe { libc::close(fd) }, 0);
        let base = rx as u64;
        let mut original = vec![0x90; PAGE];
        original[32..45].copy_from_slice(&[0xb8, 1, 0, 0, 0, 0xb9, 2, 0, 0, 0, 0x01, 0xc8, 0xc3]);
        original[256..261].copy_from_slice(&[0xb8, 11, 0, 0, 0]);
        original[261..266].copy_from_slice(&jump(base + 261, base + 37));
        original[272..277].copy_from_slice(&[0xb9, 22, 0, 0, 0]);
        original[277..282].copy_from_slice(&jump(base + 277, base + 42));
        unsafe {
            std::ptr::copy_nonoverlapping(original.as_ptr(), rw.cast(), PAGE);
        }
        let scanner = InstructionScanner::default();
        let scan = scanner.scan(&original[32..45], base + 32).unwrap();
        assert_eq!(
            scan.instructions()
                .iter()
                .map(|i| i.len())
                .collect::<Vec<_>>(),
            vec![5, 5, 2, 1]
        );
        let mut patches = Vec::new();
        for (offset, target) in [(32, 256), (37, 272)] {
            let plan = JumpPatchPlan::from_scan(
                &scanner,
                &scan,
                &original[32..45],
                base + 32,
                base + offset,
                base + target,
            )
            .unwrap();
            assert_eq!(plan.displaced_len(), 5);
            assert_eq!(plan.strategy(), PatchStrategy::AtomicWord);
            // SAFETY: both permanent aliases, known heads, no other writers,
            // same process and unblocked owned router throughout this fixture.
            patches.push(unsafe {
                SyncJumpPatch::bind(plan, rw.cast::<u8>().add(offset as usize), capability).unwrap()
            });
        }
        assert!(patches[0].plan().execute_address() + 8 > patches[1].plan().execute_address());
        assert_eq!(
            patches[0].plan().execute_address() + 5,
            patches[1].plan().execute_address()
        );
        let overlapping = [&patches[0], &patches[1]];
        assert!(matches!(
            unsafe { SynchronizedBatch::prepare(&overlapping, Direction::Apply) },
            Err(SyncPatchError::OverlappingMembers)
        ));
        assert_eq!(bytes(base, PAGE), original);
        refusals += 1;
        let mut active = [false; 2];
        let mut expected = original.clone();
        let assert_calls = |active: [bool; 2]| {
            assert_eq!(
                call((base + 32) as usize),
                (if active[0] { 11 } else { 1 }) + (if active[1] { 22 } else { 2 })
            );
            assert_eq!(
                call((base + 37) as usize),
                40 + (if active[1] { 22 } else { 2 })
            );
            assert_eq!(call((base + 42) as usize), 90);
            assert_eq!(call((base + 44) as usize), 40);
        };
        assert_calls(active);
        calls += 4;
        println!("case neighbors-O{order_index}-original");
        for (index, direction) in [
            (order[0], Direction::Apply),
            (order[1], Direction::Apply),
            (order[0], Direction::Revert),
            (order[1], Direction::Revert),
        ] {
            let refs = [&patches[index]];
            let mut batch = unsafe { SynchronizedBatch::prepare(&refs, direction).unwrap() };
            let before = expected.clone();
            for (step, phase) in [
                Phase::GuardsPublished,
                Phase::GuardsSynchronized,
                Phase::BacksPublished,
                Phase::BacksSynchronized,
                Phase::FrontsPublished,
                Phase::Complete,
            ]
            .into_iter()
            .enumerate()
            {
                let receipt = unsafe { batch.advance().unwrap() };
                assert_eq!(receipt.phase, phase);
                assert_eq!(receipt.members, 1);
                assert_eq!(
                    receipt.mutated,
                    matches!(phase, Phase::FrontsPublished | Phase::Complete)
                );
                assert_eq!(receipt.synchronizations, step.div_ceil(2));
                assert_eq!(receipt.failure, None);
                assert_eq!(receipt.writer_ownership_retained, phase != Phase::Complete);
                if phase == Phase::FrontsPublished {
                    active[index] = direction == Direction::Apply;
                    expected = original.clone();
                    for (member, offset) in [(0, 32), (1, 37)] {
                        if active[member] {
                            expected[offset..offset + 5]
                                .copy_from_slice(&patches[member].plan().replacement_bytes()[..5]);
                        }
                    }
                }
                assert_eq!(bytes(base, PAGE), expected);
                assert_eq!(bytes(rw as u64, PAGE), expected);
                if step < 4 {
                    assert_eq!(expected, before);
                }
                phases += 1;
            }
            assert_calls(active);
            calls += 4;
            println!("case neighbors-O{order_index}-P{index}-{direction:?}");
        }
        assert_eq!(active, [false; 2]);
        assert_eq!(bytes(base, PAGE), original);
        assert!(patches.iter().all(|patch| patch.handled_guard_traps() == 0));
        // No unmapping: process-lifetime canonical reservations remain valid.
    }
    assert_eq!((calls, phases, refusals), (40, 48, 2));
    println!("canonical-neighbors orders=2 operations=8 calls=40 phases=48 overlap_refusals=2");
}
