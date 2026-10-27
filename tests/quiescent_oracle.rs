#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Fixed native state-oracle corpus for quiescent relocation and generalized puns.
//! These are required positive fixtures: refusal is a test failure. Byte heads
//! are handwritten alongside the fixture bytes, independent of iced-x86.

#[path = "support/quiescent_oracle.rs"]
mod oracle;

use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryObligation, EntryProvenance, LegalEntry,
    LegalEntrySet, PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use oracle::NativeOracle;

/// Observes without changing HookContext/application state. Deliberately destroy
/// scratch GPR/flags/x87/XMM state to make save/restore failures observable.
unsafe extern "C" fn no_op_observer(_context: *mut HookContext) {
    // SAFETY: these are user-mode instructions on caller-saved state; the
    // trampoline must preserve application state around any C-ABI callback.
    unsafe {
        core::arch::asm!(
            "add rax, 1",
            "pxor xmm0, xmm0",
            "fninit",
            out("rax") _,
            out("xmm0") _,
            options(nostack),
        );
    }
}

fn source_permissions(address: *mut u8, protection: i32) -> Result<(), Refusal> {
    // SAFETY: every caller retains the private page under the fixture's lease.
    if unsafe { libc::mprotect(address.cast(), 4096, protection) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

struct Puzzle {
    name: String,
    bytes: Vec<u8>,
    heads: Vec<usize>,
    logical: usize,
    physical: usize,
    block_len: usize,
    expected_marker: Option<u8>,
}

#[test]
fn native_no_op_oracle_covers_same_site_upstream_and_every_entry() {
    let mut puzzles = vec![
        Puzzle {
            name: "same-site-gprs-flags-data-redzone".into(),
            bytes: vec![
                0x48, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08, // MOV RAX,imm64
                0x48, 0x89, 0x07, // MOV [RDI],RAX
                0x48, 0x8d, 0x48, 0x01, // LEA RCX,[RAX+1]
                0x48, 0x89, 0x4c, 0x24, 0x80, // MOV [RSP-128],RCX
                0x48, 0x83, 0xc0, 0x7f, // ADD RAX,127 (all arithmetic flags defined)
                0x48, 0x89, 0x47, 0x08, // MOV [RDI+8],RAX
                0xc3, // RET to the fixture-owned terminal boundary
            ],
            heads: vec![0, 10, 13, 17, 22, 26, 30],
            logical: 0,
            physical: 0,
            block_len: 31,
            expected_marker: None,
        },
        Puzzle {
            name: "same-site-interior-rel32-entry".into(),
            bytes: vec![
                0x66, 0x90, // two-byte NOP
                0x48, 0x8b, 0x07, // MOV RAX,[RDI]; head 2 lies inside rel32
                0xc3, // RET
            ],
            heads: vec![0, 2, 5],
            logical: 0,
            physical: 0,
            block_len: 6,
            expected_marker: None,
        },
        Puzzle {
            name: "upstream-rip-relative-and-displaced-entry".into(),
            bytes: vec![
                0x48, 0x8d, 0x05, 0xf9, 0xff, 0xff, 0xff, // LEA RAX,[RIP-7]
                0x89, 0xc0, // MOV EAX,EAX at logical PC; same-site has only 3 bytes
                0xc3, // RET; marker at head 7 is outside the 5-byte jump
            ],
            heads: vec![0, 7, 9],
            logical: 7,
            physical: 0,
            block_len: 10,
            expected_marker: Some(0x60),
        },
    ];
    let mut padded = vec![
        0x48, 0x8d, 0x05, 0xf9, 0xff, 0xff, 0xff, // LEA RAX,[RIP-7]
        0x89, 0xc0, 0xc3, // MOV EAX,EAX; RET
    ];
    padded.extend_from_slice(&[0x90; 16]);
    puzzles.push(Puzzle {
        name: "upstream-authenticated-62-fetch-window".into(),
        bytes: padded,
        heads: vec![0, 7, 9],
        logical: 7,
        physical: 0,
        // The padding is authenticated source, outside the function/block.
        // Same-site remains impossible; the marker has 15 readable fetch bytes.
        block_len: 10,
        expected_marker: Some(0x62),
    });
    // A four-bit mask independently enumerates instruction heads at offsets
    // 1..=4; offset 0 is always a head. Emit documented NOP encodings for each
    // partition of five bytes, then RET. This is all 16 layouts, with no decoder
    // or planner used to construct the input heads or expected continuation.
    const NOPS: [&[u8]; 5] = [
        &[0x90],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    ];
    for mask in 0..16_u8 {
        let mut heads = vec![0];
        for offset in 1..5 {
            if mask & (1 << (offset - 1)) != 0 {
                heads.push(offset);
            }
        }
        heads.push(5);
        let mut bytes = Vec::new();
        for pair in heads.windows(2) {
            bytes.extend_from_slice(NOPS[pair[1] - pair[0] - 1]);
        }
        bytes.push(0xc3);
        puzzles.push(Puzzle {
            name: format!("five-byte-head-layout-{mask:04b}"),
            bytes,
            heads,
            logical: 0,
            physical: 0,
            block_len: 6,
            expected_marker: None,
        });
    }
    assert_eq!(puzzles.len(), 20);
    for (name, prefix) in [
        ("nop-prefix-operand-segment", [0x66, 0x2e]),
        ("nop-prefix-segment-operand", [0x2e, 0x66]),
    ] {
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(&[0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xc3]);
        puzzles.push(Puzzle {
            name: name.into(),
            bytes,
            heads: vec![0, 10],
            logical: 0,
            physical: 0,
            block_len: 11,
            expected_marker: None,
        });
    }
    assert_eq!(puzzles.len(), 22);
    let mut prefix_order_executions = 0;
    let mut executions = 0;
    let mut routed_entries = 0;
    // Keep the 22 small private application images alive throughout the corpus:
    // address reuse must not make one layout inherit another layout's retained
    // generated-mapping collisions. Total fixture storage stays below 2 MiB.
    let mut retained_fixtures = Vec::new();
    for (index, puzzle) in puzzles.iter().enumerate() {
        let mut oracle = NativeOracle::new(&puzzle.bytes);
        let base = oracle.code.address();
        let range = AddressRange::new(base, puzzle.bytes.len()).unwrap();
        let block = AddressRange::new(base, puzzle.block_len).unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity([index as u8 + 1; 32]),
            mapping: index as u64 + 1,
            generation: 1,
        };
        let entries = LegalEntrySet {
            identity,
            scope: block,
            provenance: EntryProvenance::Declared(puzzle.name.clone()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: puzzle
                .heads
                .iter()
                .map(|&offset| LegalEntry {
                    address: base + offset as u64,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let mut allocation = AllocationPolicy::near(base + puzzle.logical as u64).unwrap();
        // This fixed layout is intentionally away from adjacent loader/stack
        // VMAs. The default bounded search is tested elsewhere; this corpus
        // requires positive execution for each head layout, not exhaustion.
        allocation.preferred_address = Some(base + 64 * 1024 * 1024 + index as u64 * 1024 * 1024);
        let prepared = plan_install(&InstallRequest {
            identity,
            code: &puzzle.bytes,
            base_address: base,
            function: block,
            block,
            logical_pc: base + puzzle.logical as u64,
            entries: &entries,
            hook: no_op_observer,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                ..SearchPolicy::default()
            },
        })
        .unwrap_or_else(|error| {
            panic!(
                "required positive puzzle {} refused: {error:?}",
                puzzle.name
            )
        });
        assert!(matches!(
            &prepared.plan().parts().kind,
            PlanKind::Relocation
        ));
        assert_eq!(
            prepared.plan().parts().physical_pc,
            base + puzzle.physical as u64,
            "puzzle {} did not use its required physical site",
            puzzle.name
        );
        assert_eq!(
            prepared.plan().parts().logical_pc,
            base + puzzle.logical as u64
        );
        if let Some(marker) = puzzle.expected_marker {
            let edit = prepared
                .plan()
                .parts()
                .writes
                .iter()
                .find(|edit| {
                    let pc = base + puzzle.logical as u64;
                    edit.address <= pc && pc < edit.address + edit.bytes.len() as u64
                })
                .unwrap();
            assert_eq!(
                edit.bytes[(base + puzzle.logical as u64 - edit.address) as usize],
                marker,
                "puzzle {} must execute its declared illegal marker",
                puzzle.name
            );
        }
        let boundaries = prepared.image().instruction_boundaries().to_vec();
        if index >= 20 {
            let body = boundaries.iter().find(|(pc, _)| *pc == base).unwrap().1;
            let at = usize::try_from(body - prepared.image().address()).unwrap();
            assert_eq!(
                &prepared.image().bytes()[at..at + 10],
                &puzzle.bytes[..10],
                "native image must retain the exact ten-byte NOP encoding"
            );
        }
        let owned_sigill: Vec<_> = prepared
            .plan()
            .parts()
            .obligations
            .iter()
            .filter_map(|obligation| {
                if let EntryObligation::Routed(route) = obligation {
                    Some(route.original)
                } else {
                    None
                }
            })
            .collect();
        if puzzle.logical != puzzle.physical {
            assert!(
                owned_sigill.contains(&(base + puzzle.logical as u64)),
                "upstream logical entry must route"
            );
        }
        if puzzle.name == "same-site-interior-rel32-entry" {
            assert!(
                owned_sigill.contains(&(base + 2)),
                "interior jump entry must route"
            );
        }
        for &head in &puzzle.heads {
            let address = base + head as u64;
            if address > base + puzzle.physical as u64
                && prepared.plan().parts().displaced.contains(address)
            {
                assert!(
                    owned_sigill.contains(&address),
                    "puzzle {} lost displaced head {head}",
                    puzzle.name
                );
            }
        }
        routed_entries += owned_sigill.len();
        let edits: Vec<_> = prepared
            .plan()
            .parts()
            .writes
            .iter()
            .map(|edit| (edit.address, edit.bytes.clone()))
            .collect();
        let mut baselines = Vec::new();
        for seed in [0x1234_5678_8765_4320_u64, 0xfedc_ba98_0123_4567] {
            for entry in 0..puzzle.heads.len() {
                let mut heads: Vec<_> = puzzle.heads[entry..]
                    .iter()
                    .map(|&offset| base + offset as u64)
                    .collect();
                heads.push(oracle.return_pc());
                baselines.push((heads[0], oracle.original(&heads, seed)));
            }
        }
        let writable = oracle.code.writable();
        let (mut installed, receipt) = {
            // SAFETY: the exclusive fixture owner is the exclusion guard. All
            // original children are reaped, no executable pointer escapes, and
            // the parent never executes the application image or its signals.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![range]) };
            source_permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: this exact private mapping owns the authenticated source
            // bytes; no child/executor exists during publication. The finalizer
            // restores RX before sync-core and the successful receipt.
            unsafe {
                prepared.publish_with(writable, &mut lease, || {
                    source_permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap()
        };
        assert_eq!(receipt.plan().parts().identity, identity);
        oracle.assert_publication(&edits);
        for (entry, baseline) in &baselines {
            oracle.assert_patched(baseline, *entry, &boundaries, &owned_sigill);
            if index < 20 {
                executions += 1;
            } else {
                prefix_order_executions += 1;
            }
        }
        {
            // SAFETY: all patched children have been reaped, so this exclusive
            // owner also excludes execution and saved resumes during retirement.
            let mut retirement_ranges = vec![range];
            retirement_ranges.extend(
                prepared
                    .plan()
                    .parts()
                    .allocations
                    .iter()
                    .map(|request| request.range),
            );
            let mut lease =
                unsafe { QuiescenceLease::new(&mut oracle, identity, retirement_ranges) };
            source_permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: the finalizer only restores permissions on the retained
            // source page and cannot admit execution or unwind.
            unsafe {
                installed.retire_with(&mut lease, || {
                    source_permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap();
        }
        oracle.assert_publication(&[]);
        retained_fixtures.push(oracle);
    }
    assert_eq!(
        executions, 160,
        "every declared entry and seed must execute"
    );
    assert_eq!(
        routed_entries, 35,
        "every interior head must have an executed route"
    );
    assert_eq!(
        prefix_order_executions, 8,
        "both prefix orders, two entries, two seeds"
    );
    assert_eq!(executions + prefix_order_executions, 168);
    eprintln!(
        "native oracle: 22 required positive puzzles (all 16 five-byte layouts plus two NOP prefix orders); 168 entry/seed executions; {routed_entries} routed heads; zero mismatches"
    );
}

#[test]
fn native_no_op_oracle_covers_generalized_puns_and_unchanged_successors() {
    // The bytes after each first instruction freeze the high rel32 bytes.
    // These four independently chosen streams force disjoint far windows,
    // away from adjacent loader mappings and the relocation corpus's targets.
    // MOV/LEA/RET preserve every compared flag; no new comparator mask is needed.
    let puzzles: [(&str, &[u8], &[usize], u32); 4] = [
        (
            "L1-NOP-LEA",
            &[
                0x90, // NOP: no free displacement byte after writing E9
                0x48, 0x8d, 0x4f, 0x08, // LEA RCX,[RDI+8]
                0xc3, // RET
            ],
            &[0, 1, 5],
            0x084f_8d48,
        ),
        (
            "L2-MOV-LEA",
            &[
                0x89, 0xc0, // MOV EAX,EAX
                0x48, 0x8d, 0x4f, 0x08, // LEA RCX,[RDI+8]
                0xc3, // RET
            ],
            &[0, 2, 6],
            0x4f8d_4800,
        ),
        (
            "L3-LEA-memory-store",
            &[
                0x48, 0x8d, 0x07, // LEA RAX,[RDI]
                0x48, 0x89, 0x07, // MOV [RDI],RAX
                0xc3, // RET
            ],
            &[0, 3, 6],
            0x8948_0000,
        ),
        (
            "L4-LEA-memory-store",
            &[
                0x48, 0x8d, 0x4f, 0x08, // LEA RCX,[RDI+8]
                0x48, 0x89, 0x0f, // MOV [RDI],RCX
                0xc3, // RET
            ],
            &[0, 4, 7],
            0x4800_0000,
        ),
    ];
    let mut executions = 0;
    let mut retired_executions = 0;
    let mut retained_fixtures = Vec::new();
    for (index, &(name, code, heads, frozen_displacement)) in puzzles.iter().enumerate() {
        let length = heads[1];
        let mut oracle = NativeOracle::new(code);
        let base = oracle.code.address();
        let range = AddressRange::new(base, code.len()).unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity([0x90 + index as u8; 32]),
            mapping: 0x90 + index as u64,
            generation: 1,
        };
        let entries = LegalEntrySet {
            identity,
            scope: range,
            provenance: EntryProvenance::Declared(name.into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: heads
                .iter()
                .map(|&offset| LegalEntry {
                    address: base + offset as u64,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let width = 1_usize << (8 * (length - 1));
        let start =
            u64::try_from(i128::from(base + 5) + i128::from(frozen_displacement as i32)).unwrap();
        let expected_window = AddressRange::new(start, width).unwrap();
        assert_eq!(width, [1, 256, 65_536, 16_777_216][index]);
        assert_eq!(
            &frozen_displacement.to_le_bytes()[length - 1..],
            &code[length..5],
            "the handwritten successor bytes must force the declared window"
        );
        let mut allocation = AllocationPolicy::near(base).unwrap();
        allocation.preferred_address = Some(start + width as u64 / 2);
        let mut request = InstallRequest {
            identity,
            code,
            base_address: base,
            function: range,
            block: range,
            logical_pc: base,
            entries: &entries,
            hook: no_op_observer,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            // Default ranking must choose the feasible generalized pun before
            // the independently feasible same-site relocation alternative.
            search: SearchPolicy::default(),
        };
        let prepared = plan_install(&request)
            .unwrap_or_else(|reason| panic!("required generalized-pun puzzle {name}: {reason:?}"));
        request.search.tactics = TacticPolicy::RelocationOnly;
        let alternative = plan_install(&request)
            .unwrap_or_else(|reason| panic!("{name}: required relocation alternative: {reason:?}"));
        assert!(matches!(
            &alternative.plan().parts().kind,
            PlanKind::Relocation
        ));
        assert_eq!(alternative.plan().parts().physical_pc, base);
        let parts = prepared.plan().parts();
        let PlanKind::GeneralizedPun(pun) = &parts.kind else {
            panic!("{name}: default ranking did not select generalized pun");
        };
        assert_eq!(parts.physical_pc, base);
        assert_eq!(parts.logical_pc, base);
        assert_eq!(parts.displaced, AddressRange::new(base, length).unwrap());
        assert_eq!(pun.instruction_len as usize, length);
        assert_eq!(pun.consumed, AddressRange::new(base, 5).unwrap());
        assert_eq!(pun.target_window, expected_window);
        assert!(expected_window.contains(prepared.image().address()));
        assert_eq!(parts.writes.len(), 1);
        assert_eq!(parts.writes[0].address, base);
        assert_eq!(parts.writes[0].bytes.len(), length);
        assert_eq!(parts.writes[0].bytes[0], 0xe9);
        assert_eq!(pun.store.address, base);
        assert_eq!(pun.store.bytes.len(), if length == 3 { 4 } else { length });
        assert_eq!(&pun.store.bytes[..length], &parts.writes[0].bytes);
        assert_eq!(
            &pun.store.bytes[length..],
            &code[length..pun.store.bytes.len()],
            "the three-byte pun's wider store must preserve its successor pad"
        );
        let mut encoded = code[..5].to_vec();
        encoded[..length].copy_from_slice(&parts.writes[0].bytes);
        assert_eq!(&encoded[length..], &code[length..5]);
        let displacement = i32::from_le_bytes(encoded[1..5].try_into().unwrap());
        assert_eq!(
            i128::from(base + 5) + i128::from(displacement),
            i128::from(prepared.image().address())
        );
        assert_eq!(prepared.image().instruction_boundaries().len(), 1);
        assert_eq!(prepared.image().instruction_boundaries()[0].0, base);
        assert!(
            parts
                .obligations
                .iter()
                .all(|obligation| !matches!(obligation, EntryObligation::Routed(_)))
        );
        assert!(!parts.requirements.sigill_router);
        let edits: Vec<_> = parts
            .writes
            .iter()
            .map(|edit| (edit.address, edit.bytes.clone()))
            .collect();
        let mut baselines = Vec::new();
        for seed in [0x1234_5678_8765_4320_u64, 0xfedc_ba98_0123_4567] {
            for entry in 0..heads.len() {
                let mut boundaries: Vec<_> = heads[entry..]
                    .iter()
                    .map(|&offset| base + offset as u64)
                    .collect();
                boundaries.push(oracle.return_pc());
                baselines.push((boundaries[0], oracle.original(&boundaries, seed)));
            }
        }
        let writable = oracle.code.writable();
        let (mut installed, receipt) = {
            // SAFETY: the exclusive fixture owner excludes every executor and
            // saved continuation; all baseline children have been reaped.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![range]) };
            source_permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: the private source and any preserved store pad are fully
            // authenticated and held. Final RX permissions precede the receipt.
            unsafe {
                prepared.publish_with(writable, &mut lease, || {
                    source_permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap()
        };
        assert_eq!(receipt.plan(), prepared.plan());
        oracle.assert_publication(&edits);
        for (entry, baseline) in &baselines {
            oracle.assert_patched(
                baseline,
                *entry,
                prepared.image().instruction_boundaries(),
                &[],
            );
            executions += 1;
        }
        assert_eq!(installed.routed_entries(), 0);
        {
            let mut ranges = vec![range];
            ranges.extend(parts.allocations.iter().map(|allocation| allocation.range));
            // SAFETY: all patched children have been reaped, draining both the
            // source and generated allocation before any restoration store.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
            source_permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            // SAFETY: finalization only changes this owned page's permissions.
            unsafe {
                installed.retire_with(&mut lease, || {
                    source_permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap();
        }
        oracle.assert_publication(&[]);
        for (entry, baseline) in &baselines {
            oracle.assert_patched(baseline, *entry, &[], &[]);
            retired_executions += 1;
        }
        retained_fixtures.push(oracle);
    }
    assert_eq!(
        executions, 24,
        "all twelve heads must execute with both seeds"
    );
    assert_eq!(retired_executions, 24);
    eprintln!(
        "native generalized-pun oracle: L1/L2/L3/L4; twelve original heads; 24 paired entry/seed executions; 24 retired comparisons; successor bytes unchanged; zero mismatches"
    );
}

#[test]
fn native_no_op_oracle_preserves_synchronous_fault_state() {
    // MOV EAX,0; MOV RAX,[RAX]; RET. The 3-byte load plus RET cannot host a
    // same-site patch, forcing the five-byte zeroing prefix before the hook.
    // The only permitted external entry is offset 0; the fault is at offset 5.
    let code = [0xb8, 0, 0, 0, 0, 0x48, 0x8b, 0, 0xc3];
    let mut oracle = NativeOracle::new(&code);
    let base = oracle.code.address();
    let range = AddressRange::new(base, code.len()).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0x7f; 32]),
        mapping: 0x7f,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: range,
        provenance: EntryProvenance::Declared("null-load synchronous fault".into()),
        completeness: EntryCompleteness::Complete,
        entries: vec![LegalEntry {
            address: base,
            requires_endbr: false,
        }],
        resumes: ResumeObligation::NoneExist,
    };
    let mut allocation = AllocationPolicy::near(base + 5).unwrap();
    allocation.preferred_address = Some(base + 96 * 1024 * 1024);
    let prepared = plan_install(&InstallRequest {
        identity,
        code: &code,
        base_address: base,
        function: range,
        block: range,
        logical_pc: base + 5,
        entries: &entries,
        hook: no_op_observer,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::RelocationOnly,
            ..SearchPolicy::default()
        },
    })
    .expect("required fault-preserving upstream puzzle refused");
    assert_eq!(prepared.plan().parts().physical_pc, base);
    assert_eq!(prepared.plan().parts().logical_pc, base + 5);
    assert_eq!(prepared.plan().parts().displaced.end(), base + 8);
    let baselines: Vec<_> = [0x1234_5678_8765_4320_u64, 0xfedc_ba98_0123_4567]
        .into_iter()
        .map(|seed| {
            // Linux SEGV_MAPERR=1; dereferencing zero has no mapped object.
            oracle.original_fault(&[base, base + 5], seed, (libc::SIGSEGV, 1, 0))
        })
        .collect();
    let writable = oracle.code.writable();
    let (mut installed, _) = {
        // SAFETY: all original children are reaped and this exclusive owner
        // excludes source/generated execution and every saved continuation.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![range]) };
        source_permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: the live source is private; final RX permissions precede the receipt.
        unsafe {
            prepared.publish_with(writable, &mut lease, || {
                source_permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap()
    };
    let edits: Vec<_> = prepared
        .plan()
        .parts()
        .writes
        .iter()
        .map(|edit| (edit.address, edit.bytes.clone()))
        .collect();
    oracle.assert_publication(&edits);
    for baseline in &baselines {
        oracle.assert_patched(
            baseline,
            base,
            prepared.image().instruction_boundaries(),
            &[],
        );
    }
    {
        let mut ranges = vec![range];
        ranges.extend(
            prepared
                .plan()
                .parts()
                .allocations
                .iter()
                .map(|allocation| allocation.range),
        );
        // SAFETY: both faulting children were killed/reaped at their ptrace
        // fault stops; no application or generated-code references survive.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
        source_permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: finalization only restores owned source permissions.
        unsafe {
            installed.retire_with(&mut lease, || {
                source_permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap();
    }
    oracle.assert_publication(&[]);
    eprintln!(
        "native fault oracle: 2 seeds; SIGSEGV/SEGV_MAPERR at address0 and original PC+5; full state matched"
    );
}

#[test]
fn native_no_op_oracle_preserves_generalized_pun_fault_state() {
    // The original zeroing prefix remains in place. Only the three-byte load
    // becomes a generalized pun; RET and authenticated padding freeze its high
    // displacement bytes, and the four-byte store must preserve the RET pad.
    let code = [0xb8, 0, 0, 0, 0, 0x48, 0x8b, 0, 0xc3, 0x90];
    let mut oracle = NativeOracle::new(&code);
    let base = oracle.code.address();
    let range = AddressRange::new(base, code.len()).unwrap();
    let block = AddressRange::new(base, 9).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([0xa0; 32]),
        mapping: 0xa0,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: block,
        provenance: EntryProvenance::Declared("generalized-pun null-load synchronous fault".into()),
        completeness: EntryCompleteness::Complete,
        entries: vec![LegalEntry {
            address: base,
            requires_endbr: false,
        }],
        resumes: ResumeObligation::NoneExist,
    };
    let window_start =
        u64::try_from(i128::from(base + 10) + i128::from(0x90c3_0000_u32 as i32)).unwrap();
    let expected_window = AddressRange::new(window_start, 65_536).unwrap();
    let mut allocation = AllocationPolicy::near(base + 5).unwrap();
    allocation.preferred_address = Some(window_start + 32_768);
    let prepared = plan_install(&InstallRequest {
        identity,
        code: &code,
        base_address: base,
        function: block,
        block,
        logical_pc: base + 5,
        entries: &entries,
        hook: no_op_observer,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::GeneralizedPunOnly,
            ..SearchPolicy::default()
        },
    })
    .expect("required fault-preserving generalized pun refused");
    let parts = prepared.plan().parts();
    let PlanKind::GeneralizedPun(pun) = &parts.kind else {
        panic!("required generalized-pun fault fixture used another tactic");
    };
    assert_eq!(parts.physical_pc, base + 5);
    assert_eq!(parts.logical_pc, base + 5);
    assert_eq!(parts.displaced, AddressRange::new(base + 5, 3).unwrap());
    assert_eq!(pun.consumed, AddressRange::new(base + 5, 5).unwrap());
    assert_eq!(pun.instruction_len, 3);
    assert_eq!(pun.target_window, expected_window);
    assert!(expected_window.contains(prepared.image().address()));
    assert_eq!(parts.writes.len(), 1);
    assert_eq!(parts.writes[0].address, base + 5);
    assert_eq!(parts.writes[0].bytes.len(), 3);
    assert_eq!(pun.store.address, base + 5);
    assert_eq!(pun.store.bytes.len(), 4);
    assert_eq!(pun.store.bytes[3], 0xc3);
    assert!(!parts.requirements.sigill_router);
    assert_eq!(prepared.metrics().upstream_bytes, 0);
    assert_eq!(prepared.metrics().prefix_instructions, 0);
    let baselines: Vec<_> = [0x1234_5678_8765_4320_u64, 0xfedc_ba98_0123_4567]
        .into_iter()
        .map(|seed| oracle.original_fault(&[base, base + 5], seed, (libc::SIGSEGV, 1, 0)))
        .collect();
    let writable = oracle.code.writable();
    let (mut installed, _) = {
        // SAFETY: the exclusive fixture owner holds all source and padding,
        // and all original faulting children have been killed and reaped.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![range]) };
        source_permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: the private source is authenticated and excludes execution;
        // finalization restores executable permissions before the receipt.
        unsafe {
            prepared.publish_with(writable, &mut lease, || {
                source_permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap()
    };
    let edits: Vec<_> = parts
        .writes
        .iter()
        .map(|edit| (edit.address, edit.bytes.clone()))
        .collect();
    oracle.assert_publication(&edits);
    for baseline in &baselines {
        oracle.assert_patched(
            baseline,
            base,
            prepared.image().instruction_boundaries(),
            &[],
        );
    }
    assert_eq!(installed.routed_entries(), 0);
    {
        let mut ranges = vec![range];
        ranges.extend(parts.allocations.iter().map(|allocation| allocation.range));
        // SAFETY: patched faulting children are killed/reaped, so no execution
        // or saved continuation survives in source or generated allocations.
        let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
        source_permissions(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        // SAFETY: finalization changes only the retained source permissions.
        unsafe {
            installed.retire_with(&mut lease, || {
                source_permissions(writable, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap();
    }
    oracle.assert_publication(&[]);
    for baseline in &baselines {
        oracle.assert_patched(baseline, base, &[], &[]);
    }
    eprintln!(
        "native generalized-pun fault oracle: 2 seeds; SIGSEGV/SEGV_MAPERR at address0 and original PC+5; installed and retired full state matched"
    );
}
