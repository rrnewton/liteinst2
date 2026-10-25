#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

// Additive exact rel32 native endpoints. Handwritten original MOV/RET heads,
// unchanged architectural comparator, exact one-candidate placement, no fallback.
#[path = "support/quiescent_oracle.rs"]
mod oracle;
use liteinst2::contracts::{
    AddressRange, CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet,
    PlanKind, QuiescenceLease, Refusal, ResumeObligation, SourceIdentity,
};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use oracle::NativeOracle;

unsafe extern "C" fn observer(_context: *mut HookContext) {
    // Deliberately clobber caller-saved state. The hook does not change the
    // application's saved context, so the original comparator remains exact.
    unsafe {
        core::arch::asm!("add rax, 1", "pxor xmm0, xmm0", "fninit", out("rax") _, out("xmm0") _, options(nostack));
    }
}
fn permission(address: *mut u8, flags: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(address.cast(), 4096, flags) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

#[test]
fn native_rel32_exact_endpoints_and_one_byte_outside() {
    let bytes = [0xb8, 42, 0, 0, 0, 0xc3];
    let mut oracle = NativeOracle::new(&bytes);
    let source = oracle.code.address();
    let range = AddressRange::new(source, bytes.len()).unwrap();
    let heads = [source, source + 5];
    let mut baselines = Vec::new();
    for seed in [0x1234_5678_8765_4320_u64, 0xfedc_ba98_0123_4567] {
        for offset in 0..heads.len() {
            let mut path = heads[offset..].to_vec();
            path.push(oracle.return_pc());
            baselines.push((heads[offset], oracle.original(&path, seed)));
        }
    }
    let mut counts = [0_usize; 3];
    for (ordinal, displacement) in [
        i64::from(i32::MIN) - 1,
        i64::from(i32::MAX) + 1,
        i64::from(i32::MIN),
        i64::from(i32::MAX),
    ]
    .into_iter()
    .enumerate()
    {
        let identity = CodeIdentity {
            source: SourceIdentity([0x71; 32]),
            mapping: 1,
            generation: ordinal as u64 + 1,
        };
        let entries = LegalEntrySet {
            identity,
            scope: range,
            provenance: EntryProvenance::Declared(
                "handwritten MOV5/RET exact signed rel32 boundary fixture".into(),
            ),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: heads
                .into_iter()
                .map(|address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let target = u64::try_from(i128::from(source + 5) + i128::from(displacement)).unwrap();
        eprintln!("rel32 case source={source:#x} target={target:#x} displacement={displacement}");
        let allocation = AllocationPolicy {
            ranges: vec![AddressRange::new(target & !4095, 8192).unwrap()],
            preferred_address: Some(target),
            max_candidates: 1,
            max_mappings: 1,
            max_mapped_bytes: 8192,
        };
        let result = plan_install(&InstallRequest {
            identity,
            code: &bytes,
            base_address: source,
            function: range,
            block: range,
            logical_pc: source,
            entries: &entries,
            hook: observer,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        });
        if i32::try_from(displacement).is_err() {
            assert_eq!(
                result.unwrap_err(),
                Refusal::AllocationUnavailable,
                "outside target must not wrap, clamp, substitute or publish"
            );
            oracle.assert_publication(&[]);
            for (entry, baseline) in &baselines {
                oracle.assert_patched(baseline, *entry, &[], &[]);
                counts[0] += 1;
            }
            continue;
        }
        let plan = result.unwrap();
        assert_eq!(
            plan.image().address(),
            target,
            "exact endpoint is mandatory"
        );
        let parts = plan.plan().parts();
        assert_eq!(parts.kind, PlanKind::Relocation);
        assert_eq!(parts.physical_pc, source);
        assert_eq!(parts.writes.len(), 1);
        let mut expected = vec![0xe9];
        expected.extend_from_slice(&(displacement as i32).to_le_bytes());
        assert_eq!(parts.writes[0].address, source);
        assert_eq!(parts.writes[0].bytes, expected);
        assert!(!parts.requirements.sigill_router);
        let boundaries = plan.image().instruction_boundaries().to_vec();
        let edits = vec![(source, expected)];
        let generated = plan.image().bytes().to_vec();
        let writable = oracle.code.writable();
        let (mut installed, receipt) = {
            // All original children were reaped. No application image is called
            // by the parent and no executor or saved context survives this gate.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, vec![range]) };
            permission(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            unsafe {
                plan.publish_with(writable, &mut lease, || {
                    permission(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap()
        };
        assert_eq!(receipt.plan().parts().identity, identity);
        oracle.assert_publication(&edits);
        for (entry, baseline) in &baselines {
            oracle.assert_patched(baseline, *entry, &boundaries, &[]);
            counts[1] += 1;
            assert_eq!(
                unsafe { std::slice::from_raw_parts(target as *const u8, generated.len()) },
                generated
            );
        }
        {
            let mut ranges = vec![range];
            ranges.extend(parts.allocations.iter().map(|a| a.range));
            // Every installed child is reaped before source retirement.
            let mut lease = unsafe { QuiescenceLease::new(&mut oracle, identity, ranges) };
            permission(writable, libc::PROT_READ | libc::PROT_WRITE).unwrap();
            unsafe {
                installed.retire_with(&mut lease, || {
                    permission(writable, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap();
        }
        oracle.assert_publication(&[]);
        for (entry, baseline) in &baselines {
            oracle.assert_patched(baseline, *entry, &[], &[]);
            counts[2] += 1;
        }
    }
    assert_eq!(counts, [8, 8, 8]);
    eprintln!(
        "native exact rel32: both signed endpoints installed; both one-byte-outside targets refused; 4 baseline / 8 refused-preservation / 8 installed / 8 retired full-state traces"
    );
}
