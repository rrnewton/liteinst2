use super::*;
use crate::contracts::{
    AddressRange, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet, ResumeObligation,
    SourceIdentity,
};
use crate::emission::{ArtifactEmission, ArtifactRequest, PlanningSite, TargetProfile};
use crate::frame_trace::FrameTraceLimits;
use crate::generated_unwind::tests::{interpret, signed, unsigned};
use crate::planner::HookSemantics;
use crate::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy, plan_install_with_emission};
use crate::trampoline::SavedExtendedStateLayout;
use std::collections::BTreeMap;

const BASE: u64 = 0x401000;
const GENERATED: u64 = 0x1000000;
const METADATA: u64 = 0x1100000;
const DOMAIN: u64 = 19;
const ID: CodeIdentity = CodeIdentity {
    source: SourceIdentity([0x71; 32]),
    mapping: 11,
    generation: 3,
};
const HOOK: SymbolicHook = SymbolicHook {
    identity: 31,
    address: Some(BASE + 0x1000),
};

fn fixture() -> ArtifactFrameTrace {
    let bytes = [0x0f, 0x1f, 0x44, 0, 0, 0xc3];
    let function = AddressRange::new(BASE, bytes.len()).unwrap();
    let entries = LegalEntrySet {
        identity: ID,
        scope: function,
        provenance: EntryProvenance::Declared("authored pure NOP5 frame fixture".into()),
        completeness: EntryCompleteness::Complete,
        entries: [BASE, BASE + 5]
            .map(|address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .to_vec(),
        resumes: ResumeObligation::NoneExist,
    };
    let allocation = AllocationPolicy {
        ranges: vec![AddressRange::new(GENERATED, 8192).unwrap()],
        preferred_address: Some(GENERATED),
        max_candidates: 256,
        max_mappings: 1,
        max_mapped_bytes: 8192,
    };
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            SavedExtendedStateLayout::describe_target_fxsave64(),
            DOMAIN,
        )
        .unwrap(),
        HOOK,
        vec![AddressRange::new(BASE, 8192).unwrap()],
    );
    let request = ArtifactRequest {
        site: PlanningSite {
            identity: ID,
            code: &bytes,
            base_address: BASE,
            function,
            block: function,
            logical_pc: BASE,
            entries: &entries,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                max_upstream_bytes: 0,
                max_sites: 1,
                ..SearchPolicy::default()
            },
        },
        emission: &emission,
    };
    plan_install_with_emission(&request)
        .unwrap()
        .frame_trace_nop5(&emission, FrameTraceLimits::default())
        .unwrap()
}

fn record(body: &[u8]) -> Vec<u8> {
    let mut result = (body.len() as u32).to_le_bytes().to_vec();
    result.extend_from_slice(body);
    result
}

fn source_record(frame_pointer: bool) -> OriginalArtifactCfi {
    // Explicit semantic model: original CFA is RSP+48, or saved RBP+16.
    // The caller's RBX is in original stack memory, distinct from hook RBX.
    let mut cie = vec![0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0];
    cie.extend_from_slice(&[
        0x0c,
        if frame_pointer { 6 } else { 7 },
        if frame_pointer { 16 } else { 48 },
    ]);
    cie.extend_from_slice(&[0x90, 1, 0x83, if frame_pointer { 3 } else { 2 }]);
    if frame_pointer {
        cie.extend_from_slice(&[0x86, 2]);
    } else {
        cie.extend_from_slice(&[8, 6]);
    }
    for reg in [12, 13, 14, 15] {
        cie.extend_from_slice(&[8, reg]);
    }
    let cie_address = BASE + 0x4000;
    let fde_address = BASE + 0x5000;
    let mut fde = ((fde_address + 4 - cie_address) as u32)
        .to_le_bytes()
        .to_vec();
    fde.extend_from_slice(&BASE.to_le_bytes());
    fde.extend_from_slice(&64_u64.to_le_bytes());
    fde.push(0);
    OriginalArtifactCfi {
        cie_address,
        cie: record(&cie),
        fde_address,
        fde: record(&fde),
    }
}

fn certificate(frame_pointer: bool) -> Arc<ArtifactSourceCertificate> {
    Arc::new(unsafe {
        ArtifactSourceCertificate::certify(
            ID,
            DOMAIN,
            vec![source_record(frame_pointer)],
            vec![BASE, BASE + 5],
            Limits::default(),
        )
        .unwrap()
    })
}

fn hook() -> ArtifactFramePreservingHook {
    unsafe { ArtifactFramePreservingHook::certify(ID, DOMAIN, HOOK).unwrap() }
}

// Independent reader of the complete encoded FDE program. The production
// encoder and source parser are not used to find rows or recover their values.
fn rows(bytes: &[u8], mut at: usize, start: u64) -> Vec<(u64, &[u8])> {
    let mut pc = start;
    let mut result = Vec::new();
    while at < bytes.len() {
        if bytes[at] == 0 {
            assert!(bytes[at..].iter().all(|byte| *byte == 0));
            break;
        }
        if bytes[at] == 4 {
            pc += u64::from(u32::from_le_bytes(
                bytes[at + 1..at + 5].try_into().unwrap(),
            ));
            at += 5;
        }
        let begin = at;
        assert_eq!(bytes[at], 0x0f);
        at += 1;
        let length = unsigned(bytes, &mut at);
        at += length;
        for expected in [3, 6, 12, 13, 14, 15, 16] {
            let op = bytes[at];
            at += 1;
            assert_eq!(unsigned(bytes, &mut at), expected);
            match op {
                8 => (),
                9 => {
                    unsigned(bytes, &mut at);
                }
                0x11 => {
                    signed(bytes, &mut at);
                }
                0x10 | 0x16 => {
                    let length = unsigned(bytes, &mut at);
                    at += length;
                }
                _ => panic!("unexpected caller rule {op:#x}"),
            }
        }
        result.push((pc, &bytes[begin..at]));
    }
    result
}

#[test]
fn encoded_artifact_rows_recover_original_caller_at_both_call_return_conventions() {
    let emission = fixture();
    let call = emission.trace().calls()[0];
    for fp in [false, true] {
        let prepared = PreparedArtifactUnwind::prepare(
            &emission,
            certificate(fp),
            hook(),
            METADATA,
            Limits::default(),
        )
        .unwrap();
        assert!(prepared.matches_trace(&emission));
        assert_eq!(prepared.source_step(), emission.source_step());
        assert!(!prepared.qualification_complete());
        assert!(
            emission
                .image()
                .metadata()
                .requirements()
                .contains(&crate::emission::ArtifactRequirement::GeneratedUnwindInformation)
        );
        assert_eq!(prepared.fdes().len(), 1);
        let bytes = prepared.bytes();
        assert_eq!(
            &bytes[4..17],
            &[0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b]
        );
        assert_eq!(&bytes[bytes.len() - 4..], &[0; 4]);
        let (start, end, offset) = prepared.fdes()[0];
        assert_eq!(start, GENERATED);
        assert_eq!(end, GENERATED + emission.image().bytes().len() as u64);
        let n = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let fde = &bytes[offset..offset + 4 + n];
        assert_eq!(
            u32::from_le_bytes(fde[4..8].try_into().unwrap()) as usize,
            offset + 4
        );
        let relative = i64::from(i32::from_le_bytes(fde[8..12].try_into().unwrap()));
        let length = i32::from_le_bytes(fde[12..16].try_into().unwrap());
        assert_eq!(u64::try_from(length).unwrap(), end - start);
        assert_eq!(fde[16], 0);
        for bias in [0_u64, 0x7000_0000_0000] {
            assert_eq!(
                (bias + METADATA + offset as u64 + 8).checked_add_signed(relative),
                Some(bias + start)
            );
        }
        let decoded = rows(fde, 17, start);
        assert_eq!(decoded.len(), emission.trace().instructions().len());
        assert_eq!(
            decoded.iter().map(|r| r.0).collect::<Vec<_>>(),
            emission
                .trace()
                .instructions()
                .iter()
                .map(|r| r.start())
                .collect::<Vec<_>>()
        );

        let original_rsp = 0x100000_u64;
        let context = original_rsp - 304;
        let mut registers = [0_u64; 16];
        registers[12] = context;
        let mut memory = BTreeMap::new();
        let mut expected = BTreeMap::new();
        for (reg, offset) in [(3, 104), (6, 96), (12, 40), (13, 32), (14, 24), (15, 16)] {
            let value = 0xabc0_0000 + reg as u64;
            memory.insert(context + offset, value);
            expected.insert(reg, value);
        }
        memory.insert(context + 104, 0x5a637c91e2d4b608);
        memory.insert(original_rsp + if fp { 24 } else { 32 }, expected[&3]);
        if fp {
            memory.insert(context + 96, original_rsp + 32);
            memory.insert(original_rsp + 32, expected[&6]);
        }
        memory.insert(original_rsp + 40, 0x7777_1234);
        expected.insert(16, 0x7777_1234);
        for pc in [call.call_pc(), call.return_pc() - 1, call.return_pc()] {
            let program = decoded.iter().rev().find(|row| row.0 <= pc).unwrap().1;
            let (cfa, recovered) = interpret(program, &registers, &memory);
            assert_eq!(cfa, original_rsp + 48);
            assert_eq!(recovered, expected);
            assert_ne!(recovered[&3], memory[&(context + 104)]);
        }
    }
}

#[test]
fn artifact_composition_refuses_wrong_binding_missing_points_and_undefined_caller() {
    let emission = fixture();
    for mutation in 0..5 {
        let mut source = certificate(false);
        let mut certified_hook = hook();
        match mutation {
            0 => Arc::get_mut(&mut source).unwrap().identity.generation += 1,
            1 => Arc::get_mut(&mut source).unwrap().bias_domain += 1,
            2 => certified_hook.hook.address = Some(HOOK.address.unwrap() + 1),
            3 => Arc::get_mut(&mut source)
                .unwrap()
                .points
                .pop()
                .map(|_| ())
                .unwrap(),
            4 => {
                Arc::get_mut(&mut source).unwrap().rows[0].rows[0].registers[3] =
                    parser::Rule::Undefined
            }
            _ => unreachable!(),
        }
        let expected = [
            Refusal::SourceIdentity,
            Refusal::SourceIdentity,
            Refusal::HookContract,
            Refusal::SourcePoint,
            Refusal::CallerRule,
        ][mutation];
        assert_eq!(
            PreparedArtifactUnwind::prepare(
                &emission,
                source,
                certified_hook,
                METADATA,
                Limits::default()
            )
            .err(),
            Some(expected)
        );
    }
    assert_eq!(
        unsafe {
            ArtifactFramePreservingHook::certify(
                ID,
                DOMAIN,
                SymbolicHook {
                    address: None,
                    ..HOOK
                },
            )
        }
        .err(),
        Some(Refusal::HookContract)
    );
}

#[test]
fn relative_records_refuse_overlap_reach_overflow_and_all_metadata_limits() {
    let emission = fixture();
    for (address, refusal) in [
        (GENERATED, Refusal::SourceIdentity),
        (0x8000_0000_0000, Refusal::Arithmetic),
        (u64::MAX, Refusal::Arithmetic),
    ] {
        assert_eq!(
            PreparedArtifactUnwind::prepare(
                &emission,
                certificate(false),
                hook(),
                address,
                Limits::default()
            )
            .err(),
            Some(refusal)
        );
    }
    for limits in [
        Limits {
            rows: 0,
            ..Limits::default()
        },
        Limits {
            fdes: 0,
            ..Limits::default()
        },
        Limits {
            expression_bytes: 0,
            ..Limits::default()
        },
        Limits {
            metadata_bytes: 0,
            ..Limits::default()
        },
    ] {
        assert_eq!(
            PreparedArtifactUnwind::prepare(
                &emission,
                certificate(false),
                hook(),
                METADATA,
                limits
            )
            .err(),
            Some(Refusal::Limit)
        );
    }
}

#[test]
fn artifact_source_certificate_keeps_original_record_and_point_guards() {
    for (records, points, limits, expected) in [
        (
            vec![source_record(false)],
            vec![BASE, BASE],
            Limits::default(),
            Refusal::SourcePoint,
        ),
        (
            vec![source_record(false)],
            vec![BASE - 1],
            Limits::default(),
            Refusal::SourcePoint,
        ),
        (
            vec![source_record(false), source_record(false)],
            vec![BASE],
            Limits::default(),
            Refusal::SourceIdentity,
        ),
        (
            vec![source_record(false)],
            vec![BASE],
            Limits {
                dependencies: 0,
                ..Limits::default()
            },
            Refusal::Limit,
        ),
        (
            vec![source_record(false)],
            vec![BASE],
            Limits {
                source_record_bytes: 1,
                ..Limits::default()
            },
            Refusal::Limit,
        ),
    ] {
        assert_eq!(
            unsafe { ArtifactSourceCertificate::certify(ID, DOMAIN, records, points, limits) }
                .err(),
            Some(expected)
        );
    }
}

#[test]
fn relative_encoder_keeps_signed32_endpoints_and_live_encoding_unchanged() {
    let row = cfi::Row {
        start: 0x9000_0000,
        end: 0x9000_0001,
        instructions: vec![8, 3],
    };
    let (live, _) = cfi::encode(core::slice::from_ref(&row), Limits::default()).unwrap();
    assert_eq!(live[16], 0);
    assert_eq!(
        u64::from_le_bytes(live[28..36].try_into().unwrap()),
        row.start
    );
    for delta in [i32::MIN, i32::MAX] {
        // One 20-byte CIE, then length and CIE pointer precede the location.
        let address = (i128::from(row.start) - i128::from(delta) - 28) as u64;
        let (bytes, _) =
            cfi::encode_relative(core::slice::from_ref(&row), address, Limits::default()).unwrap();
        assert_eq!(i32::from_le_bytes(bytes[28..32].try_into().unwrap()), delta);
        let outside = if delta < 0 { address + 1 } else { address - 1 };
        assert_eq!(
            cfi::encode_relative(core::slice::from_ref(&row), outside, Limits::default()).err(),
            Some(Refusal::Arithmetic)
        );
    }
}
