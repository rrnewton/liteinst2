use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet, ResumeKind};
use liteinst_admission::scan::*;
use liteinst_admission::{AddressRange, Generation, MappingId};

const BASE: u64 = 0x10_0000;

fn snapshot(bytes: Vec<u8>) -> Snapshot {
    Snapshot::new(
        MappingId(7),
        Generation(1),
        BASE,
        bytes,
        Boundary::NonExecutable,
        Boundary::NonExecutable,
        WriteControl::Owned,
    )
    .unwrap()
}
fn entries(s: &Snapshot, heads: &[u64], complete: Completeness) -> LegalEntrySet {
    LegalEntrySet::new(
        s.mapping,
        s.generation,
        1,
        s.range(),
        complete,
        heads
            .iter()
            .map(|&pc| (pc, EntryProvenance::VerifiedInstruction)),
        [],
    )
    .unwrap()
}
fn inspect(s: &Snapshot, heads: &[u64]) -> ScanReport {
    RuntimeScan.inspect(
        s,
        s.range(),
        &entries(s, heads, Completeness::AllInstructionHeads),
        &Policy::default(),
    )
}

#[test]
fn every_selected_encoding_is_found_at_its_known_head() {
    // Independently specified bytes and expected classes, not decoder-derived truth.
    use SiteClass::*;
    let cases: &[(&[u8], SiteClass)] = &[
        (&[0x0f, 0xa2], Cpuid),
        (&[0x0f, 0xc7, 0xf0], Rdrand),
        (&[0x66, 0x0f, 0xc7, 0xf1], Rdrand),
        (&[0x49, 0x0f, 0xc7, 0xf7], Rdrand),
        (&[0x0f, 0xc7, 0xf8], Rdseed),
        (&[0xf3, 0x0f, 0xc7, 0xf8], Rdpid),
        (&[0x0f, 0x31], Rdtsc),
        (&[0x0f, 0x01, 0xf9], Rdtscp),
        (&[0x0f, 0x05], Syscall),
    ];
    for &(encoding, class) in cases {
        let s = snapshot(encoding.to_vec());
        let report = inspect(&s, &[BASE]);
        assert!(
            report.candidates().iter().any(|c| c.address == BASE
                && c.len as usize == encoding.len()
                && c.class == class
                && c.kind == CandidateKind::KnownInstruction),
            "{encoding:x?}: {report:?}"
        );
    }
}

#[test]
fn clean_unknown_code_does_not_need_an_invented_cfg_proof() {
    let s = snapshot(vec![0x90; 4096]);
    let report = RuntimeScan.inspect(
        &s,
        s.range(),
        &entries(&s, &[], Completeness::Partial),
        &Policy::default(),
    );
    assert_eq!(report.verdict(), Verdict::Clean);
    assert_eq!(report.metrics().decoded_starts, 4096);
}

#[test]
fn embedded_no_backstop_sites_never_silently_admit() {
    for embedded in [[0x0f, 0xa2, 0x90], [0x0f, 0xc7, 0xf0], [0x0f, 0xc7, 0xf8]] {
        // mov eax,imm32 with selected bytes inside its immediate.
        let s = snapshot(vec![
            0xb8,
            embedded[0],
            embedded[1],
            embedded[2],
            0x00,
            0xc3,
        ]);
        let report = inspect(&s, &[BASE, BASE + 5]);
        assert_eq!(report.verdict(), Verdict::Refused);
        assert!(
            report
                .obligations()
                .contains(&Obligation::EmbeddedCandidate(BASE + 1))
        );
        assert_eq!(report.metrics().embedded_candidates, 1);
    }
}

#[test]
fn rdpid_keeps_the_alternate_rdseed_decode_visible() {
    let s = snapshot(vec![0xf3, 0x0f, 0xc7, 0xf8]);
    let report = inspect(&s, &[BASE]);
    assert_eq!(report.metrics().known_sites, 1);
    assert_eq!(report.metrics().embedded_candidates, 1);
    assert_eq!(report.verdict(), Verdict::Refused);
    assert_eq!(report.candidates()[1].class, SiteClass::Rdseed);
}

#[test]
fn aliases_are_selected_only_when_explicitly_requested() {
    let s = snapshot(vec![0x0f, 0x34, 0xcd, 0x80]);
    let e = entries(&s, &[BASE, BASE + 2], Completeness::AllInstructionHeads);
    assert_eq!(
        RuntimeScan
            .inspect(&s, s.range(), &e, &Policy::default())
            .verdict(),
        Verdict::Clean
    );
    let mut policy = Policy::default();
    policy
        .selected
        .extend([SiteClass::Sysenter, SiteClass::Int80]);
    let report = RuntimeScan.inspect(&s, s.range(), &e, &policy);
    assert_eq!(report.verdict(), Verdict::Sites);
    assert_eq!(report.metrics().known_sites, 2);
}

#[test]
fn all_class_encodings_are_found_across_page_edges_in_both_directions() {
    let cases: &[&[u8]] = &[
        &[0x0f, 0xa2],
        &[0x0f, 0xc7, 0xf0],
        &[0x0f, 0xc7, 0xf8],
        &[0xf3, 0x0f, 0xc7, 0xf8],
        &[0x0f, 0x31],
        &[0x0f, 0x01, 0xf9],
        &[0x0f, 0x05],
    ];
    for encoding in cases {
        for split in 1..encoding.len() {
            let mut bytes = vec![0x90; 8192];
            let offset = 4096 - split;
            bytes[offset..offset + encoding.len()].copy_from_slice(encoding);
            let s = snapshot(bytes);
            let head = BASE + offset as u64;
            let e = entries(&s, &[head], Completeness::AllInstructionHeads);
            for page in [BASE, BASE + 4096] {
                let report = RuntimeScan.inspect(
                    &s,
                    AddressRange::new(page, page + 4096).unwrap(),
                    &e,
                    &Policy::default(),
                );
                assert!(
                    report
                        .candidates()
                        .iter()
                        .any(|c| c.address == head && c.kind == CandidateKind::KnownInstruction),
                    "{encoding:x?} split {split}: {report:?}"
                );
                assert!(report.dependency().contains(head));
                assert!(
                    report
                        .dependency()
                        .contains(head + encoding.len() as u64 - 1)
                );
            }
        }
    }
}

#[test]
fn maximum_length_prefixed_instruction_needs_the_full_left_halo() {
    let mut bytes = vec![0x90; 8192];
    bytes[4082..4095].fill(0x66);
    bytes[4095..4097].copy_from_slice(&[0x0f, 0xa2]);
    let s = snapshot(bytes);
    let e = entries(&s, &[BASE + 4082], Completeness::AllInstructionHeads);
    let report = RuntimeScan.inspect(
        &s,
        AddressRange::new(BASE + 4096, BASE + 8192).unwrap(),
        &e,
        &Policy::default(),
    );
    assert!(
        report
            .candidates()
            .iter()
            .any(|c| c.address == BASE + 4082 && c.len == 15)
    );
    assert_eq!(report.verdict(), Verdict::Refused); // other candidate entries remain unresolved
}

#[test]
fn missing_boundary_bytes_are_not_a_clean_page() {
    for (before, after) in [
        (Boundary::Unknown, Boundary::NonExecutable),
        (Boundary::NonExecutable, Boundary::Unknown),
    ] {
        let mut s = snapshot(vec![0x90; 4096]);
        s.before = before;
        s.after = after;
        assert!(
            inspect(&s, &[])
                .obligations()
                .contains(&Obligation::MissingBoundaryBytes)
        );
    }
}

#[test]
fn truncated_known_instruction_and_overlapping_entry_are_refused() {
    let s = snapshot(vec![0x0f]);
    assert!(
        inspect(&s, &[BASE])
            .obligations()
            .contains(&Obligation::InvalidKnownInstruction(BASE))
    );
    let s = snapshot(vec![0xb8, 0x0f, 0xa2, 0, 0, 0xc3]);
    let report = inspect(&s, &[BASE, BASE + 1]);
    assert!(
        report
            .obligations()
            .contains(&Obligation::OverlappingInstructions(BASE + 1))
    );
    assert_eq!(report.verdict(), Verdict::Refused);
}

#[test]
fn incomplete_entries_stale_identity_saved_resumes_and_unowned_writers_refuse() {
    let mut s = snapshot(vec![0x0f, 0xa2]);
    let incomplete = entries(&s, &[BASE], Completeness::Partial);
    assert!(
        RuntimeScan
            .inspect(&s, s.range(), &incomplete, &Policy::default())
            .obligations()
            .contains(&Obligation::IncompleteEntries)
    );
    let stale = entries(&s, &[BASE], Completeness::AllInstructionHeads);
    s.generation = Generation(2);
    assert!(
        RuntimeScan
            .inspect(&s, s.range(), &stale, &Policy::default())
            .obligations()
            .contains(&Obligation::EntryIdentityMismatch)
    );
    for kind in [
        ResumeKind::ParkedThread,
        ResumeKind::SyscallReturn,
        ResumeKind::SignalFrame,
        ResumeKind::NonlocalJump,
    ] {
        let e = LegalEntrySet::new(
            s.mapping,
            s.generation,
            2,
            s.range(),
            Completeness::AllInstructionHeads,
            [(BASE, EntryProvenance::Function)],
            [(BASE, kind)],
        )
        .unwrap();
        assert!(
            RuntimeScan
                .inspect(&s, s.range(), &e, &Policy::default())
                .obligations()
                .contains(&Obligation::SavedResume(BASE))
        );
    }
    for writes in [WriteControl::UnownedAlias, WriteControl::ExternalWriter] {
        s.writes = writes;
        assert!(
            inspect(&s, &[BASE])
                .obligations()
                .contains(&Obligation::UncontrolledWrites)
        );
    }
}

#[test]
fn entry_version_and_provenance_survive_and_cannot_escape_scope() {
    let s = snapshot(vec![0x90; 16]);
    let e = LegalEntrySet::new(
        s.mapping,
        s.generation,
        27,
        s.range(),
        Completeness::Partial,
        [
            (BASE, EntryProvenance::Function),
            (BASE, EntryProvenance::Endbr64),
        ],
        [],
    )
    .unwrap();
    assert_eq!(e.version(), 27);
    assert_eq!(e.heads()[&BASE].len(), 2);
    assert!(
        LegalEntrySet::new(
            s.mapping,
            s.generation,
            28,
            s.range(),
            Completeness::Partial,
            [(BASE + 16, EntryProvenance::ThreadStart)],
            []
        )
        .is_err()
    );
}

#[test]
fn invalid_range_is_a_total_refusal_and_address_overflow_is_rejected() {
    let s = snapshot(vec![0x90]);
    assert_eq!(
        RuntimeScan
            .inspect(
                &s,
                AddressRange::new(BASE, BASE + 2).unwrap(),
                &entries(&s, &[], Completeness::Partial),
                &Policy::default()
            )
            .verdict(),
        Verdict::Refused
    );
    assert!(
        Snapshot::new(
            MappingId(1),
            Generation(1),
            u64::MAX,
            vec![0x90],
            Boundary::NonExecutable,
            Boundary::NonExecutable,
            WriteControl::Owned
        )
        .is_none()
    );
}
