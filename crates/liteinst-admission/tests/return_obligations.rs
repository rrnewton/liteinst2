//! Portable source-fact tests. ModelGate state is not evidence of OS page
//! permissions; the live gate must separately test its actual NX boundary.

use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet};
use liteinst_admission::model::{ModelGate, PageState};
use liteinst_admission::returns::{CallReturnLedger, ReturnError};
use liteinst_admission::scan::{Boundary, Policy, Snapshot, WriteControl};
use liteinst_admission::{AddressRange, Generation, MappingId};

const BASE: u64 = 0x10_0000;
const NEXT: u64 = BASE + 4096;
const DIRECT: &[u8] = &[0xe8, 0, 0, 0, 0];
const INDIRECT_REGISTER: &[u8] = &[0xff, 0xd0];
const INDIRECT_MEMORY: &[u8] = &[0xff, 0x10];

fn page(base: u64) -> AddressRange {
    AddressRange::new(base, base + 4096).unwrap()
}

fn snapshot(bytes: Vec<u8>, base: u64, generation: u64) -> Snapshot {
    Snapshot::new(
        MappingId(1),
        Generation(generation),
        base,
        bytes,
        Boundary::NonExecutable,
        Boundary::Unknown,
        WriteControl::Owned,
    )
    .unwrap()
}

fn facts(
    source: &Snapshot,
    version: u64,
    completeness: Completeness,
    heads: impl IntoIterator<Item = (u64, EntryProvenance)>,
) -> LegalEntrySet {
    LegalEntrySet::new(
        source.mapping,
        source.generation,
        version,
        source.range(),
        completeness,
        heads,
        [],
    )
    .unwrap()
}

fn boundary_call(bytes: &[u8]) -> (Snapshot, LegalEntrySet, u64) {
    let head = NEXT - bytes.len() as u64;
    // Closed-world fixture: only the selected CALL is an executable head;
    // padding is not an attested instruction stream.
    let mut image = vec![0xcc; 4096];
    image[4096 - bytes.len()..].copy_from_slice(bytes);
    let source = snapshot(image, BASE, 1);
    let entries = facts(
        &source,
        1,
        Completeness::AllInstructionHeads,
        [(head, EntryProvenance::VerifiedInstruction)],
    );
    (source, entries, head)
}

fn assert_boundary_return(call: &[u8]) {
    let (source, entries, head) = boundary_call(call);
    let destination = snapshot(vec![0xcc; 4096], NEXT, 1);
    let destination_entries = facts(&destination, 1, Completeness::Partial, []);
    let gate = ModelGate::new();
    gate.register(
        page(NEXT),
        destination,
        destination_entries,
        Policy::default(),
    )
    .unwrap();
    assert_eq!(gate.state(NEXT), Ok(PageState::Unknown));

    let mut ledger = CallReturnLedger::new();
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &entries),
        Ok(1)
    );
    let returns: Vec<_> = ledger.obligations_in(page(NEXT)).collect();
    assert_eq!(returns.len(), 1);
    let obligation = returns[0];
    assert_eq!(obligation.call_address, head);
    assert_eq!(obligation.call_bytes, call);
    assert_eq!(obligation.return_pc, NEXT);
    assert_eq!(obligation.source_mapping, source.mapping);
    assert_eq!(obligation.source_generation, source.generation);
    assert_eq!(obligation.source_entry_version, entries.version());
    // Recording did not admit the destination. Its bytes were never supplied
    // to the ledger, yet the return entry must already constrain that page.
    assert_eq!(gate.state(NEXT), Ok(PageState::Unknown));
    assert_eq!(gate.publications(), Ok(0));
    assert_eq!(
        ledger.destination_entry_facts(page(NEXT)),
        vec![(NEXT, EntryProvenance::CallReturn)]
    );
}

#[test]
fn direct_call_ending_at_boundary_obligates_unadmitted_next_page() {
    assert_boundary_return(DIRECT);
}

#[test]
fn register_indirect_call_ending_at_boundary_obligates_unadmitted_next_page() {
    assert_boundary_return(INDIRECT_REGISTER);
}

#[test]
fn memory_indirect_call_ending_at_boundary_obligates_unadmitted_next_page() {
    assert_boundary_return(INDIRECT_MEMORY);
}

#[test]
fn call_return_provenance_supplements_destination_facts_without_claiming_completeness() {
    let (source, entries, _) = boundary_call(DIRECT);
    let mut ledger = CallReturnLedger::new();
    ledger
        .record_before_admission(&source, page(BASE), &entries)
        .unwrap();
    let destination_entries = LegalEntrySet::new(
        MappingId(99),
        Generation(7),
        4,
        page(NEXT),
        Completeness::Partial,
        ledger.destination_entry_facts(page(NEXT)),
        [],
    )
    .unwrap();
    assert_eq!(destination_entries.completeness(), Completeness::Partial);
    assert!(destination_entries.heads()[&NEXT].contains(&EntryProvenance::CallReturn));
    assert!(!destination_entries.heads()[&NEXT].contains(&EntryProvenance::VerifiedInstruction));
    assert_eq!(ledger.obligations_in(page(NEXT)).count(), 1);
}

#[test]
fn call_started_on_previous_page_is_recorded_before_admitting_its_final_bytes() {
    let head = BASE - 2;
    let mut image = vec![0xcc; 4096 + 14];
    image[12..17].copy_from_slice(DIRECT);
    let source = snapshot(image, BASE - 14, 1);
    let entries = facts(
        &source,
        1,
        Completeness::AllInstructionHeads,
        [(head, EntryProvenance::VerifiedInstruction)],
    );
    let mut ledger = CallReturnLedger::new();
    ledger
        .record_before_admission(&source, page(BASE), &entries)
        .unwrap();
    let obligation = ledger.obligations_in(page(BASE)).next().unwrap();
    assert_eq!(obligation.call_address, head);
    assert_eq!(obligation.return_pc, BASE + 3);
    assert_eq!(obligation.call_bytes, DIRECT);
}

#[test]
fn unknown_leading_bytes_and_incomplete_entry_scope_are_refused() {
    let (mut source, entries, _) = boundary_call(DIRECT);
    source.before = Boundary::Unknown;
    let mut ledger = CallReturnLedger::new();
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &entries),
        Err(ReturnError::MissingLeadingBytes)
    );
    let mut source = snapshot(vec![0xcc; 4096 + 14], BASE - 14, 1);
    source.before = Boundary::Unknown;
    let entries = LegalEntrySet::new(
        source.mapping,
        source.generation,
        1,
        page(BASE),
        Completeness::AllInstructionHeads,
        [],
        [],
    )
    .unwrap();
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &entries),
        Err(ReturnError::EntryScopeTooSmall)
    );
    assert_eq!(ledger.obligations().count(), 0);
}

#[test]
fn partial_or_unverified_heads_cannot_record_a_caller() {
    let (source, _, head) = boundary_call(DIRECT);
    let mut ledger = CallReturnLedger::new();
    let partial = facts(
        &source,
        1,
        Completeness::Partial,
        [(head, EntryProvenance::VerifiedInstruction)],
    );
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &partial),
        Err(ReturnError::IncompleteEntries)
    );
    for provenance in [EntryProvenance::Function, EntryProvenance::CallReturn] {
        let unverified = facts(
            &source,
            1,
            Completeness::AllInstructionHeads,
            [(head, provenance)],
        );
        assert_eq!(
            ledger.record_before_admission(&source, page(BASE), &unverified),
            Err(ReturnError::UnverifiedInstruction(head))
        );
    }
    assert_eq!(ledger.obligations().count(), 0);
}

#[test]
fn stale_identity_and_uncontrolled_source_bytes_are_refused() {
    let (source, entries, _) = boundary_call(DIRECT);
    let mut ledger = CallReturnLedger::new();
    let mut stale = source.clone();
    stale.generation = Generation(2);
    assert_eq!(
        ledger.record_before_admission(&stale, page(BASE), &entries),
        Err(ReturnError::EntryIdentityMismatch)
    );
    stale = source.clone();
    stale.mapping = MappingId(2);
    assert_eq!(
        ledger.record_before_admission(&stale, page(BASE), &entries),
        Err(ReturnError::EntryIdentityMismatch)
    );
    for writes in [WriteControl::UnownedAlias, WriteControl::ExternalWriter] {
        let mut uncontrolled = source.clone();
        uncontrolled.writes = writes;
        assert_eq!(
            ledger.record_before_admission(&uncontrolled, page(BASE), &entries),
            Err(ReturnError::UncontrolledWrites)
        );
    }
    assert_eq!(ledger.obligations().count(), 0);
}

#[test]
fn invalid_later_instruction_refuses_without_partial_records() {
    let mut bytes = vec![0xcc; 4096];
    bytes[..DIRECT.len()].copy_from_slice(DIRECT);
    bytes[4095] = 0xe8; // Truncated CALL: the displacement bytes are unknown.
    let source = snapshot(bytes, BASE, 1);
    let entries = facts(
        &source,
        1,
        Completeness::AllInstructionHeads,
        [
            (BASE, EntryProvenance::VerifiedInstruction),
            (NEXT - 1, EntryProvenance::VerifiedInstruction),
        ],
    );
    let mut ledger = CallReturnLedger::new();
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &entries),
        Err(ReturnError::InvalidInstruction(NEXT - 1))
    );
    assert_eq!(ledger.obligations().count(), 0);
}

#[test]
fn overlapping_verified_streams_are_refused() {
    let (source, _, head) = boundary_call(DIRECT);
    let entries = facts(
        &source,
        1,
        Completeness::AllInstructionHeads,
        [
            (head, EntryProvenance::VerifiedInstruction),
            (head + 1, EntryProvenance::VerifiedInstruction),
        ],
    );
    let mut ledger = CallReturnLedger::new();
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &entries),
        Err(ReturnError::OverlappingInstructions(head + 1))
    );
    assert_eq!(ledger.obligations().count(), 0);
}

#[test]
fn repeated_admission_is_idempotent_but_changed_same_generation_bytes_are_refused() {
    let (source, entries, head) = boundary_call(DIRECT);
    let mut ledger = CallReturnLedger::new();
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &entries),
        Ok(1)
    );
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &entries),
        Ok(0)
    );
    let mut bytes = source.bytes().to_vec();
    bytes[(head - BASE) as usize + 1] = 1;
    let conflicting = snapshot(bytes, BASE, 1);
    assert_eq!(
        ledger.record_before_admission(&conflicting, page(BASE), &entries),
        Err(ReturnError::ConflictingSnapshot)
    );
    assert_eq!(ledger.obligations().count(), 1);
    assert_eq!(ledger.obligations().next().unwrap().call_bytes, DIRECT);
}

#[test]
fn newer_generation_does_not_erase_a_return_pushed_by_an_old_caller() {
    let (source, entries, _) = boundary_call(DIRECT);
    let mut ledger = CallReturnLedger::new();
    ledger
        .record_before_admission(&source, page(BASE), &entries)
        .unwrap();
    let changed = snapshot(vec![0xcc; 4096], BASE, 2);
    let newer = facts(
        &changed,
        2,
        Completeness::AllInstructionHeads,
        [(BASE, EntryProvenance::VerifiedInstruction)],
    );
    assert_eq!(
        ledger.record_before_admission(&changed, page(BASE), &newer),
        Ok(0)
    );
    assert_eq!(ledger.obligations_in(page(NEXT)).count(), 1);
    assert_eq!(
        ledger.obligations().next().unwrap().source_generation,
        Generation(1)
    );
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &entries),
        Err(ReturnError::StaleGeneration)
    );
    assert_eq!(ledger.obligations_in(page(NEXT)).count(), 1);
}

#[test]
fn stale_or_conflicting_versions_of_one_entry_scope_are_refused() {
    let (source, _, head) = boundary_call(DIRECT);
    let entries = facts(
        &source,
        3,
        Completeness::AllInstructionHeads,
        [(head, EntryProvenance::VerifiedInstruction)],
    );
    let mut ledger = CallReturnLedger::new();
    ledger
        .record_before_admission(&source, page(BASE), &entries)
        .unwrap();
    let stale = facts(
        &source,
        2,
        Completeness::AllInstructionHeads,
        [(head, EntryProvenance::VerifiedInstruction)],
    );
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &stale),
        Err(ReturnError::StaleEntries)
    );
    let conflicting = facts(
        &source,
        3,
        Completeness::AllInstructionHeads,
        [
            (head, EntryProvenance::VerifiedInstruction),
            (head, EntryProvenance::Function),
        ],
    );
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &conflicting),
        Err(ReturnError::ConflictingEntries)
    );
    let advanced_without_generation = facts(
        &source,
        4,
        Completeness::AllInstructionHeads,
        [(head, EntryProvenance::VerifiedInstruction)],
    );
    assert_eq!(
        ledger.record_before_admission(&source, page(BASE), &advanced_without_generation),
        Err(ReturnError::ConflictingEntries)
    );
    assert_eq!(ledger.obligations_in(page(NEXT)).count(), 1);
}
