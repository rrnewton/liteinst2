//! Conservative potential return addresses from verified CALL instructions.
//!
//! A CALL can push an address on a page that has never executed. Before making
//! its caller executable, the live gate must authenticate the source snapshot
//! and entry facts under its lease and record them here. An empty ledger is not
//! a census of saved PCs, and this module neither inspects stacks nor authorizes
//! publication. In particular, an unrecorded caller cannot be assumed harmless.
//!
//! Records are append-only: changing or unmapping a caller does not remove a
//! return it may already have pushed. There is deliberately no release API;
//! future retirement needs a separately qualified drain proof.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, Mnemonic};

use crate::entries::{Completeness, EntryProvenance, LegalEntrySet};
use crate::scan::{Boundary, HALO_BYTES, Snapshot, WriteControl};
use crate::{AddressRange, Generation, MappingId};

/// Positive evidence that a source CALL can create this continuation.
/// This is a potential return, not evidence that the CALL actually ran.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallReturnObligation {
    pub source_mapping: MappingId,
    pub source_generation: Generation,
    pub source_entry_version: u64,
    pub call_address: u64,
    /// Exact original bytes of the decoded CALL, including any prefixes.
    pub call_bytes: Vec<u8>,
    /// The CALL's next instruction address, even outside its source snapshot.
    pub return_pc: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReturnError {
    OutsideSnapshot,
    MissingLeadingBytes,
    EntryIdentityMismatch,
    EntryScopeTooSmall,
    IncompleteEntries,
    UncontrolledWrites,
    UnverifiedInstruction(u64),
    InvalidInstruction(u64),
    OverlappingInstructions(u64),
    StaleGeneration,
    StaleEntries,
    ConflictingSnapshot,
    ConflictingEntries,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceFacts {
    snapshot: Snapshot,
    caller: AddressRange,
    entries: LegalEntrySet,
}

/// Append-only source facts for all caller admissions owned by one live gate.
///
/// The gate must retain this ledger for its entire execution domain, serialize
/// recording with admission, and account separately for other saved resumes.
/// Constructing a fresh ledger does not establish that no returns exist.
#[derive(Debug, Default)]
pub struct CallReturnLedger {
    latest_generation: BTreeMap<MappingId, Generation>,
    sources: Vec<SourceFacts>,
    obligations: BTreeSet<CallReturnObligation>,
}

impl CallReturnLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records CALLs whose instruction bytes intersect the caller range.
    /// Returns the number of newly recorded potential returns.
    ///
    /// All instruction heads in the inspected scope must be exhaustively
    /// attested and individually marked `VerifiedInstruction`. Other provenance,
    /// including `CallReturn`, may supplement that marker but cannot replace it.
    /// A leading halo is required when preceding instruction bytes are possible.
    /// CALLs may end exactly at the snapshot boundary; no destination bytes or
    /// destination execution history are needed to retain their return address.
    ///
    /// This checks consistency with previously recorded source facts; it cannot
    /// authenticate live bytes or establish that caller-supplied generations are
    /// current. The gate must perform that check while admission is excluded.
    /// A refusal leaves every existing record unchanged.
    pub fn record_before_admission(
        &mut self,
        snapshot: &Snapshot,
        caller: AddressRange,
        entries: &LegalEntrySet,
    ) -> Result<usize, ReturnError> {
        if !snapshot.range().covers(caller) {
            return Err(ReturnError::OutsideSnapshot);
        }
        if snapshot.mapping != entries.mapping() || snapshot.generation != entries.generation() {
            return Err(ReturnError::EntryIdentityMismatch);
        }
        if snapshot.writes != WriteControl::Owned {
            return Err(ReturnError::UncontrolledWrites);
        }
        if entries.completeness() != Completeness::AllInstructionHeads {
            return Err(ReturnError::IncompleteEntries);
        }
        let first_possible_head = caller.start().saturating_sub(HALO_BYTES);
        if snapshot.range().start() > first_possible_head && snapshot.before == Boundary::Unknown {
            return Err(ReturnError::MissingLeadingBytes);
        }
        let scan_start = first_possible_head.max(snapshot.range().start());
        let head_scope = AddressRange::new(scan_start, caller.end()).unwrap();
        if !entries.scope().covers(head_scope) {
            return Err(ReturnError::EntryScopeTooSmall);
        }
        self.check_source_history(snapshot, entries)?;

        // Build everything before modifying the ledger: a bad later instruction
        // must not leave a partially recorded caller behind.
        let mut additions = BTreeSet::new();
        let mut previous_end = None;
        for (&address, provenance) in entries.heads().range(scan_start..caller.end()) {
            if !provenance.contains(&EntryProvenance::VerifiedInstruction) {
                return Err(ReturnError::UnverifiedInstruction(address));
            }
            let offset = (address - snapshot.range().start()) as usize;
            let instruction = Decoder::with_ip(
                64,
                &snapshot.bytes()[offset..],
                address,
                DecoderOptions::NONE,
            )
            .decode();
            if instruction.is_invalid() {
                return Err(ReturnError::InvalidInstruction(address));
            }
            let end = address
                .checked_add(instruction.len() as u64)
                .filter(|end| *end <= snapshot.range().end())
                .ok_or(ReturnError::InvalidInstruction(address))?;
            if previous_end.is_some_and(|prior| prior > address) {
                return Err(ReturnError::OverlappingInstructions(address));
            }
            previous_end = Some(end);
            if end > caller.start() && instruction.mnemonic() == Mnemonic::Call {
                additions.insert(CallReturnObligation {
                    source_mapping: snapshot.mapping,
                    source_generation: snapshot.generation,
                    source_entry_version: entries.version(),
                    call_address: address,
                    call_bytes: snapshot.bytes()[offset..offset + instruction.len()].to_vec(),
                    return_pc: instruction.next_ip(),
                });
            }
        }

        let source = SourceFacts {
            snapshot: snapshot.clone(),
            caller,
            entries: entries.clone(),
        };
        self.latest_generation
            .insert(snapshot.mapping, snapshot.generation);
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
        let old_len = self.obligations.len();
        self.obligations.extend(additions);
        Ok(self.obligations.len() - old_len)
    }

    /// All retained potential returns, including old source generations.
    pub fn obligations(&self) -> impl Iterator<Item = &CallReturnObligation> {
        self.obligations.iter()
    }

    /// Potential returns into this address range, independent of whether it has
    /// ever executed or currently belongs to the same destination mapping.
    pub fn obligations_in(
        &self,
        destination: AddressRange,
    ) -> impl Iterator<Item = &CallReturnObligation> {
        self.obligations
            .iter()
            .filter(move |obligation| destination.contains(obligation.return_pc))
    }

    /// Deduplicated positive entry facts for a destination page's entry set.
    /// These do not establish instruction-head completeness or absence of saved
    /// resumes, and the destination decoder must still verify its own bytes.
    pub fn destination_entry_facts(
        &self,
        destination: AddressRange,
    ) -> Vec<(u64, EntryProvenance)> {
        self.obligations_in(destination)
            .map(|obligation| (obligation.return_pc, EntryProvenance::CallReturn))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn check_source_history(
        &self,
        snapshot: &Snapshot,
        entries: &LegalEntrySet,
    ) -> Result<(), ReturnError> {
        if self
            .latest_generation
            .get(&snapshot.mapping)
            .is_some_and(|generation| *generation > snapshot.generation)
        {
            return Err(ReturnError::StaleGeneration);
        }
        for previous in &self.sources {
            if previous.snapshot.mapping != snapshot.mapping
                || previous.snapshot.generation != snapshot.generation
            {
                continue;
            }
            let start = previous
                .snapshot
                .range()
                .start()
                .max(snapshot.range().start());
            let end = previous.snapshot.range().end().min(snapshot.range().end());
            if start < end {
                let previous_start = (start - previous.snapshot.range().start()) as usize;
                let current_start = (start - snapshot.range().start()) as usize;
                let len = (end - start) as usize;
                if previous.snapshot.bytes()[previous_start..previous_start + len]
                    != snapshot.bytes()[current_start..current_start + len]
                {
                    return Err(ReturnError::ConflictingSnapshot);
                }
            }
            // Entry-set versions are scoped facts, not a global sequence shared
            // by independently discovered entry sets on every mapping page.
            if previous.entries.scope() == entries.scope() {
                if previous.entries.version() > entries.version() {
                    return Err(ReturnError::StaleEntries);
                }
                // Generation covers entry facts as well as bytes. Even a newer
                // entry-set version needs a new generation for this scope.
                if previous.entries != *entries {
                    return Err(ReturnError::ConflictingEntries);
                }
            }
        }
        Ok(())
    }
}
