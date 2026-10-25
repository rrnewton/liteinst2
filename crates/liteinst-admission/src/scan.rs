//! All-start x86-64 scanning. The ordinary core linear scanner is intentionally
//! insufficient here: constants and alternate decodes can contain selected sites.
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic};

use crate::entries::{Completeness, LegalEntrySet};
use crate::{AddressRange, Generation, MappingId};

/// Maximum bytes on either side needed to decode an overlapping x86 instruction.
pub const HALO_BYTES: u64 = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SiteClass {
    Cpuid,
    Rdrand,
    Rdseed,
    Rdpid,
    Rdtsc,
    Rdtscp,
    Syscall,
    Sysenter,
    Int80,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub version: u64,
    pub selected: BTreeSet<SiteClass>,
}

impl Default for Policy {
    fn default() -> Self {
        use SiteClass::*;
        Self {
            version: 1,
            selected: [Cpuid, Rdrand, Rdseed, Rdpid, Rdtsc, Rdtscp, Syscall]
                .into_iter()
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    /// The owner establishes the adjacent address cannot supply instruction bytes.
    NonExecutable,
    /// Adjacent executable mapping or unknown protection: a halo is required.
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteControl {
    /// Immutable owned snapshot; live clients must reauthenticate under a lease.
    Owned,
    UnownedAlias,
    ExternalWriter,
}

/// Owned original bytes, never a raw pointer into changing executable memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub mapping: MappingId,
    pub generation: Generation,
    pub before: Boundary,
    pub after: Boundary,
    pub writes: WriteControl,
    range: AddressRange,
    bytes: Vec<u8>,
}

impl Snapshot {
    pub fn new(
        mapping: MappingId,
        generation: Generation,
        base: u64,
        bytes: Vec<u8>,
        before: Boundary,
        after: Boundary,
        writes: WriteControl,
    ) -> Option<Self> {
        Some(Self {
            mapping,
            generation,
            before,
            after,
            writes,
            range: AddressRange::from_len(base, bytes.len())?,
            bytes,
        })
    }

    pub fn range(&self) -> AddressRange {
        self.range
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateKind {
    KnownInstruction,
    Embedded,
    Unresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub address: u64,
    pub len: u8,
    pub class: SiteClass,
    pub kind: CandidateKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Obligation {
    OutsideSnapshot,
    EntryIdentityMismatch,
    EntryScopeTooSmall,
    MissingBoundaryBytes,
    UncontrolledWrites,
    InvalidKnownInstruction(u64),
    OverlappingInstructions(u64),
    EmbeddedCandidate(u64),
    UnresolvedCandidate(u64),
    IncompleteEntries,
    SavedResume(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Sites,
    Refused,
}

#[derive(Clone, Debug, Default)]
pub struct ScanMetrics {
    pub elapsed: Duration,
    pub decoded_starts: usize,
    pub known_sites: usize,
    pub embedded_candidates: usize,
    pub unresolved_candidates: usize,
    pub by_class: BTreeMap<SiteClass, usize>,
}

/// Facts, never authorization to execute. Original bytes and entry facts remain
/// attached so a publisher can authenticate the exact dependency snapshot again.
#[derive(Clone, Debug)]
pub struct ScanReport {
    snapshot: Snapshot,
    entries: LegalEntrySet,
    policy: Policy,
    target: AddressRange,
    dependency: AddressRange,
    candidates: Vec<Candidate>,
    obligations: Vec<Obligation>,
    metrics: ScanMetrics,
}

impl ScanReport {
    pub fn verdict(&self) -> Verdict {
        if !self.obligations.is_empty() {
            Verdict::Refused
        } else if self.candidates.is_empty() {
            Verdict::Clean
        } else {
            Verdict::Sites
        }
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn entries(&self) -> &LegalEntrySet {
        &self.entries
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn target(&self) -> AddressRange {
        self.target
    }
    pub fn dependency(&self) -> AddressRange {
        self.dependency
    }
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }
    pub fn obligations(&self) -> &[Obligation] {
        &self.obligations
    }
    pub fn metrics(&self) -> &ScanMetrics {
        &self.metrics
    }
}

/// Runtime fallback. A verdict is always returned, including explicit refusals.
pub trait AdmissionOracle {
    fn inspect(
        &self,
        snapshot: &Snapshot,
        target: AddressRange,
        entries: &LegalEntrySet,
        policy: &Policy,
    ) -> ScanReport;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeScan;

fn selected_class(instruction: &Instruction) -> Option<SiteClass> {
    Some(match instruction.mnemonic() {
        Mnemonic::Cpuid => SiteClass::Cpuid,
        Mnemonic::Rdrand => SiteClass::Rdrand,
        Mnemonic::Rdseed => SiteClass::Rdseed,
        Mnemonic::Rdpid => SiteClass::Rdpid,
        Mnemonic::Rdtsc => SiteClass::Rdtsc,
        Mnemonic::Rdtscp => SiteClass::Rdtscp,
        Mnemonic::Syscall => SiteClass::Syscall,
        Mnemonic::Sysenter => SiteClass::Sysenter,
        Mnemonic::Int if instruction.immediate8() == 0x80 => SiteClass::Int80,
        _ => return None,
    })
}

fn decode(snapshot: &Snapshot, address: u64) -> Instruction {
    let offset = (address - snapshot.range.start()) as usize;
    Decoder::with_ip(64, &snapshot.bytes[offset..], address, DecoderOptions::NONE).decode()
}

impl AdmissionOracle for RuntimeScan {
    fn inspect(
        &self,
        snapshot: &Snapshot,
        target: AddressRange,
        entries: &LegalEntrySet,
        policy: &Policy,
    ) -> ScanReport {
        let started = Instant::now();
        let mut report = ScanReport {
            snapshot: snapshot.clone(),
            entries: entries.clone(),
            policy: policy.clone(),
            target,
            dependency: snapshot.range,
            candidates: Vec::new(),
            obligations: Vec::new(),
            metrics: ScanMetrics::default(),
        };
        if !snapshot.range.covers(target) {
            report.obligations.push(Obligation::OutsideSnapshot);
            report.metrics.elapsed = started.elapsed();
            return report;
        }
        let first = target.start().saturating_sub(HALO_BYTES);
        let last = target.end().saturating_add(HALO_BYTES);
        if (snapshot.range.start() > first && snapshot.before == Boundary::Unknown)
            || (snapshot.range.end() < last && snapshot.after == Boundary::Unknown)
        {
            report.obligations.push(Obligation::MissingBoundaryBytes);
        }
        let scan_start = first.max(snapshot.range.start());
        let scan_end = last.min(snapshot.range.end());
        report.dependency = AddressRange::new(scan_start, scan_end).unwrap();
        if entries.mapping() != snapshot.mapping || entries.generation() != snapshot.generation {
            report.obligations.push(Obligation::EntryIdentityMismatch);
        }
        if !entries.scope().covers(report.dependency) {
            report.obligations.push(Obligation::EntryScopeTooSmall);
        }
        if snapshot.writes != WriteControl::Owned {
            report.obligations.push(Obligation::UncontrolledWrites);
        }

        let mut known = BTreeMap::new();
        for (&head, _) in entries.heads().range(scan_start..scan_end) {
            let instruction = decode(snapshot, head);
            if instruction.is_invalid() {
                report
                    .obligations
                    .push(Obligation::InvalidKnownInstruction(head));
            } else {
                // Every decode is within the validated snapshot; no address wraps.
                let end = head + instruction.len() as u64;
                if known
                    .last_key_value()
                    .is_some_and(|(_, &prior_end)| prior_end > head)
                {
                    report
                        .obligations
                        .push(Obligation::OverlappingInstructions(head));
                }
                known.insert(head, end);
            }
        }
        for address in scan_start..target.end() {
            let instruction = decode(snapshot, address);
            report.metrics.decoded_starts += 1;
            if instruction.is_invalid() || instruction.next_ip() <= target.start() {
                continue;
            }
            let Some(class) =
                selected_class(&instruction).filter(|class| policy.selected.contains(class))
            else {
                continue;
            };
            let kind = if known.contains_key(&address) {
                CandidateKind::KnownInstruction
            } else if known
                .range(..address)
                .next_back()
                .is_some_and(|(_, &end)| end > address)
            {
                CandidateKind::Embedded
            } else {
                CandidateKind::Unresolved
            };
            match kind {
                CandidateKind::KnownInstruction => report.metrics.known_sites += 1,
                CandidateKind::Embedded => {
                    report.metrics.embedded_candidates += 1;
                    report
                        .obligations
                        .push(Obligation::EmbeddedCandidate(address));
                }
                CandidateKind::Unresolved => {
                    report.metrics.unresolved_candidates += 1;
                    report
                        .obligations
                        .push(Obligation::UnresolvedCandidate(address));
                }
            }
            *report.metrics.by_class.entry(class).or_default() += 1;
            report.candidates.push(Candidate {
                address,
                len: instruction.len() as u8,
                class,
                kind,
            });
        }
        if !report.candidates.is_empty() {
            if entries.completeness() != Completeness::AllInstructionHeads {
                report.obligations.push(Obligation::IncompleteEntries);
            }
            for (&pc, _) in entries.resumes().range(report.dependency.as_range()) {
                report.obligations.push(Obligation::SavedResume(pc));
            }
        }
        report.metrics.elapsed = started.elapsed();
        report
    }
}
