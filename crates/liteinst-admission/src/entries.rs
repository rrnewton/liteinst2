//! Positive entry evidence is not a completeness proof. Dynamic resumes are
//! recorded separately; a symbol census cannot discharge them.
use std::collections::{BTreeMap, BTreeSet};

use crate::{AddressRange, Generation, MappingId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryProvenance {
    Function,
    Endbr64,
    CallReturn,
    ExceptionLanding,
    JumpTable,
    DirectBranch,
    Loader,
    SignalHandler,
    SignalRestorer,
    ThreadStart,
    Jit,
    VerifiedInstruction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResumeKind {
    ParkedThread,
    SyscallReturn,
    SignalFrame,
    NonlocalJump,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completeness {
    /// Only positive evidence; indirect and other unseen entries remain possible.
    Partial,
    /// Caller attests every executable instruction head in the scope is listed,
    /// including alternate streams. This is stronger than an external-entry list.
    /// The scanner still independently rejects overlaps and embedded candidates.
    AllInstructionHeads,
}

/// Immutable facts tied to source, byte generation, scope and entry-set version.
/// Entries discovered later require a new set and invalidate dependent plans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalEntrySet {
    mapping: MappingId,
    generation: Generation,
    version: u64,
    scope: AddressRange,
    completeness: Completeness,
    heads: BTreeMap<u64, BTreeSet<EntryProvenance>>,
    resumes: BTreeMap<u64, BTreeSet<ResumeKind>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryOutsideScope(pub u64);

impl LegalEntrySet {
    pub fn new(
        mapping: MappingId,
        generation: Generation,
        version: u64,
        scope: AddressRange,
        completeness: Completeness,
        heads: impl IntoIterator<Item = (u64, EntryProvenance)>,
        resumes: impl IntoIterator<Item = (u64, ResumeKind)>,
    ) -> Result<Self, EntryOutsideScope> {
        let mut result = Self {
            mapping,
            generation,
            version,
            scope,
            completeness,
            heads: BTreeMap::new(),
            resumes: BTreeMap::new(),
        };
        for (pc, provenance) in heads {
            if !scope.contains(pc) {
                return Err(EntryOutsideScope(pc));
            }
            result.heads.entry(pc).or_default().insert(provenance);
        }
        for (pc, kind) in resumes {
            if !scope.contains(pc) {
                return Err(EntryOutsideScope(pc));
            }
            result.resumes.entry(pc).or_default().insert(kind);
        }
        Ok(result)
    }

    pub fn mapping(&self) -> MappingId {
        self.mapping
    }
    pub fn generation(&self) -> Generation {
        self.generation
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn scope(&self) -> AddressRange {
        self.scope
    }
    pub fn completeness(&self) -> Completeness {
        self.completeness
    }
    pub fn heads(&self) -> &BTreeMap<u64, BTreeSet<EntryProvenance>> {
        &self.heads
    }
    pub fn resumes(&self) -> &BTreeMap<u64, BTreeSet<ResumeKind>> {
        &self.resumes
    }
}
