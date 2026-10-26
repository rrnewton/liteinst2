//! Owner-independent planning over authenticated immutable source facts.
//!
//! These plans preserve the strict reference, typed selected, explicit coverage,
//! and A1 CPUID paths as separate choices. They confer no native stop, release,
//! writer-exclusion, publication, or mapping-generation authority. Callers must
//! authenticate live source and all saved continuations under their real owner
//! before applying a plan. A cache hit does not discharge those obligations.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use iced_x86::{Code, Decoder, DecoderOptions};
use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet};
use liteinst_admission::oracle_chain::{
    CacheCorruption, CacheLimits, CacheUsage, Inspection, OracleChain,
};
use liteinst_admission::returns::{CallReturnLedger, CallReturnObligation};
use liteinst_admission::scan::{
    AdmissionOracle, Boundary, Candidate, Obligation, Policy, ScanReport, Snapshot, Verdict,
    WriteControl,
};
use liteinst_admission::{AddressRange, Generation, MappingId};
use liteinst2::contracts as core;
use liteinst2::quiescent::AllocationPolicy;

use super::{GateError, GateOracleMetrics, ImageFacts};
use crate::core_remote::{CpuidPlanRequest, CpuidPublisher, MAX_CPUID_BUNDLE, PreparedCpuid};
use crate::trap_coverage::pending::{PendingCoverage, ResumeRequirement};
use crate::trap_coverage::{TrapCoverageBudget, TrapCoveragePlan, TrapGuard, TrapGuardRole};
use crate::{LaunchError, MemoryMapping, SignalStop};

pub(crate) const PAGE: u64 = 4096;
const MAX_IMAGES: usize = 64;
const MAX_IMAGE_BYTES: usize = 64 * 1024;
const MAX_GATED_PAGES: u64 = 16 * 1024;
static NEXT_IMAGE_ID: AtomicU64 = AtomicU64::new(1);

// No live API accepts an arbitrary AdmissionOracle or caller-created report.
// This private adapter can only call the chain's mandatory RuntimeScan terminal.
pub(crate) struct GateOracle {
    pub(super) chain: OracleChain,
    pub(super) metrics: RefCell<GateOracleMetrics>,
}

impl GateOracle {
    pub(crate) fn new(limits: CacheLimits) -> Result<Self, GateError> {
        Ok(Self {
            chain: OracleChain::new(limits)
                .map_err(|_| GateError::Refused("invalid oracle cache limits"))?,
            metrics: RefCell::new(GateOracleMetrics::default()),
        })
    }

    pub(crate) fn metrics(&self) -> GateOracleMetrics {
        self.metrics.borrow().clone()
    }

    pub(crate) fn usage(&self) -> Result<CacheUsage, CacheCorruption> {
        self.chain.usage()
    }

    fn inspect_preparation(
        &self,
        image: &Image,
        target: AddressRange,
        policy: &Policy,
    ) -> Inspection {
        let inspection =
            self.chain
                .inspect_with_evidence(&image.snapshot, target, &image.entries, policy);
        self.metrics.borrow_mut().preparation.record(&inspection);
        inspection
    }
}

impl AdmissionOracle for GateOracle {
    fn inspect(
        &self,
        snapshot: &Snapshot,
        target: AddressRange,
        entries: &LegalEntrySet,
        policy: &Policy,
    ) -> ScanReport {
        let inspection = self
            .chain
            .inspect_with_evidence(snapshot, target, entries, policy);
        self.metrics.borrow_mut().demand.record(&inspection);
        inspection.report
    }
}

/// Original immutable image facts. Sharing an mm between tasks must share
/// these facts and their identity, not create a fresh child generation. Later
/// mapping or entry-version changes require the native owner's invalidation
/// proof; this structure supplies none of that authority.
pub(crate) struct Image {
    pub(crate) mapping: MemoryMapping,
    pub(crate) snapshot: Snapshot,
    pub(crate) entries: LegalEntrySet,
    pub(crate) core_identity: core::CodeIdentity,
}

/// Validate the census-count budget before native bootstrap, as the legacy
/// gate does. This is only a budget check, never a source authentication.
pub(crate) fn validate_image_count(facts: &[ImageFacts]) -> Result<(), GateError> {
    if facts.len() > MAX_IMAGES {
        return Err(GateError::Refused("too many image censuses"));
    }
    Ok(())
}

/// Original executable page inventory. `false` is bookkeeping for the caller's
/// independently established NX state; this function changes no permissions.
pub(crate) fn initial_pages(mappings: &[MemoryMapping]) -> Result<BTreeMap<u64, bool>, GateError> {
    let page_count = mappings.iter().try_fold(0_u64, |count, mapping| {
        count.checked_add((mapping.end - mapping.start) / PAGE)
    });
    if mappings.len() > MAX_IMAGES || page_count.is_none_or(|count| count > MAX_GATED_PAGES) {
        return Err(GateError::Refused(
            "initial executable mapping budget exceeded",
        ));
    }
    let mut pages = BTreeMap::new();
    for mapping in mappings {
        if mapping.start % PAGE != 0
            || mapping.end % PAGE != 0
            || mapping.permissions.as_bytes().get(1) == Some(&b'w')
            || mapping.permissions.as_bytes().get(3) != Some(&b'p')
        {
            return Err(GateError::Refused(
                "requires page-aligned private non-writable code",
            ));
        }
        for address in (mapping.start..mapping.end).step_by(PAGE as usize) {
            pages.insert(address, false);
        }
    }
    Ok(pages)
}

/// Bind complete caller facts to the original mapping inventory and a read-only
/// source observation. The caller retains the immutable-source/exclusion proof;
/// the read callback supplies bytes only and cannot confer native authority.
/// Call validate_image_count and initial_pages at their original bootstrap phases.
/// This retains the static-image contract: an uncensused neighboring mapping
/// stays NX, and no new census may be added without a new joint-boundary proof.
pub(crate) fn prepare_images(
    facts: Vec<ImageFacts>,
    mappings: &[MemoryMapping],
    mut read_original: impl FnMut(u64, usize) -> Result<Vec<u8>, LaunchError>,
) -> Result<Vec<Image>, GateError> {
    let census_starts: BTreeSet<_> = facts.iter().map(|fact| fact.start).collect();
    let mut images = Vec::new();
    for fact in facts {
        let mapping = mappings
            .iter()
            .find(|m| m.start == fact.start && m.end - m.start == fact.bytes.len() as u64)
            .ok_or(GateError::Refused(
                "census must cover exactly one original executable VMA",
            ))?
            .clone();
        if fact.bytes.len() > MAX_IMAGE_BYTES
            || images
                .iter()
                .any(|image: &Image| image.mapping.start == fact.start)
        {
            return Err(GateError::Refused("oversized or duplicate census"));
        }
        if read_original(fact.start, fact.bytes.len())? != fact.bytes {
            return Err(GateError::Refused("original image bytes differ"));
        }
        // Adjacent admitted VMAs require a cross-mapping proof. A neighbor
        // with no census stays NX for this owner's whole lifetime: facts
        // cannot be added later and every first touch there is refused.
        if mappings.iter().any(|m| {
            census_starts.contains(&m.start) && (m.end == mapping.start || m.start == mapping.end)
        }) {
            return Err(GateError::Refused(
                "adjacent executable VMAs need a joint census",
            ));
        }
        let core_identity = new_core_identity()?;
        let identity = MappingId(core_identity.mapping);
        let snapshot = Snapshot::new(
            identity,
            Generation(0),
            fact.start,
            fact.bytes,
            Boundary::NonExecutable,
            Boundary::NonExecutable,
            WriteControl::Owned,
        )
        .ok_or(GateError::Refused("invalid census range"))?;
        let entries = LegalEntrySet::new(
            identity,
            Generation(0),
            0,
            snapshot.range(),
            Completeness::AllInstructionHeads,
            fact.heads
                .into_iter()
                .map(|pc| (pc, EntryProvenance::VerifiedInstruction)),
            [],
        )
        .map_err(|_| GateError::Refused("instruction head outside mapping"))?;
        images.push(Image {
            mapping,
            snapshot,
            entries,
            core_identity,
        });
    }
    Ok(images)
}

/// The caller must reject preparation after application execution begins.
/// The complete batch remains validated before the first inspection. As in the
/// existing gate, the scan deadline starts only after that batch validation.
pub(crate) fn prepare_oracle(
    oracle: &GateOracle,
    images: &[Image],
    page_states: &BTreeMap<u64, bool>,
    pages: &[u64],
    policy: &Policy,
    timeout: Duration,
) -> Result<Vec<Inspection>, GateError> {
    if pages.len() > 64 || oracle.metrics.borrow().preparation.inspections + pages.len() as u64 > 64
    {
        return Err(GateError::Refused(
            "oracle preparation page budget exceeded",
        ));
    }
    let unique: BTreeSet<_> = pages.iter().copied().collect();
    if unique.len() != pages.len()
        || pages.iter().any(|&page| {
            page % PAGE != 0
                || page_states.get(&page) != Some(&false)
                || !images
                    .iter()
                    .any(|image| image.snapshot.range().contains(page))
        })
    {
        return Err(GateError::Refused(
            "oracle preparation requires distinct censused whole pages",
        ));
    }
    let deadline = Instant::now() + timeout;
    let mut inspections = Vec::with_capacity(pages.len());
    for &page in pages {
        remaining(deadline)?;
        let image = images
            .iter()
            .find(|image| image.snapshot.range().contains(page))
            .expect("batch validated");
        inspections.push(oracle.inspect_preparation(
            image,
            AddressRange::new(page, page + PAGE).unwrap(),
            policy,
        ));
        remaining(deadline)?;
    }
    Ok(inspections)
}

pub(crate) fn original_byte(images: &[Image], pc: u64) -> Result<u8, GateError> {
    images
        .iter()
        .find(|image| image.snapshot.range().contains(pc))
        .map(|image| image.snapshot.bytes()[(pc - image.mapping.start) as usize])
        .ok_or(GateError::Refused("no original source byte"))
}

pub(crate) fn owned_fetch(
    images: &[Image],
    pages: &BTreeMap<u64, bool>,
    signal: &SignalStop,
) -> Result<bool, GateError> {
    let Some(address) = signal.address else {
        return Ok(false);
    };
    if pages.get(&(address & !(PAGE - 1))) != Some(&false) {
        return Ok(false);
    }
    let Some(image) = images
        .iter()
        .find(|image| image.snapshot.range().contains(signal.instruction_pointer))
    else {
        return Err(GateError::Refused("first touch has no complete census"));
    };
    if !image
        .entries
        .heads()
        .contains_key(&signal.instruction_pointer)
    {
        return Err(GateError::Refused("first touch at an undeclared head"));
    }
    let offset = (signal.instruction_pointer - image.mapping.start) as usize;
    let instruction = Decoder::with_ip(
        64,
        &image.snapshot.bytes()[offset..],
        signal.instruction_pointer,
        DecoderOptions::NONE,
    )
    .decode();
    Ok(!instruction.is_invalid() && address >= instruction.ip() && address < instruction.next_ip())
}

/// Expected strict/reference or A1 source image, retaining original bytes for
/// every unpublished address. This does not read or authenticate a live task.
pub(crate) fn expected_source_bytes(
    image: &Image,
    sites: &BTreeMap<u64, Candidate>,
    publisher: Option<&CpuidPublisher>,
) -> Vec<u8> {
    let mut expected = image.snapshot.bytes().to_vec();
    for (&pc, _) in sites.range(image.snapshot.range().as_range()) {
        expected[(pc - image.mapping.start) as usize] = 0xcc;
    }
    if let Some(publisher) = publisher {
        for installed in publisher.installed() {
            for edit in &installed.plan().parts().writes {
                if image.snapshot.range().contains(edit.address) {
                    let offset = (edit.address - image.mapping.start) as usize;
                    expected[offset..offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
                }
            }
        }
    }
    expected
}

pub(crate) fn armed_instruction(
    pc: u64,
    original: &[u8],
    sites: &BTreeMap<u64, Candidate>,
    covered_guards: &BTreeMap<u64, TrapGuard>,
) -> Vec<u8> {
    let mut armed = original.to_vec();
    let end = pc
        .checked_add(original.len() as u64)
        .expect("validated instruction range");
    for (&address, _) in sites.range(pc..end) {
        armed[(address - pc) as usize] = 0xcc;
    }
    for (&address, _) in covered_guards.range(pc..end) {
        armed[(address - pc) as usize] = 0xcc;
    }
    armed
}

/// A proposed whole-page dependency closure, not a publication receipt.
/// The CALL ledger is checked afresh by planning and remains append-only in the
/// owner; successful planning never discharges saved-continuation obligations.
pub(crate) struct AdmissionBundle {
    pub(crate) pages: BTreeSet<u64>,
    pub(crate) candidates: BTreeMap<u64, Candidate>,
    pub(crate) prepared: BTreeMap<u64, PreparedCpuid>,
}

pub(crate) fn prepare_admission(
    source: (&Image, &GateOracle),
    page: u64,
    policy: &Policy,
    returns: &CallReturnLedger,
    publisher: Option<&CpuidPublisher>,
    selected_aliases: Option<&crate::selected::SyscallAliases>,
    deadline: Instant,
) -> Result<AdmissionBundle, GateError> {
    let geometry = prepare_admission_geometry(
        source,
        page,
        policy,
        returns,
        AdmissionSelection::Legacy {
            publisher,
            selected_aliases,
        },
        deadline,
    )?;
    Ok(AdmissionBundle {
        pages: geometry.pages,
        candidates: geometry.candidates,
        prepared: geometry.prepared,
    })
}

// This intermediate is private to the shared original strict loop. In pending
// mode it never enters an AdmissionBundle or the A1 planner.
struct AdmissionGeometry {
    pages: BTreeSet<u64>,
    candidates: BTreeMap<u64, Candidate>,
    prepared: BTreeMap<u64, PreparedCpuid>,
    reports: Vec<ScanReport>,
}

enum AdmissionSelection<'a> {
    Legacy {
        publisher: Option<&'a CpuidPublisher>,
        selected_aliases: Option<&'a crate::selected::SyscallAliases>,
    },
    PendingTrap {
        aliases: &'a crate::selected::SyscallAliases,
    },
}

fn prepare_admission_geometry(
    source: (&Image, &GateOracle),
    page: u64,
    policy: &Policy,
    returns: &CallReturnLedger,
    selection: AdmissionSelection<'_>,
    deadline: Instant,
) -> Result<AdmissionGeometry, GateError> {
    let (publisher, selected_aliases, defer_saved) = match selection {
        AdmissionSelection::Legacy {
            publisher,
            selected_aliases,
        } => (publisher, selected_aliases, false),
        AdmissionSelection::PendingTrap { aliases } => (None, Some(aliases), true),
    };
    let (image, oracle) = source;
    // Close over complete pages required by every selected straddler.
    // Granting X to a halo without scanning its entire page is forbidden.
    let mut bundle = BTreeSet::from([page]);
    let mut scanned = BTreeSet::new();
    let mut candidates = BTreeMap::new();
    let mut prepared = BTreeMap::new();
    let mut reports = Vec::new();
    while let Some(next) = bundle.difference(&scanned).next().copied() {
        remaining(deadline)?;
        if !image
            .snapshot
            .range()
            .covers(AddressRange::new(next, next + PAGE).unwrap())
        {
            return Err(GateError::Refused(
                "selected instruction crosses image census",
            ));
        }
        let target = AddressRange::new(next, next + PAGE).unwrap();
        let report = oracle.inspect(&image.snapshot, target, &image.entries, policy);
        remaining(deadline)?;
        if report.verdict() == Verdict::Refused
            && (!defer_saved
                || report
                    .obligations()
                    .iter()
                    .any(|obligation| !matches!(obligation, Obligation::SavedResume(_))))
        {
            return Err(GateError::Scan(report.obligations().to_vec()));
        }
        // NX history is never an exhaustive proof that no resumes exist.
        if !report.candidates().is_empty()
            && returns.obligations_in(report.dependency()).next().is_some()
        {
            return Err(GateError::Refused(
                "potential saved CALL return intersects selected publication",
            ));
        }
        for site in report.candidates() {
            remaining(deadline)?;
            if let Some(aliases) = selected_aliases {
                let start = (site.address - image.mapping.start) as usize;
                let end = start + usize::from(site.len);
                let decoded = crate::selected::decode(
                    site.address,
                    &image.snapshot.bytes()[start..end],
                    aliases,
                )?;
                if decoded.bytes().len() != usize::from(site.len)
                    || decoded.operation().class() != site.class
                {
                    return Err(GateError::Refused("selected decode differs from scan"));
                }
            } else if site.class != liteinst_admission::scan::SiteClass::Cpuid {
                return Err(GateError::Refused(
                    "selected class lacks reference single-step qualification",
                ));
            }
            candidates.insert(site.address, *site);
            bundle.insert(site.address & !(PAGE - 1));
            bundle.insert((site.address + u64::from(site.len) - 1) & !(PAGE - 1));
            if let Some(publisher) = publisher {
                if !publisher
                    .installed()
                    .iter()
                    .any(|installed| installed.plan().parts().logical_pc == site.address)
                    && !prepared.contains_key(&site.address)
                {
                    if prepared.len() == MAX_CPUID_BUNDLE {
                        return Err(GateError::Refused(
                            "core publication bundle budget exceeded",
                        ));
                    }
                    let plan = prepare_cpuid(image, *site)?;
                    remaining(deadline)?;
                    let consumed = plan.consumed();
                    bundle.insert(consumed.start() & !(PAGE - 1));
                    bundle.insert((consumed.end() - 1) & !(PAGE - 1));
                    prepared.insert(site.address, plan);
                }
            }
        }
        scanned.insert(next);
        if defer_saved {
            reports.push(report);
        }
    }
    Ok(AdmissionGeometry {
        pages: bundle,
        candidates,
        prepared,
        reports,
    })
}

pub(crate) fn new_core_identity() -> Result<core::CodeIdentity, GateError> {
    let nonce = NEXT_IMAGE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| GateError::Refused("image identity space exhausted"))?;
    let mut source = [0; 32];
    source[..8].copy_from_slice(b"li2image");
    source[8..16].copy_from_slice(&nonce.to_le_bytes());
    // This is a non-reused owner key bound to an immutable image and policy,
    // not a content hash. Publication always authenticates exact bytes too.
    Ok(core::CodeIdentity {
        source: core::SourceIdentity(source),
        mapping: nonce,
        generation: 0,
    })
}

fn prepare_cpuid(image: &Image, site: Candidate) -> Result<PreparedCpuid, GateError> {
    let offset = (site.address - image.mapping.start) as usize;
    let mut decoder = Decoder::with_ip(
        64,
        &image.snapshot.bytes()[offset..],
        site.address,
        DecoderOptions::NONE,
    );
    while decoder.ip() < site.address + 5 {
        if !image.entries.heads().contains_key(&decoder.ip()) {
            return Err(GateError::Refused(
                "pun dependency lacks a verified instruction head",
            ));
        }
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(GateError::Refused(
                "pun dependency is not complete instructions",
            ));
        }
    }
    let size = (decoder.ip() - site.address) as usize;
    let entries = core::LegalEntrySet {
        identity: image.core_identity,
        scope: core::AddressRange::new(image.mapping.start, image.snapshot.bytes().len())
            .map_err(GateError::Core)?,
        provenance: core::EntryProvenance::Declared(
            "immutable launch instruction-head census".into(),
        ),
        completeness: core::EntryCompleteness::AllInstructionHeads,
        entries: image
            .entries
            .heads()
            .keys()
            .map(|&address| core::LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        // A conservative superset: the unsafe constructor certifies that any
        // saved continuation is a declared head. NX history proves nothing.
        resumes: core::ResumeObligation::Enumerated(
            image.entries.heads().keys().copied().collect(),
        ),
    };
    let allocation = AllocationPolicy::near(site.address).map_err(GateError::Core)?;
    PreparedCpuid::prepare(CpuidPlanRequest {
        identity: image.core_identity,
        address: site.address,
        code: &image.snapshot.bytes()[offset..offset + size],
        entries: &entries,
        allocation: &allocation,
    })
    .map_err(GateError::Core)
}

/// Explicit guard placement plus the existing live backend's qualification.
/// Original refused scanner reports stay in the returned coverage plan. Every
/// current saved CALL-return dependency is checked again even after cache hits.
/// The caller still records newly admitted CALLs before any source write.
pub(crate) fn prepare_covered_admission(
    source: (&Image, &GateOracle),
    page: u64,
    policy: &Policy,
    returns: &CallReturnLedger,
    selection: (
        &crate::selected::SyscallAliases,
        &BTreeMap<u64, TrapGuard>,
        TrapCoverageBudget,
    ),
    deadline: Instant,
) -> Result<TrapCoveragePlan, GateError> {
    let (image, oracle) = source;
    let (aliases, covered_guards, budget) = selection;
    let plan = TrapCoveragePlan::build_with_oracle(
        &image.snapshot,
        AddressRange::new(page, page + PAGE).unwrap(),
        &image.entries,
        policy,
        budget,
        oracle,
    )
    .map_err(GateError::Coverage)?;
    remaining(deadline)?;

    qualify_covered_geometry(
        &image.entries,
        plan.guards(),
        plan.dependencies(),
        aliases,
        covered_guards,
        returns,
    )?;
    Ok(plan)
}

fn qualify_covered_geometry(
    entries: &LegalEntrySet,
    guards: &BTreeMap<u64, TrapGuard>,
    dependencies: &[AddressRange],
    aliases: &crate::selected::SyscallAliases,
    covered_guards: &BTreeMap<u64, TrapGuard>,
    returns: &CallReturnLedger,
) -> Result<(), GateError> {
    // The placement proof does not qualify an execution mechanism. Validate
    // every selected decode and every collateral step before the first write.
    for guard in guards.values() {
        match guard.role() {
            TrapGuardRole::Selected(site) => {
                let decoded =
                    crate::selected::decode(guard.address(), guard.original_bytes(), aliases)?;
                if decoded.bytes() != guard.original_bytes()
                    || decoded.operation().class() != site.class
                {
                    return Err(GateError::Refused("covered selected decode differs"));
                }
            }
            TrapGuardRole::Collateral => qualify_collateral(guard)?,
        }
        if covered_guards
            .get(&guard.address())
            .is_some_and(|old| old != guard)
        {
            return Err(GateError::Refused(
                "covered guard changed within generation",
            ));
        }
    }
    // A saved CALL return may target a never-executed page. It must remain a
    // certified original head; the guard closure preserves every such head.
    for dependency in dependencies {
        if returns
            .obligations_in(*dependency)
            .any(|entry| !entries.heads().contains_key(&entry.return_pc))
        {
            return Err(GateError::Refused("saved CALL return lacks a covered head"));
        }
    }
    Ok(())
}

pub(crate) fn qualify_collateral(guard: &TrapGuard) -> Result<(), GateError> {
    let instruction = Decoder::with_ip(
        64,
        guard.original_bytes(),
        guard.address(),
        DecoderOptions::NONE,
    )
    .decode();
    // These instructions cannot branch, modify TF, suppress the debug trap or
    // enter the kernel. Additional collateral classes need their own native
    // state/fault evidence before this executor accepts them.
    if !matches!(
        instruction.code(),
        Code::Mov_r16_imm16 | Code::Mov_r32_imm32 | Code::Mov_r64_imm64
    ) || instruction.len() != guard.original_bytes().len()
    {
        return Err(GateError::Refused(
            "collateral instruction lacks native-step qualification",
        ));
    }
    Ok(())
}

pub(crate) fn remaining(deadline: Instant) -> Result<Duration, GateError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(GateError::Refused("whole-event deadline exhausted"))
}

/// Explicitly chosen pending backend. Neither variant enables A1 publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingTrapBackend {
    Strict,
    Coverage,
}

/// Distinguishes retained historical returns from prospective caller records.
/// A record can occur in both inventories; neither occurrence cancels the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CallRequirementOrigin {
    Retained,
    Planned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CallRouteRequirement {
    origin: CallRequirementOrigin,
    obligation: CallReturnObligation,
    dependency: AddressRange,
}

impl CallRouteRequirement {
    pub(crate) const fn origin(&self) -> CallRequirementOrigin {
        self.origin
    }
    pub(crate) fn obligation(&self) -> &CallReturnObligation {
        &self.obligation
    }
    pub(crate) const fn dependency(&self) -> AddressRange {
        self.dependency
    }
}

/// Conservative prospective ledger-retention counts, before deduplication
/// against history. Bytes count exact source payload, not allocator overhead;
/// entry facts count every provenance/kind row. The owner must separately reserve
/// its retained history, reports, native census and consumption witnesses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PlannedSourceFootprint {
    pub(crate) records: usize,
    pub(crate) snapshot_bytes: usize,
    pub(crate) head_facts: usize,
    pub(crate) resume_facts: usize,
}

/// Immutable planning envelope awaiting real all-mm ownership and route proof.
/// No method returns AdmissionBundle, TrapCoveragePlan or native authority.
/// The full original append-only ledger remains owned by the caller; cloned
/// return records below do not replace its retained SourceFacts or validate a
/// new generation against that history. Actual recording must still succeed
/// under the owner before any write or X grant.
pub(crate) struct PendingAdmission {
    backend: PendingTrapBackend,
    geometry: PendingCoverage,
    installed_guards: BTreeMap<u64, TrapGuard>,
    call_requirements: Vec<CallRouteRequirement>,
    planned_callers: Vec<AddressRange>,
    planned_calls: Vec<CallReturnObligation>,
    planned_source_footprint: PlannedSourceFootprint,
}

impl PendingAdmission {
    pub(crate) const fn backend(&self) -> PendingTrapBackend {
        self.backend
    }
    pub(crate) fn snapshot(&self) -> &Snapshot {
        self.geometry.snapshot()
    }
    pub(crate) fn entries(&self) -> &LegalEntrySet {
        self.geometry.entries()
    }
    pub(crate) fn policy(&self) -> &Policy {
        self.geometry.policy()
    }
    pub(crate) fn target(&self) -> AddressRange {
        self.geometry.target()
    }
    pub(crate) fn page_size(&self) -> u64 {
        self.geometry.page_size()
    }
    pub(crate) fn pages(&self) -> &BTreeSet<u64> {
        self.geometry.pages()
    }
    pub(crate) fn dependencies(&self) -> &[AddressRange] {
        self.geometry.dependencies()
    }
    pub(crate) fn guards(&self) -> &BTreeMap<u64, TrapGuard> {
        self.geometry.guards()
    }
    /// Exact complete installed inventory supplied by the domain, including
    /// other images. The native consumer must reject any inventory change and
    /// authenticate original versus armed bytes separately; these are facts,
    /// never proof that the retained guards are currently installed or valid.
    pub(crate) fn installed_guards(&self) -> &BTreeMap<u64, TrapGuard> {
        &self.installed_guards
    }
    pub(crate) fn decoded_heads(&self) -> &BTreeMap<u64, Vec<u8>> {
        self.geometry.decoded_heads()
    }
    pub(crate) fn reports(&self) -> &[ScanReport] {
        self.geometry.reports()
    }
    pub(crate) fn resume_requirements(&self) -> &[ResumeRequirement] {
        self.geometry.resume_requirements()
    }
    pub(crate) fn coverage(&self) -> Option<&PendingCoverage> {
        (self.backend == PendingTrapBackend::Coverage).then_some(&self.geometry)
    }
    pub(crate) fn call_requirements(&self) -> &[CallRouteRequirement] {
        &self.call_requirements
    }
    /// Each prospective SourceFacts row uses this plan's exact snapshot and
    /// entries plus one caller range below. Real ledger history is rechecked at
    /// actual append; no existing source/census record is discarded here.
    pub(crate) fn planned_callers(&self) -> &[AddressRange] {
        &self.planned_callers
    }
    /// Includes destinations outside this plan's dependencies. Before X, the
    /// owner must also check each destination already executable elsewhere;
    /// unaffected NX/out-of-census destinations keep their retained obligation
    /// and NX backstop rather than becoming an invented absent continuation.
    pub(crate) fn planned_calls(&self) -> &[CallReturnObligation] {
        &self.planned_calls
    }
    pub(crate) const fn planned_source_footprint(&self) -> PlannedSourceFootprint {
        self.planned_source_footprint
    }
}

/// Strict typed-trap planning with unresolved saved-resume requirements.
/// The original strict loop and deadline checks remain shared with the legacy
/// API. Candidate/overlap and retained CALL refusals are not relaxed. Complete
/// decode-tail geometry is retained before returning the pending envelope.
pub(crate) fn prepare_admission_pending_resumes(
    source: (&Image, &GateOracle),
    page: u64,
    policy: &Policy,
    returns: &CallReturnLedger,
    selection: (&BTreeMap<u64, TrapGuard>, TrapCoverageBudget),
    deadline: Instant,
) -> Result<PendingAdmission, GateError> {
    let (installed_guards, budget) = selection;
    validate_pending_selection(source.0, page, policy, budget)?;
    let aliases = crate::selected::SyscallAliases::default();
    let geometry = prepare_admission_geometry(
        source,
        page,
        policy,
        returns,
        AdmissionSelection::PendingTrap { aliases: &aliases },
        deadline,
    )?;
    let pending = PendingCoverage::from_strict_reports(
        (&source.0.snapshot, &source.0.entries, policy),
        AddressRange::new(page, page + PAGE).unwrap(),
        budget,
        (geometry.pages, geometry.candidates, geometry.reports),
    )
    .map_err(GateError::Coverage)?;
    remaining(deadline)?;
    for guard in pending.guards().values() {
        if installed_guards
            .get(&guard.address())
            .is_some_and(|old| old != guard)
        {
            return Err(GateError::Refused(
                "covered guard changed within generation",
            ));
        }
    }
    finish_pending_admission(
        PendingTrapBackend::Strict,
        pending,
        installed_guards,
        returns,
        deadline,
    )
}

/// Explicit overlap-coverage planning. Only SavedResume can remain pending;
/// candidate closure, every selected/collateral qualification, installed guard
/// equality and missing CALL-head refusal are unchanged. The native owner later
/// proves every retained/planned route; this function performs no mutation.
pub(crate) fn prepare_covered_admission_pending_resumes(
    source: (&Image, &GateOracle),
    page: u64,
    policy: &Policy,
    returns: &CallReturnLedger,
    selection: (&BTreeMap<u64, TrapGuard>, TrapCoverageBudget),
    deadline: Instant,
) -> Result<PendingAdmission, GateError> {
    let (image, oracle) = source;
    let (covered_guards, budget) = selection;
    validate_pending_selection(image, page, policy, budget)?;
    let plan = PendingCoverage::build_with_oracle(
        &image.snapshot,
        AddressRange::new(page, page + PAGE).unwrap(),
        &image.entries,
        policy,
        budget,
        oracle,
    )
    .map_err(GateError::Coverage)?;
    remaining(deadline)?;
    let aliases = crate::selected::SyscallAliases::default();
    qualify_covered_geometry(
        &image.entries,
        plan.guards(),
        plan.dependencies(),
        &aliases,
        covered_guards,
        returns,
    )?;
    finish_pending_admission(
        PendingTrapBackend::Coverage,
        plan,
        covered_guards,
        returns,
        deadline,
    )
}

fn validate_pending_selection(
    image: &Image,
    page: u64,
    policy: &Policy,
    budget: TrapCoverageBudget,
) -> Result<(), GateError> {
    if budget.page_size != PAGE {
        return Err(GateError::Refused(
            "pending trap path requires 4096-byte pages",
        ));
    }
    if !policy.selected.is_subset(&Policy::default().selected) {
        return Err(GateError::Refused(
            "pending trap path supports only default selected classes",
        ));
    }
    if page % PAGE != 0
        || page
            .checked_add(PAGE)
            .and_then(|end| AddressRange::new(page, end))
            .is_none_or(|range| !image.snapshot.range().covers(range))
    {
        return Err(GateError::Refused(
            "pending target is not an aligned image page",
        ));
    }
    Ok(())
}

fn finish_pending_admission(
    backend: PendingTrapBackend,
    geometry: PendingCoverage,
    installed_guards: &BTreeMap<u64, TrapGuard>,
    returns: &CallReturnLedger,
    deadline: Instant,
) -> Result<PendingAdmission, GateError> {
    let mut prospective = CallReturnLedger::new();
    let mut planned_callers = Vec::new();
    for &page in geometry.pages() {
        remaining(deadline)?;
        let caller = AddressRange::new(page, page + geometry.page_size()).unwrap();
        match backend {
            PendingTrapBackend::Strict => prospective
                .record_before_admission(geometry.snapshot(), caller, geometry.entries())
                .map_err(|_| GateError::Refused("CALL-return census is unresolved"))?,
            PendingTrapBackend::Coverage => prospective
                .record_independent_streams_before_admission(
                    geometry.snapshot(),
                    caller,
                    geometry.entries(),
                )
                .map_err(|_| GateError::Refused("independent CALL-return census is unresolved"))?,
        };
        remaining(deadline)?;
        planned_callers.push(caller);
    }
    // A temporary ledger enumerates future records, not the retained history.
    // Check their destinations before any real append or permission change.
    if backend == PendingTrapBackend::Strict {
        for report in geometry.reports() {
            if !report.candidates().is_empty()
                && prospective
                    .obligations_in(report.dependency())
                    .next()
                    .is_some()
            {
                return Err(GateError::Refused(
                    "potential saved CALL return intersects selected publication",
                ));
            }
        }
    }
    let mut call_requirements = Vec::new();
    for &dependency in geometry.dependencies() {
        for (origin, ledger) in [
            (CallRequirementOrigin::Retained, returns),
            (CallRequirementOrigin::Planned, &prospective),
        ] {
            for obligation in ledger.obligations_in(dependency) {
                if !geometry
                    .entries()
                    .heads()
                    .contains_key(&obligation.return_pc)
                {
                    return Err(GateError::Refused("saved CALL return lacks a covered head"));
                }
                call_requirements.push(CallRouteRequirement {
                    origin,
                    obligation: obligation.clone(),
                    dependency,
                });
            }
        }
    }
    let records = planned_callers.len();
    let count_facts = |counts: Vec<usize>| -> Result<usize, GateError> {
        counts
            .into_iter()
            .try_fold(0_usize, |sum, count| sum.checked_add(count))
            .and_then(|count| count.checked_mul(records))
            .ok_or(GateError::Refused("pending source-fact size overflow"))
    };
    let planned_source_footprint = PlannedSourceFootprint {
        records,
        snapshot_bytes: geometry
            .snapshot()
            .bytes()
            .len()
            .checked_mul(records)
            .ok_or(GateError::Refused("pending source-fact size overflow"))?,
        head_facts: count_facts(
            geometry
                .entries()
                .heads()
                .values()
                .map(BTreeSet::len)
                .collect(),
        )?,
        resume_facts: count_facts(
            geometry
                .entries()
                .resumes()
                .values()
                .map(BTreeSet::len)
                .collect(),
        )?,
    };
    let planned_calls = prospective.obligations().cloned().collect();
    Ok(PendingAdmission {
        backend,
        geometry,
        installed_guards: installed_guards.clone(),
        call_requirements,
        planned_callers,
        planned_calls,
        planned_source_footprint,
    })
}

#[cfg(test)]
mod pending_tests;
