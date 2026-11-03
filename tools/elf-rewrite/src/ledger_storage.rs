//! Optional physical storage, independent of planner and admission policies.
//! The codec authenticates bytes; this adapter checks current reads before writes.
use crate::carrier::elf64::{Elf64, ElfVaddr, ParseLimits, Storage};
use crate::ledger_codec::{self, LedgerView, Limits, ReadContract, ReadView, Record};
use crate::{
    ledger,
    model::{Error, Selection},
};
use formats::ContentId;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LedgerStorage {
    #[default]
    Inline,
    ReadChunks256,
}
pub const TABLE: &str = "read-chunks.tsv";
pub const VERIFICATION: &str = "ledger-verification.tsv";
fn fail(detail: &'static str) -> Error {
    Error::new("ledger-storage", detail)
}
fn sum(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b)
        .ok_or_else(|| fail("encoding size overflow"))
}
fn times(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b)
        .ok_or_else(|| fail("encoding size overflow"))
}
fn require(ok: bool, detail: &'static str) -> Result<(), Error> {
    if ok { Ok(()) } else { Err(fail(detail)) }
}

// This is a supported producer contract, not a generic PatchPlan restriction.
// Every actual accepted step is checked below; images already have an unchanged
// authenticated aggregate limit, and every supported sealed step owns an image.
pub(crate) fn limits(s: &Selection, original_len: usize, staging: usize) -> Result<Limits, Error> {
    require(original_len <= s.limits.input_bytes, "original input limit")?;
    Limits::new(
        ReadContract {
            max_steps: s.limits.images,
            max_reads_per_step: 1,
            max_read_bytes: original_len,
        },
        ledger_codec::ENVELOPE_BYTES,
        staging,
    )
}
pub(crate) fn check_plans(
    original: &[u8],
    s: &Selection,
    plans: &[(u64, &li2core::emission::ArtifactPlan)],
) -> Result<(), Error> {
    let mut count = 0usize;
    for (_, plan) in plans {
        require(
            plan.source_steps().len() == plan.images().count(),
            "step/image contract",
        )?;
        count = sum(count, plan.source_steps().len())?;
        for step in plan.source_steps() {
            require(
                step.parts().reads.len() == 1,
                "one current read per supported step",
            )?;
            require(
                step.parts().reads[0].bytes.len() <= original.len(),
                "mapped read length",
            )?;
        }
    }
    require(count <= s.limits.images, "step/image aggregate limit")
}

/// Bootstrap wire versions2/3 authenticate no sidecar. This rejection precedes
/// addon planning and is repeated at the bootstrap finish boundary.
pub fn require_inline_bootstrap(storage: LedgerStorage) -> Result<(), Error> {
    require(
        storage == LedgerStorage::Inline,
        "bootstrap has no authenticated chunk-table wire",
    )
}

// Before calling the shared legacy extension formatters, reserve their complete
// output and transient strings conservatively. This is encoding accounting only;
// no planner, image, file, reserve or global ceiling changes.
pub(crate) fn before_plan_extensions(
    s: &Selection,
    original_len: usize,
    plan: usize,
    table: usize,
    images: usize,
    association_bytes: usize,
) -> Result<(), Error> {
    let extension = sum(sum(times(images, 1024)?, association_bytes)?, 1024)?;
    let bound = sum(plan, extension)?;
    // Header/group/fixed replacements can retain input and two replacement
    // strings. Four complete bounds also cover temporary extension strings.
    limits(s, original_len, times(bound, 4)?)?.check_storage_lengths(bound, bound, table)
}
pub(crate) fn before_carrier_extension(
    s: &Selection,
    original_len: usize,
    plan: usize,
    table: usize,
    output: &crate::carrier::CarrierOutput,
) -> Result<(), Error> {
    let mut bound = 4096usize;
    bound = sum(bound, times(output.images.len(), 2048)?)?;
    for change in output.changes() {
        bound = sum(
            bound,
            sum(
                512,
                times(
                    sum(change.edit.expected.len(), change.edit.replacement.len())?,
                    2,
                )?,
            )?,
        )?;
    }
    for records in [
        output.dynamic.writes.len(),
        output.dynamic.symbol_references.len(),
        output.dynamic.tables.len(),
        output.dynamic.protected.len(),
    ] {
        bound = sum(bound, times(records, 512)?)?;
    }
    let final_bound = sum(plan, bound)?;
    // The shared appender owns an extension String while the final Vec may
    // reallocate; this bound includes both and the subsequent RX-run string.
    limits(
        s,
        original_len,
        sum(times(bound, 4)?, times(final_bound, 2)?)?,
    )?
    .check_storage_lengths(plan, final_bound, table)
}

pub enum ExpectedRead<'a> {
    Inline(&'a [u8]),
    Chunks(ReadView<'a>),
}
impl ExpectedRead<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Inline(b) => b.len(),
            Self::Chunks(r) => r.len,
        }
    }
}
pub fn mapped_range(
    elf: &Elf64<'_>,
    address: u64,
    len: usize,
) -> Result<std::ops::Range<usize>, Error> {
    let mapped = elf
        .virtual_to_storage(ElfVaddr(address), len as u64)
        .map_err(|e| Error::new("ledger-read-mapping", e))?;
    let Storage::FileBacked(range) = mapped.storage else {
        return Err(fail("file-backed read required"));
    };
    let start = usize::try_from(range.start().0).map_err(|_| fail("file offset overflow"))?;
    Ok(start..sum(start, len)?)
}
/// Shared primitive used by both the existing fixture verifier and compact
/// replay. Fixture ownership, foreign/router and write checks stay at callers.
pub fn compare_current(
    elf: &Elf64<'_>,
    overlay: &[u8],
    address: u64,
    expected: ExpectedRead<'_>,
) -> Result<(), Error> {
    let range = mapped_range(elf, address, expected.len())?;
    let current = overlay
        .get(range)
        .ok_or_else(|| fail("current read outside original"))?;
    let equal = match expected {
        ExpectedRead::Inline(bytes) => current == bytes,
        ExpectedRead::Chunks(read) => read.compare_current(current).is_ok(),
    };
    if equal {
        Ok(())
    } else {
        Err(Error::new(
            "ledger-current-read",
            "expected current bytes changed",
        ))
    }
}

// The legacy verifier still supplies its exact router-mode gate and fixed
// header/value checks. The generic shape primitive does not add accepted tags.
pub fn legacy_record_width(tag: &str, router: bool) -> Option<usize> {
    Some(match tag {
        "LI2LEDGER"
        | "original_sha256"
        | "selection_sha256"
        | "bias_policy"
        | "bias_domain"
        | "qualification_complete"
        | "execution_authority"
        | "grouping"
        | "unresolved"
        | "CARRIER-EXTENSION"
        | "candidate_sha256"
        | "new_load_pages"
        | "phdr_vaddr" => 2,
        "requirement" | "route" | "restored-boundary" | "unmet-requirement" | "entry-preserved" => {
            4
        }
        "entry-router-required" if router => 5,
        "hook"
        | "step-read"
        | "semantic-write"
        | "live-store-span"
        | "pc-range"
        | "elf-change"
        | "original-symbol-reference" => 5,
        "step" => 8,
        "live-prerequisites-not-receipts" | "allocation" | "elf-image" => 6,
        "source-relay-geometry-hex"
        | "byte-lock"
        | "original-file-dependency"
        | "phdr_file"
        | "original-loader-table"
        | "original-loader-protected" => 3,
        "image" | "original-loader-write" => 7,
        "field" => 10,
        _ => return None,
    })
}
fn compact_record_width(tag: &str) -> Option<usize> {
    if let Some(width) = legacy_record_width(tag, true) {
        return Some(width);
    }
    Some(match tag {
        "LI2GROUPED-LEDGER"
        | "ENTRY-VENEER-EXTENSION"
        | "GROUP-ASSOCIATIONS"
        | "policy_sha256"
        | "accepted_member_count"
        | "complete_site_count"
        | "RX-RUN-EXTENSION"
        | "carrier_layout"
        | "rx_run_count"
        | "rx_run_image_count"
        | "fixed-original-field-ownership"
        | "fixed-output-readback" => 2,
        "unmet-fixed-image-binding" | "original-fixed-field" | "rx-run-member" => 7,
        "required-fixed-source" | "member" => 6,
        "accepted-unit" => 5,
        "entry-veneer" => 15,
        "rx-run" => 10,
        _ => return None,
    })
}
// Reject wide semantic rows before allocating any per-field collection.
// Fifteen is the largest existing accepted record (entry-veneer); fields borrow
// the already member-bounded input and one extra field causes immediate refusal.
fn semantic_fields(line: &str) -> Result<[&str; 15], Error> {
    let mut fields = line.split('\t');
    let tag = fields
        .next()
        .ok_or_else(|| fail("unknown or malformed semantic record"))?;
    let width =
        compact_record_width(tag).ok_or_else(|| fail("unknown or malformed semantic record"))?;
    let mut out = [""; 15];
    require(width <= out.len(), "semantic row schema")?;
    out[0] = tag;
    for value in &mut out[1..width] {
        *value = fields
            .next()
            .ok_or_else(|| fail("unknown or malformed semantic record"))?;
    }
    require(
        fields.next().is_none(),
        "unknown or malformed semantic record",
    )?;
    Ok(out)
}
fn number(text: &str) -> Result<u64, Error> {
    require(
        !text.is_empty()
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text == "0" || !text.starts_with('0')),
        "noncanonical ledger number",
    )?;
    text.parse().map_err(|_| fail("ledger number overflow"))
}
fn unhex(text: &str, max: usize) -> Result<Vec<u8>, Error> {
    require(
        text.len() % 2 == 0 && text.len() / 2 <= max,
        "semantic byte bound",
    )?;
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(fail("noncanonical hex")),
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}

/// Verify the physical files and replay each current read before its writes.
/// This is not a replacement for full selection/routes/ownership/carrier checks.
pub(crate) fn verify(
    original: &[u8],
    s: &Selection,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    require(ContentId::of(original) == s.original, "original identity")?;
    let get = |name: &str| {
        files
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| fail("missing storage member"))
    };
    let (plan, final_ledger, table) = (get("plan-ledger.tsv")?, get("ledger.tsv")?, get(TABLE)?);
    let view = LedgerView::new(plan, final_ledger, table, limits(s, original.len(), 0)?)?;
    let elf = Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: s.limits.program_headers,
        },
    )
    .map_err(|e| Error::new("ledger-read-mapping", e))?;
    let ids: BTreeSet<_> = s.sites.iter().map(|site| site.id).collect();
    let mut overlay = original.to_vec();
    let mut step_counts = BTreeMap::<u64, usize>::new();
    let mut current = None;
    let mut read_count = 0;
    let mut wrote = false;
    let mut steps = 0;
    for record in view.records() {
        match record {
            Record::Read(read) => {
                require(
                    current == Some((read.site, read.step)) && !wrote && read.ordinal == read_count,
                    "ordered current read",
                )?;
                compare_current(&elf, &overlay, read.address, ExpectedRead::Chunks(read))?;
                read_count += 1;
            }
            Record::Other(line) => {
                let r = semantic_fields(line)?;
                if r[0] == "step" {
                    require(
                        current.is_none() || read_count == 1,
                        "one current read per supported step",
                    )?;
                    let id = number(r[1])?;
                    let step = usize::try_from(number(r[2])?).map_err(|_| fail("step overflow"))?;
                    require(
                        ids.contains(&id) && step == *step_counts.entry(id).or_default(),
                        "step selection/order",
                    )?;
                    *step_counts.get_mut(&id).unwrap() += 1;
                    require(
                        matches!(r[3], "relocation" | "generalized-pun" | "prefixed-pun"),
                        "step kind",
                    )?;
                    current = Some((id, step));
                    read_count = 0;
                    wrote = false;
                    steps += 1;
                } else if r[0] == "semantic-write" || r[0] == "live-store-span" {
                    let key = (
                        number(r[1])?,
                        usize::try_from(number(r[2])?).map_err(|_| fail("step overflow"))?,
                    );
                    require(
                        current == Some(key) && read_count == 1,
                        "write before complete current reads",
                    )?;
                    let bytes = unhex(r[4], original.len())?;
                    let range = mapped_range(&elf, number(r[3])?, bytes.len())?;
                    let target = overlay
                        .get_mut(range)
                        .ok_or_else(|| fail("write outside original"))?;
                    if r[0] == "semantic-write" {
                        target.copy_from_slice(&bytes);
                        wrote = true;
                    } else {
                        require(&*target == bytes.as_slice(), "prospective live-store span")?;
                    }
                }
            }
        }
    }
    require(
        current.is_none() || read_count == 1,
        "one current read per supported step",
    )?;
    let canonical = view.summary()?;
    require(
        steps == canonical.counts.steps && steps == canonical.counts.reads,
        "read/step census",
    )?;
    let mut out = format!(
        "LI2LEDGER-VERIFICATION\t1\nstorage\t{}\noriginal_sha256\t{}\nselection_sha256\t{}\nwire\tchecked\ncurrent_overlay_reads\tchecked-before-writes\nsemantic_scope\tcurrent-reads-and-record-shape-only\nbootstrap\tunsupported\nmember_limit\t{}\naggregate_limit\t{}\n",
        ledger_codec::PROFILE,
        ledger::hex(&s.original.0),
        ledger::hex(&ContentId::of(&s.manifest).0),
        ledger_codec::MEMBER_BYTES,
        ledger_codec::ENVELOPE_BYTES
    );
    use std::fmt::Write as _;
    for (name, bytes) in [
        ("plan-ledger.tsv", plan),
        ("ledger.tsv", final_ledger),
        (TABLE, table),
    ] {
        writeln!(
            out,
            "member\t{name}\t{}\t{}",
            bytes.len(),
            ledger::hex(&ContentId::of(bytes).0)
        )
        .unwrap();
    }
    writeln!(out, "canonical_bytes\t{}\ncanonical_sha256\t{}\nsteps\t{}\nreads\t{}\nreferences\t{}\nqualification_complete\tfalse", canonical.bytes, ledger::hex(&canonical.sha256.0), canonical.counts.steps, canonical.counts.reads, canonical.counts.references).unwrap();
    Ok(out.into_bytes())
}

/// Rechecks the same files through the sole Rust codec/replay before CLI closure.
pub fn verify_jump_stack(
    original: &[u8],
    selected: &crate::disassembly::whole::JumpStackWholeSelection,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Error> {
    require(
        files.get(VERIFICATION) == Some(&verify(original, &selected.selection, files)?),
        "verification/member mismatch",
    )
}
