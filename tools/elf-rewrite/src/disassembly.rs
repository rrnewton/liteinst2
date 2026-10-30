//! Trusted complete instruction locations for artifact-only code regions.
//! Decoding checks the supplied facts; it cannot discover omitted code or prove
//! the no-overlap/no-code-as-data contract. No recovered function is asserted.
use crate::carrier::elf64::{Elf64, ElfVaddr, ParseLimits, SegmentType};
use crate::model::{Error, Selection};
use crate::{addr, ledger, selection, translate};
use formats::ContentId;
use iced_x86::{Code, FlowControl, Instruction, OpKind};
use li2core::contracts::{AddressRange, EntryCompleteness};
use li2core::scanner::InstructionScanner;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

pub const PROFILE: &str = "elf-disassembly-null-jumps-v1";
/// Explicit same-region short-only neighbor family; never long+short union.
pub const SHORT_ONLY_PROFILE: &str = "elf-disassembly-null-jumps-short-only-v1";
/// Explicit inherited admission for complete short-neighbor T3 pairs only.
pub const SHORT_T3_OWNERSHIP_PROFILE: &str = "elf-disassembly-null-jumps-short-t3-ownership-v1";
/// Explicit complete pending-instruction ownership during short T3 admission.
pub const SHORT_T3_PENDING_PROFILE: &str = "elf-disassembly-null-jumps-short-t3-pending-v1";
const SHORT_PENDING: &str = "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\n";
const SHORT_FAMILY: &str = "neighbor_victims\tshort-only\n";
const SHORT_OWNERSHIP: &str = "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NeighborMode {
    LongOnly,
    ShortOnly,
    ShortT3Ownership,
    ShortT3Pending,
}
impl NeighborMode {
    fn profile(self) -> &'static str {
        match self {
            Self::LongOnly => PROFILE,
            Self::ShortOnly => SHORT_ONLY_PROFILE,
            Self::ShortT3Ownership => SHORT_T3_OWNERSHIP_PROFILE,
            Self::ShortT3Pending => SHORT_T3_PENDING_PROFILE,
        }
    }
    fn metadata(self) -> &'static str {
        match self {
            Self::LongOnly => "",
            Self::ShortOnly => SHORT_FAMILY,
            Self::ShortT3Ownership => SHORT_OWNERSHIP,
            Self::ShortT3Pending => SHORT_PENDING,
        }
    }
}
pub const TEXT_LIMIT: usize = 1024 * 1024;
pub const INPUT_LIMIT: usize = 256 * 1024 * 1024;

/// Complete requested denominator, before tactic qualification or placement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JumpSite {
    pub id: u64,
    pub pc: u64,
    pub length: usize,
    pub file_offset: u64,
    /// Original contiguous code region, not a recovered function.
    pub region: AddressRange,
    /// Conservative straight-line interval ending at its first non-Next flow.
    pub block: AddressRange,
}
#[derive(Clone, Debug)]
struct Region {
    range: AddressRange,
    offset: u64,
    instructions: Vec<Instruction>,
}

/// Sealed checked locations; completeness is an explicitly trusted input fact.
#[derive(Clone, Debug)]
pub struct Disassembly {
    original: ContentId,
    ledger: Vec<u8>,
    regions: Vec<Region>,
    jumps: Vec<JumpSite>,
}
impl Disassembly {
    #[cfg(feature = "offline-router")]
    pub(crate) fn original_heads(&self) -> Vec<u64> {
        self.regions
            .iter()
            .flat_map(|r| r.instructions.iter().map(Instruction::ip))
            .collect()
    }
    pub fn jumps(&self) -> &[JumpSite] {
        &self.jumps
    }
    pub fn inventory(&self) -> Vec<u8> {
        self.inventory_mode(false)
    }
    /// Same complete verified denominator, explicitly labeled for ShortOnly.
    pub fn inventory_short_neighbors(&self) -> Vec<u8> {
        self.inventory_mode(true)
    }
    /// Complete verified denominator, labeled for inherited short T3 admission.
    pub fn inventory_short_t3_ownership(&self) -> Vec<u8> {
        self.inventory_with_mode(NeighborMode::ShortT3Ownership)
    }
    /// Complete verified denominator, labeled before pending-mode binding.
    pub fn inventory_short_t3_pending(&self) -> Vec<u8> {
        self.inventory_with_mode(NeighborMode::ShortT3Pending)
    }
    fn inventory_mode(&self, short_only: bool) -> Vec<u8> {
        self.inventory_with_mode(if short_only {
            NeighborMode::ShortOnly
        } else {
            NeighborMode::LongOnly
        })
    }
    fn inventory_with_mode(&self, mode: NeighborMode) -> Vec<u8> {
        let profile = mode.profile();
        let family = mode.metadata();
        let mut out = format!(
            "LI2DISASSEMBLY-INVENTORY\t1\nprofile\t{profile}\n{family}original_sha256\t{}\nledger_sha256\t{}\ncomplete_jump_count\t{}\nqualification_complete\tfalse\nid\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length\n",
            ledger::hex(&self.original.0),
            ledger::hex(&ContentId::of(&self.ledger).0),
            self.jumps.len()
        );
        for s in &self.jumps {
            writeln!(
                out,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                s.id,
                s.pc,
                s.length,
                s.file_offset,
                s.region.start(),
                s.region.len(),
                s.block.start(),
                s.block.len()
            )
            .unwrap();
        }
        out.into_bytes()
    }

    /// Bind prospective target/search/placement limits, never a planning result.
    /// Every jump gets exactly one search and two allocation records through the
    /// unchanged LI2TOOL parser. No subset, inferred arena or automatic retry.
    pub fn bind(
        self,
        policy: &[u8],
        expected_policy: ContentId,
    ) -> Result<DisassemblySelection, Error> {
        self.bind_mode(policy, expected_policy, false)
    }

    /// Bind the explicit version-two ShortOnly policy and its complete digest.
    /// The generated family row is retained in the selection identity; ordinary
    /// selection replay refuses it instead of silently selecting another family.
    pub fn bind_short_neighbors(
        self,
        policy: &[u8],
        expected_policy: ContentId,
    ) -> Result<DisassemblySelection, Error> {
        self.bind_mode(policy, expected_policy, true)
    }

    /// Bind version three with short victims and inherited T3 admission sealed.
    /// Only neighboring-instruction eviction checks inherited ownership during
    /// search. Generalized pun, ordinary relocation, prefixed pun and successor
    /// eviction retain their first local success and possible final append refusal.
    /// Complete population, final append, hook, aggregate and carrier checks remain.
    pub fn bind_short_t3_ownership(
        self,
        policy: &[u8],
        expected_policy: ContentId,
    ) -> Result<DisassemblySelection, Error> {
        self.bind_with_mode(policy, expected_policy, NeighborMode::ShortT3Ownership)
    }

    /// Bind version four and the complete outstanding original instruction set.
    /// Short neighboring-instruction eviction admits a complete pair only while
    /// every other pending instruction remains unclaimed. Generalized pun,
    /// ordinary relocation, prefixed pun and successor eviction retain local
    /// success; their final pending conflict refuses without another tactic try.
    /// Final append, hook, dependency, aggregate and carrier checks remain required.
    pub fn bind_short_t3_pending(
        self,
        policy: &[u8],
        expected_policy: ContentId,
    ) -> Result<DisassemblySelection, Error> {
        self.bind_with_mode(policy, expected_policy, NeighborMode::ShortT3Pending)
    }

    fn bind_mode(
        self,
        policy: &[u8],
        expected_policy: ContentId,
        short_only: bool,
    ) -> Result<DisassemblySelection, Error> {
        self.bind_with_mode(
            policy,
            expected_policy,
            if short_only {
                NeighborMode::ShortOnly
            } else {
                NeighborMode::LongOnly
            },
        )
    }

    fn bind_with_mode(
        self,
        policy: &[u8],
        expected_policy: ContentId,
        mode: NeighborMode,
    ) -> Result<DisassemblySelection, Error> {
        self.bind_with_manifest_extra(policy, expected_policy, mode, None)
    }

    fn bind_with_manifest_extra(
        self,
        policy: &[u8],
        expected_policy: ContentId,
        mode: NeighborMode,
        extra: Option<&str>,
    ) -> Result<DisassemblySelection, Error> {
        check(policy.len() <= TEXT_LIMIT, "policy size")?;
        check(ContentId::of(policy) == expected_policy, "policy digest")?;
        let rows = rows(policy)?;
        let ledger_id = ContentId::of(&self.ledger);
        let (shift, header) = match mode {
            NeighborMode::LongOnly => (0, "LI2DISASM-POLICY 1"),
            NeighborMode::ShortOnly => (1, "LI2DISASM-POLICY 2"),
            NeighborMode::ShortT3Ownership => (2, "LI2DISASM-POLICY 3"),
            NeighborMode::ShortT3Pending => (3, "LI2DISASM-POLICY 4"),
        };
        check(
            rows.len() >= 8 + shift && rows[0] == header,
            "policy header",
        )?;
        if mode != NeighborMode::LongOnly {
            check(rows[3] == "neighbor-victims short-only", "neighbor family")?;
        }
        if mode == NeighborMode::ShortT3Ownership {
            check(
                rows[4] == "neighbor-ownership inherited-t3",
                "neighbor ownership",
            )?;
        }
        if mode == NeighborMode::ShortT3Pending {
            check(
                rows[4] == "neighbor-ownership inherited-t3",
                "neighbor ownership",
            )?;
            check(
                rows[5] == "pending-selected full-instruction-ownership",
                "pending selected ownership",
            )?;
        }
        check(
            rows[1] == format!("original {}", ledger::hex(&self.original.0)),
            "policy original",
        )?;
        check(
            rows[2] == format!("ledger {}", ledger::hex(&ledger_id.0)),
            "policy ledger",
        )?;
        for (row, tag) in rows[3 + shift..7 + shift]
            .iter()
            .zip(["target", "domain", "carrier", "limits"])
        {
            check(row.starts_with(&format!("{tag} ")), "policy order")?;
        }
        let hook = fields(rows[7 + shift], "null-hook", 2)?;
        let hook = selection::num(hook[1])?;
        check(
            self.regions
                .iter()
                .flat_map(|r| &r.instructions)
                .any(|i| i.ip() == hook && i.code() == Code::Retnq && i.len() == 1),
            "null hook is not an original C3 head",
        )?;
        let projection_family = match mode {
            NeighborMode::LongOnly => "",
            NeighborMode::ShortOnly => "neighbor-victims short-only\n",
            NeighborMode::ShortT3Ownership => {
                "neighbor-victims short-only\nneighbor-ownership inherited-t3\n"
            }
            NeighborMode::ShortT3Pending => {
                "neighbor-victims short-only\nneighbor-ownership inherited-t3\npending-selected full-instruction-ownership\n"
            }
        };
        let mut manifest = format!(
            "LI2TOOL 1\n{}\n{projection_family}{}\n{}\n{}\n{}\nhook 1 {hook} 1 {}\n",
            rows[1],
            rows[3 + shift],
            rows[4 + shift],
            rows[5 + shift],
            rows[6 + shift],
            ledger::hex(&ContentId::of(&[0xc3]).0)
        );
        for site in &self.jumps {
            let r = self
                .regions
                .iter()
                .find(|r| r.range == site.region)
                .unwrap();
            append(
                &mut manifest,
                &format!(
                    "site {} {} {} {} {} {} {} {} {} {} 1 observe original-decode\nentries {} complete {}",
                    site.id,
                    site.pc,
                    site.length,
                    site.file_offset,
                    r.range.start(),
                    r.range.len(),
                    r.range.start(),
                    r.range.len(),
                    site.block.start(),
                    site.block.len(),
                    site.id,
                    ledger::hex(&ledger_id.0)
                ),
            )?;
            for i in &r.instructions {
                let endbr = usize::from(i.code() == Code::Endbr64 || i.code() == Code::Endbr32);
                append(&mut manifest, &format!(" {}:{endbr}", i.ip()))?;
            }
            append(&mut manifest, &format!("\nresumes {} none\n", site.id))?;
        }
        for row in &rows[8 + shift..] {
            check(
                row.starts_with("search ") || row.starts_with("allocation "),
                "policy record",
            )?;
            append(&mut manifest, row)?;
            append(&mut manifest, "\n")?;
        }
        // Inherit every old numeric ceiling, exact record cardinality and permit
        // check. No zero-site success or overflowing whole-program batching.
        let projection = manifest.clone();
        if let Some(extra) = extra {
            let pivot = "pending-selected full-instruction-ownership\n";
            check(
                mode == NeighborMode::ShortT3Pending,
                "adjacent projection mode",
            )?;
            let full = manifest.replacen(pivot, &(pivot.to_owned() + extra), 1);
            check(full.len() <= TEXT_LIMIT, "whole selection exceeds 1 MiB")?;
            manifest = full;
        }
        // Check the FULL new bytes before invoking the old projection parser.
        let mut selection = match mode {
            NeighborMode::LongOnly => selection::parse(projection.as_bytes())?,
            NeighborMode::ShortOnly => {
                selection::parse_short_neighbor_projection(projection.as_bytes())?
            }
            NeighborMode::ShortT3Ownership => {
                selection::parse_short_t3_ownership_projection(projection.as_bytes())?
            }
            NeighborMode::ShortT3Pending => {
                selection::parse_short_t3_pending_projection(projection.as_bytes())?
            }
        };
        selection.manifest = manifest.into_bytes();
        check(
            selection.sites.len() == self.jumps.len(),
            "selection denominator",
        )?;
        for site in &mut selection.sites {
            // Not recovered Complete function entries: every independently
            // verified head is conservatively legal in this artifact region.
            site.completeness = EntryCompleteness::AllInstructionHeads;
        }
        let profile_name = mode.profile();
        let family = mode.metadata();
        let profile = format!(
            "LI2PLANNING\t1\nprofile\t{profile_name}\n{family}scope\tartifact-code-regions-not-functions\nentries\tall-verified-instruction-heads\noriginal_sha256\t{}\nledger_sha256\t{}\npolicy_sha256\t{}\nselection_sha256\t{}\ncomplete_jump_count\t{}\nqualification_complete\tfalse\n",
            ledger::hex(&self.original.0),
            ledger::hex(&ledger_id.0),
            ledger::hex(&expected_policy.0),
            ledger::hex(&ContentId::of(&selection.manifest).0),
            self.jumps.len()
        );
        Ok(DisassemblySelection {
            mode,
            selection,
            files: BTreeMap::from([
                ("planning-profile.tsv".into(), profile.into_bytes()),
                ("disassembly.txt".into(), self.ledger.clone()),
                ("disassembly-policy.txt".into(), policy.to_vec()),
                (
                    "disassembly-inventory.tsv".into(),
                    self.inventory_with_mode(mode),
                ),
            ]),
        })
    }
}

/// Only this module can construct the artifact-region lowering. No mutable
/// selection, InstallRequest, recovered-function or owned-neighbor conversion.
#[derive(Clone, Debug)]
pub struct DisassemblySelection {
    pub(crate) mode: NeighborMode,
    pub(crate) selection: Selection,
    pub(crate) files: BTreeMap<String, Vec<u8>>,
}
impl DisassemblySelection {
    /// Bound planning profile, never a runtime qualification result.
    pub fn profile(&self) -> &'static str {
        self.mode.profile()
    }
    /// Canonical projection bound to this profile. ShortOnly includes an explicit
    /// family row that legacy selection/comparator readers must reject. The
    /// `function` columns mean code regions only under the bound profile file.
    pub fn manifest(&self) -> &[u8] {
        &self.selection.manifest
    }
}

/// Independently decode every declared head against the exact whole original.
/// The ledger must declare *all* original executable instruction streams; data
/// gaps are not decoded or used as padding. This trust premise is not inferred
/// from symbols, a successful decode, or a successful structural candidate.
pub fn import(
    original: &[u8],
    ledger_bytes: &[u8],
    expected_ledger: ContentId,
) -> Result<Disassembly, Error> {
    check(original.len() <= INPUT_LIMIT, "original size")?;
    check(ledger_bytes.len() <= TEXT_LIMIT, "ledger size")?;
    check(
        ContentId::of(ledger_bytes) == expected_ledger,
        "ledger digest",
    )?;
    let rows = rows(ledger_bytes)?;
    check(rows.len() >= 5 && rows[0] == "LI2DISASM 1", "ledger header")?;
    let original_id = ContentId::of(original);
    check(
        rows[1] == format!("original {}", ledger::hex(&original_id.0)),
        "whole original digest",
    )?;
    check(
        rows[2] == "contract complete-code no-overlap no-code-as-data private-image",
        "trusted contract",
    )?;
    let elf = Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: 4096,
        },
    )
    .map_err(|e| Error::new("disassembly-elf", e))?;
    elf.check_load_page_congruence(4096)
        .map_err(|e| Error::new("disassembly-elf", e))?;
    let mut regions: Vec<Region> = Vec::new();
    let mut at = 3;
    while at < rows.len() {
        let row = fields(rows[at], "region", 4)?;
        let pc = selection::num(row[1])?;
        let offset = selection::num(row[2])?;
        let range = addr(pc, selection::num(row[3])?)?;
        check(
            regions.last().is_none_or(|r| r.range.end() <= pc),
            "region ordering/overlap",
        )?;
        let mapped = translate(&elf, pc, range.len())?;
        check(mapped.start().0 == offset, "region file offset")?;
        let code = elf
            .executable_bytes(ElfVaddr(pc), range.len())
            .map_err(|e| Error::new("disassembly-bytes", e))?;
        at += 1;
        let first_head = at;
        let mut next = pc;
        // Bound decoding work by the already bounded complete ledger, before
        // allocating a scan for an invalid enormous declared region.
        while at < rows.len() && rows[at].starts_with("head ") {
            let head = fields(rows[at], "head", 3)?;
            check(selection::num(head[1])? == next, "head location/order")?;
            check(
                (2..=30).contains(&head[2].len()) && head[2].len() % 2 == 0,
                "head byte count",
            )?;
            let length = head[2].len() as u64 / 2;
            let end = next
                .checked_add(length)
                .ok_or_else(|| Error::new("disassembly", "head overflow"))?;
            check(end <= range.end(), "head outside region")?;
            check(
                head[2] == ledger::hex(&code[(next - pc) as usize..(end - pc) as usize]),
                "head bytes",
            )?;
            next = end;
            at += 1;
        }
        check(next == range.end(), "incomplete region heads")?;
        let scan = InstructionScanner::default()
            .scan(code, pc)
            .map_err(|e| Error::new("disassembly-decode", e))?;
        check(
            scan.instructions().len() == at - first_head,
            "head decode count",
        )?;
        let mut instructions = Vec::new();
        for (item, row) in scan.instructions().iter().zip(&rows[first_head..at]) {
            let head = fields(row, "head", 3)?;
            check(
                selection::num(head[1])? == item.address() && head[2].len() == 2 * item.len(),
                "independent head decode",
            )?;
            instructions.push(*item.instruction());
        }
        regions.push(Region {
            range,
            offset,
            instructions,
        });
    }
    let heads: BTreeSet<_> = regions
        .iter()
        .flat_map(|r| r.instructions.iter().map(Instruction::ip))
        .collect();
    check(
        elf.header().entry.0 == 0 || heads.contains(&elf.header().entry.0),
        "ELF entry missing from code ledger",
    )?;
    let mut cuts: BTreeSet<_> = regions
        .iter()
        .flat_map(|r| [r.range.start(), r.range.end()])
        .collect();
    for i in regions.iter().flat_map(|r| &r.instructions) {
        if i.flow_control() != FlowControl::Next {
            cuts.insert(i.next_ip());
        }
        if let Some(target) = direct(i) {
            let original_executable = elf.segments(SegmentType::Load).any(|s| {
                s.flags.executable() && s.vaddr.0 <= target && target - s.vaddr.0 < s.memory_size
            });
            check(
                !original_executable || heads.contains(&target),
                "direct target contradicts complete ledger",
            )?;
            if heads.contains(&target) {
                cuts.insert(target);
            }
        }
    }
    let mut jumps = Vec::new();
    for r in &regions {
        for i in r.instructions.iter().filter(|i| jump(i)) {
            let start = *cuts.range(r.range.start()..=i.ip()).next_back().unwrap();
            let end = *cuts
                .range((
                    std::ops::Bound::Excluded(i.ip()),
                    std::ops::Bound::Included(r.range.end()),
                ))
                .next()
                .unwrap();
            jumps.push(JumpSite {
                id: jumps.len() as u64 + 1,
                pc: i.ip(),
                length: i.len(),
                file_offset: r.offset + (i.ip() - r.range.start()),
                region: r.range,
                block: addr(start, end - start)?,
            });
        }
    }
    Ok(Disassembly {
        original: original_id,
        ledger: ledger_bytes.to_vec(),
        regions,
        jumps,
    })
}

fn jump(i: &Instruction) -> bool {
    // Literal existing common_sites asm=j.* classifier, not a reachability test.
    format!("{:?}", i.mnemonic())
        .to_ascii_lowercase()
        .starts_with('j')
}
fn direct(i: &Instruction) -> Option<u64> {
    if i.op_count() > 0
        && matches!(
            i.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
    {
        Some(i.near_branch_target())
    } else {
        None
    }
}
fn rows(bytes: &[u8]) -> Result<Vec<&str>, Error> {
    check(
        bytes.len() <= TEXT_LIMIT && bytes.last() == Some(&b'\n'),
        "text bound/final LF",
    )?;
    check(
        bytes
            .iter()
            .all(|b| *b == b'\n' || (b' '..=b'~').contains(b)),
        "ASCII text",
    )?;
    let text = std::str::from_utf8(bytes).map_err(|e| Error::new("disassembly-text", e))?;
    let rows: Vec<_> = text.lines().collect();
    check(
        rows.iter()
            .all(|row| !row.is_empty() && row.split(' ').all(|v| !v.is_empty())),
        "single-space records",
    )?;
    Ok(rows)
}
fn fields<'a>(row: &'a str, tag: &str, count: usize) -> Result<Vec<&'a str>, Error> {
    let f: Vec<_> = row.split(' ').collect();
    check(f.len() == count && f[0] == tag, "record shape/order")?;
    Ok(f)
}
fn append(out: &mut String, text: &str) -> Result<(), Error> {
    check(
        out.len()
            .checked_add(text.len())
            .is_some_and(|n| n <= TEXT_LIMIT),
        "whole selection exceeds 1 MiB",
    )?;
    out.push_str(text);
    Ok(())
}
fn check(ok: bool, why: &'static str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::new("disassembly", why))
    }
}

pub mod adjacent_b2;
pub use adjacent_b2::{AdjacentB2DisassemblySelection, AdjacentB2Limits};

pub mod adjacent_routed_jmp;
pub use adjacent_routed_jmp::{AdjacentRoutedJmpDisassemblySelection, AdjacentRoutedJmpLimits};

#[cfg(test)]
mod tests;
