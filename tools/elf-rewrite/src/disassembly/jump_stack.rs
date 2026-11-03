//! Explicit complete union selection, not a bound policy or candidate.
//!
//! This type has no conversion to the legacy jump-only selection or planner.
//! Whole-policy binding and CLI/RPC integration use separate typed adapters.
//! In particular, successful import does not discharge whole-program caps.

use super::{CheckedRegions, Error, JumpSite, collect_sites, import_regions, ledger};
use formats::ContentId;
use li2core::x86::{JumpStackClass, jump_or_register_stack};
use std::fmt::Write as _;

/// Complete `j*` plus exact `Push_r64`/`Pop_r64` selection identity.
pub const PROFILE: &str = "jumps-gpr-stack64-v1";

/// One immutable selected head and its independently decoded class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Site {
    geometry: JumpSite,
    class: JumpStackClass,
}
impl Site {
    /// Source geometry; this is not qualification or placement success.
    pub const fn geometry(&self) -> &JumpSite {
        &self.geometry
    }

    /// Descriptive class, including later-refused prefixes and RSP operands.
    pub const fn class(&self) -> JumpStackClass {
        self.class
    }
}

/// Sealed complete rows sharing the ordinary importer's validation and cuts.
/// Completeness remains the caller's trusted code-ledger premise.
#[derive(Clone, Debug)]
pub struct JumpStackDisassembly {
    checked: CheckedRegions,
    ledger: Vec<u8>,
    sites: Vec<Site>,
}
impl JumpStackDisassembly {
    pub(crate) fn population(&self) -> super::whole::Population<'_> {
        super::whole::Population::jump_stack(
            self.checked.original,
            &self.ledger,
            &self.checked.regions,
            &self.sites,
        )
    }

    /// Exact selector, independent of any future address-binding profile.
    pub const fn profile(&self) -> &'static str {
        PROFILE
    }

    /// Every selected head in original PC order; no qualifier filtering.
    pub fn sites(&self) -> &[Site] {
        &self.sites
    }

    /// Digest of the whole original authenticated by the shared importer.
    pub const fn original(&self) -> ContentId {
        self.checked.original
    }

    /// Exact complete input ledger, including unselected heads.
    pub fn ledger(&self) -> &[u8] {
        &self.ledger
    }

    /// Independently checked head count, including all unselected regions.
    pub fn head_count(&self) -> usize {
        self.checked
            .regions
            .iter()
            .map(|r| r.instructions.len())
            .sum()
    }

    /// Explicitly unbound metadata. Neither this inventory nor this type is an
    /// accepted `WholeProgramSelection`; all old whole-policy bounds remain.
    pub fn inventory(&self) -> Vec<u8> {
        let mut counts = [0_usize; 3];
        for site in &self.sites {
            counts[match site.class {
                JumpStackClass::Jump => 0,
                JumpStackClass::PushRegister64 => 1,
                JumpStackClass::PopRegister64 => 2,
            }] += 1;
        }
        let mut out = format!(
            "LI2DISASSEMBLY-INVENTORY\t1\nprofile\t{PROFILE}\nselection_status\tclassified-unbound\noriginal_sha256\t{}\nledger_sha256\t{}\ncomplete_head_count\t{}\ncomplete_site_count\t{}\njump_count\t{}\npush_r64_count\t{}\npop_r64_count\t{}\nqualification_complete\tfalse\nid\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length\tclass\n",
            ledger::hex(&self.checked.original.0),
            ledger::hex(&ContentId::of(&self.ledger).0),
            self.head_count(),
            self.sites.len(),
            counts[0],
            counts[1],
            counts[2],
        );
        for site in &self.sites {
            let s = &site.geometry;
            let class = site.class.name();
            writeln!(
                out,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{class}",
                s.id,
                s.pc,
                s.length,
                s.file_offset,
                s.region.start(),
                s.region.len(),
                s.block.start(),
                s.block.len(),
            )
            .unwrap();
        }
        out.into_bytes()
    }
}

/// Uses the exact old ledger/error-order pass, then selects the complete union.
/// No semantic qualifier, placement search, cap expansion or native execution.
pub fn import(
    original: &[u8],
    ledger: &[u8],
    expected_ledger: ContentId,
) -> Result<JumpStackDisassembly, Error> {
    let checked = import_regions(original, ledger, expected_ledger)?;
    let sites = collect_sites(&checked, jump_or_register_stack, |geometry, class| Site {
        geometry,
        class,
    })?;
    Ok(JumpStackDisassembly {
        checked,
        ledger: ledger.to_vec(),
        sites,
    })
}
