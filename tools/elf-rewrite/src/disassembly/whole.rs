//! Explicit bounded whole-program frontend. Sharing changes representation,
//! never the complete entry obligations or the existing planning transaction.
use super::*;
use li2core::contracts::LegalEntry;
use std::sync::Arc;

pub const PROFILE: &str = "elf-disassembly-null-jumps-shared-4096-v1";
pub(super) const NEIGHBOR_METADATA: &str =
    "neighbor_victims\tlong-only\nneighbor_ownership\tinherited-t3\n";
/// Additive mode identity; the complete whole-program profile is unchanged.
pub const CURRENT_PLACEMENT_METADATA: &str = "artifact_placement\tcurrent-composition-single-candidate-v1\nselected_placement_tactics\tB1,B2,T1\npaired_placement_tactics\tlegacy-T2,T3\npaired_ownership\tinherited-long-T3\n";
/// Separate mixed-neighbor mode; the original whole/current labels stay literal.
pub const MIXED_PENDING_METADATA: &str = "neighbor_victims\tmixed-short-and-long\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\nartifact_placement\tcurrent-composition-single-candidate-v1\nselected_placement_tactics\tB1,B2,T1\npaired_placement_tactics\tlegacy-T2,mixed-T3\npaired_ownership\tinherited-mixed-T3\n";
/// Separate fitting mode; certification does not grant runtime qualification.
pub const FITTING_MIXED_METADATA: &str = "neighbor_victims\tmixed-short-and-long\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\nartifact_placement\tcurrent-composition-certified-fit-v1\nselected_placement_tactics\tB1,B2,T1\npaired_placement_tactics\tlegacy-T2,fitting-mixed-T3\npaired_ownership\tinherited-mixed-T3\nlocal_plan_admission\tinherited-and-pending-before-tactic-success\n";
/// Separate storage/entry layout, restricted to short-T3 selected images.
pub const ENTRY_VENEER_MIXED_METADATA: &str = "neighbor_victims\tmixed-short-and-long\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\nartifact_placement\tcurrent-composition-certified-fit-v1\nselected_placement_tactics\tB1,B2,T1\npaired_placement_tactics\tlegacy-T2,fitting-mixed-T3-short-selected-entry-veneer\npaired_ownership\tinherited-mixed-T3\nlocal_plan_admission\tinherited-and-pending-before-tactic-success\nartifact_entry_layout\tshort-T3-selected-same-page-e9-v1\n";
/// Serialization identity only; the entry-veneer planner and all its caps remain unchanged.
pub const PACKED_RX_RUNS_METADATA: &str = "carrier_layout\tlinux-adjacent-generated-rx-runs-v1\ncarrier_page_bytes\t4096\ncarrier_program_header_limit\t1170\n";
pub const PACKED_ENTRY_VENEER_MIXED_METADATA: &str = "neighbor_victims\tmixed-short-and-long\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\nartifact_placement\tcurrent-composition-certified-fit-v1\nselected_placement_tactics\tB1,B2,T1\npaired_placement_tactics\tlegacy-T2,fitting-mixed-T3-short-selected-entry-veneer\npaired_ownership\tinherited-mixed-T3\nlocal_plan_admission\tinherited-and-pending-before-tactic-success\nartifact_entry_layout\tshort-T3-selected-same-page-e9-v1\ncarrier_layout\tlinux-adjacent-generated-rx-runs-v1\ncarrier_page_bytes\t4096\ncarrier_program_header_limit\t1170\n";
pub const MATERIAL_PROFILE: &str = "e9patch-full-sections-null-jumps-4096-v1";
pub const SITE_LIMIT: usize = 4096;
pub const HEAD_LIMIT: usize = 16384;
pub const MESSAGE_LIMIT: usize = 32768;
pub const SELECTION_LIMIT: usize = 2 * 1024 * 1024;
const POLICY_HEADER: &str = "LI2DISASM-WHOLE-POLICY 1";

/// Only the complete importer constructs this selection. There is no conversion
/// to a legacy manifest or caller-supplied recovered-function authority.
#[derive(Clone, Debug)]
pub struct WholeProgramSelection {
    pub(crate) selection: Selection,
    pub(crate) files: BTreeMap<String, Vec<u8>>,
}
impl WholeProgramSelection {
    pub const fn profile(&self) -> &'static str {
        PROFILE
    }
    pub fn manifest(&self) -> &[u8] {
        &self.selection.manifest
    }

    pub(crate) fn mixed_pending_files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut files = self.files.clone();
        let profile = files
            .get_mut("planning-profile.tsv")
            .expect("typed whole-program selection retains its profile");
        let text = std::str::from_utf8(profile).expect("typed profile is ASCII");
        let (before, after) = text
            .split_once(NEIGHBOR_METADATA)
            .expect("typed profile has exactly one original neighbor identity");
        *profile = format!("{before}{MIXED_PENDING_METADATA}{after}").into_bytes();
        files
    }

    pub(crate) fn fitting_mixed_files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut files = self.files.clone();
        let profile = files
            .get_mut("planning-profile.tsv")
            .expect("typed whole-program selection retains its profile");
        let text = std::str::from_utf8(profile).expect("typed profile is ASCII");
        let (before, after) = text
            .split_once(NEIGHBOR_METADATA)
            .expect("typed profile has exactly one original neighbor identity");
        *profile = format!("{before}{FITTING_MIXED_METADATA}{after}").into_bytes();
        files
    }

    pub(crate) fn packed_entry_veneer_mixed_files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut files = self.entry_veneer_mixed_files();
        let profile = files
            .get_mut("planning-profile.tsv")
            .expect("typed whole-program selection retains its profile");
        let text = std::str::from_utf8(profile).expect("typed profile is ASCII");
        let (before, after) = text
            .split_once(ENTRY_VENEER_MIXED_METADATA)
            .expect("typed profile retains the original entry-veneer identity");
        *profile = format!("{before}{PACKED_ENTRY_VENEER_MIXED_METADATA}{after}").into_bytes();
        files
    }

    pub(crate) fn entry_veneer_mixed_files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut files = self.files.clone();
        let profile = files
            .get_mut("planning-profile.tsv")
            .expect("typed whole-program selection retains its profile");
        let text = std::str::from_utf8(profile).expect("typed profile is ASCII");
        let (before, after) = text
            .split_once(NEIGHBOR_METADATA)
            .expect("typed profile has exactly one original neighbor identity");
        *profile = format!("{before}{ENTRY_VENEER_MIXED_METADATA}{after}").into_bytes();
        files
    }
}

fn append(out: &mut String, text: &str) -> Result<(), Error> {
    check(
        out.len()
            .checked_add(text.len())
            .is_some_and(|n| n <= SELECTION_LIMIT),
        "whole shared selection exceeds 2 MiB",
    )?;
    out.push_str(text);
    Ok(())
}

impl Disassembly {
    /// Same independently decoded complete denominator, under the explicit new
    /// resource/representation identity. This never reports planning success.
    pub fn inventory_whole_program(&self) -> Vec<u8> {
        let old = String::from_utf8(self.inventory()).expect("ASCII inventory");
        old.replacen(
            &format!("profile\t{}\n", super::PROFILE),
            &format!("profile\t{PROFILE}\n"),
            1,
        )
        .into_bytes()
    }

    fn shared_regions(&self) -> Result<Vec<selection::SharedRegion>, Error> {
        let heads = self
            .regions
            .iter()
            .try_fold(0_usize, |n, r| n.checked_add(r.instructions.len()));
        check(
            heads.is_some_and(|n| n > 0 && n <= HEAD_LIMIT),
            "whole complete head bound",
        )?;
        check(
            !self.jumps.is_empty() && self.jumps.len() <= SITE_LIMIT,
            "whole complete site bound",
        )?;
        Ok(self
            .regions
            .iter()
            .map(|r| selection::SharedRegion {
                range: r.range,
                heads: Arc::new(
                    r.instructions
                        .iter()
                        .map(|i| LegalEntry {
                            address: i.ip(),
                            requires_endbr: matches!(i.code(), Code::Endbr64 | Code::Endbr32),
                        })
                        .collect(),
                ),
            })
            .collect())
    }

    /// Explicit new policy header; old bind methods/ceilings remain unchanged.
    /// Ledger and policy remain <=1 MiB, complete heads <=16384, sites <=4096.
    /// The shared manifest is <=2 MiB; all other old numeric ceilings apply.
    /// Core accepted plans still retain full entry/read vectors, so frontend
    /// sharing is not a whole-planner memory bound or performance claim.
    pub fn bind_whole_program(
        self,
        policy: &[u8],
        expected_policy: ContentId,
    ) -> Result<WholeProgramSelection, Error> {
        check(policy.len() <= TEXT_LIMIT, "policy size")?;
        check(ContentId::of(policy) == expected_policy, "policy digest")?;
        let rows = rows(policy)?;
        let ledger_id = ContentId::of(&self.ledger);
        check(
            rows.len() >= 8 && rows[0] == POLICY_HEADER,
            "whole policy header",
        )?;
        check(
            rows[1] == format!("original {}", ledger::hex(&self.original.0)),
            "policy original",
        )?;
        check(
            rows[2] == format!("ledger {}", ledger::hex(&ledger_id.0)),
            "policy ledger",
        )?;
        for (row, tag) in rows[3..7]
            .iter()
            .zip(["target", "domain", "carrier", "limits"])
        {
            check(row.starts_with(&format!("{tag} ")), "policy order")?;
        }
        let hook = fields(rows[7], "null-hook", 2)?;
        let hook = selection::num(hook[1])?;
        check(
            self.regions
                .iter()
                .flat_map(|r| &r.instructions)
                .any(|i| i.ip() == hook && i.code() == Code::Retnq && i.len() == 1),
            "null hook is not an original C3 head",
        )?;
        let regions = self.shared_regions()?;
        let mut manifest = format!(
            "LI2TOOL-SHARED-REGIONS 1\nprofile {PROFILE}\n{}\nledger {}\n{}\n{}\n{}\n{}\nhook 1 {hook} 1 {}\n",
            rows[1],
            ledger::hex(&ledger_id.0),
            rows[3],
            rows[4],
            rows[5],
            rows[6],
            ledger::hex(&ContentId::of(&[0xc3]).0)
        );
        check(
            manifest.len() <= SELECTION_LIMIT,
            "whole shared selection exceeds 2 MiB",
        )?;
        for (index, region) in regions.iter().enumerate() {
            append(
                &mut manifest,
                &format!(
                    "region-entries {} all-instruction-heads {}",
                    index + 1,
                    ledger::hex(&ledger_id.0)
                ),
            )?;
            for head in region.heads.iter() {
                append(
                    &mut manifest,
                    &format!(" {}:{}", head.address, usize::from(head.requires_endbr)),
                )?;
            }
            append(&mut manifest, "\n")?;
        }
        for site in &self.jumps {
            let region = regions
                .iter()
                .position(|r| r.range == site.region)
                .ok_or_else(|| Error::new("disassembly", "missing imported region"))?;
            append(
                &mut manifest,
                &format!(
                    "site {} {} {} {} {} {} {} {} {} {} 1 observe original-decode\nentries-ref {} {}\nresumes {} none\n",
                    site.id,
                    site.pc,
                    site.length,
                    site.file_offset,
                    site.region.start(),
                    site.region.len(),
                    site.region.start(),
                    site.region.len(),
                    site.block.start(),
                    site.block.len(),
                    site.id,
                    region + 1,
                    site.id
                ),
            )?;
        }
        for row in &rows[8..] {
            check(
                row.starts_with("search ") || row.starts_with("allocation "),
                "policy record",
            )?;
            append(&mut manifest, row)?;
            append(&mut manifest, "\n")?;
        }
        let selection = selection::parse_shared_projection(
            manifest.as_bytes(),
            &selection::SharedEntries {
                original: self.original,
                ledger: ledger_id,
                regions: &regions,
                sites: &self.jumps,
                null_hook: hook,
            },
        )?;
        let profile = format!(
            "LI2PLANNING\t1\nprofile\t{PROFILE}\n{NEIGHBOR_METADATA}scope\tartifact-code-regions-not-functions\nentries\tall-verified-instruction-heads\noriginal_sha256\t{}\nledger_sha256\t{}\npolicy_sha256\t{}\nselection_sha256\t{}\ncomplete_jump_count\t{}\nqualification_complete\tfalse\n",
            ledger::hex(&self.original.0),
            ledger::hex(&ledger_id.0),
            ledger::hex(&expected_policy.0),
            ledger::hex(&ContentId::of(&selection.manifest).0),
            self.jumps.len()
        );
        Ok(WholeProgramSelection {
            selection,
            files: BTreeMap::from([
                ("planning-profile.tsv".into(), profile.into_bytes()),
                ("disassembly.txt".into(), self.ledger.clone()),
                ("disassembly-policy.txt".into(), policy.to_vec()),
                (
                    "disassembly-inventory.tsv".into(),
                    self.inventory_whole_program(),
                ),
            ]),
        })
    }
}

#[cfg(test)]
mod tests;
