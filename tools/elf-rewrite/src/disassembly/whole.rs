//! Explicit bounded whole-program frontend. Sharing changes representation,
//! never the complete entry obligations or the existing planning transaction.
use super::*;
use li2core::contracts::LegalEntry;
use std::sync::Arc;

/// Opt-in input-independent policy construction with fixed legacy ceilings.
pub mod policy;

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
/// Separate six-byte overlapping relay; no old T3 family or carrier limit changes.
pub const PACKED_OVERLAPPING_METADATA: &str = "neighbor_victims\toriginal-6-to-15\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\nartifact_placement\tcurrent-composition-certified-fit-v1\nselected_placement_tactics\tB1,B2,T1\npaired_placement_tactics\tlegacy-T2,joint-overlapping-T3\npaired_ownership\tinherited-overlapping-T3\nlocal_plan_admission\tinherited-and-pending-before-tactic-success\nneighbor_relay\toverlapping-e9-v-v+1-six-bytes-v1\nartifact_entry_layout\tdirect-body-entry\ncarrier_layout\tlinux-adjacent-generated-rx-runs-v1\ncarrier_page_bytes\t4096\ncarrier_program_header_limit\t1170\n";
pub const MATERIAL_PROFILE: &str = "e9patch-full-sections-null-jumps-4096-v1";
pub const SITE_LIMIT: usize = 4096;
pub const HEAD_LIMIT: usize = 16384;
pub const MESSAGE_LIMIT: usize = 32768;
pub const SELECTION_LIMIT: usize = 2 * 1024 * 1024;
const POLICY_HEADER: &str = "LI2DISASM-WHOLE-POLICY 1";
const JUMP_STACK_POLICY_HEADER: &str = "LI2DISASM-JUMP-STACK-WHOLE-POLICY 1";

#[derive(Clone, Copy)]
enum Sites<'a> {
    Jumps(&'a [JumpSite]),
    JumpStack(&'a [super::jump_stack::Site]),
}

/// Borrowed sealed population: only the two checked importers construct it.
/// It carries no planner, loader, fault-transparency or execution authority.
#[derive(Clone, Copy)]
pub(crate) struct Population<'a> {
    original: ContentId,
    ledger: &'a [u8],
    regions: &'a [Region],
    sites: Sites<'a>,
}
impl<'a> Population<'a> {
    pub(super) fn jump_stack(
        original: ContentId,
        ledger: &'a [u8],
        regions: &'a [Region],
        sites: &'a [super::jump_stack::Site],
    ) -> Self {
        Self {
            original,
            ledger,
            regions,
            sites: Sites::JumpStack(sites),
        }
    }
    pub(crate) fn original(self) -> ContentId {
        self.original
    }
    pub(crate) fn ledger_id(self) -> ContentId {
        ContentId::of(self.ledger)
    }
    pub(crate) fn profile(self) -> &'static str {
        match self.sites {
            Sites::Jumps(_) => PROFILE,
            Sites::JumpStack(_) => super::jump_stack::PROFILE,
        }
    }
    fn policy_header(self) -> &'static str {
        match self.sites {
            Sites::Jumps(_) => POLICY_HEADER,
            Sites::JumpStack(_) => JUMP_STACK_POLICY_HEADER,
        }
    }
    pub(crate) fn site_count(self) -> usize {
        match self.sites {
            Sites::Jumps(s) => s.len(),
            Sites::JumpStack(s) => s.len(),
        }
    }
    pub(crate) fn site(
        self,
        index: usize,
    ) -> Option<(&'a JumpSite, Option<li2core::x86::JumpStackClass>)> {
        match self.sites {
            Sites::Jumps(s) => s.get(index).map(|s| (s, None)),
            Sites::JumpStack(s) => s.get(index).map(|s| (s.geometry(), Some(s.class()))),
        }
    }
    fn sites(
        self,
    ) -> impl ExactSizeIterator<Item = (&'a JumpSite, Option<li2core::x86::JumpStackClass>)> {
        (0..self.site_count()).map(move |index| self.site(index).expect("sealed population index"))
    }
}

/// Complete union, with no conversion to the public legacy selection type.
/// Binding is not an accepted plan or qualification result.
#[derive(Clone, Debug)]
pub struct JumpStackWholeSelection {
    pub(crate) selection: Selection,
    files: BTreeMap<String, Vec<u8>>,
}
impl JumpStackWholeSelection {
    pub const fn profile(&self) -> &'static str {
        super::jump_stack::PROFILE
    }
    pub fn manifest(&self) -> &[u8] {
        &self.selection.manifest
    }
    pub(crate) fn packed_overlapping_files(&self) -> BTreeMap<String, Vec<u8>> {
        packed_overlapping_files(&self.files)
    }
}

fn packed_overlapping_files(source: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
    let mut files = source.clone();
    let profile = files
        .get_mut("planning-profile.tsv")
        .expect("typed whole-program selection retains its profile");
    let text = std::str::from_utf8(profile).expect("typed profile is ASCII");
    let (before, after) = text
        .split_once(NEIGHBOR_METADATA)
        .expect("typed profile has exactly one original neighbor identity");
    *profile = format!("{before}{PACKED_OVERLAPPING_METADATA}{after}").into_bytes();
    files
}

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

    pub(crate) fn packed_overlapping_files(&self) -> BTreeMap<String, Vec<u8>> {
        packed_overlapping_files(&self.files)
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

    fn population(&self) -> Population<'_> {
        Population {
            original: self.original,
            ledger: &self.ledger,
            regions: &self.regions,
            sites: Sites::Jumps(&self.jumps),
        }
    }

    #[cfg(test)]
    fn shared_regions(&self) -> Result<Vec<selection::SharedRegion>, Error> {
        self.population().shared_regions()
    }

    /// Bind the complete legacy jump population with its unchanged identity.
    pub fn bind_whole_program(
        self,
        policy: &[u8],
        expected_policy: ContentId,
    ) -> Result<WholeProgramSelection, Error> {
        let (selection, mut files) = self.population().bind(policy, expected_policy)?;
        files.insert(
            "disassembly-inventory.tsv".into(),
            self.inventory_whole_program(),
        );
        Ok(WholeProgramSelection { selection, files })
    }
}

impl super::jump_stack::JumpStackDisassembly {
    /// Bind every jump/register-stack head, including RSP and later-refused prefixes.
    /// No conversion to the old public selection and no qualification is granted.
    pub fn bind_whole_program(
        self,
        policy: &[u8],
        expected_policy: ContentId,
    ) -> Result<JumpStackWholeSelection, Error> {
        let (selection, mut files) = self.population().bind(policy, expected_policy)?;
        files.insert("disassembly-inventory.tsv".into(), self.inventory());
        Ok(JumpStackWholeSelection { selection, files })
    }
}

impl Population<'_> {
    fn shared_regions(self) -> Result<Vec<selection::SharedRegion>, Error> {
        let heads = self
            .regions
            .iter()
            .try_fold(0_usize, |n, r| n.checked_add(r.instructions.len()));
        check(
            heads.is_some_and(|n| n > 0 && n <= HEAD_LIMIT),
            "whole complete head bound",
        )?;
        check(
            self.site_count() > 0 && self.site_count() <= SITE_LIMIT,
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
    fn bind(
        self,
        policy: &[u8],
        expected_policy: ContentId,
    ) -> Result<(Selection, BTreeMap<String, Vec<u8>>), Error> {
        check(policy.len() <= TEXT_LIMIT, "policy size")?;
        check(ContentId::of(policy) == expected_policy, "policy digest")?;
        let rows = rows(policy)?;
        let ledger_id = ContentId::of(self.ledger);
        check(
            rows.len() >= 8 && rows[0] == self.policy_header(),
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
        let profile_name = self.profile();
        let mut manifest = format!(
            "LI2TOOL-SHARED-REGIONS 1\nprofile {profile_name}\n{}\nledger {}\n{}\n{}\n{}\n{}\nhook 1 {hook} 1 {}\n",
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
        for (site, class) in self.sites() {
            let class_suffix = class.map_or_else(String::new, |class| format!(" {}", class.name()));
            let region = regions
                .iter()
                .position(|r| r.range == site.region)
                .ok_or_else(|| Error::new("disassembly", "missing imported region"))?;
            append(
                &mut manifest,
                &format!(
                    "site {} {} {} {} {} {} {} {} {} {} 1 observe original-decode{class_suffix}\nentries-ref {} {}\nresumes {} none\n",
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
        let selection = match self.sites {
            Sites::Jumps(sites) => selection::parse_shared_projection(
                manifest.as_bytes(),
                &selection::SharedEntries {
                    original: self.original,
                    ledger: ledger_id,
                    regions: &regions,
                    sites,
                    null_hook: hook,
                },
            ),
            Sites::JumpStack(_) => {
                selection::parse_population_projection(manifest.as_bytes(), self, &regions, hook)
            }
        }?;
        if matches!(self.sites, Sites::JumpStack(_)) {
            policy::check_jump_stack_selection(&selection)?;
        }
        let census = match self.sites {
            Sites::Jumps(sites) => format!("complete_jump_count\t{}\n", sites.len()),
            Sites::JumpStack(sites) => {
                use li2core::x86::JumpStackClass;
                let count = |class| sites.iter().filter(|site| site.class() == class).count();
                format!(
                    "complete_site_count\t{}\njump_count\t{}\npush_r64_count\t{}\npop_r64_count\t{}\n",
                    sites.len(),
                    count(JumpStackClass::Jump),
                    count(JumpStackClass::PushRegister64),
                    count(JumpStackClass::PopRegister64)
                )
            }
        };
        let profile = format!(
            "LI2PLANNING\t1\nprofile\t{profile_name}\n{NEIGHBOR_METADATA}scope\tartifact-code-regions-not-functions\nentries\tall-verified-instruction-heads\noriginal_sha256\t{}\nledger_sha256\t{}\npolicy_sha256\t{}\nselection_sha256\t{}\n{census}qualification_complete\tfalse\n",
            ledger::hex(&self.original.0),
            ledger::hex(&ledger_id.0),
            ledger::hex(&expected_policy.0),
            ledger::hex(&ContentId::of(&selection.manifest).0)
        );
        Ok((
            selection,
            BTreeMap::from([
                ("planning-profile.tsv".into(), profile.into_bytes()),
                ("disassembly.txt".into(), self.ledger.to_vec()),
                ("disassembly-policy.txt".into(), policy.to_vec()),
            ]),
        ))
    }
}

#[cfg(test)]
mod tests;
