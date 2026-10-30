//! Sealed, separately named routed-JMP union input profile. No runtime authority.
use super::*;

pub const PROFILE: &str = "elf-disassembly-null-jumps-adjacent-routed-jmp-short-t3-pending-v1";
pub(crate) const FAMILY: &str = "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\nadjacent_pairs\toriginal-geometry-jcc-or-routed-jmp-v1\n";
const MARKER: &str = "adjacent-pairs original-geometry-jcc-or-routed-jmp-v1\n";

/// Prospective pair work, independent of every unchanged singleton allocation cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdjacentRoutedJmpLimits {
    pub upper: usize,
    pub lower: usize,
    pub joint: usize,
}

/// Only the checked disassembly binder can create this profile.
#[derive(Clone, Debug)]
pub struct AdjacentRoutedJmpDisassemblySelection {
    pub(crate) base: DisassemblySelection,
    pub(crate) limits: AdjacentRoutedJmpLimits,
}
impl AdjacentRoutedJmpDisassemblySelection {
    pub const fn profile(&self) -> &'static str {
        PROFILE
    }
    pub fn manifest(&self) -> &[u8] {
        &self.base.selection.manifest
    }
}

impl Disassembly {
    /// Complete original jump denominator, labeled before policy binding.
    pub fn inventory_adjacent_routed_jmp(&self) -> Vec<u8> {
        let old = self.inventory_short_t3_pending();
        let text = String::from_utf8(old).expect("inventory is ASCII");
        text.replacen(SHORT_T3_PENDING_PROFILE, PROFILE, 1)
            .replacen(
                "pending_selected\tfull-instruction-ownership\n",
                "pending_selected\tfull-instruction-ownership\nadjacent_pairs\toriginal-geometry-jcc-or-routed-jmp-v1\n",
                1,
            )
            .into_bytes()
    }

    /// Strict v6 binding. Full bytes are bounded before any legacy projection.
    pub fn bind_adjacent_routed_jmp(
        self,
        policy: &[u8],
        expected_policy: ContentId,
    ) -> Result<AdjacentRoutedJmpDisassemblySelection, Error> {
        check(policy.len() <= TEXT_LIMIT, "policy size")?;
        check(ContentId::of(policy) == expected_policy, "policy digest")?;
        let r = rows(policy)?;
        check(
            r.len() >= 13 && r[0] == "LI2DISASM-POLICY 6",
            "adjacent policy header",
        )?;
        check(
            r[3] == "neighbor-victims short-only"
                && r[4] == "neighbor-ownership inherited-t3"
                && r[5] == "pending-selected full-instruction-ownership"
                && r[6] == MARKER.trim_end(),
            "adjacent policy markers",
        )?;
        let f = fields(r[7], "adjacent-pair-budgets", 4)?;
        let cap = |s: &str| -> Result<usize, Error> {
            check(
                !s.is_empty()
                    && s.bytes().all(|b| b.is_ascii_digit())
                    && (s == "0" || !s.starts_with('0')),
                "canonical adjacent cap",
            )?;
            let n = selection::num(s)?;
            check(n <= 256, "adjacent cap ceiling")?;
            Ok(n as usize)
        };
        let limits = AdjacentRoutedJmpLimits {
            upper: cap(f[1])?,
            lower: cap(f[2])?,
            joint: cap(f[3])?,
        };
        check(limits.joint <= limits.upper, "adjacent J exceeds U")?;
        let inventory = self.inventory_adjacent_routed_jmp();
        let ledger_id = ContentId::of(&self.ledger);
        let original = self.original;
        let count = self.jumps.len();
        // This private projection only reuses the unchanged old parser. The
        // public wrapper retains the FULL new manifest and is not replayable.
        let mut projected = vec!["LI2DISASM-POLICY 4"];
        projected.extend_from_slice(&r[1..6]);
        projected.extend_from_slice(&r[8..]);
        let projected = (projected.join("\n") + "\n").into_bytes();
        let extra = format!(
            "{MARKER}adjacent-pair-budgets {} {} {}\n",
            limits.upper, limits.lower, limits.joint
        );
        let mut base = self.bind_with_manifest_extra(
            &projected,
            ContentId::of(&projected),
            NeighborMode::ShortT3Pending,
            Some(&extra),
        )?;
        base.files
            .insert("disassembly-policy.txt".into(), policy.to_vec());
        base.files
            .insert("disassembly-inventory.tsv".into(), inventory);
        base.files.insert("planning-profile.tsv".into(), format!(
            "LI2PLANNING\t1\nprofile\t{PROFILE}\n{FAMILY}adjacent_upper\t{}\nadjacent_lower\t{}\nadjacent_joint\t{}\nscope\tartifact-code-regions-not-functions\nentries\tall-verified-instruction-heads\noriginal_sha256\t{}\nledger_sha256\t{}\npolicy_sha256\t{}\nselection_sha256\t{}\ncomplete_jump_count\t{count}\nqualification_complete\tfalse\n",
            limits.upper, limits.lower, limits.joint, ledger::hex(&original.0),
            ledger::hex(&ledger_id.0), ledger::hex(&expected_policy.0),
            ledger::hex(&ContentId::of(&base.selection.manifest).0)).into_bytes());
        Ok(AdjacentRoutedJmpDisassemblySelection { base, limits })
    }
}
