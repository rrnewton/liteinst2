//! One inspectable artifact attempt. Never maps or executes candidate bytes.
#![forbid(unsafe_code)]
use formats::ContentId;
use liteinst_rewrite::{disassembly, prepare_disassembly, selection};
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("input size bound".into());
    }
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> String {
    ContentId::of(bytes)
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}
// Choose the profile before any input read or binding, including refusal paths.
fn arguments(args: &[String]) -> Result<(&[String], bool), String> {
    if args.len() == 7 {
        Ok((&args[1..], false))
    } else if args.len() == 8
        && args[1] == "--short-neighbors-only"
        && !args[2..].iter().any(|s| s == "--short-neighbors-only")
    {
        Ok((&args[2..], true))
    } else {
        Err("disassembly_sites [--short-neighbors-only] ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into())
    }
}

fn labels(short_only: bool) -> (&'static str, &'static str, &'static str) {
    if short_only {
        (
            disassembly::SHORT_ONLY_PROFILE,
            "neighbor_victims\tshort-only\n",
            " neighbor_victims=short-only",
        )
    } else {
        (disassembly::PROFILE, "", "")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    LongOnly,
    ShortOnly,
    ShortT3Ownership,
    ShortT3Pending,
    Whole4096,
    WholeCurrentPlacement4096,
    WholeCurrentPlacementMixedPending4096,
    WholeFittingMixedPending4096,
    WholeEntryVeneerMixedPending4096,
    WholePackedEntryVeneerMixedPending4096,
    WholePackedOverlapping4096,
    WholeFixedExecPackedOverlapping4096,
}

fn arguments_with_ownership(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--short-neighbors-owned" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--short-neighbors-only" | "--short-neighbors-owned"
            )
        }) {
            return Err("disassembly_sites --short-neighbors-owned ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::ShortT3Ownership))
    } else {
        arguments(args).map(|(args, short_only)| {
            (
                args,
                if short_only {
                    Mode::ShortOnly
                } else {
                    Mode::LongOnly
                },
            )
        })
    }
}

// Recognize only this new leading form; every legacy positional form delegates.
fn arguments_with_pending(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--short-neighbors-pending" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--short-neighbors-only" | "--short-neighbors-owned" | "--short-neighbors-pending"
            )
        }) {
            return Err("disassembly_sites --short-neighbors-pending ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::ShortT3Pending))
    } else {
        arguments_with_ownership(args)
    }
}

// Only the new complete leading form selects this profile. A seven-argument
// invocation still treats every positional token as a literal filename/digest.
fn arguments_with_whole(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--whole-program-4096" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--whole-program-4096"
                    | "--short-neighbors-only"
                    | "--short-neighbors-owned"
                    | "--short-neighbors-pending"
            )
        }) {
            return Err("disassembly_sites --whole-program-4096 ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::Whole4096))
    } else {
        arguments_with_pending(args)
    }
}

// Only this new leading form opts in. Every old argument wrapper stays literal,
// including its positional-filename and mixed-token behavior.
fn arguments_with_current_placement(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--whole-program-current-placement-4096" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--whole-program-current-placement-4096"
                    | "--whole-program-4096"
                    | "--short-neighbors-only"
                    | "--short-neighbors-owned"
                    | "--short-neighbors-pending"
            )
        }) {
            return Err("disassembly_sites --whole-program-current-placement-4096 ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::WholeCurrentPlacement4096))
    } else {
        arguments_with_whole(args)
    }
}

// Opt-in only at this complete leading form; all prior wrappers stay literal.
fn arguments_with_mixed_pending(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--whole-program-current-placement-mixed-neighbors-4096" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--whole-program-current-placement-mixed-neighbors-4096"
                    | "--whole-program-current-placement-4096"
                    | "--whole-program-4096"
                    | "--short-neighbors-only"
                    | "--short-neighbors-owned"
                    | "--short-neighbors-pending"
            )
        }) {
            return Err("disassembly_sites --whole-program-current-placement-mixed-neighbors-4096 ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::WholeCurrentPlacementMixedPending4096))
    } else {
        arguments_with_current_placement(args)
    }
}

// Only the complete leading form opts in; prior wrappers remain literal.
fn arguments_with_fitting_mixed(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--whole-program-fitting-mixed-neighbors-4096" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--whole-program-fitting-mixed-neighbors-4096"
                    | "--whole-program-current-placement-mixed-neighbors-4096"
                    | "--whole-program-current-placement-4096"
                    | "--whole-program-4096"
                    | "--short-neighbors-only"
                    | "--short-neighbors-owned"
                    | "--short-neighbors-pending"
            )
        }) {
            return Err("disassembly_sites --whole-program-fitting-mixed-neighbors-4096 ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::WholeFittingMixedPending4096))
    } else {
        arguments_with_mixed_pending(args)
    }
}

// Only the complete leading form opts in; prior wrappers remain literal.
fn arguments_with_entry_veneer(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--whole-program-entry-veneer-mixed-neighbors-4096" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--whole-program-entry-veneer-mixed-neighbors-4096"
                    | "--whole-program-fitting-mixed-neighbors-4096"
                    | "--whole-program-current-placement-mixed-neighbors-4096"
                    | "--whole-program-current-placement-4096"
                    | "--whole-program-4096"
                    | "--short-neighbors-only"
                    | "--short-neighbors-owned"
                    | "--short-neighbors-pending"
            )
        }) {
            return Err("disassembly_sites --whole-program-entry-veneer-mixed-neighbors-4096 ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::WholeEntryVeneerMixedPending4096))
    } else {
        arguments_with_fitting_mixed(args)
    }
}

fn arguments_with_packed_entry_veneer(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--whole-program-packed-entry-veneer-mixed-neighbors-4096" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--whole-program-packed-entry-veneer-mixed-neighbors-4096"
                    | "--whole-program-entry-veneer-mixed-neighbors-4096"
                    | "--whole-program-fitting-mixed-neighbors-4096"
                    | "--whole-program-current-placement-mixed-neighbors-4096"
                    | "--whole-program-current-placement-4096"
                    | "--whole-program-4096"
                    | "--short-neighbors-only"
                    | "--short-neighbors-owned"
                    | "--short-neighbors-pending"
            )
        }) {
            return Err("disassembly_sites --whole-program-packed-entry-veneer-mixed-neighbors-4096 ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::WholePackedEntryVeneerMixedPending4096))
    } else {
        arguments_with_entry_veneer(args)
    }
}

fn arguments_with_packed_overlapping(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--whole-program-packed-overlapping-neighbors-4096" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--whole-program-packed-overlapping-neighbors-4096"
                    | "--whole-program-packed-entry-veneer-mixed-neighbors-4096"
                    | "--whole-program-entry-veneer-mixed-neighbors-4096"
                    | "--whole-program-fitting-mixed-neighbors-4096"
                    | "--whole-program-current-placement-mixed-neighbors-4096"
                    | "--whole-program-current-placement-4096"
                    | "--whole-program-4096"
                    | "--short-neighbors-only"
                    | "--short-neighbors-owned"
                    | "--short-neighbors-pending"
            )
        }) {
            return Err("disassembly_sites --whole-program-packed-overlapping-neighbors-4096 ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::WholePackedOverlapping4096))
    } else {
        arguments_with_packed_entry_veneer(args)
    }
}

// Only the complete new leading form opts into fixed address fields. Every
// legacy parser and its positional filename semantics remain unchanged.
fn arguments_with_fixed_exec(args: &[String]) -> Result<(&[String], Mode), String> {
    const FLAG: &str = "--whole-program-fixed-exec-packed-overlapping-neighbors-4096";
    if args.len() == 8 && args[1] == FLAG {
        if args[2..].iter().any(|arg| {
            arg.starts_with("--whole-program-")
                || matches!(
                    arg.as_str(),
                    "--short-neighbors-only"
                        | "--short-neighbors-owned"
                        | "--short-neighbors-pending"
                )
        }) {
            return Err("disassembly_sites fixed-exec: mixed/repeated profile selector".into());
        }
        Ok((&args[2..], Mode::WholeFixedExecPackedOverlapping4096))
    } else {
        arguments_with_packed_overlapping(args)
    }
}

fn labels_with_ownership(mode: Mode) -> (&'static str, &'static str, &'static str) {
    match mode {
        Mode::WholeFixedExecPackedOverlapping4096 => (
            liteinst_rewrite::FIXED_EXEC_BINDING_PROFILE,
            liteinst_rewrite::FIXED_EXEC_METADATA,
            " address_binding=fixed-exec-zero-bias-indexed-jump32-v1 required_object_type=ET_EXEC required_load_bias=0 planner=whole-program-packed-overlapping-neighbors-4096",
        ),
        Mode::WholePackedOverlapping4096 => (
            disassembly::whole::PROFILE,
            disassembly::whole::PACKED_OVERLAPPING_METADATA,
            " neighbor_victims=original-6-to-15 neighbor_ownership=inherited-t3 pending_selected=full-instruction-ownership artifact_placement=current-composition-certified-fit-v1 selected_placement_tactics=B1,B2,T1 paired_placement_tactics=legacy-T2,joint-overlapping-T3 paired_ownership=inherited-overlapping-T3 local_plan_admission=inherited-and-pending-before-tactic-success neighbor_relay=overlapping-e9-v-v+1-six-bytes-v1 artifact_entry_layout=direct-body-entry carrier_layout=linux-adjacent-generated-rx-runs-v1 carrier_page_bytes=4096 carrier_program_header_limit=1170",
        ),
        Mode::WholePackedEntryVeneerMixedPending4096 => (
            disassembly::whole::PROFILE,
            disassembly::whole::PACKED_ENTRY_VENEER_MIXED_METADATA,
            " neighbor_victims=mixed-short-and-long neighbor_ownership=inherited-t3 pending_selected=full-instruction-ownership artifact_placement=current-composition-certified-fit-v1 selected_placement_tactics=B1,B2,T1 paired_placement_tactics=legacy-T2,fitting-mixed-T3-short-selected-entry-veneer paired_ownership=inherited-mixed-T3 local_plan_admission=inherited-and-pending-before-tactic-success artifact_entry_layout=short-T3-selected-same-page-e9-v1 carrier_layout=linux-adjacent-generated-rx-runs-v1 carrier_page_bytes=4096 carrier_program_header_limit=1170",
        ),
        Mode::WholeEntryVeneerMixedPending4096 => (
            disassembly::whole::PROFILE,
            disassembly::whole::ENTRY_VENEER_MIXED_METADATA,
            " neighbor_victims=mixed-short-and-long neighbor_ownership=inherited-t3 pending_selected=full-instruction-ownership artifact_placement=current-composition-certified-fit-v1 selected_placement_tactics=B1,B2,T1 paired_placement_tactics=legacy-T2,fitting-mixed-T3-short-selected-entry-veneer paired_ownership=inherited-mixed-T3 local_plan_admission=inherited-and-pending-before-tactic-success artifact_entry_layout=short-T3-selected-same-page-e9-v1",
        ),
        Mode::WholeFittingMixedPending4096 => (
            disassembly::whole::PROFILE,
            disassembly::whole::FITTING_MIXED_METADATA,
            " neighbor_victims=mixed-short-and-long neighbor_ownership=inherited-t3 pending_selected=full-instruction-ownership artifact_placement=current-composition-certified-fit-v1 selected_placement_tactics=B1,B2,T1 paired_placement_tactics=legacy-T2,fitting-mixed-T3 paired_ownership=inherited-mixed-T3 local_plan_admission=inherited-and-pending-before-tactic-success",
        ),
        Mode::WholeCurrentPlacementMixedPending4096 => (
            disassembly::whole::PROFILE,
            disassembly::whole::MIXED_PENDING_METADATA,
            " neighbor_victims=mixed-short-and-long neighbor_ownership=inherited-t3 pending_selected=full-instruction-ownership artifact_placement=current-composition-single-candidate-v1 selected_placement_tactics=B1,B2,T1 paired_placement_tactics=legacy-T2,mixed-T3 paired_ownership=inherited-mixed-T3",
        ),
        Mode::Whole4096 => (disassembly::whole::PROFILE, "", ""),
        Mode::WholeCurrentPlacement4096 => (
            disassembly::whole::PROFILE,
            disassembly::whole::CURRENT_PLACEMENT_METADATA,
            " artifact_placement=current-composition-single-candidate-v1 selected_placement_tactics=B1,B2,T1 paired_placement_tactics=legacy-T2,T3 paired_ownership=inherited-long-T3",
        ),
        Mode::LongOnly => labels(false),
        Mode::ShortOnly => labels(true),
        Mode::ShortT3Pending => (
            disassembly::SHORT_T3_PENDING_PROFILE,
            "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\n",
            " neighbor_victims=short-only neighbor_ownership=inherited-t3 pending_selected=full-instruction-ownership",
        ),
        Mode::ShortT3Ownership => (
            disassembly::SHORT_T3_OWNERSHIP_PROFILE,
            "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\n",
            " neighbor_victims=short-only neighbor_ownership=inherited-t3",
        ),
    }
}

fn prepare_inputs(
    original: &[u8],
    ledger: &[u8],
    expected_ledger: ContentId,
    policy: &[u8],
    expected_policy: ContentId,
    mode: Mode,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<liteinst_rewrite::Product, liteinst_rewrite::Error> {
    let (profile, _, _) = labels_with_ownership(mode);
    let imported = disassembly::import(original, ledger, expected_ledger)?;
    // This denominator is retained even if policy/placement/loader refuses.
    files.insert(
        "disassembly-inventory.tsv".into(),
        match mode {
            Mode::Whole4096 => imported.inventory_whole_program(),
            Mode::WholeCurrentPlacement4096 => imported.inventory_whole_program(),
            Mode::WholeCurrentPlacementMixedPending4096 => imported.inventory_whole_program(),
            Mode::WholeFittingMixedPending4096 => imported.inventory_whole_program(),
            Mode::WholePackedEntryVeneerMixedPending4096 => imported.inventory_whole_program(),
            Mode::WholePackedOverlapping4096 => imported.inventory_whole_program(),
            Mode::WholeFixedExecPackedOverlapping4096 => imported.inventory_whole_program(),
            Mode::WholeEntryVeneerMixedPending4096 => imported.inventory_whole_program(),
            Mode::LongOnly => imported.inventory(),
            Mode::ShortOnly => imported.inventory_short_neighbors(),
            Mode::ShortT3Ownership => imported.inventory_short_t3_ownership(),
            Mode::ShortT3Pending => imported.inventory_short_t3_pending(),
        },
    );
    let selected = match mode {
        Mode::WholeFixedExecPackedOverlapping4096 => {
            let selected = imported.bind_whole_program(policy, expected_policy)?;
            assert_eq!(selected.profile(), disassembly::whole::PROFILE);
            files.insert("selection.txt".into(), selected.manifest().to_vec());
            return liteinst_rewrite::prepare_disassembly_whole_fixed_exec_packed_overlapping_neighbors(original, &selected);
        }
        Mode::WholePackedOverlapping4096 => {
            let selected = imported.bind_whole_program(policy, expected_policy)?;
            assert_eq!(selected.profile(), profile);
            files.insert("selection.txt".into(), selected.manifest().to_vec());
            return liteinst_rewrite::prepare_disassembly_whole_packed_overlapping_neighbors(
                original, &selected,
            );
        }
        Mode::WholePackedEntryVeneerMixedPending4096 => {
            let selected = imported.bind_whole_program(policy, expected_policy)?;
            assert_eq!(selected.profile(), profile);
            files.insert("selection.txt".into(), selected.manifest().to_vec());
            return liteinst_rewrite::prepare_disassembly_whole_packed_entry_veneer_mixed_neighbors(
                original, &selected,
            );
        }
        Mode::WholeEntryVeneerMixedPending4096 => {
            let selected = imported.bind_whole_program(policy, expected_policy)?;
            assert_eq!(selected.profile(), profile);
            files.insert("selection.txt".into(), selected.manifest().to_vec());
            return liteinst_rewrite::prepare_disassembly_whole_entry_veneer_mixed_neighbors(
                original, &selected,
            );
        }
        Mode::WholeFittingMixedPending4096 => {
            let selected = imported.bind_whole_program(policy, expected_policy)?;
            assert_eq!(selected.profile(), profile);
            files.insert("selection.txt".into(), selected.manifest().to_vec());
            return liteinst_rewrite::prepare_disassembly_whole_fitting_mixed_neighbors(
                original, &selected,
            );
        }
        Mode::WholeCurrentPlacementMixedPending4096 => {
            let selected = imported.bind_whole_program(policy, expected_policy)?;
            assert_eq!(selected.profile(), profile);
            files.insert("selection.txt".into(), selected.manifest().to_vec());
            return liteinst_rewrite::prepare_disassembly_whole_current_placement_mixed_neighbors(
                original, &selected,
            );
        }
        Mode::WholeCurrentPlacement4096 => {
            let selected = imported.bind_whole_program(policy, expected_policy)?;
            assert_eq!(selected.profile(), profile);
            files.insert("selection.txt".into(), selected.manifest().to_vec());
            return liteinst_rewrite::prepare_disassembly_whole_current_placement(
                original, &selected,
            );
        }
        Mode::Whole4096 => {
            let selected = imported.bind_whole_program(policy, expected_policy)?;
            assert_eq!(selected.profile(), profile);
            files.insert("selection.txt".into(), selected.manifest().to_vec());
            return liteinst_rewrite::prepare_disassembly_whole(original, &selected);
        }
        Mode::LongOnly => imported.bind(policy, expected_policy)?,
        Mode::ShortOnly => imported.bind_short_neighbors(policy, expected_policy)?,
        Mode::ShortT3Ownership => imported.bind_short_t3_ownership(policy, expected_policy)?,
        Mode::ShortT3Pending => imported.bind_short_t3_pending(policy, expected_policy)?,
    };
    assert_eq!(selected.profile(), profile);
    files.insert("selection.txt".into(), selected.manifest().to_vec());
    prepare_disassembly(original, &selected)
}

// The selector is separate from every old placement mode. Its type cannot be
// passed to the old jump-only binder or planning adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PopulationMode {
    Existing(Mode),
    JumpStack,
    JumpStackGrouped,
    JumpStackGroupedUpstream,
}
const JUMP_STACK_FLAG: &str = "--whole-program-fixed-exec-packed-overlapping-jump-stack64-4096";
const GROUPED_FLAG: &str = "--whole-program-fixed-exec-block-observation-jump-stack64-4096";
fn arguments_with_jump_stack(args: &[String]) -> Result<(&[String], PopulationMode), String> {
    if args.get(1).is_some_and(|arg| arg == GROUPED_FLAG) && args.len() != 8 {
        return Err("disassembly_sites grouped: exact argument count required".into());
    }
    if args.len() == 8 && matches!(args[1].as_str(), JUMP_STACK_FLAG | GROUPED_FLAG) {
        if args[2..].iter().any(|arg| {
            arg.starts_with("--whole-program-")
                || arg.starts_with("--short-neighbors-")
                || matches!(
                    arg.as_str(),
                    "--input-profile"
                        | "--policy-profile"
                        | "--original-sha256"
                        | "--trusted-complete-code"
                )
        }) {
            return Err("disassembly_sites jump-stack: mixed/repeated profile selector".into());
        }
        Ok((
            &args[2..],
            if args[1] == GROUPED_FLAG {
                PopulationMode::JumpStackGrouped
            } else {
                PopulationMode::JumpStack
            },
        ))
    } else {
        arguments_with_fixed_exec(args).map(|(args, mode)| (args, PopulationMode::Existing(mode)))
    }
}
const GROUPED_UPSTREAM_FLAG: &str = "--whole-program-fixed-exec-block-upstream-jump-stack64-4096";
fn arguments_with_grouped_upstream(args: &[String]) -> Result<(&[String], PopulationMode), String> {
    if args.get(1).is_some_and(|arg| arg == GROUPED_UPSTREAM_FLAG) {
        // Reuse exact-profile arity and mixed-selector guards. Only the typed
        // selector changes; positional names are returned from the original argv.
        let mut exact = args.to_vec();
        exact[1] = GROUPED_FLAG.into();
        arguments_with_jump_stack(&exact)?;
        Ok((&args[2..], PopulationMode::JumpStackGroupedUpstream))
    } else {
        arguments_with_jump_stack(args)
    }
}
fn is_grouped(mode: PopulationMode) -> bool {
    matches!(
        mode,
        PopulationMode::JumpStackGrouped | PopulationMode::JumpStackGroupedUpstream
    )
}
fn labels_with_population(mode: PopulationMode) -> (&'static str, &'static str, &'static str) {
    match mode {
        PopulationMode::Existing(mode) => labels_with_ownership(mode),
        PopulationMode::JumpStackGrouped => (
            liteinst_rewrite::GROUPED_PROFILE,
            "", // run() supplies the shared owned canonical metadata string.
            " selection_profile=jumps-gpr-stack64-v1 grouped_profile=jumps-gpr-stack64-block-observation-v1 address_binding=fixed-exec-zero-bias-indexed-jump32-v1 required_object_type=ET_EXEC required_load_bias=0",
        ),
        PopulationMode::JumpStackGroupedUpstream => (
            liteinst_rewrite::GROUPED_UPSTREAM_PROFILE,
            "",
            " selection_profile=jumps-gpr-stack64-v1 grouped_profile=jumps-gpr-stack64-block-upstream-v1 address_binding=fixed-exec-zero-bias-indexed-jump32-v1 required_object_type=ET_EXEC required_load_bias=0",
        ),
        PopulationMode::JumpStack => (
            disassembly::jump_stack::PROFILE,
            liteinst_rewrite::FIXED_EXEC_METADATA,
            " selection_profile=jumps-gpr-stack64-v1 address_binding=fixed-exec-zero-bias-indexed-jump32-v1 required_object_type=ET_EXEC required_load_bias=0 planner=whole-program-packed-overlapping-neighbors-4096",
        ),
    }
}
fn prepare_population_inputs(
    original: &[u8],
    ledger: &[u8],
    expected_ledger: ContentId,
    policy: &[u8],
    expected_policy: ContentId,
    mode: PopulationMode,
    capture: (&mut BTreeMap<String, Vec<u8>>, &mut Option<[usize; 3]>),
) -> Result<liteinst_rewrite::Product, liteinst_rewrite::Error> {
    let (files, classes) = capture;
    match mode {
        PopulationMode::Existing(mode) => prepare_inputs(
            original,
            ledger,
            expected_ledger,
            policy,
            expected_policy,
            mode,
            files,
        ),
        PopulationMode::JumpStack
        | PopulationMode::JumpStackGrouped
        | PopulationMode::JumpStackGroupedUpstream => {
            use li2core::x86::JumpStackClass;
            let imported = disassembly::jump_stack::import(original, ledger, expected_ledger)?;
            let mut counts = [0; 3];
            for site in imported.sites() {
                counts[match site.class() {
                    JumpStackClass::Jump => 0,
                    JumpStackClass::PushRegister64 => 1,
                    JumpStackClass::PopRegister64 => 2,
                }] += 1;
            }
            assert_eq!(counts.iter().sum::<usize>(), imported.sites().len());
            *classes = Some(counts);
            files.insert("disassembly-inventory.tsv".into(), imported.inventory());
            // The binder consumes the import. Retain only checked geometry for
            // the grouped verifier; legacy mode allocates no duplicate roster.
            let geometry: Vec<_> = if is_grouped(mode) {
                imported
                    .sites()
                    .iter()
                    .map(|site| site.geometry().clone())
                    .collect()
            } else {
                Vec::new()
            };
            let selected = imported.bind_whole_program(policy, expected_policy)?;
            assert_eq!(selected.profile(), disassembly::jump_stack::PROFILE);
            files.insert("selection.txt".into(), selected.manifest().to_vec());
            if mode == PopulationMode::JumpStackGroupedUpstream {
                let product =
                    liteinst_rewrite::prepare_disassembly_jump_stack_grouped_upstream_fixed_exec(
                        original, &selected,
                    )?;
                verify_grouped_metadata_for_profile(
                    original,
                    &geometry,
                    selected.manifest(),
                    &product,
                    product.files(),
                    true,
                )?;
                Ok(product)
            } else if mode == PopulationMode::JumpStackGrouped {
                let product = liteinst_rewrite::prepare_disassembly_jump_stack_grouped_fixed_exec(
                    original, &selected,
                )?;
                verify_grouped_metadata(
                    original,
                    &geometry,
                    selected.manifest(),
                    &product,
                    product.files(),
                )?;
                Ok(product)
            } else {
                liteinst_rewrite::prepare_disassembly_jump_stack_fixed_exec_packed_overlapping_neighbors(
                    original, &selected,
                )
            }
        }
    }
}
// Binary metadata is verified by its existing Rust format implementation, never
// by a second Python decoder. Files are borrowed and no candidate is executed.
fn verify_grouped_metadata(
    original: &[u8],
    geometry: &[disassembly::JumpSite],
    manifest: &[u8],
    product: &liteinst_rewrite::Product,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), liteinst_rewrite::Error> {
    verify_grouped_metadata_for_profile(original, geometry, manifest, product, files, false)
}
fn verify_grouped_metadata_for_profile(
    original: &[u8],
    geometry: &[disassembly::JumpSite],
    manifest: &[u8],
    product: &liteinst_rewrite::Product,
    files: &BTreeMap<String, Vec<u8>>,
    upstream: bool,
) -> Result<(), liteinst_rewrite::Error> {
    let failure = |detail: &str| liteinst_rewrite::Error {
        stage: "grouped-cli-metadata",
        detail: detail.into(),
    };
    let get = |name: &str| {
        files
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| failure("missing required group product member"))
    };
    let binding = product
        .fixed_image_binding()
        .ok_or_else(|| failure("missing fixed binding"))?;
    let binding_policy = if upstream {
        liteinst_rewrite::grouped_upstream_fixed_exec_binding_policy
    } else {
        liteinst_rewrite::grouped_fixed_exec_binding_policy
    };
    let expected = binding_policy(
        binding,
        ContentId::of(manifest),
        ContentId::of(get("grouping-policy.tsv")?),
    );
    if get("binding-policy.tsv")? != expected || get("selection.txt")? != manifest {
        return Err(failure("grouping policy/selection binding mismatch"));
    }
    let compatibility = formats::Compatibility {
        planner: li2core::contracts::CONTRACT_VERSION,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(get("target.tsv")?),
        binding: ContentId::of(&expected),
    };
    let metadata_bytes = get("metadata.li2meta")?;
    let metadata =
        formats::Metadata::decode(metadata_bytes, &compatibility, formats::Limits::default())
            .map_err(|_| failure("portable compatibility or metadata integrity"))?;
    metadata
        .verify_original(original)
        .map_err(|_| failure("portable original identity"))?;
    let ids: Vec<_> = geometry.iter().map(|site| site.id).collect();
    metadata
        .verify_selection(ContentId::of(manifest), &ids)
        .map_err(|_| failure("portable complete selection"))?;
    if product.reports().len() != ids.len()
        || metadata.declares_complete_trampoline_coverage() != product.candidate_complete()
    {
        return Err(failure("portable outcome count/coverage"));
    }
    for ((actual, report), site) in metadata.sites().iter().zip(product.reports()).zip(geometry) {
        if (
            actual.id,
            actual.original_pc,
            actual.file_offset,
            usize::from(actual.length),
        ) != (site.id, site.pc, site.file_offset, site.length)
            || (
                report.id,
                report.pc,
                report.file_offset,
                usize::from(report.length),
            ) != (site.id, site.pc, site.file_offset, site.length)
            || report.candidate_emitted != product.candidate_complete()
        {
            return Err(failure("portable per-site identity/emission"));
        }
        let outcome = if report.candidate_emitted && report.refusal.is_none() {
            use li2core::engine::Tactic;
            formats::Outcome::Rewritten(
                match report
                    .core_tactic
                    .ok_or_else(|| failure("missing tactic"))?
                {
                    Tactic::Relocation => formats::Tactic::Relocation,
                    Tactic::GeneralizedPun => formats::Tactic::GeneralizedPun,
                    Tactic::PrefixedPun => formats::Tactic::PrefixedPun,
                    Tactic::SuccessorEviction => formats::Tactic::SuccessorEviction,
                    Tactic::NeighborEviction => formats::Tactic::NeighborEviction,
                },
            )
        } else {
            formats::Outcome::Refused(report.refusal_code.unwrap_or(10_003))
        };
        if actual.outcome != outcome {
            return Err(failure("portable per-site outcome"));
        }
    }
    if product.candidate_complete() {
        let candidate = get("candidate.elf")?;
        let marker = b"LI2TOOL-CANDIDATE-UNREADY-V1\0";
        // Reuse the checked ELF reader. The existing carrier places its payload
        // at the eight-byte-aligned end of the appended program table. Marker
        // bytes in original data are legal and are never searched or counted.
        let output = formats::elf64::Elf64::parse(
            candidate,
            formats::elf64::ParseLimits {
                max_program_headers: 2910, // unchanged sealed whole-policy ceiling
            },
        )
        .map_err(|_| failure("embedded carrier ELF"))?;
        let header = output.header();
        if header.program_offset.0 < original.len() as u64 {
            return Err(failure("embedded table is not appended"));
        }
        let end = header
            .program_offset
            .0
            .checked_add(u64::from(header.program_count) * u64::from(header.program_entry_size))
            .ok_or_else(|| failure("embedded table overflow"))?;
        let payload = usize::try_from(
            end.checked_add(7)
                .ok_or_else(|| failure("embedded alignment overflow"))?
                & !7,
        )
        .map_err(|_| failure("embedded host offset"))?;
        let at = payload
            .checked_add(marker.len())
            .ok_or_else(|| failure("embedded marker overflow"))?;
        if candidate.get(payload..at) != Some(marker.as_slice())
            || candidate.get(at..at + 32) != Some(ContentId::of(metadata_bytes).0.as_slice())
            || candidate.get(at + 32..at + 64)
                != Some(ContentId::of(get("plan-ledger.tsv")?).0.as_slice())
        {
            return Err(failure("embedded metadata/plan identity"));
        }
    } else if files.contains_key("candidate.elf") || files.contains_key("source.li2sparse") {
        return Err(failure("incomplete product has candidate payload"));
    }
    Ok(())
}

fn jump_stack_fields(counts: Option<[usize; 3]>) -> String {
    let value =
        |index: usize| counts.map_or_else(|| "unavailable".into(), |n| n[index].to_string());
    let total = counts.map_or_else(
        || "unavailable".into(),
        |n| n.iter().sum::<usize>().to_string(),
    );
    format!(
        "selection_profile\tjumps-gpr-stack64-v1\ncomplete_site_count\t{total}\njump_count\t{}\npush_r64_count\t{}\npop_r64_count\t{}\n",
        value(0),
        value(1),
        value(2)
    )
}

fn run() -> Result<bool, String> {
    let raw_args: Vec<_> = std::env::args().collect();
    let (args, mode) = arguments_with_grouped_upstream(&raw_args)?;
    let (profile, family, stdout_family) = labels_with_population(mode);
    let grouped_family = if mode == PopulationMode::JumpStackGroupedUpstream {
        liteinst_rewrite::grouped_upstream_fixed_exec_metadata()
    } else if mode == PopulationMode::JumpStackGrouped {
        liteinst_rewrite::grouped_fixed_exec_metadata()
    } else {
        String::new()
    };
    let family = if is_grouped(mode) {
        grouped_family.as_str()
    } else {
        family
    };
    let expected_ledger = selection::id(&args[2]).map_err(|e| e.to_string())?;
    let expected_policy = selection::id(&args[4]).map_err(|e| e.to_string())?;
    let original = read(Path::new(&args[0]), disassembly::INPUT_LIMIT)?;
    let ledger = read(Path::new(&args[1]), disassembly::TEXT_LIMIT)?;
    let policy = read(Path::new(&args[3]), disassembly::TEXT_LIMIT)?;
    let mut files = BTreeMap::from([
        ("disassembly.txt".to_owned(), ledger.clone()),
        ("disassembly-policy.txt".to_owned(), policy.clone()),
    ]);
    let mut classes = None;
    let prepared = prepare_population_inputs(
        &original,
        &ledger,
        expected_ledger,
        &policy,
        expected_policy,
        mode,
        (&mut files, &mut classes),
    );
    // Same input reread ordering as the existing prepare CLI: no outcome is
    // dispatched and no output is published before all three snapshots agree.
    if read(Path::new(&args[0]), disassembly::INPUT_LIMIT)? != original
        || read(Path::new(&args[1]), disassembly::TEXT_LIMIT)? != ledger
        || read(Path::new(&args[3]), disassembly::TEXT_LIMIT)? != policy
    {
        return Err("inputs changed during preparation".into());
    }
    let mut fixed_binding = None;
    let complete = match prepared {
        Ok(product) => {
            fixed_binding = product.fixed_image_binding();
            files.extend(product.files().clone());
            product.candidate_complete()
        }
        Err(error) => {
            // An invalid/untrusted ledger has no verified denominator, but the
            // program failure and exact attempted inputs are never a success.
            let detail: String = error
                .to_string()
                .bytes()
                .map(|b| format!("{b:02x}"))
                .collect();
            files.insert("program-failure.tsv".into(), format!(
                "LI2DISASSEMBLY-FAILURE\t1\nprofile\t{profile}\n{family}observed_original_sha256\t{}\nexpected_ledger_sha256\t{}\nexpected_policy_sha256\t{}\nqualification_complete\tfalse\ndetail_hex\t{detail}\n",
                digest(&original), args[2], args[4]).into_bytes());
            false
        }
    };
    let output = Path::new(&args[5]);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| e.to_string())?;
    let mut index = format!(
        "LI2DISASSEMBLY-DIRECTORY\t1\nprofile\t{profile}\n{family}observed_original_sha256\t{}\ncandidate_complete\t{complete}\nqualification_complete\tfalse\n",
        digest(&original)
    );
    if matches!(
        mode,
        PopulationMode::JumpStack
            | PopulationMode::JumpStackGrouped
            | PopulationMode::JumpStackGroupedUpstream
    ) {
        index.push_str(&jump_stack_fields(classes));
    }
    if matches!(
        mode,
        PopulationMode::JumpStack
            | PopulationMode::JumpStackGrouped
            | PopulationMode::JumpStackGroupedUpstream
            | PopulationMode::Existing(Mode::WholeFixedExecPackedOverlapping4096)
    ) {
        match fixed_binding {
            Some(binding) => index.push_str(&format!(
                "fixed_binding_status\tsource-ET_EXEC-bound\nfixed_source_sha256\t{}\nfixed_source_mapping\t{}\nfixed_source_generation\t{}\nfixed_output_readback\t{}\n",
                binding.identity().source.0.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                binding.identity().mapping, binding.identity().generation,
                if complete { "checked" } else { "not-complete" },
            )),
            None => index.push_str("fixed_binding_status\tunbound\nfixed_output_readback\tnot-complete\n"),
        }
    }
    if is_grouped(mode) {
        index.push_str(if fixed_binding.is_some() {
            "portable_metadata_verification\tchecked\n"
        } else {
            "portable_metadata_verification\tunavailable\n"
        });
        index.push_str(if complete {
            "embedded_metadata_binding\tchecked\n"
        } else {
            "embedded_metadata_binding\tnot-complete\n"
        });
    }
    for (name, bytes) in &files {
        write(&output.join(name), bytes)?;
        index.push_str(&format!(
            "file\t{name}\t{}\t{}\n",
            bytes.len(),
            digest(bytes)
        ));
    }
    write(&output.join("COMPLETE"), index.as_bytes())?;
    std::fs::File::open(output)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!(
        "profile={profile}{stdout_family} candidate_complete={complete} qualification_complete=false"
    );
    Ok(complete)
}
fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_profile_cli_labels_mode_before_policy_binding() {
        let old: Vec<String> = [
            "program",
            "--literal-path",
            "ledger",
            "ledger-sha",
            "policy",
            "policy-sha",
            "out",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let (positional, mode) = arguments(&old).unwrap();
        assert_eq!(positional, &old[1..]);
        assert!(!mode);
        assert_eq!(labels(mode), (disassembly::PROFILE, "", ""));
        let mut short = old.clone();
        short.insert(1, "--short-neighbors-only".into());
        let (positional, mode) = arguments(&short).unwrap();
        assert_eq!(positional, &old[1..]);
        assert!(mode);
        let (profile, family, stdout) = labels(mode);
        assert_eq!(profile, disassembly::SHORT_ONLY_PROFILE);
        assert_eq!(family, "neighbor_victims\tshort-only\n");
        assert_eq!(stdout, " neighbor_victims=short-only");
        // These labels exist before an invalid original/ledger can be bound.
        assert!(disassembly::import(&[], &[], ContentId::of(&[])).is_err());
        assert_eq!(labels(mode), (profile, family, stdout));
        for bad in [
            short[..7]
                .iter()
                .cloned()
                .chain(["extra".into(), "extra".into()])
                .collect::<Vec<_>>(),
            {
                let mut a = short.clone();
                a[1] = "--unknown".into();
                a
            },
            {
                let mut a = short.clone();
                a.swap(1, 2);
                a
            },
            {
                let mut a = short.clone();
                a[2] = "--short-neighbors-only".into();
                a
            },
            old[..6].to_vec(),
        ] {
            assert!(arguments(&bad).is_err());
        }
    }

    #[test]
    fn owned_short_cli_preserves_positional_paths_and_exact_prebind_labels() {
        let base: Vec<String> = [
            "program",
            "original",
            "ledger",
            "ledger-sha",
            "policy",
            "policy-sha",
            "out",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        for path in ["--short-neighbors-only", "--short-neighbors-owned"] {
            let mut old = base.clone();
            old[1] = path.into();
            let (positional, mode) = arguments_with_ownership(&old).unwrap();
            assert_eq!(positional, &old[1..]);
            assert_eq!(mode, Mode::LongOnly);
            assert_eq!(labels_with_ownership(mode), labels(false));
        }
        let mut old_short = base.clone();
        old_short[1] = "--short-neighbors-owned".into(); // an existing legal positional filename
        old_short.insert(1, "--short-neighbors-only".into());
        let (positional, mode) = arguments_with_ownership(&old_short).unwrap();
        assert_eq!(positional, &old_short[2..]);
        assert_eq!(mode, Mode::ShortOnly);
        assert_eq!(labels_with_ownership(mode), labels(true));
        let mut owned = base.clone();
        owned.insert(1, "--short-neighbors-owned".into());
        let (positional, mode) = arguments_with_ownership(&owned).unwrap();
        assert_eq!(positional, &base[1..]);
        assert_eq!(mode, Mode::ShortT3Ownership);
        let expected = (
            disassembly::SHORT_T3_OWNERSHIP_PROFILE,
            "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\n",
            " neighbor_victims=short-only neighbor_ownership=inherited-t3",
        );
        assert_eq!(labels_with_ownership(mode), expected);
        assert!(disassembly::import(&[], &[], ContentId::of(&[])).is_err());
        assert_eq!(labels_with_ownership(mode), expected);
        for flag in ["--short-neighbors-only", "--short-neighbors-owned"] {
            let mut bad = owned.clone();
            bad[2] = flag.into();
            assert!(arguments_with_ownership(&bad).is_err());
        }
        let mut unknown = owned.clone();
        unknown[1] = "--unknown".into();
        assert_eq!(
            arguments_with_ownership(&unknown).unwrap_err(),
            arguments(&unknown).unwrap_err()
        );
        assert!(arguments_with_ownership(&owned[..6]).is_err());
        let mut extra = owned;
        extra.push("extra".into());
        assert!(arguments_with_ownership(&extra).is_err());
    }

    #[test]
    fn pending_short_cli_preserves_legacy_paths_and_exact_prebind_labels() {
        let base: Vec<String> = [
            "program",
            "original",
            "ledger",
            "ledger-sha",
            "policy",
            "policy-sha",
            "out",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let flags = [
            "--short-neighbors-only",
            "--short-neighbors-owned",
            "--short-neighbors-pending",
        ];
        for path in flags {
            let mut old = base.clone();
            old[1] = path.into();
            assert_eq!(arguments_with_pending(&old), arguments_with_ownership(&old));
            let (positional, mode) = arguments_with_pending(&old).unwrap();
            assert_eq!(positional, &old[1..]);
            assert_eq!(mode, Mode::LongOnly);
            assert_eq!(labels_with_ownership(mode), labels(false));
        }
        for path in ["--short-neighbors-owned", "--short-neighbors-pending"] {
            let mut old_short = base.clone();
            old_short[1] = path.into();
            old_short.insert(1, "--short-neighbors-only".into());
            assert_eq!(
                arguments_with_pending(&old_short),
                arguments_with_ownership(&old_short)
            );
            let (positional, mode) = arguments_with_pending(&old_short).unwrap();
            assert_eq!(positional, &old_short[2..]);
            assert_eq!(mode, Mode::ShortOnly);
            assert_eq!(labels_with_ownership(mode), labels(true));
        }
        let mut pending = base.clone();
        pending.insert(1, "--short-neighbors-pending".into());
        let (positional, mode) = arguments_with_pending(&pending).unwrap();
        assert_eq!(positional, &base[1..]);
        assert_eq!(mode, Mode::ShortT3Pending);
        let expected = (
            disassembly::SHORT_T3_PENDING_PROFILE,
            "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\n",
            " neighbor_victims=short-only neighbor_ownership=inherited-t3 pending_selected=full-instruction-ownership",
        );
        assert_eq!(labels_with_ownership(mode), expected);
        assert!(disassembly::import(&[], &[], ContentId::of(&[])).is_err());
        assert_eq!(labels_with_ownership(mode), expected);
        for position in 2..8 {
            for flag in flags {
                let mut bad = pending.clone();
                bad[position] = flag.into();
                assert!(arguments_with_pending(&bad).is_err());
            }
        }
        // Seven arguments are still six literal paths, even if this resembles
        // a truncated pending invocation. It must never activate pending mode.
        let (positional, mode) = arguments_with_pending(&pending[..7]).unwrap();
        assert_eq!(positional, &pending[1..7]);
        assert_eq!(mode, Mode::LongOnly);
        assert_eq!(
            arguments_with_pending(&pending[..7]),
            arguments_with_ownership(&pending[..7])
        );
        for flag in flags {
            let mut mixed = pending.clone();
            mixed.insert(2, flag.into());
            assert!(arguments_with_pending(&mixed).is_err());
        }
        let mut unknown = pending.clone();
        unknown[1] = "--unknown".into();
        assert_eq!(
            arguments_with_pending(&unknown),
            arguments_with_ownership(&unknown)
        );
        assert!(arguments_with_pending(&unknown).is_err());
        let mut misplaced = pending.clone();
        misplaced.swap(1, 2);
        assert!(arguments_with_pending(&misplaced).is_err());
        assert!(arguments_with_pending(&pending[..6]).is_err());
        let mut extra = pending;
        extra.push("extra".into());
        assert!(arguments_with_pending(&extra).is_err());
    }
}

#[cfg(test)]
#[path = "disassembly_sites/whole_tests.rs"]
mod whole_tests;

#[cfg(test)]
mod fixed_exec_cli_tests {
    use super::*;
    #[test]
    fn fixed_exec_selector_is_explicit_and_preserves_legacy_parsers() {
        let positional: Vec<_> = [
            "program",
            "original",
            "ledger",
            "ledger-sha",
            "policy",
            "policy-sha",
            "out",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(
            arguments_with_fixed_exec(&positional),
            arguments_with_packed_overlapping(&positional)
        );
        for flag in [
            "--whole-program-packed-overlapping-neighbors-4096",
            "--whole-program-packed-entry-veneer-mixed-neighbors-4096",
            "--whole-program-4096",
            "--short-neighbors-only",
        ] {
            let mut old = positional.clone();
            old.insert(1, flag.into());
            assert_eq!(
                arguments_with_fixed_exec(&old),
                arguments_with_packed_overlapping(&old)
            );
        }
        let mut args = positional.clone();
        args.insert(
            1,
            "--whole-program-fixed-exec-packed-overlapping-neighbors-4096".into(),
        );
        assert_eq!(
            arguments_with_fixed_exec(&args).unwrap(),
            (&positional[1..], Mode::WholeFixedExecPackedOverlapping4096)
        );
        let (profile, metadata, _) =
            labels_with_ownership(Mode::WholeFixedExecPackedOverlapping4096);
        assert_eq!(profile, liteinst_rewrite::FIXED_EXEC_BINDING_PROFILE);
        assert!(metadata.contains("required_load_bias\t0\n"));
        for flag in [
            args[1].clone(),
            "--whole-program-packed-overlapping-neighbors-4096".into(),
            "--short-neighbors-only".into(),
        ] {
            let mut mixed = args.clone();
            mixed[2] = flag;
            assert!(arguments_with_fixed_exec(&mixed).is_err());
        }
        assert!(arguments_with_fixed_exec(&args[..7]).is_ok()); // old seven positional filenames
        args.push("extra".into());
        assert!(arguments_with_fixed_exec(&args).is_err());
    }
}

#[cfg(test)]
#[path = "disassembly_sites/grouped_tests.rs"]
mod grouped_tests;

#[cfg(test)]
#[path = "disassembly_sites/grouped_upstream_tests.rs"]
mod grouped_upstream_tests;
