//! Supplied-data models only. No completed native proof, owner or source
//! release is constructed, and no native observation is claimed.
use super::*;
use crate::linux::remote::dynamic::owner::admission::runtime::maps::{
    FetchGeometry, verify_closed,
};
use crate::linux::remote::dynamic::owner::admission::source_identity::backing::DescriptorIdentity;
use std::time::Duration;

const LOWER: &str = "00400000-00401000 r--p 00000000 08:02 17    /main a  \n";
const UPPER: &str = "00401000-00402000 r-xp 00001000 08:02 17    /main a  \n";
const UPPER_NX: &str = "00401000-00402000 r--p 00001000 08:02 17    /main a  \n";
const UNION: &str = "00400000-00402000 r--p 00000000 08:02 17    /main a  \n";
const EXTRA: &str = "00500000-00504000 r-xp 00003000 08:02 17    /main a  \n";
const ISLAND: &str = "00600000-00601000 r-xp 00000000 00:00 0\n";
const VDSO: &str = "00700000-00701000 r-xp 00000000 00:00 0  [vdso]\n";
const VDSO_NX: &str = "00700000-00701000 r--p 00000000 00:00 0  [vdso]\n";
fn entry() -> EntryEvidence {
    EntryEvidence {
        first_image: crate::FirstImage::Executable,
        executable_entry: 0x401000,
        interpreter_base: 0,
        initial_instruction: 0x401000,
        interpreter: None,
    }
}
fn executable() -> ExecutableIdentity {
    let vma = FileIdentity {
        major: 8,
        minor: 2,
        inode: 17,
    };
    ExecutableIdentity {
        opened: DescriptorIdentity {
            file: vma,
            mode: libc::S_IFREG | 0o500,
            length: 0x7000,
        },
        vma,
    }
}
fn profile(total: usize) -> InitialCaptureProfile {
    InitialCaptureProfile {
        max_vmas: 4,
        max_windows: 8,
        max_window_bytes: 8192,
        max_total_capture_bytes: total,
    }
}
fn original(extra: bool) -> Vec<u8> {
    [LOWER, UPPER, if extra { EXTRA } else { "" }, VDSO]
        .concat()
        .into_bytes()
}
fn plan(raw: &[u8]) -> InitialMapPlan {
    InitialMapPlan::select(raw, &entry(), (8, 2, 17))
        .unwrap()
        .unwrap()
}
fn current(merged: bool) -> Vec<u8> {
    if merged {
        [UNION, ISLAND, VDSO_NX].concat().into_bytes()
    } else {
        [LOWER, UPPER_NX, ISLAND, VDSO_NX].concat().into_bytes()
    }
}
fn describe(raw: &[u8], current: &[u8]) -> InitialSourceVma {
    let p = plan(raw);
    let projection = p
        .verify_snapshot(raw, current, &(0x600000..0x601000), p.executable_count())
        .unwrap();
    let view = projection
        .view(raw, current, &(0x600000..0x601000))
        .unwrap();
    let originals = InitialOriginalInventory::new(raw, &entry(), executable().vma, &p).unwrap();
    InitialSourceVma::from_inventory(&originals, &view, 1).unwrap()
}
fn prepared(extra: bool, total: usize) -> (PreparedInitialSources, InitialMapPlan) {
    let mut value =
        PreparedInitialSources::allocate(profile(total), Instant::now() + Duration::from_secs(3))
            .unwrap();
    value.allocate_coalescence_payloads().unwrap();
    let raw = original(extra);
    let p = plan(&raw);
    value.storage.original_maps[..raw.len()].copy_from_slice(&raw);
    value.storage.original_read = SourceReadProgress {
        started: true,
        attempted: true,
        complete: true,
        requested_bytes: MAP_BYTES,
        copied_bytes: raw.len(),
        filesystem_type: Some(libc::PROC_SUPER_MAGIC),
        ..SourceReadProgress::default()
    };
    value.storage.original = Some(OriginalBinding {
        token: DynamicStop {
            session: 1,
            sequence: 0,
            tid: 12,
            task: None,
        },
        entry: entry(),
    });
    value.storage.original_complete = true;
    (value, p)
}
fn changed(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert_eq!(text.matches(from).count(), 1);
    text.replace(from, to).into_bytes()
}

#[test]
fn coalesced_source_keeps_original_rx_and_excludes_header_authority() {
    let raw = original(false);
    let maps = current(true);
    let source = describe(&raw, &maps);
    assert_eq!(
        (
            source.source().start,
            source.source().end,
            source.source().offset
        ),
        (0x401000, 0x402000, 0x1000)
    );
    assert_eq!(
        (
            source.container().start,
            source.container().end,
            source.container().offset
        ),
        (0x400000, 0x402000, 0)
    );
    assert!(source.source().view(&raw, &maps).is_err()); // old strict view is unchanged
    let p = plan(&raw);
    let originals = InitialOriginalInventory::new(&raw, &entry(), executable().vma, &p).unwrap();
    assert!(originals.source(0).is_err());
    assert!(
        FetchGeometry::for_initial_source(source, AddressRange::new(0x400fff, 0x401000).unwrap())
            .is_err()
    );
    assert!(
        FetchGeometry::for_initial_source(source, AddressRange::new(0x401fff, 0x402001).unwrap())
            .is_err()
    );
    assert!(
        FetchGeometry::for_instruction(
            *source.source(),
            AddressRange::new(0x401000, 0x401001).unwrap()
        )
        .unwrap()
        .projected_rows(&maps)
        .is_err()
    );
}

#[test]
fn coalesced_fetch_opens_only_original_rx_and_requires_exact_closed_table() {
    let raw = original(false);
    let maps = current(true);
    let source = describe(&raw, &maps);
    let fetch =
        FetchGeometry::for_initial_source(source, AddressRange::new(0x401000, 0x401001).unwrap())
            .unwrap();
    assert_eq!(
        fetch.pages(),
        AddressRange::new(0x401000, 0x402000).unwrap()
    );
    let open = [LOWER, UPPER, ISLAND, VDSO_NX].concat().into_bytes();
    assert_eq!(fetch.projected_rows(&maps).unwrap(), 4);
    fetch.verify_open(&maps, &open).unwrap();
    for bad in [
        changed(&open, LOWER, &LOWER.replace("r--p", "r-xp")),
        changed(&open, "00001000 08:02", "00000000 08:02"),
        changed(&open, "00:00 0  [vdso]", "00:00 1  [vdso]"),
        changed(&open, UPPER, &UPPER.replace("17    /main", "17   /main")),
    ] {
        assert!(fetch.verify_open(&maps, &bad).is_err());
    }
    verify_closed(&maps, &maps).unwrap();
    assert!(verify_closed(&maps, &current(false)).is_err());
    assert!(verify_closed(&maps, &changed(&maps, "17    /main", "17   /main")).is_err());
}

#[test]
fn coalesced_separate_nx_uses_same_original_source_without_fictitious_union() {
    let raw = original(false);
    let maps = current(false);
    let source = describe(&raw, &maps);
    assert_eq!(
        (source.container().start, source.container().end),
        (0x401000, 0x402000)
    );
    source.source().view(&raw, &maps).unwrap();
    let fetch =
        FetchGeometry::for_initial_source(source, AddressRange::new(0x401fff, 0x402000).unwrap())
            .unwrap();
    assert_eq!(fetch.projected_rows(&maps).unwrap(), 4);
    fetch
        .verify_open(
            &maps,
            &[LOWER, UPPER, ISLAND, VDSO_NX].concat().into_bytes(),
        )
        .unwrap();
}

#[test]
fn coalesced_preflight_charges_pair_and_exact_overlapping_windows() {
    let (mut value, p) = prepared(false, 4096 + PAIR_CAPTURE_BYTES);
    let sizing = value.preflight_coalesced(&p, executable()).unwrap();
    assert_eq!(sizing.window_bytes(), 4096);
    assert_eq!(sizing.pair_capture_bytes(), 16384);
    assert_eq!(sizing.total_capture_bytes().unwrap(), 20480);
    assert_eq!(value.storage.preflight_filled, 1);
    assert_eq!(
        value.storage.windows[0].geometry.unwrap().snapshot,
        AddressRange::new(0x401000, 0x402000).unwrap()
    );
    assert_eq!(
        value.storage.windows[0].entries.completeness(),
        Completeness::Partial
    );
    assert_eq!(
        value.storage.windows[0]
            .entries
            .heads()
            .map(|(pc, _)| pc)
            .collect::<Vec<_>>(),
        [0x401000]
    );
    assert!(
        value
            .storage
            .windows
            .iter()
            .all(|w| w.id.is_none() && w.snapshot.is_none())
    );
    assert!(value.storage.identities.is_empty());
    let (mut short, p) = prepared(false, 20479);
    assert!(matches!(
        short.preflight_coalesced(&p, executable()),
        Err(GateError::Refused(
            "initial runtime pair and overlapping capture bytes exceed their bound"
        ))
    ));
    assert!(short.storage.failure.is_some());
    let (mut multi, p) = prepared(true, 8 * 8192);
    let sizing = multi.preflight_coalesced(&p, executable()).unwrap();
    assert_eq!(sizing.window_bytes(), 4096 + 4124 + 4138 + 4138 + 4110);
    assert_eq!(sizing.windows, 5);
    assert_eq!(sizing.vmas, 2);
}

#[test]
fn coalesced_preflight_failure_retains_geometry_capacity_and_no_ids() {
    let (mut value, p) = prepared(true, 20480 + 4124 - 1);
    let bytes = value.allocated_bytes().unwrap();
    assert!(value.preflight_coalesced(&p, executable()).is_err());
    assert_eq!(value.storage.preflight_filled, 1);
    assert!(value.storage.windows[0].original_witness.is_some());
    assert!(value.storage.windows[0].geometry.is_some());
    assert_eq!(value.storage.initial_rows.capacity(), 4);
    assert_eq!(value.allocated_bytes().unwrap(), bytes);
    assert!(
        value
            .storage
            .windows
            .iter()
            .all(|w| w.id.is_none() && w.snapshot.is_none())
    );
    assert!(value.storage.preflight_sizing.is_none());
    assert!(value.preflight_coalesced(&p, executable()).is_err());
    assert_eq!(value.storage.preflight_filled, 1);
}

#[test]
fn coalesced_window_recheck_rejects_each_original_dependency_change() {
    for mutation in 0..18 {
        let (mut value, p) = prepared(false, 20480);
        value.preflight_coalesced(&p, executable()).unwrap();
        let raw = original(false);
        let maps = current(true);
        let source = describe(&raw, &maps);
        value.storage.rows.push(*source.source());
        value.storage.initial_rows.push(source);
        let slot = &mut value.storage.windows[0];
        match mutation {
            0 => slot.original_witness.as_mut().unwrap().original_span.0 += 1,
            1 => slot.original_witness.as_mut().unwrap().lower_span = None,
            2 => slot.entries.heads[0] = None,
            3 => slot.original_witness.as_mut().unwrap().geometry.before = Boundary::Unknown,
            4 => slot.vma = 1,
            5 => slot.original_witness.as_mut().unwrap().original_index += 1,
            6 => slot.original_witness.as_mut().unwrap().original_span.1 -= 1,
            7 => slot.original_witness.as_mut().unwrap().upper_span = Some((0, 1)),
            8 => slot.original_witness.as_mut().unwrap().offset += 4096,
            9 => slot.original_witness.as_mut().unwrap().file.inode += 1,
            10 => {
                slot.original_witness.as_mut().unwrap().geometry.range =
                    AddressRange::new(0x400000, 0x402000).unwrap()
            }
            11 => slot.original_witness.as_mut().unwrap().geometry.after = Boundary::Unknown,
            12 => {
                slot.geometry.as_mut().unwrap().target =
                    AddressRange::new(0x400000, 0x402000).unwrap()
            }
            13 => {
                slot.geometry.as_mut().unwrap().snapshot =
                    AddressRange::new(0x400fff, 0x402000).unwrap()
            }
            14 => {
                slot.geometry.as_mut().unwrap().head_scope =
                    AddressRange::new(0x401000, 0x402001).unwrap()
            }
            15 => slot.geometry.as_mut().unwrap().before = Boundary::Unknown,
            16 => slot.geometry.as_mut().unwrap().after = Boundary::Unknown,
            17 => slot.entries.heads[1] = Some(0x401001),
            _ => unreachable!(),
        }
        assert!(matches!(
            value.storage.plan_coalesced_windows(executable()),
            Err(GateError::Refused(
                "initial coalescence authenticated window differs from preflight"
            ))
        ));
        assert!(value.storage.identities.is_empty());
        assert!(value.storage.windows[0].id.is_none());
    }
    let (mut value, p) = prepared(false, 20480);
    value.preflight_coalesced(&p, executable()).unwrap();
    let source = describe(&original(false), &current(true));
    value.storage.rows.push(*source.source());
    value.storage.initial_rows.push(source);
    value.storage.plan_coalesced_windows(executable()).unwrap();
    assert_eq!(value.storage.planned, 1);
    assert_eq!(value.storage.identities.len(), 1);
    assert_eq!(
        value.storage.windows[0].id.unwrap().identity,
        value.storage.identities[0]
    );
    assert_eq!(value.storage.windows[0].id.unwrap().index, 0);
    assert!(!value.storage.capture_complete); // a pure plan is still not native capture
}

#[test]
fn coalesced_sidecar_exact_capacity_is_separately_retained_once() {
    let p = profile(20480);
    let mut value =
        PreparedInitialSources::allocate(p, Instant::now() + Duration::from_secs(3)).unwrap();
    let before = value.allocated_bytes().unwrap();
    assert_eq!(value.storage.initial_rows.capacity(), 0);
    let extra = PreparedInitialSources::coalescence_payload_reservation(p).unwrap();
    assert_eq!(extra, p.max_vmas * size_of::<InitialSourceVma>());
    value.allocate_coalescence_payloads().unwrap();
    assert_eq!(value.storage.initial_rows.capacity(), p.max_vmas);
    assert_eq!(value.storage.initial_rows.len(), 0);
    assert_eq!(value.allocated_bytes().unwrap(), before + extra);
    assert!(value.allocate_coalescence_payloads().is_err());
    assert_eq!(value.allocated_bytes().unwrap(), before + extra);
    let mut ordered =
        PreparedInitialSources::allocate(p, Instant::now() + Duration::from_secs(3)).unwrap();
    let raw = original(false);
    let plan = plan(&raw);
    ordered.storage.original_maps[..raw.len()].copy_from_slice(&raw);
    ordered.storage.original_read = SourceReadProgress {
        started: true,
        attempted: true,
        complete: true,
        requested_bytes: MAP_BYTES,
        copied_bytes: raw.len(),
        filesystem_type: Some(libc::PROC_SUPER_MAGIC),
        ..SourceReadProgress::default()
    };
    ordered.storage.original = Some(OriginalBinding {
        token: DynamicStop {
            session: 2,
            sequence: 0,
            tid: 13,
            task: None,
        },
        entry: entry(),
    });
    ordered.storage.original_complete = true;
    let before = ordered.allocated_bytes().unwrap();
    ordered.preflight_coalesced(&plan, executable()).unwrap();
    assert_eq!(ordered.storage.initial_rows.capacity(), 0);
    assert_eq!(ordered.allocated_bytes().unwrap(), before);
    ordered.allocate_coalescence_payloads().unwrap();
    assert_eq!(ordered.allocated_bytes().unwrap(), before + extra);
}

#[test]
fn coalesced_preflight_preserves_alias_and_original_executable_neighbor_refusals() {
    let raw = original(false);
    let alias = [
        LOWER,
        UPPER,
        "00500000-00501000 r--p 00001000 08:02 17    /main a  \n",
        VDSO,
    ]
    .concat()
    .into_bytes();
    assert!(
        InitialMapPlan::select(&alias, &entry(), (8, 2, 17))
            .unwrap()
            .is_none()
    );
    let other = [
        LOWER,
        UPPER,
        "00402000-00403000 r-xp 00000000 09:01 33 /other\n",
        VDSO,
    ]
    .concat()
    .into_bytes();
    let p = plan(&other);
    let originals = InitialOriginalInventory::new(&other, &entry(), executable().vma, &p).unwrap();
    assert!(matches!(
        walk_windows(&originals, &entry(), profile(20480), |_, _, _, _, _| Ok(())),
        Err(GateError::Refused(_))
    ));
    let p = plan(&raw);
    assert!(
        InitialOriginalInventory::new(
            &raw,
            &entry(),
            FileIdentity {
                inode: 18,
                ..executable().vma
            },
            &p
        )
        .is_err()
    );
}
