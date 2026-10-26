//! Pure source/dispatch controls. Synthetic maps and identities confer no
//! native exec, file-object, exclusion, cleanup or complete-head authority.
use super::*;

const ORIGINAL: &str = concat!(
    "00400000-00401000 r--p 00000000 08:01 100 /objects/main  image\n",
    "00401000-00403000 r-xp 00001000 08:01 100 /objects/main  image\n",
    "00600000-00601000 rw-p 00000000 00:00 0\n",
    "00800000-00802000 r-xp 00000000 08:01 200 /objects/interpreter\n",
    "00900000-00901000 r-xp 00000000 00:00 0 [vdso]\n",
    "00a00000-00a01000 rw-p 00000000 00:00 0 [stack]\n",
    "ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]\n",
);
const ISLAND: &str = "00b00000-00b01000 r-xp 00000000 00:00 0\n";

fn profile() -> DynamicExecProfile {
    DynamicExecProfile {
        max_capture_images: 4,
        max_capture_bytes: 8192,
        max_total_capture_bytes: 32768,
        max_argument_pointers: 8,
        max_string_bytes: 1024,
    }
}
fn entry() -> EntryEvidence {
    EntryEvidence {
        first_image: FirstImage::Interpreter,
        executable_entry: 0x401000,
        interpreter_base: 0,
        initial_instruction: 0x801000,
        // This descriptive spelling intentionally does not select an inode.
        interpreter: Some(std::path::PathBuf::from("/descriptive/path-only")),
    }
}
fn quarantine(old: &str) -> String {
    old.replace("r-xp", "r--p")
        .replace("ffffffffff600000-", &format!("{ISLAND}ffffffffff600000-"))
}
fn descriptors(raw: &[u8]) -> Vec<MemoryMapping> {
    parse(raw)
        .unwrap()
        .entries()
        .map(|row| descriptor(row, row.permissions.bytes()).unwrap())
        .collect()
}

struct Fixture {
    original: String,
    final_maps: String,
    originals: Vec<MemoryMapping>,
    current: Vec<MemoryMapping>,
    entry: EntryEvidence,
    profile: DynamicExecProfile,
    executable: FileIdentity,
    island: Range<u64>,
}
impl Fixture {
    fn new(original: &str) -> Self {
        let final_maps = quarantine(original);
        let originals = parse(original.as_bytes())
            .unwrap()
            .entries()
            .filter(|row| row.permissions.bytes()[2] == b'x' && !fixed_vsyscall(*row))
            .map(|row| descriptor(row, row.permissions.bytes()).unwrap())
            .collect();
        let current = descriptors(final_maps.as_bytes());
        Self {
            original: original.into(),
            final_maps,
            originals,
            current,
            entry: entry(),
            profile: profile(),
            executable: FileIdentity {
                major: 8,
                minor: 1,
                inode: 100,
            },
            island: 0xb00000..0xb01000,
        }
    }
    fn derive(&self) -> Result<Vec<SourceRow>, GateError> {
        let mut rows = reserve(self.profile.max_capture_images)?;
        derive_rows(
            parse(self.original.as_bytes())?,
            parse(self.final_maps.as_bytes())?,
            &Geometry {
                originals: &self.originals,
                current: &self.current,
                island: &self.island,
                entry: &self.entry,
                executable: self.executable,
                profile: &self.profile,
            },
            &mut rows,
        )?;
        Ok(rows)
    }
    fn update_final(&mut self, from: &str, to: &str) {
        assert!(self.final_maps.contains(from));
        self.final_maps = self.final_maps.replace(from, to);
        self.current = descriptors(self.final_maps.as_bytes());
    }
}
fn refused_exact<T>(result: Result<T, GateError>, expected: &'static str) {
    assert!(matches!(result, Err(GateError::Refused(message)) if message == expected));
}

#[test]
fn exec_sources_select_every_runtime_main_and_interpreter_rx_vma() {
    let mut fixture = Fixture::new(ORIGINAL);
    let rows = fixture.derive().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].start, rows[0].end, rows[0].offset, rows[0].role),
        (0x401000, 0x403000, 0x1000, ImageRole::Executable)
    );
    assert_eq!(
        (rows[1].start, rows[1].end, rows[1].offset, rows[1].role),
        (0x800000, 0x802000, 0, ImageRole::Interpreter)
    );
    assert_eq!(rows[0].file.inode, 100);
    assert_eq!(rows[1].file.inode, 200);
    assert_eq!(fixture.originals.len(), 3); // vDSO remains in full NX inventory.
    assert!(!rows.iter().any(|row| row.start == 0x900000));
    let retained = &fixture.original.as_bytes()
        [rows[0].original_span.0..rows[0].original_span.0 + rows[0].original_span.1];
    assert!(retained.ends_with(b"/objects/main  image"));

    let old = ORIGINAL.replace(
        "00600000-",
        "00500000-00501000 r-xp 00003000 08:01 100 /different descriptive name\n00600000-",
    );
    fixture = Fixture::new(&old);
    let rows = fixture.derive().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1].file, rows[0].file);
    assert_eq!(
        (rows[1].start, rows[1].offset, rows[1].role),
        (0x500000, 0x3000, ImageRole::Executable)
    );
    assert_eq!(rows[2].role, ImageRole::Interpreter);
}

#[test]
fn exec_sources_refuse_omitted_segments_and_exact_whole_vma_bounds() {
    let mut f = Fixture::new(ORIGINAL);
    f.originals.pop();
    refused_exact(
        f.derive(),
        "exec quarantine changed executable descriptor identity",
    );
    let mut f = Fixture::new(ORIGINAL);
    f.executable.inode = 101;
    refused_exact(
        f.derive(),
        "exec main entry is not the actual executable object",
    );
    let mut f = Fixture::new(ORIGINAL);
    f.profile.max_capture_bytes = 4096;
    f.profile.max_total_capture_bytes = 16384;
    refused_exact(
        f.derive(),
        "exec whole source VMA exceeds its declared profile",
    );
    let mut f = Fixture::new(ORIGINAL);
    f.profile.max_capture_images = 1;
    f.profile.max_total_capture_bytes = 8192;
    refused_exact(
        f.derive(),
        "exec whole source VMA exceeds its declared profile",
    );
    let mut f = Fixture::new(ORIGINAL);
    f.profile.max_total_capture_bytes = 12288;
    refused_exact(
        f.derive(),
        "exec whole source VMA exceeds its declared profile",
    );
    let mut f = Fixture::new(ORIGINAL);
    f.entry.first_image = FirstImage::Executable;
    refused_exact(f.derive(), "exec main-only entry facts differ");
    let mut f = Fixture::new(ORIGINAL);
    f.entry.interpreter_base = 0x801000;
    refused_exact(f.derive(), "exec interpreter backing identity differs");
}

#[test]
fn exec_sources_check_uncensused_nx_and_every_unaffected_map() {
    let mut f = Fixture::new(ORIGINAL);
    f.update_final("00900000-00901000 r--p", "00900000-00901000 r-xp");
    refused_exact(
        f.derive(),
        "exec quarantine changed executable descriptor identity",
    );
    let mut f = Fixture::new(ORIGINAL);
    f.update_final("00a00000-00a01000 rw-p", "00a00000-00a01000 r--p");
    refused_exact(f.derive(), "exec quarantine changed an unaffected mapping");
    let mut f = Fixture::new(ORIGINAL);
    f.update_final("00b00000-00b01000 r-xp", "00b00000-00b01000 rwxp");
    refused_exact(f.derive(), "exec source trusted island mapping differs");
    let mut f = Fixture::new(ORIGINAL);
    f.update_final(
        "00b00000-00b01000 r-xp 00000000 00:00 0",
        "00b00000-00b01000 r-xp 00000000 08:01 300 /object",
    );
    refused_exact(f.derive(), "exec source trusted island mapping differs");
    let mut f = Fixture::new(ORIGINAL);
    f.update_final(
        "--xp 00000000 00:00 0 [vsyscall]",
        "r-xp 00000000 00:00 0 [vsyscall]",
    );
    refused_exact(f.derive(), "exec quarantine changed an unaffected mapping");
    let forged = ORIGINAL.replace("ffffffffff600000-ffffffffff601000", "00c00000-00c01000");
    let mut f = Fixture::new(&forged);
    f.final_maps = f
        .final_maps
        .replace("00c00000-", &format!("{ISLAND}00c00000-"));
    f.current = descriptors(f.final_maps.as_bytes());
    refused_exact(
        f.derive(),
        "exec quarantine changed executable descriptor identity",
    );
}

#[test]
fn exec_sources_reject_visible_rw_rx_and_readonly_backing_aliases() {
    for permissions in ["rw-p", "r-xp", "r--p"] {
        let alias =
            format!("00500000-00501000 {permissions} 00001000 08:01 100 /different spelling\n");
        let old = ORIGINAL.replace("00600000-", &format!("{alias}00600000-"));
        let f = Fixture::new(&old);
        refused_exact(f.derive(), "exec source has a visible file-offset alias");
    }
    let old = ORIGINAL.replace(
        "00600000-",
        "00500000-00501000 rw-p 00003000 08:01 100 /nonoverlapping data\n00600000-",
    );
    assert_eq!(Fixture::new(&old).derive().unwrap().len(), 2);
    let old = ORIGINAL.replace(
        "00600000-",
        "00500000-00501000 r--p fffffffffffff000 08:01 100 /overflow\n00600000-",
    );
    refused_exact(
        Fixture::new(&old).derive(),
        "exec alias backing interval overflows",
    );
}

#[test]
fn exec_sources_preserve_raw_path_spacing_and_device_inode_identity() {
    let f = Fixture::new(ORIGINAL);
    let rows = f.derive().unwrap();
    let map = parse(f.final_maps.as_bytes())
        .unwrap()
        .entries()
        .nth(rows[0].current_index)
        .unwrap();
    let projected = descriptor(map, *b"r--p").unwrap();
    assert_eq!(projected.pathname.as_deref(), Some("/objects/main  image"));
    for (from, to) in [
        ("/objects/main  image", "/objects/main image"),
        ("08:01 100", "08:02 100"),
        ("08:01 100", "08:01 101"),
        ("00001000 08:01 100", "00002000 08:01 100"),
    ] {
        let mut changed = Fixture::new(ORIGINAL);
        changed.update_final(from, to);
        assert!(matches!(changed.derive(), Err(GateError::Refused(_))));
    }
    let mut raw = b"00400000-00401000 r--p 00000000 08:01 100 /invalid".to_vec();
    raw.extend_from_slice(&[255, b'\n']);
    let map = parse(&raw).unwrap().entries().next().unwrap();
    refused_exact(
        descriptor(map, map.permissions.bytes()),
        "exec source descriptor is not UTF-8",
    );
}

#[test]
fn exec_sources_refuse_merged_quarantine_and_unreserved_geometry_storage() {
    let mut f = Fixture::new(ORIGINAL);
    f.update_final(
        concat!(
            "00400000-00401000 r--p 00000000 08:01 100 /objects/main  image\n",
            "00401000-00403000 r--p 00001000 08:01 100 /objects/main  image\n"
        ),
        "00400000-00403000 r--p 00000000 08:01 100 /objects/main  image\n",
    );
    refused_exact(f.derive(), "exec source final bootstrap inventory differs");
    let f = Fixture::new(ORIGINAL);
    let geometry = Geometry {
        originals: &f.originals,
        current: &f.current,
        island: &f.island,
        entry: &f.entry,
        executable: f.executable,
        profile: &f.profile,
    };
    let mut missing = Vec::new();
    refused_exact(
        derive_rows(
            parse(f.original.as_bytes()).unwrap(),
            parse(f.final_maps.as_bytes()).unwrap(),
            &geometry,
            &mut missing,
        ),
        "exec source geometry storage differs",
    );
    assert!(missing.is_empty());
    let mut repeated = f.derive().unwrap();
    let retained = repeated.clone();
    refused_exact(
        derive_rows(
            parse(f.original.as_bytes()).unwrap(),
            parse(f.final_maps.as_bytes()).unwrap(),
            &geometry,
            &mut repeated,
        ),
        "exec source geometry storage differs",
    );
    assert_eq!(repeated, retained);
}

#[test]
fn exec_source_image_binding_rejects_short_bytes_stale_ids_and_neighbor_changes() {
    let f = Fixture::new(ORIGINAL);
    let rows = f.derive().unwrap();
    let maps = parse(f.final_maps.as_bytes()).unwrap();
    let row = &rows[0];
    let map = maps.entries().nth(row.current_index).unwrap();
    let request = DynamicSourceRequestId {
        session: 12,
        serial: 9,
    };
    let make = || DynamicSourceImage {
        id: DynamicSourceCaptureId { request, index: 0 },
        mapping_incarnation: 50,
        original: descriptor(map, *b"r-xp").unwrap(),
        quarantined: descriptor(map, *b"r--p").unwrap(),
        bytes: Arc::from(vec![0x90; 8192]),
        lower_neighbor: Some(
            descriptor(maps.entries().nth(row.current_index - 1).unwrap(), *b"r--p").unwrap(),
        ),
        upper_neighbor: None,
    };
    assert!(image_matches(&make(), row, map, maps, request, 0, 50));
    for case in 0..9 {
        let mut image = make();
        match case {
            0 => image.id.request.serial += 1,
            1 => image.id.request.session += 1,
            2 => image.id.index = 1,
            3 => image.mapping_incarnation += 1,
            4 => image.bytes = Arc::from(vec![0x90; 8191]),
            5 => image.original.permissions = "r--p".into(),
            6 => image.quarantined.pathname = Some("/different".into()),
            7 => image.lower_neighbor = None,
            8 => image.lower_neighbor.as_mut().unwrap().permissions = "r-xp".into(),
            _ => unreachable!(),
        }
        assert!(
            !image_matches(&image, row, map, maps, request, 0, 50),
            "binding case {case}"
        );
    }
    assert!(image_matches(&make(), row, map, maps, request, 0, 50));

    // Actual pure registry identities; records below are explicitly synthetic
    // descriptor evidence, never a journal/native authority constructor.
    use crate::lifecycle::{HoldReason, LifecycleRegistry};
    use crate::linux::remote::dynamic::owner::exec_journal::ExecMapsRecord;
    let mut registry = LifecycleRegistry::new(
        crate::lifecycle::Limits {
            tasks: 2,
            processes: 1,
            address_spaces: 2,
            obligations: 8,
        },
        101,
        0x401000,
    )
    .unwrap();
    let old = registry.root_task();
    let old_record = registry.task(old).unwrap();
    let previous = DynamicTask {
        task: old,
        process: old_record.process,
        address_space: old_record.address_space,
        generation: 0,
    };
    registry.resume(old, 0).unwrap();
    registry
        .observe_stop(old, 1, 0x401002, HoldReason::SyscallEntry)
        .unwrap();
    let ticket = registry.prepare_exec(old).unwrap();
    registry.resume(old, 1).unwrap();
    let replaced = registry
        .observe_exec_event(ticket, 2, 101, 101, 0x801000)
        .unwrap();
    let record = registry.task(replaced.task).unwrap();
    let current = DynamicTask {
        task: replaced.task,
        process: record.process,
        address_space: record.address_space,
        generation: 0,
    };
    let exit = DynamicStop {
        session: 12,
        sequence: 1,
        tid: 101,
        task: Some(current.task),
    };
    let final_stop = DynamicStop {
        sequence: 12,
        ..exit.clone()
    };
    let make_record = |bytes: &[u8]| ExecMapsRecord {
        status: ExecMapsStatus::Complete,
        tid: 101,
        raw_status: 0,
        open: None,
        filesystem: None,
        filesystem_type: libc::PROC_SUPER_MAGIC as i64,
        read_calls: 0,
        last_read: None,
        overflow_byte: 0,
        close: None,
        observed_bytes: bytes.len(),
        initialized: bytes.to_vec(),
    };
    let exit_record = make_record(f.original.as_bytes());
    let final_record = make_record(f.final_maps.as_bytes());
    let view = || ExecSourceMaps {
        previous,
        replacement: current,
        exit_ordinal: 2,
        exit_stop: KernelStopIdentity::from(&exit),
        final_stop: KernelStopIdentity::from(&final_stop),
        exit: &exit_record,
        exit_bytes: f.original.as_bytes(),
        quarantine: &final_record,
        quarantine_bytes: f.final_maps.as_bytes(),
    };
    bind_view(&view(), previous, current, &exit, &final_stop).unwrap();
    for case in 0..7 {
        let mut changed = view();
        match case {
            0 => changed.previous = current,
            1 => changed.replacement = previous,
            2 => changed.exit_stop.task = Some(old),
            3 => changed.exit_stop.session += 1,
            4 => changed.final_stop.sequence -= 1,
            5 => changed.final_stop.tid += 1,
            6 => changed.quarantine_bytes = &f.final_maps.as_bytes()[1..],
            _ => unreachable!(),
        }
        refused_exact(
            bind_view(&changed, previous, current, &exit, &final_stop),
            "exec source journal phase or identity differs",
        );
    }
    bind_view(&view(), previous, current, &exit, &final_stop).unwrap();

    // The actual Vec transfer keeps the same allocation. Its original charge
    // remains in the lifetime account; only new immutable payloads add a debit.
    let mut prepared = PreparedExecSources::new(&f.profile).unwrap();
    prepared.rows.push(rows[0]);
    let pointer = prepared.rows.as_ptr();
    let capacity = prepared.rows.capacity();
    let before_transfer = prepared.allocated_bytes().unwrap();
    let moved = std::mem::take(&mut prepared.rows);
    let after_transfer = prepared.allocated_bytes().unwrap();
    assert_eq!(moved.as_ptr(), pointer);
    assert_eq!(moved.capacity(), capacity);
    assert_eq!(
        before_transfer - after_transfer,
        capacity * size_of::<SourceRow>()
    );
    let captured = CapturedExecSources {
        profile: f.profile.clone(),
        attempt: KernelAttemptId {
            session: 12,
            invocation: 1,
        },
        request,
        first_incarnation: 50,
        previous,
        current,
        exit,
        stop: final_stop,
        until: Instant::now(),
        exit_ordinal: 2,
        executable: f.executable,
        rows: moved,
        images: Arc::from(vec![make()]),
    };
    assert_eq!(captured.rows.as_ptr(), pointer);
    let increment = captured.newly_retained_bytes().unwrap();
    assert_eq!(
        captured.retained_bytes().unwrap(),
        size_of::<CapturedExecSources>() + (before_transfer - after_transfer) + increment
    );
    assert!(increment > captured.images[0].bytes.len() + size_of::<DynamicSourceImage>());
    assert_eq!(prepared.allocated_bytes().unwrap(), after_transfer);
}

#[test]
fn exec_source_reservations_and_complete_parser_remain_bounded() {
    let profile = profile();
    let prepared = PreparedExecSources::new(&profile).unwrap();
    assert_eq!(prepared.maps.len(), MAP_BYTES);
    assert!(prepared.maps.iter().all(|byte| *byte == 0));
    assert_eq!(prepared.staging.len(), profile.max_capture_images);
    assert!(
        prepared
            .staging
            .iter()
            .all(|bytes| bytes.is_empty() && bytes.capacity() >= profile.max_capture_bytes)
    );
    assert!(
        prepared.allocated_bytes().unwrap()
            <= PreparedExecSources::reservation_bytes(&profile).unwrap()
    );
    for value in [0, 65, usize::MAX] {
        let mut changed = profile.clone();
        changed.max_capture_images = value;
        refused_exact(
            PreparedExecSources::reservation_bytes(&changed),
            "exec source capture profile differs",
        );
    }
    refused_exact(
        checked_add(usize::MAX, 1),
        "exec source allocation size overflows",
    );
    refused_exact(
        checked_mul(usize::MAX, 2),
        "exec source allocation size overflows",
    );
    refused_exact(
        arc_bytes::<DynamicSourceImage>(usize::MAX),
        "exec source Arc layout overflows",
    );
    let mut malformed = ORIGINAL.as_bytes().to_vec();
    malformed.extend_from_slice(b"broken suffix\n");
    refused_exact(
        parse(&malformed),
        "exec source maps are malformed or excessive",
    );
    refused_exact(
        parse(&vec![b'x'; MAP_BYTES + 1]),
        "exec source maps exceed fixed capture bound",
    );
    let mut too_many = String::new();
    for index in 0..=MAP_ROWS {
        let start = 0x1000 * (index + 1);
        let end = start + 0x1000;
        too_many.push_str(&format!("{start:x}-{end:x} r--p 0 00:00 0\n"));
    }
    refused_exact(
        parse(too_many.as_bytes()),
        "exec source maps are malformed or excessive",
    );
}
