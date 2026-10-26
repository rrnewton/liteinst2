use super::*;
use liteinst_launch::{
    KernelCaptureStatus, KernelFailureKind, KernelJournalFact, KernelJournalStage, KernelStateSlot,
    KernelWriterStatus, MappingCaptureSlot, MappingCaptureStatus,
};
use std::sync::mpsc::{Receiver, SyncSender};

pub struct Provider {
    pub rows: Arc<Vec<raw::Observation>>,
    pub calls: usize,
}
impl InstructionProvider for Provider {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        let expected = &self.rows[self.calls];
        assert_eq!(*input.registers(), expected.before.architecture.registers);
        assert_eq!(
            input.instruction().logical_pc(),
            expected.before.architecture.registers.rip
        );
        assert_eq!(
            input.instruction().bytes(),
            if matches!(expected.kind, Kind::CpuA | Kind::CpuB) {
                &[0x0f, 0xa2][..]
            } else {
                &[0x0f, 0x05][..]
            }
        );
        self.calls += 1;
        Ok(ProviderDecision::Native)
    }
}
pub struct Witness {
    pub pin: OwnedFd,
    pub until: Instant,
}
pub enum Mode {
    Correct,
    Stale,
    Panic,
    Block {
        ready: SyncSender<Witness>,
        release: Receiver<()>,
    },
}
pub struct Resolver {
    fixture: Arc<Fixture>,
    pub calls: usize,
    mode: Mode,
    pub captures: Vec<DynamicSourceCaptureId>,
    pub incarnations: Vec<u64>,
    pub epochs: Vec<(u64, u64)>,
    pub owned: Option<OwnedFd>,
}
impl DynamicSourceResolver for Resolver {
    fn resolve(&mut self, request: &DynamicSourceRequest) -> Result<DynamicSourceFacts, GateError> {
        assert!(self.calls < 2);
        assert_eq!(request.images().len(), 1);
        let image = &request.images()[0];
        let version = self.calls;
        assert_eq!(image.range(), TARGET..TARGET + PAGE as u64);
        assert_eq!(
            image.bytes(),
            if version == 0 {
                &self.fixture.a[..]
            } else {
                &self.fixture.b[..]
            }
        );
        assert_eq!(image.original_mapping().permissions, "r-xp");
        assert_eq!(image.quarantined_mapping().permissions, "r--p");
        assert_eq!(image.original_mapping().file_offset, 0);
        assert_eq!(image.original_mapping().pathname, None);
        assert!(image.lower_neighbor().is_none() && image.upper_neighbor().is_none());
        assert_eq!(request.task().generation, request.previous_epoch());
        assert_eq!(
            request.previous_epoch().checked_add(1),
            Some(request.candidate_epoch())
        );
        assert_eq!(image.id().request(), request.id());
        assert_eq!(image.id().index(), 0);
        if let Some(old) = self.captures.first() {
            assert_ne!(*old, image.id());
            assert_eq!(old.request().session(), request.id().session());
            assert!(request.id().serial() > old.request().serial());
        }
        if let Some(old) = self.incarnations.first() {
            assert_eq!(*old, image.mapping_incarnation());
        }
        assert_ne!(image.mapping_incarnation(), 0);
        self.captures.push(image.id());
        self.incarnations.push(image.mapping_incarnation());
        self.epochs
            .push((request.previous_epoch(), request.candidate_epoch()));
        self.calls += 1;
        match &self.mode {
            Mode::Panic => std::panic::panic_any("intentional mapping source resolver panic"),
            Mode::Block { ready, release } => {
                ready
                    .send(Witness {
                        pin: duplicate(self.owned.as_ref().unwrap()),
                        until: request.expires_at(),
                    })
                    .unwrap();
                // This is a test-harness cleanup observation bound, not a new
                // transaction. The owner must expire at request.expires_at().
                let cleanup_until = request.expires_at() + TIMEOUT;
                let remaining = cleanup_until
                    .checked_duration_since(Instant::now())
                    .unwrap();
                if release.recv_timeout(remaining).is_err() {
                    std::process::abort();
                }
            }
            Mode::Correct | Mode::Stale => {}
        }
        let capture = if matches!(&self.mode, Mode::Stale) && version == 1 {
            self.captures[0]
        } else {
            image.id()
        };
        let heads = if version == 0 {
            self.fixture.a_heads.clone()
        } else {
            self.fixture.b_heads.clone()
        };
        Ok(DynamicSourceFacts {
            images: vec![DynamicSourceHeads { capture, heads }],
        })
    }
}
type Session = DynamicSourceSession<Provider, Resolver>;
pub struct Owned {
    pub session: Option<Session>,
    pub pin: OwnedFd,
    pub pid: i32,
    pub baseline: Maps,
    pub archive: KernelProgressReader,
}
impl Owned {
    pub fn launch(fixture: Arc<Fixture>, rows: Arc<Vec<raw::Observation>>, mode: Mode) -> Self {
        let application = Mask::set(APP_MASK);
        let file_fork = FILE_FORK.lock().unwrap();
        // SAFETY: one owned singleton, complete literal initial and generated
        // heads, private original RW stores, no aliases/code-as-data/signals,
        // untracked contexts or external writers. Only five original mapping
        // syscalls fall inside the explicit isolated target envelope.
        let result = unsafe {
            DynamicAdmissionSession::launch_with_mappings(
                &LaunchCommand::new(&fixture.path),
                fixture.facts(),
                DynamicAdmissionOptions::default(),
                fixture.profile(),
                Provider { rows, calls: 0 },
                Resolver {
                    fixture: Arc::clone(&fixture),
                    calls: 0,
                    mode,
                    captures: Vec::new(),
                    incarnations: Vec::new(),
                    epochs: Vec::new(),
                    owned: None,
                },
                TIMEOUT,
            )
        };
        drop(file_fork);
        drop(application);
        let session = result.unwrap();
        let pid = session.pid();
        let pin = pin(pid);
        let archive = session.kernel_progress();
        let mut owner = Self {
            session: Some(session),
            pin,
            pid,
            baseline: Maps {
                raw: Vec::new(),
                rows: Vec::new(),
            },
            archive,
        };
        let resolver_pin = duplicate(&owner.pin);
        owner.session().source_resolver_mut().owned = Some(resolver_pin);
        owner.baseline = Maps::read(owner.pid, &owner.pin);
        assert!(owner.baseline.target().is_none());
        owner
    }
    pub fn session(&mut self) -> &mut Session {
        self.session.as_mut().unwrap()
    }
    pub fn finish(&mut self) {
        let receipt = match self.session.take().unwrap().terminate(TIMEOUT) {
            Ok(receipt) => receipt,
            Err(_) => std::process::abort(),
        };
        if !gone(&self.pin) {
            std::process::abort();
        }
        assert_eq!(receipt.reaped, [self.pid]);
        reaped(&self.pin);
        assert_eq!(self.archive.snapshot().writer, KernelWriterStatus::Cleaned);
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            if session.terminate(TIMEOUT).is_err() || !gone(&self.pin) {
                std::process::abort();
            }
            reaped(&self.pin);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapKey(
    pub u64,
    pub u64,
    pub String,
    pub u64,
    pub String,
    pub u64,
    pub Option<String>,
);
fn key(map: &Map) -> MapKey {
    MapKey(
        map.start,
        map.end,
        map.permissions.clone(),
        map.offset,
        map.device.clone(),
        map.inode,
        map.path.clone(),
    )
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Expected {
    architecture: Architecture,
    data: Vec<u8>,
    source: Vec<u8>,
    target: Option<Vec<u8>>,
    maps: Vec<MapKey>,
}
fn expected(fixture: &Fixture, row: &raw::Observation, baseline: &Maps) -> Expected {
    let controller = !matches!(row.kind, Kind::CpuA | Kind::CpuB);
    let mut maps = baseline
        .rows
        .iter()
        .filter(|map| !(map.start < BASE + SOURCE_BYTES as u64 && BASE < map.end))
        .map(key)
        .collect::<Vec<_>>();
    let original = baseline
        .rows
        .iter()
        .find(|map| map.start == BASE && map.end == BASE + SOURCE_BYTES as u64)
        .unwrap();
    assert_eq!(original.permissions, "r--p");
    assert_eq!(original.offset, 0);
    assert_eq!(original.path.as_deref(), fixture.path.to_str());
    if controller {
        let mut header = key(original);
        header.1 = BASE + PAGE as u64;
        maps.push(header);
        let mut code = key(original);
        code.0 = BASE + PAGE as u64;
        code.2 = "r-xp".into();
        code.3 = PAGE as u64;
        maps.push(code);
    } else {
        maps.push(key(original));
    }
    let mut target = row.after.target.clone();
    if let Some(original) = row.after.maps.target() {
        let mut map = key(original);
        map.2 = match row.kind {
            Kind::Map | Kind::Write => "rw-p",
            Kind::SealA | Kind::SealB => "r--p",
            Kind::CpuA | Kind::CpuB => "r-xp",
            Kind::Unmap => unreachable!(),
        }
        .into();
        maps.push(map);
    }
    if matches!(row.kind, Kind::CpuA | Kind::CpuB) {
        let offset = if row.kind == Kind::CpuA { 0 } else { 16 };
        let target = target.as_mut().unwrap();
        assert_eq!(target[offset], 0x0f);
        target[offset] = 0xcc;
    }
    maps.sort_by_key(|map| map.0);
    Expected {
        architecture: row.after.architecture.clone(),
        data: row.after.data.clone(),
        source: fixture.armed_source(controller),
        target,
        maps,
    }
}
pub fn matches_complete(actual: &Frame, expected: &Expected) -> bool {
    actual.architecture == expected.architecture
        && actual.data == expected.data
        && actual.source == expected.source
        && actual.target == expected.target
        && actual.maps.rows.iter().map(key).collect::<Vec<_>>() == expected.maps
}
pub fn completion(
    owner: &mut Owned,
    fixture: &Fixture,
    row: &raw::Observation,
) -> (Frame, Expected) {
    let DynamicAdmissionEvent::Completed(done) = owner.session().next_event().unwrap() else {
        panic!("mapping trajectory lacks exact completion")
    };
    assert_eq!(done.selected.execution, SelectedExecution::Native);
    assert_eq!(
        *done.selected.input.registers(),
        row.before.architecture.registers
    );
    assert_eq!(done.selected.before_xstate, row.before.architecture.xstate);
    assert_eq!(done.before_signal_mask, row.before.architecture.mask);
    assert_eq!(done.selected.after, row.after.architecture.registers);
    assert_eq!(done.selected.xstate, row.after.architecture.xstate);
    assert_eq!(done.signal_mask, row.after.architecture.mask);
    assert_eq!(done.before_task.task, done.after_task.task);
    assert_eq!(done.before_task.process, done.after_task.process);
    assert_eq!(
        done.before_task.address_space,
        done.after_task.address_space
    );
    assert_eq!(
        done.before_task.generation.checked_add(1),
        Some(done.after_task.generation)
    );
    let state = owner.session().state(done.after_task.task).unwrap();
    assert_eq!(state.task, done.after_task);
    let maps = Maps::read(owner.pid, &owner.pin);
    let target = if maps.target().is_some() {
        Some(
            owner
                .session()
                .read_memory(done.after_task.task, TARGET, PAGE)
                .unwrap(),
        )
    } else {
        None
    };
    let actual = Frame {
        architecture: Architecture {
            registers: state.registers,
            xstate: state.xstate,
            mask: state.signal_mask,
        },
        data: owner
            .session()
            .read_memory(done.after_task.task, DATA, DATA_BYTES)
            .unwrap(),
        source: owner
            .session()
            .read_memory(done.after_task.task, BASE, SOURCE_BYTES)
            .unwrap(),
        target,
        maps,
    };
    let expected = expected(fixture, row, &owner.baseline);
    assert!(
        matches_complete(&actual, &expected),
        "complete native mapping state/bytes/map geometry differ"
    );
    // All maps outside the known controller/target ranges retain their exact
    // own-lane descriptors, including the actual private island and ASLR maps.
    assert_eq!(actual.maps.outside(), owner.baseline.outside());
    (actual, expected)
}

fn unique_vdso(maps: &Maps) -> &Map {
    let mut found = maps
        .rows
        .iter()
        .filter(|map| map.path.as_deref() == Some("[vdso]"));
    let original = found.next().expect("fixture map table has no vDSO");
    assert!(
        found.next().is_none(),
        "fixture map table has multiple vDSOs"
    );
    original
}

// Change exactly the execute byte in both the parsed descriptor and its actual
// retained line. The rest of the line, including whitespace, stays byte-exact.
fn change_vdso_execute(map: &mut Map, executable: bool) {
    let (old, new) = if executable {
        ("r--p", "r-xp")
    } else {
        ("r-xp", "r--p")
    };
    assert_eq!(map.permissions, old);
    let line = map.line.as_bytes();
    let range_end = line.iter().position(u8::is_ascii_whitespace).unwrap();
    let permissions = range_end
        + line[range_end..]
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap();
    assert_eq!(&line[permissions..permissions + 4], old.as_bytes());
    assert!(line[permissions + 4].is_ascii_whitespace());
    map.permissions.replace_range(2..3, &new[2..3]);
    map.line
        .replace_range(permissions + 2..permissions + 3, &new[2..3]);
}

fn archive_phase_baseline(row: &raw::Observation, baseline: &Maps, phase: usize) -> Maps {
    assert!(phase < 5);
    assert!(baseline.target().is_none());
    let pristine = unique_vdso(&row.before.maps);
    assert_eq!(pristine.permissions, "r-xp");
    assert_eq!(unique_vdso(&row.entry.as_ref().unwrap().maps), pristine);
    assert_eq!(unique_vdso(&row.after.maps), pristine);
    let original = unique_vdso(baseline);
    assert_eq!(original.permissions, "r--p");
    // The independent raw lane establishes the original executable role and
    // backing geometry. ASLR addresses remain distinct: every expected gated
    // address and raw-line byte comes from that lane's own fixed baseline.
    assert_eq!(original.end - original.start, pristine.end - pristine.start);
    assert_eq!(original.offset, pristine.offset);
    assert_eq!(original.device, pristine.device);
    assert_eq!(original.inode, pristine.inode);
    assert_eq!(original.path, pristine.path);
    let raw_lines = |maps: &Maps| {
        maps.rows
            .iter()
            .flat_map(|map| map.line.bytes().chain(std::iter::once(b'\n')))
            .collect::<Vec<_>>()
    };
    assert_eq!(raw_lines(baseline), baseline.raw);
    let mut expected = baseline.clone();
    if matches!(phase, 1..=3) {
        let vdso = expected
            .rows
            .iter_mut()
            .find(|map| map.path.as_deref() == Some("[vdso]"))
            .unwrap();
        change_vdso_execute(vdso, true);
    }
    expected.raw = raw_lines(&expected);
    assert_eq!(expected.raw.len(), baseline.raw.len());
    assert_eq!(
        expected
            .raw
            .iter()
            .zip(&baseline.raw)
            .filter(|(a, b)| a != b)
            .count(),
        usize::from(matches!(phase, 1..=3)),
    );
    expected
}

pub struct ArchiveOutside {
    phase: usize,
    actual: Vec<Map>,
    expected: Vec<Map>,
}

fn archived_maps(
    attempt: &liteinst_launch::KernelAttemptSnapshot,
    row: &raw::Observation,
    baseline: &Maps,
) -> Vec<ArchiveOutside> {
    let capture = attempt
        .mapping
        .as_ref()
        .expect("mapping attempt lost its persistent capture archive");
    assert_eq!(capture.attempt, attempt.id);
    assert!(!capture.archive_poisoned);
    let slots = [
        MappingCaptureSlot::BeforeWindow,
        MappingCaptureSlot::LogicalWindow,
        MappingCaptureSlot::FirstWait,
        MappingCaptureSlot::SecondWait,
        MappingCaptureSlot::Quarantined,
    ];
    assert_eq!(capture.records.len(), slots.len());
    let mut maps = Vec::new();
    let mut phase_baselines = Vec::new();
    let mut outside = Vec::new();
    for (index, (record, slot)) in capture.records.iter().zip(slots).enumerate() {
        assert_eq!(record.slot, slot);
        assert_eq!(record.tid, Some(attempt.original_stop.tid));
        assert_eq!(record.status, MappingCaptureStatus::Complete);
        assert_eq!(
            record.wait_status,
            if index == 2 || index == 3 {
                Some(((libc::SIGTRAP | 0x80) << 8) | 0x7f)
            } else {
                None
            }
        );
        let bytes = record.bytes().unwrap();
        let storage = record.initialized_storage().unwrap();
        assert_eq!(storage.len(), 65536);
        assert_eq!(bytes.len(), record.initialized_len);
        assert!(!bytes.is_empty());
        assert_eq!(bytes, &storage[..record.initialized_len]);
        assert!(
            storage[record.initialized_len..]
                .iter()
                .all(|byte| *byte == 0)
        );
        // This independent fixture parser inspects the actual retained prefix,
        // never production ParsedMaps or an invented zero-filled map table.
        let parsed = Maps::parse(bytes.to_vec());
        let expected_baseline = archive_phase_baseline(row, baseline, index);
        let actual_outside = parsed.outside();
        let expected_outside = expected_baseline.outside();
        assert_eq!(actual_outside, expected_outside);
        outside.push(ArchiveOutside {
            phase: index,
            actual: actual_outside,
            expected: expected_outside,
        });
        phase_baselines.push(expected_baseline);
        maps.push(parsed);
    }
    assert_eq!(
        maps[1], maps[2],
        "original ENTRY changed the logical-window map table"
    );
    let original = baseline
        .rows
        .iter()
        .find(|map| map.start == BASE && map.end == BASE + SOURCE_BYTES as u64)
        .unwrap();
    assert_eq!(original.permissions, "r--p");
    assert_eq!(original.offset, 0);
    for (index, observed) in maps.iter().enumerate() {
        let mut expected = phase_baselines[index]
            .rows
            .iter()
            .filter(|map| !(map.start < BASE + SOURCE_BYTES as u64 && BASE < map.end))
            .map(key)
            .collect::<Vec<_>>();
        if index == 0 {
            let mut header = key(original);
            header.1 = BASE + PAGE as u64;
            expected.push(header);
            let mut code = key(original);
            code.0 = BASE + PAGE as u64;
            code.2 = "r-xp".into();
            code.3 = PAGE as u64;
            expected.push(code);
        } else {
            let mut controller = key(original);
            controller.2 = if index == 4 { "r--p" } else { "r-xp" }.into();
            expected.push(controller);
        }
        let native = if index <= 2 {
            row.before.maps.target()
        } else {
            row.after.maps.target()
        };
        if let Some(native) = native {
            let mut target = key(native);
            if (index == 0 || index == 4) && target.2 == "r-xp" {
                target.2 = "r--p".into();
            }
            expected.push(target);
        }
        expected.sort_by_key(|map| map.0);
        assert_eq!(
            observed.rows.iter().map(key).collect::<Vec<_>>(),
            expected,
            "retained mapping capture {index} differs from exact own-lane window/effect/quarantine geometry"
        );
    }
    outside
}

pub fn archive(
    reader: &KernelProgressReader,
    rows: &[raw::Observation],
    completed: usize,
    baseline: &Maps,
) -> Vec<ArchiveOutside> {
    let snapshot = reader.snapshot();
    assert!(!snapshot.archive_poisoned);
    let pristine = unique_vdso(&rows.first().unwrap().before.maps);
    assert_eq!(pristine.permissions, "r-xp");
    for row in rows {
        assert_eq!(unique_vdso(&row.before.maps), pristine);
        if let Some(entry) = &row.entry {
            assert_eq!(unique_vdso(&entry.maps), pristine);
        }
        assert_eq!(unique_vdso(&row.after.maps), pristine);
    }
    let kernel_rows = rows
        .iter()
        .filter(|row| row.entry.is_some())
        .collect::<Vec<_>>();
    assert_eq!(snapshot.attempts.len(), kernel_rows.len());
    let mut outside = Vec::new();
    for (index, (attempt, row)) in snapshot.attempts.iter().zip(kernel_rows).enumerate() {
        assert_eq!(
            *attempt.input.registers(),
            row.before.architecture.registers
        );
        outside.extend(archived_maps(attempt, row, baseline));
        for (slot, expected) in [
            (KernelStateSlot::Original, &row.before.architecture),
            (
                KernelStateSlot::Entry,
                &row.entry.as_ref().unwrap().architecture,
            ),
            (KernelStateSlot::Exit, &row.after.architecture),
            (KernelStateSlot::ParentBridge, &row.after.architecture),
        ] {
            let matching = attempt
                .states
                .iter()
                .filter(|state| state.slot == slot)
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1);
            assert_eq!(matching[0].status, KernelCaptureStatus::Complete);
            let state = matching[0].state.as_ref().unwrap();
            assert_eq!(state.registers, expected.registers);
            assert_eq!(state.xstate, expected.xstate);
            assert_eq!(state.signal_mask, expected.mask);
        }
        let info = attempt
            .facts
            .iter()
            .filter_map(|fact| {
                if let KernelJournalFact::SyscallInfo { info, .. } = fact {
                    Some((info.returned_bytes, info.initialized))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(info, [row.entry_info.unwrap(), row.exit_info.unwrap()]);
        let raw = attempt
            .facts
            .iter()
            .filter_map(|fact| {
                if let KernelJournalFact::RawStop { record, status, .. } = fact {
                    Some((*record, *status))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            raw,
            [
                (0, ((libc::SIGTRAP | 0x80) << 8) | 0x7f),
                (1, ((libc::SIGTRAP | 0x80) << 8) | 0x7f)
            ]
        );
        assert_eq!(
            attempt
                .facts
                .iter()
                .filter(|fact| matches!(fact, KernelJournalFact::ValidatedEntry { .. }))
                .count(),
            1
        );
        assert_eq!(
            attempt
                .facts
                .iter()
                .filter(|fact| matches!(fact, KernelJournalFact::ValidatedExit { .. }))
                .count(),
            1
        );
        assert_eq!(
            attempt
                .facts
                .iter()
                .filter(|fact| matches!(
                    fact,
                    KernelJournalFact::TransportComplete { newborn: None, .. }
                ))
                .count(),
            1
        );
        assert_eq!(
            attempt
                .facts
                .iter()
                .filter(|fact| matches!(fact, KernelJournalFact::AdmissionComplete { .. }))
                .count(),
            usize::from(index < completed)
        );
        if index < completed {
            assert!(attempt.failure.is_none());
        } else {
            let failure = attempt
                .failure
                .expect("unfinished mapping lost its failure provenance");
            assert_eq!(failure.stage, KernelJournalStage::Transport);
            assert_eq!(failure.kind, KernelFailureKind::Cancelled);
        }
    }
    outside
}

pub struct Observed {
    complete: Vec<(Frame, Expected)>,
    archive_outside: Vec<ArchiveOutside>,
}

pub fn positive(fixture: Arc<Fixture>, rows: Arc<Vec<raw::Observation>>) -> Observed {
    let mut owner = Owned::launch(Arc::clone(&fixture), Arc::clone(&rows), Mode::Correct);
    let mut observed = Vec::new();
    let (mut charged, mut retained) = (0, 0);
    for (index, row) in rows.iter().enumerate() {
        observed.push(completion(&mut owner, &fixture, row));
        let metrics = owner.session().metrics().unwrap();
        assert_eq!(metrics.fetch_faults, [1, 1, 2, 3, 3, 4, 5][index]);
        assert_eq!(metrics.guard_stops, index + 1);
        assert!(
            metrics.charged_source_bytes >= charged && metrics.retained_source_bytes >= retained
        );
        assert!(metrics.retained_source_bytes <= metrics.charged_source_bytes);
        assert!(metrics.charged_source_bytes <= 64 * 1024 * 1024);
        charged = metrics.charged_source_bytes;
        retained = metrics.retained_source_bytes;
    }
    assert_eq!(owner.session().provider().calls, 7);
    assert_eq!(owner.session().source_resolver().calls, 2);
    assert_eq!(owner.session().source_resolver().incarnations.len(), 2);
    let _ = archive(&owner.archive, &rows, 5, &owner.baseline);
    owner.finish();
    let archive_outside = archive(&owner.archive, &rows, 5, &owner.baseline);
    Observed {
        complete: observed,
        archive_outside,
    }
}

pub fn stale(fixture: Arc<Fixture>, rows: Arc<Vec<raw::Observation>>) {
    let mut owner = Owned::launch(Arc::clone(&fixture), Arc::clone(&rows), Mode::Stale);
    for row in &rows[..4] {
        completion(&mut owner, &fixture, row);
    }
    assert!(matches!(
        owner.session().next_event(),
        Err(GateError::Refused("dynamic source reply image set differs"))
    ));
    assert_eq!(owner.session().provider().calls, 5);
    assert_eq!(owner.session().source_resolver().calls, 2);
    assert!(owner.session().is_closed());
    owner.finish();
    let _ = archive(&owner.archive, &rows[..5], 3, &owner.baseline);
}

pub fn panic(fixture: Arc<Fixture>, rows: Arc<Vec<raw::Observation>>) {
    let mut owner = Owned::launch(Arc::clone(&fixture), Arc::clone(&rows), Mode::Panic);
    completion(&mut owner, &fixture, &rows[0]);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.session().next_event()
    }));
    assert_eq!(
        outcome.unwrap_err().downcast_ref::<&str>(),
        Some(&"intentional mapping source resolver panic")
    );
    assert_eq!(owner.session().provider().calls, 2);
    assert_eq!(owner.session().source_resolver().calls, 1);
    assert!(owner.session().is_closed());
    owner.finish();
    let _ = archive(&owner.archive, &rows[..2], 1, &owner.baseline);
}

pub fn timeout(fixture: Arc<Fixture>, rows: Arc<Vec<raw::Observation>>) {
    let (ready, waiting) = std::sync::mpsc::sync_channel(1);
    let (release, held) = std::sync::mpsc::sync_channel(1);
    let (send, finished) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut owner = Owned::launch(
                Arc::clone(&fixture),
                Arc::clone(&rows),
                Mode::Block {
                    ready,
                    release: held,
                },
            );
            completion(&mut owner, &fixture, &rows[0]);
            assert!(matches!(
                owner.session().next_event(),
                Err(GateError::Control(LaunchError::Timeout(
                    "dynamic source acquisition"
                )))
            ));
            assert_eq!(owner.session().provider().calls, 2);
            assert_eq!(owner.session().source_resolver().calls, 1);
            assert!(owner.session().is_closed());
            owner.finish();
            let _ = archive(&owner.archive, &rows[..2], 1, &owner.baseline);
        }));
        let _ = send.send(outcome);
    });
    // Three sequential existing bounds: constructor, mmap, then RX capture.
    let witness = match waiting.recv_timeout(3 * TIMEOUT) {
        Ok(value) => value,
        Err(_) => std::process::abort(),
    };
    let cleanup_until = witness.until + TIMEOUT;
    while !gone(&witness.pin) {
        if Instant::now() >= cleanup_until {
            std::process::abort();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        Instant::now() >= witness.until,
        "owner cleanup happened before the original pending deadline"
    );
    reaped(&witness.pin);
    if release.send(()).is_err() {
        std::process::abort();
    }
    let outcome = match finished.recv_timeout(TIMEOUT) {
        Ok(result) => result,
        Err(_) => std::process::abort(),
    };
    if worker.join().is_err() {
        std::process::abort();
    }
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

pub fn corrupt(observations: &Observed) {
    for (actual, expected) in &observations.complete {
        assert!(matches_complete(actual, expected));
        for corruption in 0..8 {
            let mut bad = actual.clone();
            match corruption {
                0 => bad.architecture.registers.rax ^= 1,
                1 => bad.architecture.registers.eflags ^= 1,
                2 => bad.architecture.registers.orig_rax ^= 1,
                3 => bad.architecture.xstate[0] ^= 1,
                4 => bad.architecture.mask ^= 1,
                5 => bad.data[0] ^= 1,
                6 => bad.source[0] ^= 1,
                7 => bad.maps.rows[0].offset ^= 1,
                _ => unreachable!(),
            }
            assert!(
                !matches_complete(&bad, expected),
                "full comparator accepted corruption {corruption}"
            );
        }
        if actual.target.is_some() {
            let mut bad = actual.clone();
            bad.target.as_mut().unwrap()[0] ^= 1;
            assert!(!matches_complete(&bad, expected));
        }
    }
    // These additional controls use retained actual archive rows after both
    // native lanes have physically cleaned up. No corruption is a new sample.
    assert_eq!(observations.archive_outside.len(), 25);
    for observation in &observations.archive_outside {
        assert_eq!(observation.actual, observation.expected);
        let index = observation
            .actual
            .iter()
            .position(|map| map.path.as_deref() == Some("[vdso]"))
            .unwrap();
        let executable = matches!(observation.phase, 1..=3);
        assert_eq!(
            observation.actual[index].permissions,
            if executable { "r-xp" } else { "r--p" }
        );
        for corruption in 0..8 {
            let mut bad = observation.actual.clone();
            let vdso = &mut bad[index];
            match corruption {
                0 => change_vdso_execute(vdso, !executable),
                1 => vdso.start += PAGE as u64,
                2 => vdso.end += PAGE as u64,
                3 => vdso.offset ^= 1,
                4 => vdso.device.push('0'),
                5 => vdso.inode ^= 1,
                6 => vdso.path = Some("[vdso-corrupt]".into()),
                7 => vdso.line.push(' '),
                _ => unreachable!(),
            }
            assert_ne!(
                bad, observation.expected,
                "archive phase {} accepted vDSO corruption {corruption}",
                observation.phase
            );
        }
    }
}
