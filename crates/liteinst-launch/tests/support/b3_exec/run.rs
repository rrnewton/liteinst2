use super::*;
use std::sync::{
    Mutex,
    mpsc::{Receiver, SyncSender},
};

pub struct Provider {
    fixture: Arc<Fixture>,
    reference: Arc<raw::Transcript>,
    replay: bool,
    pub inputs: Vec<SelectedInput>,
    ready: Arc<Mutex<Option<Architecture>>>,
    owned: Option<(i32, OwnedFd)>,
    old_maps: Arc<Mutex<Option<Maps>>>,
}
impl InstructionProvider for Provider {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        let index = self.inputs.len();
        assert!(index < 4);
        let expected = match index {
            0 => self.reference.old_cpu.before.architecture.registers,
            1 => self.reference.before_exec.architecture.registers,
            2 => self.ready.lock().unwrap().as_ref().unwrap().registers,
            3 => self.reference.final_cpu.before.architecture.registers,
            _ => unreachable!(),
        };
        assert_eq!(*input.registers(), expected);
        assert_eq!(input.instruction().logical_pc(), expected.rip);
        assert_eq!(
            input.instruction().bytes(),
            if index == 1 {
                &[0x0f, 0x05][..]
            } else {
                &[0x0f, 0xa2][..]
            }
        );
        if index == 1 {
            let (pid, pin) = self.owned.as_ref().unwrap();
            let maps = Maps::read(*pid, pin);
            let arguments = held_memory(*pid, pin, INPUT, PAGE);
            compare::arguments(&self.fixture, input.registers(), &maps, &arguments);
            assert_eq!(held_memory(*pid, pin, OLD, CODE), self.fixture.armed(false));
            assert_eq!(
                held_memory(*pid, pin, OLD_DATA, DATA_LEN),
                self.reference.before_exec.data
            );
            assert!(self.old_maps.lock().unwrap().replace(maps).is_none());
        }
        self.inputs.push(input.clone());
        if !self.replay || index == 1 {
            return Ok(ProviderDecision::Native);
        }
        let r = match index {
            0 => self.reference.old_cpu.after.architecture.registers,
            2 => self.reference.first_cpu.after.architecture.registers,
            3 => self.reference.final_cpu.after.architecture.registers,
            _ => unreachable!(),
        };
        Ok(ProviderDecision::Complete(SelectedResult::Cpuid {
            eax: r.rax as u32,
            ebx: r.rbx as u32,
            ecx: r.rcx as u32,
            edx: r.rdx as u32,
        }))
    }
}
pub struct Witness {
    pub pin: OwnedFd,
    pub until: Instant,
    pub reader: ExecProgressReader,
}
pub enum Mode {
    Correct,
    Stale(DynamicSourceCaptureId),
    Panic,
    Block {
        ready: SyncSender<Witness>,
        release: Receiver<()>,
    },
}
pub struct Resolver {
    fixture: Arc<Fixture>,
    reference: Arc<raw::Transcript>,
    mode: Mode,
    owned: Option<(i32, OwnedFd, ExecProgressReader)>,
    ready: Arc<Mutex<Option<Architecture>>>,
    old_maps: Arc<Mutex<Option<Maps>>>,
    previous: Option<liteinst_launch::DynamicTask>,
    pub context: Option<archive::Context>,
    pub reply: Option<DynamicSourceFacts>,
    pub calls: usize,
}
impl DynamicSourceResolver for Resolver {
    fn resolve(&mut self, request: &DynamicSourceRequest) -> Result<DynamicSourceFacts, GateError> {
        assert_eq!(self.calls, 0);
        self.calls += 1;
        let (pid, pin, reader) = self.owned.as_ref().unwrap();
        alive(pin);
        let snapshot = reader.snapshot();
        let a = snapshot.attempt.as_ref().unwrap();
        assert_eq!(request.transition(), DynamicSourceTransition::Exec);
        assert_eq!(request.images().len(), 1);
        assert_eq!(request.previous_task(), a.previous);
        assert_eq!(request.previous_epoch(), a.source_epoch);
        let initial = self.previous.unwrap();
        assert_eq!(
            (
                a.previous.task,
                a.previous.process,
                a.previous.address_space
            ),
            (initial.task, initial.process, initial.address_space)
        );
        assert!(a.previous.generation > initial.generation);
        assert_eq!(request.task(), a.replacement.unwrap());
        assert_eq!(request.candidate_epoch(), 0);
        assert_eq!(request.task().generation, 0);
        assert_eq!(request.kernel_attempt(), a.id);
        assert_eq!(request.expires_at(), a.original_until);
        assert!(Instant::now() < request.expires_at());
        let image = &request.images()[0];
        assert_eq!(image.range(), NEW..NEW + CODE as u64);
        assert_eq!(image.bytes(), self.fixture.new_source);
        for (map, permissions) in [
            (image.original_mapping(), "r-xp"),
            (image.quarantined_mapping(), "r--p"),
        ] {
            assert_eq!(
                (map.start, map.end, map.file_offset),
                (NEW, NEW + CODE as u64, 0)
            );
            assert_eq!(map.permissions, permissions);
            assert_eq!(map.pathname.as_deref(), self.fixture.new_path.to_str());
        }
        assert!(image.lower_neighbor().is_none() && image.upper_neighbor().is_none());
        let current = Maps::read(*pid, pin);
        assert_eq!(current, archive::maps(&a.quarantined_maps));
        let logical = archive::maps(&a.raw[1].maps);
        let stack_map = logical.covering(a.raw[1].registers.rsp, 8).clone();
        let count = usize::try_from(stack_map.end - a.raw[1].registers.rsp).unwrap();
        assert!(count <= 65536);
        let stack = Stack {
            start: a.raw[1].registers.rsp,
            bytes: held_memory(*pid, pin, a.raw[1].registers.rsp, count),
            map: stack_map,
        };
        let source = held_memory(*pid, pin, NEW, CODE);
        let data = held_memory(*pid, pin, NEW_DATA, DATA_LEN);
        assert_eq!(source, image.bytes());
        let actual_file = fs::metadata(&self.fixture.new_path).unwrap();
        let map = logical.covering(NEW, CODE);
        assert_eq!(map.inode, actual_file.ino());
        let (major, minor) = map.device.split_once(':').unwrap();
        assert_eq!(
            u32::from_str_radix(major, 16).unwrap(),
            libc::major(actual_file.dev())
        );
        assert_eq!(
            u32::from_str_radix(minor, 16).unwrap(),
            libc::minor(actual_file.dev())
        );
        let context = archive::Context {
            stack,
            before: DynamicAdmissionState {
                task: a.previous,
                registers: a.before.registers,
                xstate: a.before.xstate.clone(),
                signal_mask: a.before.signal_mask,
            },
            tid: *pid,
            request: request.id(),
            capture: image.id(),
            incarnation: image.mapping_incarnation(),
            journal_bytes: snapshot.allocated_bytes,
            attempt: request.kernel_attempt(),
            until: request.expires_at(),
            candidate: request.task(),
            source,
            data,
            current,
            old_maps: self.old_maps.lock().unwrap().as_ref().unwrap().clone(),
        };
        let expected = archive::check(
            &self.fixture,
            &self.reference,
            &snapshot,
            &context,
            false,
            false,
        );
        assert!(self.ready.lock().unwrap().replace(expected).is_none());
        self.context = Some(context);
        match &self.mode {
            Mode::Panic => std::panic::panic_any("intentional exec source resolver panic"),
            Mode::Block { ready, release } => {
                ready
                    .send(Witness {
                        pin: duplicate(pin),
                        until: request.expires_at(),
                        reader: reader.clone(),
                    })
                    .unwrap();
                let remaining = (request.expires_at() + TIMEOUT)
                    .checked_duration_since(Instant::now())
                    .unwrap();
                if release.recv_timeout(remaining).is_err() {
                    std::process::abort();
                }
            }
            Mode::Correct | Mode::Stale(_) => {}
        }
        let capture = match self.mode {
            Mode::Stale(capture) => {
                assert_ne!(capture.request().session(), request.id().session());
                capture
            }
            _ => image.id(),
        };
        let facts = DynamicSourceFacts {
            images: vec![DynamicSourceHeads {
                capture,
                heads: self.fixture.new_heads.clone(),
            }],
        };
        if !matches!(self.mode, Mode::Stale(_)) {
            assert!(facts_match(&self.fixture, image.id(), &facts));
        }
        assert!(self.reply.replace(facts.clone()).is_none());
        Ok(facts)
    }
}
fn facts_match(f: &Fixture, capture: DynamicSourceCaptureId, facts: &DynamicSourceFacts) -> bool {
    facts.images
        == [DynamicSourceHeads {
            capture,
            heads: f.new_heads.clone(),
        }]
}
type Session = DynamicSourceSession<Provider, Resolver>;
pub struct Owned {
    session: Option<Session>,
    pin: OwnedFd,
    pid: i32,
    reader: ExecProgressReader,
    baseline: Maps,
}
impl Owned {
    pub fn launch(
        f: Arc<Fixture>,
        reference: Arc<raw::Transcript>,
        mode: Mode,
        replay: bool,
    ) -> Self {
        let ready = Arc::new(Mutex::new(None));
        let old_maps = Arc::new(Mutex::new(None));
        let mask = Mask::set(APP_MASK);
        let lock = FILE_FORK.read().unwrap();
        // SAFETY: owned immutable literal sources and read-only argument page,
        // complete heads (including the genuine CALL return), singleton default
        // lifecycle, no writers/aliases/signals/untracked contexts/reapers.
        let result = unsafe {
            DynamicAdmissionSession::launch_with_exec(
                &LaunchCommand::new(&f.old_path),
                f.facts(),
                f.options(),
                f.profile(),
                Provider {
                    fixture: Arc::clone(&f),
                    reference: Arc::clone(&reference),
                    replay,
                    inputs: Vec::new(),
                    ready: Arc::clone(&ready),
                    owned: None,
                    old_maps: Arc::clone(&old_maps),
                },
                Resolver {
                    fixture: f,
                    reference,
                    mode,
                    owned: None,
                    ready,
                    old_maps,
                    previous: None,
                    context: None,
                    reply: None,
                    calls: 0,
                },
                TIMEOUT,
            )
        };
        drop(lock);
        drop(mask);
        let session = result.unwrap();
        let pid = session.pid();
        // pin() aborts the entire supervised command on failure, so successful
        // launch cannot unwind before a cleanup-owning wrapper exists.
        let pin = pin(pid);
        let reader = match session.exec_progress() {
            Some(value) => value,
            None => {
                let _ = session.terminate(TIMEOUT);
                std::process::abort();
            }
        };
        let mut owned = Self {
            session: Some(session),
            pin,
            pid,
            reader,
            baseline: Maps {
                raw: Vec::new(),
                rows: Vec::new(),
            },
        };
        let resolver_pin = duplicate(&owned.pin);
        let provider_pin = duplicate(&owned.pin);
        let progress = owned.reader.clone();
        let initial = owned.session().initial_state().task;
        owned.session().source_resolver_mut().previous = Some(initial);
        owned.session().provider_mut().owned = Some((pid, provider_pin));
        owned.session().source_resolver_mut().owned = Some((pid, resolver_pin, progress));
        owned.baseline = Maps::read(pid, &owned.pin);
        owned
    }
    pub fn session(&mut self) -> &mut Session {
        self.session.as_mut().unwrap()
    }
    pub fn finish(&mut self) {
        let receipt = match self.session.take().unwrap().terminate(TIMEOUT) {
            Ok(v) => v,
            Err(_) => std::process::abort(),
        };
        if !gone(&self.pin) {
            std::process::abort();
        }
        assert_eq!(receipt.reaped, [self.pid]);
        reaped(&self.pin);
        assert_eq!(self.reader.snapshot().cleanup_complete, Some(true));
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
#[derive(Clone, Debug)]
pub struct Compared {
    pub actual: Architecture,
    pub expected: Architecture,
    pub data: Vec<u8>,
    pub expected_data: Vec<u8>,
    pub source: Vec<u8>,
    pub expected_source: Vec<u8>,
    pub maps: Maps,
    pub expected_maps: Vec<Map>,
}
impl Compared {
    pub fn matches(&self) -> bool {
        self.actual == self.expected
            && self.data == self.expected_data
            && self.source == self.expected_source
            && self.maps.rows == self.expected_maps
    }
}
fn completion(
    owner: &mut Owned,
    f: &Fixture,
    before: &Architecture,
    after: &Architecture,
    expected_data: &[u8],
    new: bool,
    replay: bool,
) -> Compared {
    let DynamicAdmissionEvent::Completed(done) = owner.session().next_event().unwrap() else {
        panic!("original CPU did not produce its exact completion")
    };
    assert_eq!(
        done.selected.execution,
        if replay {
            SelectedExecution::Scripted
        } else {
            SelectedExecution::Native
        }
    );
    assert_eq!(*done.selected.input.registers(), before.registers);
    assert_eq!(done.selected.before_xstate, before.xstate);
    assert_eq!(done.before_signal_mask, before.mask);
    assert_eq!(done.selected.after, after.registers);
    assert_eq!(done.selected.xstate, after.xstate);
    assert_eq!(done.signal_mask, after.mask);
    assert_eq!(
        (
            done.before_task.task,
            done.before_task.process,
            done.before_task.address_space
        ),
        (
            done.after_task.task,
            done.after_task.process,
            done.after_task.address_space
        )
    );
    assert_eq!(
        done.before_task.generation.checked_add(1),
        Some(done.after_task.generation)
    );
    let state = owner.session().state(done.after_task.task).unwrap();
    assert_eq!(state.task, done.after_task);
    let (base, data) = if new {
        (NEW, NEW_DATA)
    } else {
        (OLD, OLD_DATA)
    };
    let actual = Architecture::admitted(&state);
    let source = owner
        .session()
        .read_memory(done.after_task.task, base, CODE)
        .unwrap();
    let data = owner
        .session()
        .read_memory(done.after_task.task, data, DATA_LEN)
        .unwrap();
    let maps = Maps::read(owner.pid, &owner.pin);
    if new {
        let stack = owner
            .session()
            .source_resolver()
            .context
            .as_ref()
            .unwrap()
            .stack
            .clone();
        assert_eq!(
            held_memory(owner.pid, &owner.pin, stack.start, stack.bytes.len()),
            stack.bytes
        );
    }
    let baseline = if new {
        owner
            .session()
            .source_resolver()
            .context
            .as_ref()
            .unwrap()
            .current
            .clone()
    } else {
        owner.baseline.clone()
    };
    let mut expected_maps = baseline.rows;
    // Only the selected source's second page is rearmed; the first header page
    // remains NX. A split descriptor is expected, with exact file offset/path.
    let index = expected_maps
        .iter()
        .position(|m| m.start == base && m.end == base + CODE as u64)
        .unwrap();
    let full = expected_maps.remove(index);
    assert_eq!(full.permissions, "r--p");
    // Kernel textual maps formatting for a split cannot be copied from the
    // other process. Bind all semantic fields and validate each raw line below.
    let observed = maps
        .rows
        .iter()
        .filter(|m| m.start < base + CODE as u64 && base < m.end)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(observed.len(), 2);
    for (i, map) in observed.iter().enumerate() {
        assert_eq!(
            (map.start, map.end, map.offset),
            (
                base + i as u64 * PAGE as u64,
                base + (i + 1) as u64 * PAGE as u64,
                i as u64 * PAGE as u64
            )
        );
        assert_eq!(map.permissions, if i == 0 { "r--p" } else { "r-xp" });
        assert_eq!(
            (&map.device, map.inode, &map.path),
            (&full.device, full.inode, &full.path)
        );
    }
    expected_maps.extend(observed);
    expected_maps.sort_by_key(|m| m.start);
    let result = Compared {
        actual,
        expected: after.clone(),
        data,
        expected_data: expected_data.to_vec(),
        source,
        expected_source: f.armed(new),
        maps,
        expected_maps,
    };
    assert!(
        result.matches(),
        "complete CPU architecture/source/memory/maps differ"
    );
    result
}
#[derive(Clone, Debug)]
pub struct Observed {
    pub comparisons: Vec<Compared>,
    pub snapshot: ExecProgressSnapshot,
    pub context: archive::Context,
    pub reply: DynamicSourceFacts,
    pub reference: Arc<raw::Transcript>,
    pub fixture: Arc<Fixture>,
}
fn lane(f: Arc<Fixture>, reference: Arc<raw::Transcript>, replay: bool) -> Observed {
    let mut owner = Owned::launch(
        Arc::clone(&f),
        Arc::clone(&reference),
        Mode::Correct,
        replay,
    );
    let mut comparisons = vec![completion(
        &mut owner,
        &f,
        &reference.old_cpu.before.architecture,
        &reference.old_cpu.after.architecture,
        &reference.old_cpu.after.data,
        false,
        replay,
    )];
    let old = owner.session().metrics().unwrap();
    assert!(old.retained_call_obligations >= 1);
    assert_eq!(old.oldest_call_generation, Some(0));
    let DynamicAdmissionEvent::ImageReplaced(replaced) = owner.session().next_event().unwrap()
    else {
        panic!("original exec was not a distinct image replacement")
    };
    let context = owner
        .session()
        .source_resolver()
        .context
        .as_ref()
        .unwrap()
        .clone();
    let snapshot = owner.reader.snapshot();
    let ready = archive::check(&f, &reference, &snapshot, &context, true, false);
    assert_eq!(replaced.before, context.before);
    assert_eq!(replaced.attempt, snapshot.attempt.as_ref().unwrap().id);
    assert_eq!(replaced.input, owner.session().provider().inputs[1]);
    assert_eq!(replaced.ready.task, context.candidate);
    assert_eq!(Architecture::admitted(&replaced.ready), ready);
    let state = owner.session().state(replaced.ready.task.task).unwrap();
    assert_eq!(state, replaced.ready);
    assert_eq!(
        owner
            .session()
            .read_memory(state.task.task, NEW, CODE)
            .unwrap(),
        f.new_source
    );
    assert_eq!(
        owner
            .session()
            .read_memory(state.task.task, NEW_DATA, DATA_LEN)
            .unwrap(),
        f.new_data
    );
    assert_eq!(Maps::read(owner.pid, &owner.pin), context.current);
    assert_eq!(
        held_memory(
            owner.pid,
            &owner.pin,
            context.stack.start,
            context.stack.bytes.len()
        ),
        context.stack.bytes
    );
    let reply = owner
        .session()
        .source_resolver()
        .reply
        .as_ref()
        .unwrap()
        .clone();
    assert!(facts_match(&f, context.capture, &reply));
    let committed = owner.session().metrics().unwrap();
    assert!(
        committed.charged_source_bytes >= old.charged_source_bytes
            && committed.retained_source_bytes >= old.retained_source_bytes
    );
    assert!(
        committed.retained_source_bytes <= committed.charged_source_bytes
            && committed.charged_source_bytes <= 64 * 1024 * 1024
    );
    let after = cpu_expected(&ready, &reference.first_cpu.after.architecture);
    comparisons.push(completion(
        &mut owner,
        &f,
        &ready,
        &after,
        &f.new_data,
        true,
        replay,
    ));
    comparisons.push(completion(
        &mut owner,
        &f,
        &reference.final_cpu.before.architecture,
        &reference.final_cpu.after.architecture,
        &reference.final_cpu.after.data,
        true,
        replay,
    ));
    assert_eq!(owner.session().provider().inputs.len(), 4);
    assert_eq!(owner.session().source_resolver().calls, 1);
    let metrics = owner.session().metrics().unwrap();
    assert!(
        metrics.charged_source_bytes >= committed.charged_source_bytes
            && metrics.retained_source_bytes >= committed.retained_source_bytes
    );
    assert!(
        metrics.retained_source_bytes <= metrics.charged_source_bytes
            && metrics.charged_source_bytes <= 64 * 1024 * 1024
    );
    // Complete retired-history equality is covered only by the separate private
    // connected control, not inferred from these public monotone counters.
    owner.finish();
    let snapshot = owner.reader.snapshot();
    archive::check(&f, &reference, &snapshot, &context, true, true);
    Observed {
        comparisons,
        snapshot,
        context,
        reply,
        reference,
        fixture: f,
    }
}
fn cpu_expected(before: &Architecture, raw_after: &Architecture) -> Architecture {
    let mut after = before.clone();
    let r = &mut after.registers;
    [r.rax, r.rbx, r.rcx, r.rdx] = compare::outputs(raw_after.registers);
    r.rip += 2;
    compare::cpu(before, &after);
    after
}
pub fn positive(f: Arc<Fixture>, reference: Arc<raw::Transcript>) -> Vec<Observed> {
    vec![
        lane(Arc::clone(&f), Arc::clone(&reference), true),
        lane(f, reference, false),
    ]
}
fn old_cpu(owner: &mut Owned, f: &Fixture, reference: &raw::Transcript) {
    completion(
        owner,
        f,
        &reference.old_cpu.before.architecture,
        &reference.old_cpu.after.architecture,
        &reference.old_cpu.after.data,
        false,
        false,
    );
}
fn failed(owner: &mut Owned, f: &Fixture, reference: &raw::Transcript) {
    assert_eq!(owner.session().provider().inputs.len(), 2);
    assert_eq!(owner.session().source_resolver().calls, 1);
    assert!(owner.session().is_closed());
    let context = owner
        .session()
        .source_resolver()
        .context
        .as_ref()
        .unwrap()
        .clone();
    owner.finish();
    archive::check(
        f,
        reference,
        &owner.reader.snapshot(),
        &context,
        false,
        true,
    );
}
pub fn stale(f: Arc<Fixture>, reference: Arc<raw::Transcript>) {
    let donor = lane(Arc::clone(&f), Arc::clone(&reference), false);
    let id = donor.context.capture;
    let mut owner = Owned::launch(
        Arc::clone(&f),
        Arc::clone(&reference),
        Mode::Stale(id),
        false,
    );
    old_cpu(&mut owner, &f, &reference);
    assert!(matches!(
        owner.session().next_event(),
        Err(GateError::Refused("dynamic source reply image set differs"))
    ));
    failed(&mut owner, &f, &reference);
}
pub fn panic(f: Arc<Fixture>, reference: Arc<raw::Transcript>) {
    let mut owner = Owned::launch(Arc::clone(&f), Arc::clone(&reference), Mode::Panic, false);
    old_cpu(&mut owner, &f, &reference);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.session().next_event()
    }));
    assert_eq!(
        outcome.unwrap_err().downcast_ref::<&str>(),
        Some(&"intentional exec source resolver panic")
    );
    failed(&mut owner, &f, &reference);
}
pub fn timeout(f: Arc<Fixture>, reference: Arc<raw::Transcript>) {
    let (ready, waiting) = std::sync::mpsc::sync_channel(1);
    let (release, held) = std::sync::mpsc::sync_channel(1);
    let (send, finished) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut owner = Owned::launch(
                Arc::clone(&f),
                Arc::clone(&reference),
                Mode::Block {
                    ready,
                    release: held,
                },
                false,
            );
            old_cpu(&mut owner, &f, &reference);
            assert!(matches!(
                owner.session().next_event(),
                Err(GateError::Control(LaunchError::Timeout(
                    "dynamic source acquisition"
                )))
            ));
            failed(&mut owner, &f, &reference);
        }));
        let _ = send.send(outcome);
    });
    let witness = match waiting.recv_timeout(3 * TIMEOUT) {
        Ok(v) => v,
        Err(_) => std::process::abort(),
    };
    let cleanup_until = witness.until + TIMEOUT;
    while !gone(&witness.pin) || witness.reader.snapshot().cleanup_complete != Some(true) {
        if Instant::now() >= cleanup_until
            || witness.reader.snapshot().cleanup_complete == Some(false)
        {
            std::process::abort();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        Instant::now() >= witness.until,
        "owner cleaned before the unchanged source deadline"
    );
    reaped(&witness.pin);
    assert_eq!(witness.reader.snapshot().cleanup_complete, Some(true));
    if release.send(()).is_err() {
        std::process::abort();
    }
    let result = match finished.recv_timeout(TIMEOUT) {
        Ok(v) => v,
        Err(_) => std::process::abort(),
    };
    if worker.join().is_err() {
        std::process::abort();
    }
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn rejected(action: impl FnOnce()) {
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)).is_err(),
        "native oracle comparator accepted corruption"
    );
}
pub fn corrupt(observed: &[Observed]) {
    assert_eq!(observed.len(), 2);
    for lane in observed {
        let other = &observed[usize::from(lane.context.request == observed[0].context.request)];
        assert_ne!(other.context.request, lane.context.request);
        assert_ne!(
            other.context.before.task.task,
            lane.context.before.task.task
        );
        assert_ne!(
            other.context.before.task.process,
            lane.context.before.task.process
        );
        assert_ne!(
            other.context.before.task.address_space,
            lane.context.before.task.address_space
        );
        assert_ne!(other.context.candidate.task, lane.context.candidate.task);
        assert_ne!(
            other.context.candidate.address_space,
            lane.context.candidate.address_space
        );
        for compared in &lane.comparisons {
            assert!(compared.matches());
            for index in 0..27 {
                let mut bad = compared.clone();
                flip_register(&mut bad.actual.registers, index);
                assert!(!bad.matches());
            }
            for bit in 0..64 {
                let mut bad = compared.clone();
                bad.actual.mask ^= 1_u64 << bit;
                assert!(!bad.matches());
            }
            for index in 0..compared.actual.xstate.len() {
                let mut bad = compared.clone();
                bad.actual.xstate[index] ^= 1;
                assert!(!bad.matches());
            }
            for longer in [false, true] {
                let mut bad = compared.clone();
                if longer {
                    bad.actual.xstate.push(0);
                } else {
                    bad.actual.xstate.pop();
                }
                assert!(!bad.matches());
            }
            for index in [0, compared.source.len() - 1] {
                let mut bad = compared.clone();
                bad.source[index] ^= 1;
                assert!(!bad.matches());
            }
            for index in [
                0,
                compared.data.len() - 1,
                (sp(OLD_DATA) - 8 - OLD_DATA) as usize,
            ] {
                let mut bad = compared.clone();
                bad.data[index] ^= 1;
                assert!(!bad.matches());
            }
            for column in 0..8 {
                let mut bad = compared.clone();
                let row = &mut bad.maps.rows[0];
                match column {
                    0 => row.start += PAGE as u64,
                    1 => row.end += PAGE as u64,
                    2 => row.permissions = "rwxp".into(),
                    3 => row.offset ^= 1,
                    4 => row.device.push('0'),
                    5 => row.inode ^= 1,
                    6 => row.path = Some("/wrong-object".into()),
                    7 => row.line.push(' '),
                    _ => unreachable!(),
                };
                assert!(!bad.matches());
            }
            // Each permission character is changed independently on every
            // actual row, retaining a syntactically valid private/shared field.
            for row in 0..compared.maps.rows.len() {
                for column in 0..4 {
                    let mut bad = compared.clone();
                    bad.maps = permission_changed(&compared.maps, row, column);
                    assert!(!bad.matches());
                }
            }
        }
        let check = |snapshot: &ExecProgressSnapshot, context: &archive::Context| {
            archive::check(
                &lane.fixture,
                &lane.reference,
                snapshot,
                context,
                true,
                true,
            );
        };
        check(&lane.snapshot, &lane.context);
        for case in 0..64 {
            let mut snapshot = lane.snapshot.clone();
            let mut context = lane.context.clone();
            match case {
                0 => snapshot.session ^= 1,
                1 => snapshot.archive_poisoned = true,
                2 => snapshot.cleanup_complete = Some(false),
                3 => {
                    snapshot.first_failure =
                        Some((ExecJournalStage::Sources, KernelFailureKind::Cancelled))
                }
                4 => snapshot.attempt.as_mut().unwrap().raw[0].status ^= 0x100,
                5 => snapshot.attempt.as_mut().unwrap().raw[0].syscall_info[0] = 2,
                6 => {
                    snapshot.attempt.as_mut().unwrap().raw[0]
                        .syscall_read
                        .as_mut()
                        .unwrap()
                        .result = 79
                }
                7 => snapshot.attempt.as_mut().unwrap().raw[1].event_message ^= 1,
                8 => snapshot.attempt.as_mut().unwrap().raw[2].syscall_info[32] = 1,
                9 => snapshot.attempt.as_mut().unwrap().raw[2].syscall_info[24] = 1,
                10 => snapshot.attempt.as_mut().unwrap().raw[3].siginfo[8] ^= 1,
                11 => snapshot.attempt.as_mut().unwrap().raw[3].ordinal = 2,
                12 => snapshot.attempt.as_mut().unwrap().raw[1].registers.rsp ^= 8,
                13 => snapshot.attempt.as_mut().unwrap().raw[3].registers.orig_rax = 59,
                14 => snapshot.attempt.as_mut().unwrap().raw[3].initialized_xstate[160] ^= 1,
                15 => {
                    snapshot.attempt.as_mut().unwrap().raw[0]
                        .xstate_query
                        .as_mut()
                        .unwrap()
                        .pointer_unchanged = false
                }
                16 => snapshot.attempt.as_mut().unwrap().raw[0].mask_read = None,
                17 => snapshot.attempt.as_mut().unwrap().raw[2].maps.initialized[0] ^= 1,
                18 => {
                    snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .quarantined_maps
                        .observed_bytes -= 1
                }
                19 => {
                    snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .input
                        .initialized_instruction[0] ^= 1
                }
                20 => snapshot.attempt.as_mut().unwrap().input.arguments[0] ^= 1,
                21 => snapshot.attempt.as_mut().unwrap().previous.generation += 1,
                22 => {
                    snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .replacement
                        .as_mut()
                        .unwrap()
                        .generation = 1
                }
                23 => {
                    snapshot.attempt.as_mut().unwrap().pending_stop.task =
                        Some(context.candidate.task)
                }
                24 => snapshot.attempt.as_mut().unwrap().facts.swap(6, 7),
                25 => {
                    let a = snapshot.attempt.as_mut().unwrap();
                    let fact = a
                        .facts
                        .iter_mut()
                        .find(|f| {
                            matches!(
                                f,
                                ExecJournalFact::Validated {
                                    phase: ExecValidatedPhase::Replaced,
                                    ..
                                }
                            )
                        })
                        .unwrap();
                    if let ExecJournalFact::Validated { stop, .. } = fact {
                        stop.sequence = 1;
                    }
                }
                26 => {
                    let a = snapshot.attempt.as_mut().unwrap();
                    let fact = a
                        .facts
                        .iter_mut()
                        .find(|f| {
                            matches!(
                                f,
                                ExecJournalFact::Validated {
                                    phase: ExecValidatedPhase::Exit,
                                    ..
                                }
                            )
                        })
                        .unwrap();
                    if let ExecJournalFact::Validated { stop, .. } = fact {
                        stop.sequence = 0;
                    }
                }
                27 => {
                    let a = snapshot.attempt.as_mut().unwrap();
                    let fact = a
                        .facts
                        .iter_mut()
                        .find(|f| matches!(f, ExecJournalFact::SourcesRequested { .. }))
                        .unwrap();
                    if let ExecJournalFact::SourcesRequested { request, .. } = fact {
                        *request += 1;
                    }
                }
                28 => snapshot
                    .attempt
                    .as_mut()
                    .unwrap()
                    .facts
                    .pop()
                    .map(|_| ())
                    .unwrap(),
                29 => snapshot.attempt.as_mut().unwrap().original_until += Duration::from_nanos(1),
                30 => context.stack.start += 8,
                31 => context.stack.bytes[0] ^= 1,
                32 => context.stack.bytes[8] ^= 1,
                33 => context.stack.bytes[24] = 1,
                34 => context.stack.bytes[48] = 1,
                35 => {
                    // The first auxv value can be randomized AT_SYSINFO_EHDR.
                    // Corrupt the independently checked literal AT_ENTRY value.
                    let mut offset = 56;
                    loop {
                        assert!(offset < 56 + 64 * 16 && offset + 16 <= context.stack.bytes.len());
                        let key = u64::from_le_bytes(
                            context.stack.bytes[offset..offset + 8].try_into().unwrap(),
                        );
                        assert_ne!(key, 0, "actual stack did not contain required AT_ENTRY");
                        if key == 9 {
                            context.stack.bytes[offset + 8] ^= 1;
                            break;
                        }
                        offset += 16;
                    }
                }
                36 => snapshot.stage = ExecJournalStage::Sources,
                37 => snapshot.allocated_bytes += 1,
                38 => {
                    snapshot.attempt.as_mut().unwrap().previous.task =
                        other.context.before.task.task
                }
                39 => {
                    snapshot.attempt.as_mut().unwrap().previous.process =
                        other.context.before.task.process
                }
                40 => {
                    snapshot.attempt.as_mut().unwrap().previous.address_space =
                        other.context.before.task.address_space
                }
                41 => {
                    snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .replacement
                        .as_mut()
                        .unwrap()
                        .task = other.context.candidate.task
                }
                42 => {
                    snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .replacement
                        .as_mut()
                        .unwrap()
                        .process = other.context.candidate.process
                }
                43 => {
                    snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .replacement
                        .as_mut()
                        .unwrap()
                        .address_space = other.context.candidate.address_space
                }
                44 => {
                    let fact = snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .facts
                        .iter_mut()
                        .find(|fact| {
                            matches!(
                                fact,
                                ExecJournalFact::Validated {
                                    phase: ExecValidatedPhase::Entry,
                                    ..
                                }
                            )
                        })
                        .unwrap();
                    if let ExecJournalFact::Validated { identity, .. } = fact {
                        identity.task = other.context.before.task.task;
                    }
                }
                45 => {
                    let fact = snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .facts
                        .iter_mut()
                        .find(|fact| {
                            matches!(
                                fact,
                                ExecJournalFact::Validated {
                                    phase: ExecValidatedPhase::Replaced,
                                    ..
                                }
                            )
                        })
                        .unwrap();
                    if let ExecJournalFact::Validated { identity, .. } = fact {
                        identity.process = other.context.candidate.process;
                    }
                }
                46 => {
                    let fact = snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .facts
                        .iter_mut()
                        .find(|fact| {
                            matches!(
                                fact,
                                ExecJournalFact::Validated {
                                    phase: ExecValidatedPhase::Exit,
                                    ..
                                }
                            )
                        })
                        .unwrap();
                    if let ExecJournalFact::Validated { identity, .. } = fact {
                        identity.address_space = other.context.candidate.address_space;
                    }
                }
                47 => {
                    snapshot.attempt.as_mut().unwrap().pending_stop.session =
                        other.context.request.session()
                }
                48 => change_result(
                    snapshot.attempt.as_mut().unwrap(),
                    ExecBootstrapEffect::MapIsland,
                    |value| value ^ PAGE as u64,
                ),
                49 => change_result(
                    snapshot.attempt.as_mut().unwrap(),
                    ExecBootstrapEffect::QueryMembarrier,
                    |value| value & !(1 << 5),
                ),
                50 => change_result(
                    snapshot.attempt.as_mut().unwrap(),
                    ExecBootstrapEffect::QueryMembarrier,
                    |value| value & !(1 << 6),
                ),
                51 => {
                    let fact = snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .facts
                        .iter_mut()
                        .find(|fact| matches!(fact, ExecJournalFact::SourcesAccepted { .. }))
                        .unwrap();
                    if let ExecJournalFact::SourcesAccepted { heads, .. } = fact {
                        *heads += 1;
                    }
                }
                52 => {
                    let fact = snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .facts
                        .iter_mut()
                        .find(|fact| matches!(fact, ExecJournalFact::SourcesRequested { .. }))
                        .unwrap();
                    if let ExecJournalFact::SourcesRequested { images, .. } = fact {
                        *images += 1;
                    }
                }
                53 => {
                    let fact = snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .facts
                        .iter_mut()
                        .find(|fact| matches!(fact, ExecJournalFact::SourcesRequested { .. }))
                        .unwrap();
                    if let ExecJournalFact::SourcesRequested { bytes, .. } = fact {
                        *bytes += 1;
                    }
                }
                54 => {
                    let fact = snapshot
                        .attempt
                        .as_mut()
                        .unwrap()
                        .facts
                        .iter_mut()
                        .find(|fact| {
                            matches!(fact, ExecJournalFact::QuarantinedMapsComplete { .. })
                        })
                        .unwrap();
                    if let ExecJournalFact::QuarantinedMapsComplete { stop } = fact {
                        stop.sequence += 1;
                    }
                }
                55 => snapshot.attempt.as_mut().unwrap().raw[1].ordinal = 0,
                56 => snapshot.attempt.as_mut().unwrap().raw[3]
                    .initialized_xstate
                    .push(0),
                57 => context.incarnation = 0,
                58 => snapshot.attempt.as_mut().unwrap().id.invocation += 1,
                59 => snapshot.attempt.as_mut().unwrap().input.logical_pc ^= 1,
                60 => snapshot.attempt.as_mut().unwrap().input.next_pc ^= 1,
                61 => snapshot.attempt.as_mut().unwrap().input.instruction_bytes = 3,
                62 => context.stack.bytes[32] ^= 1,
                63 => snapshot.attempt.as_mut().unwrap().source_epoch ^= 1,
                _ => unreachable!(),
            }
            rejected(|| check(&snapshot, &context));
        }
        // Five complete captured tables: original ENTRY, EXEC, EXIT, first
        // user and final quarantine. Mutating one permission never drops a row.
        for table in 0..5 {
            let original = if table == 4 {
                &lane.snapshot.attempt.as_ref().unwrap().quarantined_maps
            } else {
                &lane.snapshot.attempt.as_ref().unwrap().raw[table].maps
            };
            let parsed = archive::maps(original);
            for row in 0..parsed.rows.len() {
                for column in 0..4 {
                    let changed = permission_changed(&parsed, row, column);
                    let mut snapshot = lane.snapshot.clone();
                    let target = if table == 4 {
                        &mut snapshot.attempt.as_mut().unwrap().quarantined_maps
                    } else {
                        &mut snapshot.attempt.as_mut().unwrap().raw[table].maps
                    };
                    assert_eq!(changed.raw.len(), target.observed_bytes);
                    target.initialized[..changed.raw.len()].copy_from_slice(&changed.raw);
                    rejected(|| check(&snapshot, &lane.context));
                }
            }
        }
        // The exact complete authored reply is checked before production use.
        // These are comparator controls; production reply rejection remains
        // separately exercised by the authentic prior-session stale fixture.
        assert!(facts_match(
            &lane.fixture,
            lane.context.capture,
            &lane.reply
        ));
        for head in &lane.fixture.new_heads {
            let mut bad = lane.reply.clone();
            assert!(bad.images[0].heads.remove(head));
            assert!(!facts_match(&lane.fixture, lane.context.capture, &bad));
        }
        for case in 0..6 {
            let mut bad = lane.reply.clone();
            match case {
                0 => bad.images.clear(),
                1 => bad.images.push(bad.images[0].clone()),
                2 => bad.images[0].heads.clear(),
                3 => {
                    assert!(bad.images[0].heads.insert(NEW - 1));
                }
                4 => {
                    assert!(bad.images[0].heads.insert(lane.fixture.first_cpu + 1));
                }
                5 => bad.images[0].capture = other.context.capture,
                _ => unreachable!(),
            }
            assert!(!facts_match(&lane.fixture, lane.context.capture, &bad));
        }
        for index in [0, 0x200, 0x210, 0x220, 0x230, 0x30b, 0x330] {
            let mut changed = lane.reference.arguments.clone();
            changed[index] ^= 1;
            rejected(|| {
                compare::arguments(
                    &lane.fixture,
                    &lane.reference.before_exec.architecture.registers,
                    &lane.reference.before_exec.maps,
                    &changed,
                )
            });
        }
        for offset in [0x200, 0x220] {
            let mut changed = lane.reference.arguments.clone();
            let first: [u8; 8] = changed[offset..offset + 8].try_into().unwrap();
            changed.copy_within(offset + 8..offset + 16, offset);
            changed[offset + 8..offset + 16].copy_from_slice(&first);
            assert_ne!(changed, lane.reference.arguments);
            rejected(|| {
                compare::arguments(
                    &lane.fixture,
                    &lane.reference.before_exec.architecture.registers,
                    &lane.reference.before_exec.maps,
                    &changed,
                )
            });
        }
        // A real foreign capture/session supplies this mutation; IDs are not
        // synthesized through an authority constructor.
        let mut context = lane.context.clone();
        context.request = other.context.request;
        context.capture = other.context.capture;
        rejected(|| check(&lane.snapshot, &context));
    }
}
fn change_result(
    attempt: &mut ExecAttemptSnapshot,
    effect: ExecBootstrapEffect,
    change: impl FnOnce(u64) -> u64,
) {
    let fact=attempt.facts.iter_mut().find(|fact|matches!(fact,ExecJournalFact::EffectComplete{effect:actual,..} if *actual==effect)).unwrap();
    let ExecJournalFact::EffectComplete { result, .. } = fact else {
        unreachable!()
    };
    let original = result.unwrap();
    let changed = change(original);
    assert_ne!(changed, original);
    *result = Some(changed);
}
fn permission_changed(maps: &Maps, row: usize, column: usize) -> Maps {
    assert!(column < 4);
    let mut rows = maps.rows.clone();
    let target = &mut rows[row];
    let mut bytes = target.permissions.as_bytes().to_vec();
    let present = [b'r', b'w', b'x', b'p'][column];
    let absent = if column == 3 { b's' } else { b'-' };
    assert!(bytes[column] == present || bytes[column] == absent);
    bytes[column] = if bytes[column] == present {
        absent
    } else {
        present
    };
    let changed = String::from_utf8(bytes).unwrap();
    assert_ne!(changed, target.permissions);
    let offset = target.line.find(&target.permissions).unwrap();
    target.line.replace_range(offset..offset + 4, &changed);
    let raw = rows
        .iter()
        .flat_map(|row| row.line.as_bytes().iter().copied().chain([b'\n']))
        .collect();
    Maps::parse(raw)
}
fn flip_register(r: &mut RegisterSnapshot, index: usize) {
    match index {
        0 => r.r15 ^= 1,
        1 => r.r14 ^= 1,
        2 => r.r13 ^= 1,
        3 => r.r12 ^= 1,
        4 => r.rbp ^= 1,
        5 => r.rbx ^= 1,
        6 => r.r11 ^= 1,
        7 => r.r10 ^= 1,
        8 => r.r9 ^= 1,
        9 => r.r8 ^= 1,
        10 => r.rax ^= 1,
        11 => r.rcx ^= 1,
        12 => r.rdx ^= 1,
        13 => r.rsi ^= 1,
        14 => r.rdi ^= 1,
        15 => r.orig_rax ^= 1,
        16 => r.rip ^= 1,
        17 => r.cs ^= 1,
        18 => r.eflags ^= 1,
        19 => r.rsp ^= 1,
        20 => r.ss ^= 1,
        21 => r.fs_base ^= 1,
        22 => r.gs_base ^= 1,
        23 => r.ds ^= 1,
        24 => r.es ^= 1,
        25 => r.fs ^= 1,
        26 => r.gs ^= 1,
        _ => unreachable!(),
    }
}
