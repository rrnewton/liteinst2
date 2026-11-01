//! Real metadata receipts and complete state images; no native execution.
use super::*;
use liteinst2::contracts::{CodeIdentity, SourceIdentity};

const ENTRIES: [u64; 2] = [0x1000, 0x1100];
const IDS: [FunctionId; 2] = [FunctionId(11), FunctionId(29)];
const WORDS: [u64; 4] = [0x9008, 0x9010, 0x9018, 0x9020];
struct Fixture {
    state: NormalState,
    physical: PhysicalState,
    controller: EarlyEntryModuleSessionController,
    banks: Vec<IntervalEpochStorage>,
    epoch: IntervalEpoch,
}
impl Fixture {
    fn new(k: usize, order: [usize; 2]) -> Self {
        let (site, writers) = site::ordinary::ModuleSite::synthetic_early(
            CodeIdentity {
                source: SourceIdentity([196; 32]),
                mapping: ENTRIES[0],
                generation: 1,
            },
            [
                (
                    ENTRIES[0],
                    ENTRIES[0] + 32,
                    vec![ENTRIES[0] + 16, ENTRIES[0] + 24],
                ),
                (
                    ENTRIES[1],
                    ENTRIES[1] + 32,
                    vec![ENTRIES[1] + 16, ENTRIES[1] + 24],
                ),
            ],
        );
        let mut p =
            PreparedEarlyEntryModuleSessionController::prepare(site, writers, 72, IDS, k).unwrap();
        let mut banks = p.prepare_epoch_storage().unwrap();
        // SAFETY: metadata only; synthetic site mints no loaded or callable owner.
        let (mut controller, client) = unsafe { p.activate_concurrent() }.unwrap();
        let epoch = controller.stage_prepared(banks.pop().unwrap()).unwrap();
        let binding = Arc::clone(&client.shared.binding);
        let model = binding.session.register_thread(7).unwrap();
        let mut state = NormalState::new(
            binding,
            7,
            ReadableStack {
                start: 0x7000,
                end: 0x100000,
            },
            IntervalJournal::allocate(),
            model,
        );
        state.journal.header(state.tid, 0);
        let physical = PhysicalState {
            shared: client.shared,
            order: order.map(|i| state.selection(i).unwrap()),
            words: WORDS,
            batches: 0,
            calls: 0,
            active: None,
        };
        Self {
            state,
            physical,
            controller,
            banks,
            epoch,
        }
    }
    fn input(&self, entry: bool) -> Visit {
        let b = self.physical.active.as_ref().unwrap();
        let position = b.position;
        let selected = self.physical.order[position % 2];
        let pc = ENTRIES[selected.index]
            + if entry {
                0
            } else {
                16 + (position % 2) as u64 * 8
            };
        let stamp = RawTimestamp {
            ticks: b.number * 1000 + position as u64 * 100 + u64::from(!entry) * 10,
            aux: 7,
        };
        Visit {
            selected,
            pc,
            rsp: 0x8008,
            word: WORDS[position],
            stamp,
            entry,
        }
    }
    fn visit(&mut self, entry: bool) -> Result<(), BridgeError> {
        let input = self.input(entry);
        self.physical.visit(&mut self.state, input)
    }
    fn visit_original(&mut self, entry: bool) -> Result<(), BridgeError> {
        let input = self.input(entry);
        self.physical.visit_with_full_shapes(&mut self.state, input)
    }
    fn call(&mut self, seen: bool) {
        if seen {
            self.visit(true).unwrap();
        }
        self.visit(false).unwrap();
    }
    fn finish(&mut self) -> (Option<NormalModuleBatch>, [EarlyEntryModulePhysicalRow; 4]) {
        let rows = self.physical.returned(&self.state).unwrap();
        let (out, journal) = EarlyOutput::allocate().unwrap();
        let sparse = self.state.transfer_into(out, journal).unwrap();
        self.physical
            .complete(&self.state, rows, sparse.as_ref())
            .unwrap();
        (sparse, rows)
    }
}

// Literal pre-optimization visit body, renamed only. Both normal transitions use
// their original full-shape wrappers; this reference shares the unchanged tails.
impl PhysicalState {
    fn visit_with_full_shapes(
        &mut self,
        state: &mut NormalState,
        visit: Visit,
    ) -> Result<(), BridgeError> {
        let Visit {
            selected,
            pc,
            rsp,
            word,
            stamp,
            entry,
        } = visit;
        self.shape(state)?;
        let b = self.active.as_mut().ok_or(error(Cause::Outstanding))?;
        let index = b.position;
        if index >= 4
            || selected != self.order[index % 2]
            || word != self.words[index]
            || b.rsp.is_some_and(|prior| prior != rsp)
        {
            return Err(error(Cause::Return));
        }
        if entry {
            if b.seen[index].is_some()
                || state.pending.as_ref().is_some_and(|p| p.returned.is_none())
            {
                return Err(error(Cause::Return));
            }
            let ordinal = state.next;
            state.enter_function(selected, pc, rsp, word, stamp)?;
            b.rsp = Some(rsp);
            b.seen[index] = Some(ordinal);
            b.pending_position = Some(index);
        } else {
            let BindingProfile::Module { site, .. } = &state.binding.profile else {
                return Err(error(Cause::Identity));
            };
            state.selected_geometry(
                selected,
                site.functions()[selected.index].entry(),
                Some(pc),
            )?;
            if let Some(ordinal) = b.seen[index] {
                if b.pending_position != Some(index)
                    || state
                        .pending
                        .as_ref()
                        .is_none_or(|p| p.ordinal != ordinal || p.returned.is_some())
                {
                    return Err(error(Cause::Return));
                }
                state.observe_function(selected, pc, rsp, word, stamp)?;
            } else if state.pending.as_ref().is_some_and(|p| p.returned.is_none()) {
                return Err(error(Cause::Return));
            }
            b.rsp = Some(rsp);
            b.rows[index] = Some(EarlyEntryModulePhysicalRow {
                batch: b.number,
                position: index,
                function: selected.function,
                observed_ordinal: b.seen[index],
                return_pc: pc,
                entry_rsp: rsp,
                return_word: word,
            });
            b.position += 1;
        }
        self.shape(state)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PendingImage {
    selected: SelectedFunction,
    ordinal: u64,
    rsp: u64,
    word: u64,
    entry_pc: u64,
    start: RawTimestamp,
    slot: ModelReturnSlot,
    summary: Option<IntervalEntrySummary>,
    actual_summary: Option<IntervalEntrySummary>,
    returned: Option<RawInterval>,
}
#[derive(Debug, Eq, PartialEq)]
struct NormalImage {
    pending: Option<PendingImage>,
    records: [Option<NormalRecord>; CALLS],
    functions: [Option<SelectedFunction>; CALLS],
    journal: [u64; 512],
    actual_thread: ThreadId,
    tid: u64,
    registration: u64,
    stack: (u64, u64),
    len: usize,
    next: u64,
    totals: NormalTotals,
    cursor: Cursor,
    model_identity: u64,
    depth: usize,
    sequence: u64,
    retained: usize,
    failure: Option<BridgeError>,
    busy: bool,
}
#[derive(Debug, Eq, PartialEq)]
struct BatchImage {
    number: u64,
    before_cursor: Cursor,
    before_next: u64,
    position: usize,
    rsp: Option<u64>,
    seen: [Option<u64>; 4],
    rows: [Option<EarlyEntryModulePhysicalRow>; 4],
    pending_position: Option<usize>,
}
#[derive(Debug, Eq, PartialEq)]
struct PhysicalImage {
    order: [SelectedFunction; 2],
    words: [u64; 4],
    batches: u64,
    calls: u64,
    failed: bool,
    active: Option<BatchImage>,
}
fn normal_image(s: &NormalState) -> NormalImage {
    NormalImage {
        pending: s.pending.as_ref().map(|p| PendingImage {
            selected: p.selected,
            ordinal: p.ordinal,
            rsp: p.rsp,
            word: p.word,
            entry_pc: p.entry_pc,
            start: p.start,
            slot: p.slot,
            summary: p.summary,
            actual_summary: p.receipt.summary(),
            returned: p.returned,
        }),
        records: *s.records,
        functions: *s.functions,
        journal: s.journal.page.0,
        actual_thread: s.actual_thread,
        tid: s.tid,
        registration: s.registration,
        stack: (s.stack.start, s.stack.end),
        len: s.len,
        next: s.next,
        totals: s.totals,
        cursor: s.cursor,
        model_identity: s.model.identity(),
        depth: s.model.depth(),
        sequence: s.model.completed_sequence(),
        retained: s.binding.session.retained_epochs(),
        failure: s.failure,
        busy: s.busy,
    }
}
fn physical_image(p: &PhysicalState) -> PhysicalImage {
    PhysicalImage {
        order: p.order,
        words: p.words,
        batches: p.batches,
        calls: p.calls,
        failed: p.shared.failed.load(Ordering::Acquire),
        active: p.active.as_ref().map(|b| BatchImage {
            number: b.number,
            before_cursor: b.before.cursor,
            before_next: b.before.next,
            position: b.position,
            rsp: b.rsp,
            seen: b.seen,
            rows: b.rows,
            pending_position: b.pending_position,
        }),
    }
}
fn identities(s: &NormalState, p: &PhysicalState) -> [u64; 5] {
    [
        Arc::as_ptr(&s.binding) as usize as u64,
        Arc::as_ptr(&s.binding.key) as usize as u64,
        Arc::as_ptr(&p.shared) as usize as u64,
        Arc::as_ptr(&p.shared.binding) as usize as u64,
        s.journal.address(),
    ]
}
fn refused_visit(f: &mut Fixture, entry: bool, cause: Cause) {
    let before = (normal_image(&f.state), physical_image(&f.physical));
    let owners = identities(&f.state, &f.physical);
    assert_eq!(f.visit(entry), Err(error(cause)));
    assert_eq!(
        (normal_image(&f.state), physical_image(&f.physical)),
        before
    );
    assert_eq!(identities(&f.state, &f.physical), owners);
}

#[test]
fn checked_visit_initial_corruption_refuses_before_mutation() {
    let corruptions: [fn(&mut NormalState); 15] = [
        |s| s.len = CALLS + 1,
        |s| s.totals.unsampled += 1,
        |s| s.totals.entered += 1,
        |s| s.totals.ret_observed += 1,
        |s| s.next += 1,
        |s| s.cursor.totals.confirmed += 1,
        |s| {
            s.totals.completed -= 1;
            s.totals.unsampled += 1;
        },
        |s| s.registration += 1,
        |s| s.pending.as_mut().unwrap().summary = None,
        |s| s.journal.word(0, s.journal.used() as u64 + 1),
        |s| s.records.set(0, None),
        |s| s.records.set(s.len, s.records[0]),
        |s| s.functions.set(0, None),
        |s| s.functions.set(s.len, s.functions[0]),
        |s| {
            s.totals.completed = u64::MAX;
            s.totals.unsampled = 1;
        },
    ];
    for order in [[0, 1], [1, 0]] {
        for entry in [true, false] {
            for corrupt in corruptions {
                let mut f = Fixture::new(10, order);
                f.controller.arm(&f.epoch).unwrap();
                f.physical.begin(&f.state).unwrap();
                f.call(true);
                f.call(true);
                assert_eq!(f.state.len, 1);
                assert_eq!(f.state.model.completed_sequence(), 1);
                f.physical.shape(&f.state).unwrap();
                corrupt(&mut f.state);
                refused_visit(&mut f, entry, Cause::Invariant);
                assert!(f.controller.report(&f.epoch).unwrap().is_none());
            }
        }
    }
}

#[test]
fn checked_visit_fresh_used_keeps_entry_and_return_error_order() {
    for order in [[0, 1], [1, 0]] {
        for entry in [true, false] {
            for (bad_count, bad_geometry) in [(true, false), (true, true), (false, true)] {
                let mut f = Fixture::new(10, order);
                f.controller.arm(&f.epoch).unwrap();
                f.physical.begin(&f.state).unwrap();
                if !entry {
                    f.visit(true).unwrap();
                }
                let Visit {
                    selected,
                    pc,
                    rsp,
                    word,
                    stamp,
                    ..
                } = f.input(entry);
                let prior_used = f.state.journal.used();
                let checked = CheckedVisit::new(&f.physical, &mut f.state).unwrap();
                // Test-only access from this child module: corrupt ONLY the
                // volatile field after proof construction, never pure metadata.
                if bad_count {
                    checked.state.journal.word(0, prior_used as u64 + 1);
                }
                let before = (normal_image(checked.state), physical_image(&f.physical));
                let owners = identities(checked.state, &f.physical);
                let pc = pc + u64::from(bad_geometry);
                let result = if entry {
                    checked.enter(selected, pc, rsp, word, stamp)
                } else {
                    checked.observe(selected, pc, rsp, word, stamp)
                };
                let expected = if bad_geometry && (entry || !bad_count) {
                    Cause::Identity
                } else {
                    Cause::Invariant
                };
                assert_eq!(result, Err(error(expected)));
                assert_eq!(
                    (normal_image(&f.state), physical_image(&f.physical)),
                    before
                );
                assert_eq!(identities(&f.state, &f.physical), owners);
                f.state.journal.word(0, prior_used as u64);
                f.controller.disarm(&f.epoch).unwrap();
                if entry {
                    // No refusal may have reserved an admitted payload/frame.
                    assert_eq!(
                        f.controller
                            .report(&f.epoch)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        0
                    );
                } else {
                    assert!(f.controller.report(&f.epoch).unwrap().is_none());
                    f.visit(false).unwrap();
                    for _ in 0..3 {
                        f.call(false);
                    }
                    let batch = f.finish().0.unwrap();
                    assert_eq!(batch.records().len(), 1);
                    assert_eq!(
                        f.controller
                            .report(&f.epoch)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        1
                    );
                }
            }
        }
    }
}

#[test]
fn checked_visit_revalidates_after_return_and_preserves_old_owner_across_rearm() {
    for order in [[0, 1], [1, 0]] {
        let mut f = Fixture::new(10, order);
        f.controller.arm(&f.epoch).unwrap();
        f.physical.begin(&f.state).unwrap();
        f.call(true);
        f.controller.disarm(&f.epoch).unwrap();
        assert!(f.controller.report(&f.epoch).unwrap().is_none());
        let second = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
        f.controller.arm(&second).unwrap();
        let before = normal_image(&f.state);
        let next = f.state.next;
        f.state.next += 1;
        refused_visit(&mut f, false, Cause::Invariant);
        f.state.next = next; // Restore exactly the deliberate hostile input.
        assert_eq!(normal_image(&f.state), before);
        for _ in 0..3 {
            f.call(false);
            assert_eq!(normal_image(&f.state), before);
            assert!(f.controller.report(&f.epoch).unwrap().is_none());
        }
        let batch = f.finish().0.unwrap();
        assert_eq!(batch.records().len(), 1);
        assert!(matches!(
            batch.records()[0].record.raw.owner,
            RawIntervalOwner::Sampled { generation, .. } if generation == f.epoch.generation().get()
        ));
        assert_eq!(
            f.controller
                .report(&f.epoch)
                .unwrap()
                .unwrap()
                .records()
                .count(),
            1
        );
        f.controller.disarm(&second).unwrap();
        assert_eq!(
            f.controller
                .report(&second)
                .unwrap()
                .unwrap()
                .records()
                .count(),
            0
        );
    }
}

// Actual staged A/B owners define this bijection. No numeric ID ordering or
// identity fallback is allowed; an unknown owner always refuses comparison.
struct Generations {
    roles: [Option<(GenerationId, GenerationId)>; 2],
}
impl Generations {
    fn new(checked: GenerationId, original: GenerationId) -> Self {
        let mut result = Self { roles: [None; 2] };
        result.bind(0, checked, original);
        result
    }
    fn bind(&mut self, role: usize, checked: GenerationId, original: GenerationId) {
        assert!(role < self.roles.len());
        assert!(self.roles[role].is_none());
        assert_ne!(checked, original);
        for &(a, b) in self.roles.iter().flatten() {
            assert!(a != checked && a != original && b != checked && b != original);
        }
        self.roles[role] = Some((checked, original));
    }
    fn id(&self, original: GenerationId) -> Option<GenerationId> {
        self.roles
            .iter()
            .flatten()
            .find_map(|&(a, b)| (b == original).then_some(a))
    }
    fn word(&self, original: u64) -> Option<u64> {
        self.roles
            .iter()
            .flatten()
            .find_map(|&(a, b)| (b.get() == original).then_some(a.get()))
    }
    fn binding(&self, binding: BindingChange) -> Option<BindingChange> {
        Some(match binding {
            BindingChange::Initial => BindingChange::Initial,
            BindingChange::Published {
                action_index,
                generation,
            } => BindingChange::Published {
                action_index,
                generation: self.id(generation)?,
            },
            BindingChange::Removed {
                action_index,
                generation,
            } => BindingChange::Removed {
                action_index,
                generation: self.id(generation)?,
            },
        })
    }
    fn summary(&self, summary: IntervalEntrySummary) -> Option<IntervalEntrySummary> {
        Some(match summary {
            IntervalEntrySummary::Admitted {
                generation,
                invocation,
                history_len,
                binding,
            } => IntervalEntrySummary::Admitted {
                generation: self.id(generation)?,
                invocation,
                history_len,
                binding: self.binding(binding)?,
            },
            IntervalEntrySummary::Unsampled {
                reason,
                history_len,
                binding,
            } => IntervalEntrySummary::Unsampled {
                reason: match reason {
                    UnsampledSummary::InitialDisarmed => UnsampledSummary::InitialDisarmed,
                    UnsampledSummary::Removed { generation } => UnsampledSummary::Removed {
                        generation: self.id(generation)?,
                    },
                    UnsampledSummary::FunctionClosed {
                        generation,
                        function,
                    } => UnsampledSummary::FunctionClosed {
                        generation: self.id(generation)?,
                        function,
                    },
                },
                history_len,
                binding: self.binding(binding)?,
            },
        })
    }
    fn raw(&self, raw: &mut RawInterval) -> Option<()> {
        match &mut raw.owner {
            RawIntervalOwner::Sampled { generation, .. }
            | RawIntervalOwner::Removed { generation }
            | RawIntervalOwner::FunctionClosed { generation } => {
                *generation = self.word(*generation)?;
            }
            RawIntervalOwner::InitialDisarmed => {}
        }
        Some(())
    }
    fn journal(&self, journal: &mut [u64]) -> Option<()> {
        if journal.len() != 512 {
            return None;
        }
        // All 64 fixed row-generation positions; every other word is unchanged.
        // A zero is preserved only when the original word is already the zero
        // sentinel. Nonzero IDs must name an actual paired staged owner.
        for row in journal[4..4 + EVENTS * 7].chunks_exact_mut(7) {
            if row[5] != 0 {
                row[5] = self.word(row[5])?;
            }
        }
        Some(())
    }
    fn image(&self, mut image: NormalImage) -> Option<NormalImage> {
        if let Some(p) = &mut image.pending {
            if let Some(summary) = p.summary {
                p.summary = Some(self.summary(summary)?);
            }
            if let Some(summary) = p.actual_summary {
                p.actual_summary = Some(self.summary(summary)?);
            }
            if let Some(raw) = &mut p.returned {
                self.raw(raw)?;
            }
        }
        for record in image.records.iter_mut().flatten() {
            self.raw(&mut record.raw)?;
        }
        self.journal(&mut image.journal)?;
        Some(image)
    }
    fn matches(&self, checked: &NormalImage, original: NormalImage) -> bool {
        self.image(original).as_ref() == Some(checked)
    }
}

fn compare_visit(
    checked: &mut Fixture,
    original: &mut Fixture,
    generations: &Generations,
    entry: bool,
) {
    let checked_owners = identities(&checked.state, &checked.physical);
    let original_owners = identities(&original.state, &original.physical);
    assert_eq!(checked.visit(entry), Ok(()));
    assert_eq!(original.visit_original(entry), Ok(()));
    assert_eq!(
        Some(normal_image(&checked.state)),
        generations.image(normal_image(&original.state))
    );
    assert_eq!(
        physical_image(&checked.physical),
        physical_image(&original.physical)
    );
    assert_eq!(
        identities(&checked.state, &checked.physical),
        checked_owners
    );
    assert_eq!(
        identities(&original.state, &original.physical),
        original_owners
    );
}
fn compare_finish(checked: &mut Fixture, original: &mut Fixture, generations: &Generations) {
    let (a, a_rows) = checked.finish();
    let (b, b_rows) = original.finish();
    assert_eq!(a_rows, b_rows);
    assert_eq!(a.is_some(), b.is_some());
    if let (Some(mut a), Some(mut b)) = (a, b) {
        // Independent Sessions intentionally have different opaque stream keys.
        // Authenticate each key against its own real binding before comparing
        // every remaining batch field with the existing complete Eq comparator.
        assert_eq!(
            a.stream,
            crate::frontend_native::always_on::normal::module::session_history::early_stream_for(
                &checked.state.binding
            )
        );
        assert_eq!(
            b.stream,
            crate::frontend_native::always_on::normal::module::session_history::early_stream_for(
                &original.state.binding
            )
        );
        assert_ne!(a.stream, b.stream);
        a.stream = None;
        b.stream = None;
        for record in &mut b.records {
            generations
                .raw(&mut record.record.raw)
                .expect("bound staged owner");
        }
        generations
            .journal(&mut b.journal)
            .expect("bound journal owners");
        assert_eq!(a, b);
    }
    assert_eq!(
        Some(normal_image(&checked.state)),
        generations.image(normal_image(&original.state))
    );
    assert_eq!(
        physical_image(&checked.physical),
        physical_image(&original.physical)
    );
}

#[test]
fn checked_visit_matches_full_shapes_for_every_mask_and_rearm() {
    for k in [10, 1000] {
        for order in [[0, 1], [1, 0]] {
            for mask in 0u8..16 {
                let mut checked = Fixture::new(k, order);
                let mut original = Fixture::new(k, order);
                let mut generations =
                    Generations::new(checked.epoch.generation(), original.epoch.generation());
                checked.controller.arm(&checked.epoch).unwrap();
                original.controller.arm(&original.epoch).unwrap();
                checked.physical.begin(&checked.state).unwrap();
                original.physical.begin(&original.state).unwrap();
                for index in 0..4 {
                    if mask & (1 << index) != 0 {
                        compare_visit(&mut checked, &mut original, &generations, true);
                    }
                    compare_visit(&mut checked, &mut original, &generations, false);
                    if index == 0 {
                        checked.controller.disarm(&checked.epoch).unwrap();
                        original.controller.disarm(&original.epoch).unwrap();
                        let a = checked
                            .controller
                            .stage_prepared(checked.banks.pop().unwrap())
                            .unwrap();
                        let b = original
                            .controller
                            .stage_prepared(original.banks.pop().unwrap())
                            .unwrap();
                        generations.bind(1, a.generation(), b.generation());
                        checked.controller.arm(&a).unwrap();
                        original.controller.arm(&b).unwrap();
                    }
                }
                compare_finish(&mut checked, &mut original, &generations);
            }
        }
    }
}

#[test]
fn checked_visit_function_closed_retains_full_receipt_on_refusal() {
    for order in [[0, 1], [1, 0]] {
        let mut checked = Fixture::new(10, order);
        let mut original = Fixture::new(10, order);
        let generations = Generations::new(checked.epoch.generation(), original.epoch.generation());
        checked.controller.arm(&checked.epoch).unwrap();
        original.controller.arm(&original.epoch).unwrap();
        for _ in 0..5 {
            checked.physical.begin(&checked.state).unwrap();
            original.physical.begin(&original.state).unwrap();
            for _ in 0..4 {
                compare_visit(&mut checked, &mut original, &generations, true);
                compare_visit(&mut checked, &mut original, &generations, false);
            }
            compare_finish(&mut checked, &mut original, &generations);
        }
        checked.physical.begin(&checked.state).unwrap();
        original.physical.begin(&original.state).unwrap();
        compare_visit(&mut checked, &mut original, &generations, true);
        assert!(matches!(
            checked.state.pending.as_ref().unwrap().summary,
            Some(IntervalEntrySummary::Unsampled {
                reason: UnsampledSummary::FunctionClosed { .. },
                ..
            })
        ));
        let next = checked.state.next;
        checked.state.next += 1;
        refused_visit(&mut checked, false, Cause::Invariant);
        checked.state.next = next;
        compare_visit(&mut checked, &mut original, &generations, false);
        for _ in 0..3 {
            compare_visit(&mut checked, &mut original, &generations, false);
        }
        compare_finish(&mut checked, &mut original, &generations);
        assert_eq!(
            checked.state.totals,
            NormalTotals {
                entered: 21,
                ret_observed: 21,
                confirmed: 21,
                completed: 20,
                unsampled: 1,
            }
        );
        assert_eq!(checked.controller.scan_closed().unwrap(), 2);
        assert_eq!(original.controller.scan_closed().unwrap(), 2);
    }
}

#[test]
fn checked_visit_correspondence_rejects_swapped_and_unknown_generation_fields() {
    let mut checked = Fixture::new(10, [0, 1]);
    let mut original = Fixture::new(10, [0, 1]);
    let mut generations = Generations::new(checked.epoch.generation(), original.epoch.generation());
    checked.controller.arm(&checked.epoch).unwrap();
    original.controller.arm(&original.epoch).unwrap();
    checked.physical.begin(&checked.state).unwrap();
    original.physical.begin(&original.state).unwrap();
    for _ in 0..2 {
        compare_visit(&mut checked, &mut original, &generations, true);
        compare_visit(&mut checked, &mut original, &generations, false);
    }
    // Bind role B from actual second staged owners; never infer it from IDs.
    let checked_b = checked
        .controller
        .stage_prepared(checked.banks.pop().unwrap())
        .unwrap();
    let original_b = original
        .controller
        .stage_prepared(original.banks.pop().unwrap())
        .unwrap();
    generations.bind(1, checked_b.generation(), original_b.generation());
    // Third owners are real but deliberately outside this two-role comparison.
    let _checked_c = checked
        .controller
        .stage_prepared(checked.banks.pop().unwrap())
        .unwrap();
    let original_c = original
        .controller
        .stage_prepared(original.banks.pop().unwrap())
        .unwrap();
    let expected = normal_image(&checked.state);
    assert!(generations.matches(&expected, normal_image(&original.state)));
    for wrong in [original_b.generation(), original_c.generation()] {
        for location in 0..10 {
            let mut damaged = normal_image(&original.state);
            match location {
                0 | 1 => {
                    let p = damaged.pending.as_mut().unwrap();
                    let summary = if location == 0 {
                        &mut p.summary
                    } else {
                        &mut p.actual_summary
                    };
                    let Some(IntervalEntrySummary::Admitted { generation, .. }) = summary else {
                        panic!("fixture is admitted to role A");
                    };
                    *generation = wrong;
                }
                2 | 3 => {
                    let p = damaged.pending.as_mut().unwrap();
                    let summary = if location == 2 {
                        &mut p.summary
                    } else {
                        &mut p.actual_summary
                    };
                    let Some(IntervalEntrySummary::Admitted { binding, .. }) = summary else {
                        panic!("fixture is admitted to role A");
                    };
                    let BindingChange::Published { generation, .. } = binding else {
                        panic!("fixture has the published role A binding");
                    };
                    *generation = wrong;
                }
                4 | 5 => {
                    let raw = if location == 4 {
                        &mut damaged.records[0].as_mut().unwrap().raw
                    } else {
                        damaged.pending.as_mut().unwrap().returned.as_mut().unwrap()
                    };
                    let RawIntervalOwner::Sampled { generation, .. } = &mut raw.owner else {
                        panic!("fixture is sampled in role A");
                    };
                    *generation = wrong.get();
                }
                6..=9 => damaged.journal[4 + (location - 6) * 7 + 5] = wrong.get(),
                _ => unreachable!(),
            }
            assert!(!generations.matches(&expected, damaged));
        }
    }
    // This control altered only copied images, never either real owner/state.
    assert!(generations.matches(&expected, normal_image(&original.state)));
}

// Literal complete pre-fusion shape, renamed only. Both methods inspect the same
// real fixture, so no generation renaming or simulated model can hide a change.
impl PhysicalState {
    fn shape_before_fusion(&self, state: &NormalState) -> Result<(), BridgeError> {
        self.matches(state)?;
        state.shape()?;
        let b = self.active.as_ref().ok_or(error(Cause::Outstanding))?;
        if b.number != self.batches.checked_add(1).ok_or(error(Cause::Capacity))?
            || b.position > 4
            || state.cursor != b.before.cursor
            || b.rows[..b.position].iter().any(Option::is_none)
            || b.rows[b.position..].iter().any(Option::is_some)
            || b.seen[b.position.saturating_add(1).min(4)..]
                .iter()
                .any(Option::is_some)
            || state
                .totals
                .entered
                .checked_sub(b.before.cursor.totals.entered)
                != Some(b.seen.iter().flatten().count() as u64)
            || state
                .totals
                .ret_observed
                .checked_sub(b.before.cursor.totals.ret_observed)
                != Some(
                    b.rows
                        .iter()
                        .flatten()
                        .filter(|r| r.observed_ordinal.is_some())
                        .count() as u64,
                )
        {
            return Err(error(Cause::Invariant));
        }
        let mut ordinal = b.before.next;
        let mut confirmed = 0;
        for index in 0..4 {
            if let Some(n) = b.seen[index] {
                if n != ordinal {
                    return Err(error(Cause::Invariant));
                }
                ordinal = ordinal.checked_add(1).ok_or(error(Cause::Capacity))?;
            }
            if let Some(row) = b.rows[index] {
                if row.batch != b.number
                    || row.position != index
                    || row.function != self.order[index % 2].function
                    || row.observed_ordinal != b.seen[index]
                    || row.return_word != self.words[index]
                    || Some(row.entry_rsp) != b.rsp
                {
                    return Err(error(Cause::Invariant));
                }
                let BindingProfile::Module { site, .. } = &state.binding.profile else {
                    return Err(error(Cause::Identity));
                };
                state.selected_geometry(
                    self.order[index % 2],
                    site.functions()[self.order[index % 2].index].entry(),
                    Some(row.return_pc),
                )?;
                if row.observed_ordinal.is_some() && b.pending_position != Some(index) {
                    let r = state
                        .records
                        .get(confirmed)
                        .and_then(|r| *r)
                        .ok_or(error(Cause::Invariant))?;
                    if state.functions[confirmed] != Some(self.order[index % 2])
                        || Some(r.raw.ordinal) != row.observed_ordinal
                        || r.raw.return_pc != row.return_pc
                        || r.entry_rsp != row.entry_rsp
                        || r.return_word != row.return_word
                    {
                        return Err(error(Cause::Invariant));
                    }
                    confirmed += 1;
                }
            }
        }
        if state.next != ordinal || state.len != confirmed {
            return Err(error(Cause::Invariant));
        }
        match (b.pending_position, &state.pending) {
            (None, None) if b.position == 4 || b.seen[b.position].is_none() => {}
            (Some(index), Some(p)) if index < 4 => {
                if b.seen[index] != Some(p.ordinal)
                    || p.selected != self.order[index % 2]
                    || p.word != self.words[index]
                    || Some(p.rsp) != b.rsp
                    || (p.returned.is_some() && (index >= b.position || b.rows[index].is_none()))
                    || (p.returned.is_none() && (index != b.position || b.rows[index].is_some()))
                    || (b.position < 4 && index != b.position && b.seen[b.position].is_some())
                {
                    return Err(error(Cause::Return));
                }
            }
            _ => return Err(error(Cause::Return)),
        }
        Ok(())
    }
}

fn compare_physical_shape_unchanged(f: &Fixture, expected: Result<(), BridgeError>) {
    let before = (
        normal_image(&f.state),
        physical_image(&f.physical),
        identities(&f.state, &f.physical),
    );
    let original = f.physical.shape_before_fusion(&f.state);
    assert_eq!(original, expected);
    assert_eq!(
        (
            normal_image(&f.state),
            physical_image(&f.physical),
            identities(&f.state, &f.physical)
        ),
        before
    );
    assert_eq!(f.physical.shape(&f.state), original);
    assert_eq!(
        (
            normal_image(&f.state),
            physical_image(&f.physical),
            identities(&f.state, &f.physical)
        ),
        before
    );
}

#[test]
fn physical_shape_fusion_matches_original_for_all_6480_metadata_patterns() {
    let mut f = Fixture::new(10, [0, 1]);
    f.physical.begin(&f.state).unwrap();
    for _ in 0..4 {
        f.call(false);
    }
    // Derive geometry/content from actual mandatory-return transitions. Only
    // occupancy, row observation kind and physical position vary in this grid.
    let rows = f.physical.returned(&f.state).unwrap();
    assert_eq!(f.state.totals, NormalTotals::default());
    let mut accepted = 0;
    let mut refused = 0;
    for seen_mask in 0u8..16 {
        for row_pattern in 0usize..81 {
            for position in 0..=4 {
                let b = f.physical.active.as_mut().unwrap();
                b.position = position;
                b.rsp = (position != 0).then_some(rows[0].entry_rsp);
                b.seen = std::array::from_fn(|index| {
                    (seen_mask & (1 << index) != 0).then_some(index as u64 + 1)
                });
                let mut digits = row_pattern;
                for (index, slot) in b.rows.iter_mut().enumerate() {
                    let kind = digits % 3;
                    digits /= 3;
                    let mut row = rows[index];
                    row.observed_ordinal = (kind == 2).then_some(index as u64 + 1);
                    *slot = (kind != 0).then_some(row);
                }
                assert_eq!(digits, 0);
                // Prove these cases reach physical checks, not NormalState's
                // earlier refusal path. The five accepted shapes are exactly
                // the empty/one/two/three/four all-bypass return prefixes.
                assert_eq!(f.physical.matches(&f.state), Ok(()));
                assert_eq!(f.state.shape(), Ok(()));
                let bypass_prefix = (3usize.pow(position as u32) - 1) / 2;
                if seen_mask == 0 && row_pattern == bypass_prefix {
                    compare_physical_shape_unchanged(&f, Ok(()));
                    accepted += 1;
                } else {
                    compare_physical_shape_unchanged(&f, Err(error(Cause::Invariant)));
                    refused += 1;
                }
            }
        }
    }
    assert_eq!((accepted, refused), (5, 6475));
    let b = f.physical.active.as_mut().unwrap();
    b.position = 4;
    b.rsp = Some(rows[0].entry_rsp);
    b.seen = [None; 4];
    b.rows = rows.map(Some);
    compare_physical_shape_unchanged(&f, Ok(()));
    assert!(f.finish().0.is_none());
}

#[test]
fn physical_shape_fusion_matches_original_live_prefixes_and_rearm() {
    let mut batches = 0;
    for k in [10, 1000] {
        for order in [[0, 1], [1, 0]] {
            for mask in 0u8..16 {
                let mut f = Fixture::new(k, order);
                f.controller.arm(&f.epoch).unwrap();
                compare_physical_shape_unchanged(&f, Err(error(Cause::Outstanding)));
                f.physical.begin(&f.state).unwrap();
                compare_physical_shape_unchanged(&f, Ok(()));
                for index in 0..4 {
                    if mask & (1 << index) != 0 {
                        f.visit(true).unwrap();
                        compare_physical_shape_unchanged(&f, Ok(()));
                    }
                    f.visit(false).unwrap();
                    compare_physical_shape_unchanged(&f, Ok(()));
                    if index == 0 {
                        f.controller.disarm(&f.epoch).unwrap();
                        let second = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
                        f.controller.arm(&second).unwrap();
                        // Same real old pending receipt survives a real rearm.
                        compare_physical_shape_unchanged(&f, Ok(()));
                    }
                }
                let (sparse, rows) = f.finish();
                assert_eq!(
                    rows.iter().filter(|r| r.observed_ordinal.is_some()).count(),
                    mask.count_ones() as usize
                );
                assert_eq!(
                    sparse.as_ref().map_or(0, |s| s.records().len()),
                    mask.count_ones() as usize
                );
                compare_physical_shape_unchanged(&f, Err(error(Cause::Outstanding)));
                batches += 1;
            }
        }
    }
    assert_eq!(batches, 64);
}

#[test]
fn physical_shape_fusion_keeps_exact_error_precedence_and_underflow() {
    for order in [[0, 1], [1, 0]] {
        let mut f = Fixture::new(10, order);
        f.physical.begin(&f.state).unwrap();
        compare_physical_shape_unchanged(&f, Ok(()));
        // The initial overflow is after matches/normal/active, but before any
        // physical occupancy or cursor check. Restore each fault explicitly.
        f.physical.batches = u64::MAX;
        f.physical.shared.failed.store(true, Ordering::Release);
        compare_physical_shape_unchanged(&f, Err(error(Cause::Identity)));
        f.physical.shared.failed.store(false, Ordering::Release);
        f.state.len = CALLS + 1;
        compare_physical_shape_unchanged(&f, Err(error(Cause::Invariant)));
        f.state.len = 0;
        let active = f.physical.active.take();
        compare_physical_shape_unchanged(&f, Err(error(Cause::Outstanding)));
        f.physical.active = active;
        assert_eq!(f.state.shape(), Ok(()));
        for position in [5, usize::MAX] {
            f.physical.active.as_mut().unwrap().position = position;
            compare_physical_shape_unchanged(&f, Err(error(Cause::Capacity)));
            f.physical.batches = 0;
            compare_physical_shape_unchanged(&f, Err(error(Cause::Invariant)));
            f.physical.batches = u64::MAX;
        }
        f.physical.active.as_mut().unwrap().position = 0;
        f.physical.active.as_mut().unwrap().seen[3] = Some(1);
        compare_physical_shape_unchanged(&f, Err(error(Cause::Capacity)));
        f.physical.batches = 0;
        compare_physical_shape_unchanged(&f, Err(error(Cause::Invariant)));
        f.physical.active.as_mut().unwrap().seen[3] = None;
        compare_physical_shape_unchanged(&f, Ok(()));
        // NormalState only uses cursor.confirmed here. Change the independent
        // cursor entered/RET totals on BOTH sides of the physical cursor join,
        // making checked_sub fail without an earlier normal/cursor mismatch.
        let cursor = f.state.cursor;
        for entered in [true, false] {
            f.state.cursor = cursor;
            if entered {
                f.state.cursor.totals.entered = 1;
                assert_eq!(
                    f.state
                        .totals
                        .entered
                        .checked_sub(f.state.cursor.totals.entered),
                    None
                );
            } else {
                f.state.cursor.totals.ret_observed = 1;
                assert_eq!(
                    f.state
                        .totals
                        .ret_observed
                        .checked_sub(f.state.cursor.totals.ret_observed),
                    None
                );
            }
            f.physical.active.as_mut().unwrap().before.cursor = f.state.cursor;
            assert_eq!(f.state.shape(), Ok(()));
            compare_physical_shape_unchanged(&f, Err(error(Cause::Invariant)));
        }
        f.state.cursor = cursor;
        f.physical.active.as_mut().unwrap().before.cursor = cursor;
        compare_physical_shape_unchanged(&f, Ok(()));
        f.controller.arm(&f.epoch).unwrap();
        f.call(true);
        compare_physical_shape_unchanged(&f, Ok(()));
        let old_next = f.physical.active.as_ref().unwrap().before.next;
        let old_seen = f.physical.active.as_ref().unwrap().seen[0];
        let old_row = f.physical.active.as_ref().unwrap().rows[0];
        let b = f.physical.active.as_mut().unwrap();
        b.before.next = u64::MAX;
        b.seen[0] = Some(u64::MAX);
        b.rows[0].as_mut().unwrap().observed_ordinal = Some(u64::MAX);
        assert_eq!(f.state.shape(), Ok(()));
        // Counts/prefix are valid: later ordinal overflow must remain Capacity.
        compare_physical_shape_unchanged(&f, Err(error(Cause::Capacity)));
        let row = f.physical.active.as_mut().unwrap().rows[0].take();
        compare_physical_shape_unchanged(&f, Err(error(Cause::Invariant)));
        f.physical.active.as_mut().unwrap().rows[0] = row;
        f.physical.active.as_mut().unwrap().rows[0]
            .as_mut()
            .unwrap()
            .return_pc += 1;
        compare_physical_shape_unchanged(&f, Err(error(Cause::Capacity)));
        let b = f.physical.active.as_mut().unwrap();
        b.before.next = old_next;
        b.seen[0] = old_seen;
        b.rows[0].as_mut().unwrap().observed_ordinal = old_row.unwrap().observed_ordinal;
        compare_physical_shape_unchanged(&f, Err(error(Cause::Identity)));
        f.physical.active.as_mut().unwrap().rows[0] = old_row;
        compare_physical_shape_unchanged(&f, Ok(()));
        for _ in 0..3 {
            f.call(false);
        }
        assert_eq!(f.finish().0.unwrap().records().len(), 1);
    }
}
