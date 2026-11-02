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

// Pre-optimization visit with mechanical slot-store adaptations. Its physical
// checks use the literal pre-occupancy shape below; both normal transitions keep
// their original full-shape wrappers and unchanged tails.
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
        self.shape_before_occupancy(state)?;
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
            b.seen.set(index, Some(ordinal));
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
            b.rows.set(
                index,
                Some(EarlyEntryModulePhysicalRow {
                    batch: b.number,
                    position: index,
                    function: selected.function,
                    observed_ordinal: b.seen[index],
                    return_pc: pc,
                    entry_rsp: rsp,
                    return_word: word,
                }),
            );
            b.position += 1;
        }
        self.shape_before_occupancy(state)
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
            seen: *b.seen,
            rows: *b.rows,
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

#[test]
fn ret_proof_rejects_hostile_prefix_before_current_geometry_or_mutation() {
    for order in [[0, 1], [1, 0]] {
        for observed in [false, true] {
            for bad_geometry in [false, true] {
                for corruption in 0..8 {
                    let mut f = Fixture::new(10, order);
                    f.controller.arm(&f.epoch).unwrap();
                    f.physical.begin(&f.state).unwrap();
                    f.call(true);
                    if observed {
                        f.visit(true).unwrap();
                    }
                    f.physical.shape(&f.state).unwrap();
                    let mut candidate = f.input(false);
                    let mut reference = f.input(false);
                    candidate.pc += u64::from(bad_geometry);
                    reference.pc += u64::from(bad_geometry);
                    let expected = match corruption {
                        0 => {
                            f.physical.active.as_mut().unwrap().rows.set(0, None);
                            Cause::Invariant
                        }
                        1 => {
                            let b = f.physical.active.as_mut().unwrap();
                            b.rows.set(3, b.rows[0]);
                            Cause::Invariant
                        }
                        2 => {
                            f.physical
                                .active
                                .as_mut()
                                .unwrap()
                                .seen
                                .set(3, Some(f.state.next));
                            Cause::Invariant
                        }
                        3 => {
                            let b = f.physical.active.as_mut().unwrap();
                            b.seen.set(0, Some(b.seen[0].unwrap() + 1));
                            Cause::Invariant
                        }
                        4 => {
                            let rows = &mut f.physical.active.as_mut().unwrap().rows;
                            let mut row = rows[0].unwrap();
                            row.return_pc += 1;
                            rows.set(0, Some(row));
                            Cause::Identity
                        }
                        5 => {
                            f.physical.active.as_mut().unwrap().pending_position = Some(3);
                            if observed {
                                Cause::Return
                            } else {
                                Cause::Invariant
                            }
                        }
                        6 => {
                            f.physical.batches = u64::MAX;
                            Cause::Capacity
                        }
                        7 => {
                            f.physical.active = None;
                            Cause::Outstanding
                        }
                        _ => unreachable!(),
                    };
                    let before = (normal_image(&f.state), physical_image(&f.physical));
                    let owners = identities(&f.state, &f.physical);
                    assert_eq!(
                        f.physical.visit(&mut f.state, candidate),
                        Err(error(expected))
                    );
                    assert_eq!(
                        (normal_image(&f.state), physical_image(&f.physical)),
                        before
                    );
                    assert_eq!(identities(&f.state, &f.physical), owners);
                    // Same actual fixture and generations; the old full visit
                    // must choose exactly the same error without changing it.
                    assert_eq!(
                        f.physical.visit_with_full_shapes(&mut f.state, reference),
                        Err(error(expected))
                    );
                    assert_eq!(
                        (normal_image(&f.state), physical_image(&f.physical)),
                        before
                    );
                    assert_eq!(identities(&f.state, &f.physical), owners);
                }
            }
        }
    }
}

#[test]
fn ret_proof_late_shared_and_journal_failures_keep_exact_committed_state() {
    for order in [[0, 1], [1, 0]] {
        for observed in [false, true] {
            for (bad_shared, bad_used) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                let mut f = Fixture::new(10, order);
                f.controller.arm(&f.epoch).unwrap();
                f.physical.begin(&f.state).unwrap();
                f.call(true);
                if observed {
                    f.visit(true).unwrap();
                }
                let normal_before = normal_image(&f.state);
                let owners = identities(&f.state, &f.physical);
                let Visit {
                    selected,
                    pc,
                    rsp,
                    word,
                    stamp,
                    ..
                } = f.input(false);
                let committed = CheckedRet::new(&mut f.physical, &mut f.state)
                    .unwrap()
                    .commit(selected, pc, rsp, word, stamp)
                    .unwrap();
                // This is the production commit and production finish. Child
                // access changes only the fresh shared/volatile observations.
                // No hook or mutable state view is added to production.
                committed
                    .checked
                    .physical
                    .shape(committed.checked.state)
                    .unwrap();
                if !observed {
                    assert_eq!(normal_image(committed.checked.state), normal_before);
                }
                let used = committed.checked.state.journal.used();
                if bad_shared {
                    committed
                        .checked
                        .physical
                        .shared
                        .failed
                        .store(true, Ordering::Release);
                }
                if bad_used {
                    committed.checked.state.journal.word(0, used as u64 + 1);
                }
                let at_postcheck = (
                    normal_image(committed.checked.state),
                    physical_image(committed.checked.physical),
                );
                assert_eq!(at_postcheck.1.active.as_ref().unwrap().position, 2);
                assert_eq!(
                    at_postcheck.1.active.as_ref().unwrap().rows[1],
                    Some(committed.row)
                );
                let expected = if bad_shared {
                    Err(error(Cause::Identity))
                } else if bad_used {
                    Err(error(Cause::Invariant))
                } else {
                    Ok(())
                };
                assert_eq!(
                    committed.checked.physical.shape(committed.checked.state),
                    expected
                );
                assert_eq!(committed.finish(), expected);
                assert_eq!(
                    (normal_image(&f.state), physical_image(&f.physical)),
                    at_postcheck
                );
                assert_eq!(identities(&f.state, &f.physical), owners);
                // Repair only the two deliberate late faults, then finish the
                // actual receipts; refusal did not roll back or double-commit.
                f.physical.shared.failed.store(false, Ordering::Release);
                f.state.journal.word(0, used as u64);
                f.physical.shape(&f.state).unwrap();
                f.call(false);
                f.call(false);
                assert_eq!(
                    f.finish().0.unwrap().records().len(),
                    if observed { 2 } else { 1 }
                );
            }
        }
    }
}

#[test]
fn ret_proof_preserves_all_receipt_kinds_across_bypass_and_rearm() {
    for order in [[0, 1], [1, 0]] {
        // InitialDisarmed, Admitted, FunctionClosed: no owner is inferred from
        // whichever epoch the controller happens to publish after this RET.
        for mode in 0..3 {
            let mut f = Fixture::new(10, order);
            if mode != 0 {
                f.controller.arm(&f.epoch).unwrap();
            }
            if mode == 2 {
                for _ in 0..5 {
                    f.physical.begin(&f.state).unwrap();
                    for _ in 0..4 {
                        f.call(true);
                    }
                    assert_eq!(f.finish().0.unwrap().records().len(), 4);
                }
            }
            f.physical.begin(&f.state).unwrap();
            f.call(true);
            let original_raw = f.state.pending.as_ref().unwrap().returned.unwrap();
            match mode {
                0 => assert!(matches!(
                    original_raw.owner,
                    RawIntervalOwner::InitialDisarmed
                )),
                1 => assert!(
                    matches!(original_raw.owner, RawIntervalOwner::Sampled { generation, .. }
                    if generation == f.epoch.generation().get())
                ),
                2 => assert!(
                    matches!(original_raw.owner, RawIntervalOwner::FunctionClosed { generation }
                    if generation == f.epoch.generation().get())
                ),
                _ => unreachable!(),
            }
            if mode != 0 {
                f.controller.disarm(&f.epoch).unwrap();
            }
            let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
            f.controller.arm(&next).unwrap();
            let retained = normal_image(&f.state);
            let owners = identities(&f.state, &f.physical);
            let report_before = f
                .controller
                .report(&f.epoch)
                .unwrap()
                .map(|r| r.records().count());
            if mode == 1 {
                assert_eq!(report_before, None);
            }
            if mode == 2 {
                assert_eq!(report_before, Some(20));
            }
            for _ in 0..3 {
                f.call(false);
                assert_eq!(normal_image(&f.state), retained);
                assert_eq!(identities(&f.state, &f.physical), owners);
                assert_eq!(
                    f.physical.active.as_ref().unwrap().pending_position,
                    Some(0)
                );
                assert_eq!(
                    f.controller
                        .report(&f.epoch)
                        .unwrap()
                        .map(|r| r.records().count()),
                    report_before
                );
            }
            let batch = f.finish().0.unwrap();
            assert_eq!(batch.records().len(), 1);
            assert_eq!(batch.records()[0].record.raw, original_raw);
            assert!(f.state.pending.is_none());
            if mode == 1 {
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
            f.controller.disarm(&next).unwrap();
            assert_eq!(
                f.controller
                    .report(&next)
                    .unwrap()
                    .unwrap()
                    .records()
                    .count(),
                0
            );
        }
    }
}

fn compare_entry_refusal(
    checked: &mut Fixture,
    original: &mut Fixture,
    generations: &Generations,
    cause: Cause,
) {
    let a = identities(&checked.state, &checked.physical);
    let b = identities(&original.state, &original.physical);
    assert_eq!(checked.visit(true), Err(error(cause)));
    assert_eq!(original.visit_original(true), Err(error(cause)));
    assert_eq!(
        Some(normal_image(&checked.state)),
        generations.image(normal_image(&original.state))
    );
    assert_eq!(
        physical_image(&checked.physical),
        physical_image(&original.physical)
    );
    assert_eq!(identities(&checked.state, &checked.physical), a);
    assert_eq!(identities(&original.state, &original.physical), b);
}

#[test]
fn entry_proof_hostile_prefix_refuses_before_entry_mutation() {
    for order in [[0, 1], [1, 0]] {
        for bad_geometry in [false, true] {
            for corruption in 0..10 {
                let mut f = Fixture::new(10, order);
                f.controller.arm(&f.epoch).unwrap();
                f.physical.begin(&f.state).unwrap();
                f.call(true);
                f.call(false);
                f.physical.shape(&f.state).unwrap();
                let mut candidate = f.input(true);
                let mut reference = f.input(true);
                candidate.pc += u64::from(bad_geometry);
                reference.pc += u64::from(bad_geometry);
                let cause = match corruption {
                    0 => {
                        f.physical.active.as_mut().unwrap().rows.set(0, None);
                        Cause::Invariant
                    }
                    1 => {
                        let b = f.physical.active.as_mut().unwrap();
                        b.rows.set(3, b.rows[0]);
                        Cause::Invariant
                    }
                    2 => {
                        f.physical
                            .active
                            .as_mut()
                            .unwrap()
                            .seen
                            .set(3, Some(f.state.next));
                        Cause::Invariant
                    }
                    3 => {
                        let b = f.physical.active.as_mut().unwrap();
                        b.seen.set(0, Some(b.seen[0].unwrap() + 1));
                        Cause::Invariant
                    }
                    4 => {
                        let rows = &mut f.physical.active.as_mut().unwrap().rows;
                        let mut row = rows[0].unwrap();
                        row.return_pc += 1;
                        rows.set(0, Some(row));
                        Cause::Identity
                    }
                    5 => {
                        f.physical.active.as_mut().unwrap().pending_position = Some(1);
                        Cause::Invariant
                    }
                    6 => {
                        f.physical.batches = u64::MAX;
                        Cause::Capacity
                    }
                    7 => {
                        f.physical.active = None;
                        Cause::Outstanding
                    }
                    8 => {
                        f.state.cursor.totals.confirmed += 1;
                        Cause::Invariant
                    }
                    9 => {
                        let rows = &mut f.physical.active.as_mut().unwrap().rows;
                        let mut row = rows[1].unwrap();
                        row.return_word += 8;
                        rows.set(1, Some(row));
                        Cause::Invariant
                    }
                    _ => unreachable!(),
                };
                let before = (normal_image(&f.state), physical_image(&f.physical));
                let owners = identities(&f.state, &f.physical);
                assert_eq!(f.physical.visit(&mut f.state, candidate), Err(error(cause)));
                assert_eq!(
                    (normal_image(&f.state), physical_image(&f.physical)),
                    before
                );
                assert_eq!(identities(&f.state, &f.physical), owners);
                assert_eq!(
                    f.physical.visit_with_full_shapes(&mut f.state, reference),
                    Err(error(cause))
                );
                assert_eq!(
                    (normal_image(&f.state), physical_image(&f.physical)),
                    before
                );
                assert_eq!(identities(&f.state, &f.physical), owners);
            }
        }
    }
}

#[test]
fn entry_proof_new_confirmation_keeps_full_older_row_join() {
    for order in [[0, 1], [1, 0]] {
        for bypasses in 0..3 {
            let mut checked = Fixture::new(10, order);
            let mut original = Fixture::new(10, order);
            let generations =
                Generations::new(checked.epoch.generation(), original.epoch.generation());
            for f in [&mut checked, &mut original] {
                f.controller.arm(&f.epoch).unwrap();
                f.physical.begin(&f.state).unwrap();
                f.call(true);
                for _ in 0..bypasses {
                    f.call(false);
                }
                // A different legal RET passes the old pending-row geometry
                // check but must fail the newly confirmed record relation.
                let rows = &mut f.physical.active.as_mut().unwrap().rows;
                let mut row = rows[0].unwrap();
                row.return_pc += 8;
                rows.set(0, Some(row));
                f.physical.shape(&f.state).unwrap();
            }
            let old_raw = checked.state.pending.as_ref().unwrap().returned.unwrap();
            compare_entry_refusal(&mut checked, &mut original, &generations, Cause::Invariant);
            assert_eq!(checked.state.len, 1);
            assert_eq!(checked.state.model.completed_sequence(), 1);
            assert_eq!(checked.state.records[0].unwrap().raw, old_raw);
            assert_eq!(checked.state.pending.as_ref().unwrap().ordinal, 2);
            assert_eq!(
                checked.physical.active.as_ref().unwrap().pending_position,
                Some(1 + bypasses)
            );
            // Repair only the deliberately inconsistent old row. Both actual
            // receipts remain correctly owned; no refusal rolled back entry.
            for f in [&mut checked, &mut original] {
                let rows = &mut f.physical.active.as_mut().unwrap().rows;
                let mut row = rows[0].unwrap();
                row.return_pc = f.state.records[0].unwrap().raw.return_pc;
                rows.set(0, Some(row));
                f.physical.shape(&f.state).unwrap();
            }
            compare_visit(&mut checked, &mut original, &generations, false);
            for _ in 0..2 - bypasses {
                compare_visit(&mut checked, &mut original, &generations, false);
            }
            compare_finish(&mut checked, &mut original, &generations);
        }
        for field in 0..5 {
            let mut f = Fixture::new(10, order);
            f.controller.arm(&f.epoch).unwrap();
            f.physical.begin(&f.state).unwrap();
            f.call(true);
            f.call(false);
            f.call(false);
            let Visit {
                selected,
                pc,
                rsp,
                word,
                stamp,
                ..
            } = f.input(true);
            let committed = CheckedEntry::new(&mut f.physical, &mut f.state)
                .unwrap()
                .commit(selected, pc, rsp, word, stamp)
                .unwrap();
            let record = committed.checked.state.records[0];
            let function = committed.checked.state.functions[0];
            // Test-child access targets each complete new-record predicate.
            // It adds no unchecked path or mutation capability to production.
            match field {
                0 => committed
                    .checked
                    .state
                    .functions
                    .set(0, Some(committed.checked.physical.order[1])),
                1 => {
                    committed
                        .checked
                        .state
                        .records
                        .value_mut(0)
                        .unwrap()
                        .raw
                        .ordinal += 1
                }
                2 => {
                    committed
                        .checked
                        .state
                        .records
                        .value_mut(0)
                        .unwrap()
                        .raw
                        .return_pc += 8
                }
                3 => {
                    committed
                        .checked
                        .state
                        .records
                        .value_mut(0)
                        .unwrap()
                        .entry_rsp += 16
                }
                4 => {
                    committed
                        .checked
                        .state
                        .records
                        .value_mut(0)
                        .unwrap()
                        .return_word += 8
                }
                _ => unreachable!(),
            }
            committed.checked.state.shape().unwrap();
            let before = (
                normal_image(committed.checked.state),
                physical_image(committed.checked.physical),
            );
            assert_eq!(
                committed.checked.physical.shape(committed.checked.state),
                Err(error(Cause::Invariant))
            );
            assert_eq!(committed.finish(), Err(error(Cause::Invariant)));
            assert_eq!(
                (normal_image(&f.state), physical_image(&f.physical)),
                before
            );
            f.state.records.set(0, record);
            f.state.functions.set(0, function);
            f.physical.shape(&f.state).unwrap();
            f.visit(false).unwrap();
            assert_eq!(f.finish().0.unwrap().records().len(), 2);
        }
    }
}

#[test]
fn entry_proof_late_shared_and_journal_failures_keep_committed_entry() {
    for order in [[0, 1], [1, 0]] {
        for prior in [false, true] {
            for (bad_shared, bad_used) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                let mut f = Fixture::new(10, order);
                f.controller.arm(&f.epoch).unwrap();
                f.physical.begin(&f.state).unwrap();
                if prior {
                    f.call(true);
                    f.call(false);
                    f.call(false);
                }
                let owners = identities(&f.state, &f.physical);
                let Visit {
                    selected,
                    pc,
                    rsp,
                    word,
                    stamp,
                    ..
                } = f.input(true);
                let committed = CheckedEntry::new(&mut f.physical, &mut f.state)
                    .unwrap()
                    .commit(selected, pc, rsp, word, stamp)
                    .unwrap();
                committed
                    .checked
                    .physical
                    .shape(committed.checked.state)
                    .unwrap();
                let used = committed.checked.state.journal.used();
                if bad_shared {
                    committed
                        .checked
                        .physical
                        .shared
                        .failed
                        .store(true, Ordering::Release);
                }
                if bad_used {
                    committed.checked.state.journal.word(0, used as u64 + 1);
                }
                let at_postcheck = (
                    normal_image(committed.checked.state),
                    physical_image(committed.checked.physical),
                );
                assert_eq!(at_postcheck.0.len, usize::from(prior));
                assert_eq!(at_postcheck.0.depth, 1);
                assert_eq!(at_postcheck.0.sequence, u64::from(prior));
                let expected = if bad_shared {
                    Err(error(Cause::Identity))
                } else if bad_used {
                    Err(error(Cause::Invariant))
                } else {
                    Ok(())
                };
                assert_eq!(
                    committed.checked.physical.shape(committed.checked.state),
                    expected
                );
                assert_eq!(committed.finish(), expected);
                assert_eq!(
                    (normal_image(&f.state), physical_image(&f.physical)),
                    at_postcheck
                );
                assert_eq!(identities(&f.state, &f.physical), owners);
                f.physical.shared.failed.store(false, Ordering::Release);
                f.state.journal.word(0, used as u64);
                f.physical.shape(&f.state).unwrap();
                f.visit(false).unwrap();
                if !prior {
                    for _ in 0..3 {
                        f.call(false);
                    }
                }
                assert_eq!(
                    f.finish().0.unwrap().records().len(),
                    1 + usize::from(prior)
                );
            }
        }
    }
}

#[test]
fn entry_proof_partial_confirmation_failure_preserves_consumed_owner() {
    for order in [[0, 1], [1, 0]] {
        for bypasses in [0, 2] {
            for consume_before_error in [false, true] {
                let mut checked = Fixture::new(10, order);
                let mut original = Fixture::new(10, order);
                let generations =
                    Generations::new(checked.epoch.generation(), original.epoch.generation());
                for f in [&mut checked, &mut original] {
                    f.controller.arm(&f.epoch).unwrap();
                    f.physical.begin(&f.state).unwrap();
                    f.call(true);
                    for _ in 0..bypasses {
                        f.call(false);
                    }
                    if consume_before_error {
                        // Forge only diagnostic invocation metadata and its
                        // exact journal encoding. Confirmation preparation can
                        // succeed, but actual receipt completion must disagree.
                        let p = f.state.pending.as_mut().unwrap();
                        let IntervalEntrySummary::Admitted {
                            generation,
                            invocation,
                            history_len,
                            binding,
                        } = p.summary.unwrap()
                        else {
                            panic!()
                        };
                        let forged = IntervalEntrySummary::Admitted {
                            generation,
                            invocation: invocation + 1,
                            history_len,
                            binding,
                        };
                        p.summary = Some(forged);
                        p.returned.as_mut().unwrap().owner = timing::owner(forged);
                        let (_, _, bits) = history::packed_for_function(
                            &f.state.binding.session,
                            p.selected.function,
                            forged,
                        )
                        .unwrap();
                        f.state.journal.word(10, bits);
                        f.state.journal.word(17, bits);
                        assert!(
                            f.state
                                .confirmation(NormalAcknowledgement::NextEntry {
                                    ordinal: f.state.next
                                })
                                .is_ok()
                        );
                    } else {
                        f.state.journal.word(6, f.state.journal.page.0[6] + 1);
                    }
                    f.physical.shape(&f.state).unwrap();
                }
                let before = (
                    normal_image(&checked.state),
                    physical_image(&checked.physical),
                );
                compare_entry_refusal(&mut checked, &mut original, &generations, Cause::Invariant);
                assert_eq!(physical_image(&checked.physical), before.1);
                if consume_before_error {
                    for f in [&mut checked, &mut original] {
                        assert_eq!(f.state.model.completed_sequence(), 1);
                        assert_eq!(f.state.model.depth(), 0);
                        assert_eq!(f.state.len, 0);
                        assert_eq!(f.state.totals.confirmed, 0);
                        assert_eq!(f.state.totals.completed, 0);
                        let p = f.state.pending.as_mut().unwrap();
                        assert!(p.receipt.summary().is_none());
                        assert_eq!(p.slot.word, TOKEN);
                        assert_eq!(
                            f.state.model.finish_interval(
                                &mut p.receipt,
                                &mut p.slot,
                                p.returned.unwrap().observation()
                            ),
                            Err(IntervalExitError::Consumed)
                        );
                    }
                    // An attempted visit now fails at its unchanged pre-shape;
                    // it cannot replay the consumed receipt or admit a new one.
                    let failed = (
                        normal_image(&checked.state),
                        physical_image(&checked.physical),
                    );
                    compare_entry_refusal(
                        &mut checked,
                        &mut original,
                        &generations,
                        Cause::Invariant,
                    );
                    assert_eq!(
                        (
                            normal_image(&checked.state),
                            physical_image(&checked.physical)
                        ),
                        failed
                    );
                    for f in [&mut checked, &mut original] {
                        f.controller.disarm(&f.epoch).unwrap();
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
                } else {
                    assert_eq!(normal_image(&checked.state), before.0);
                    assert!(
                        checked
                            .state
                            .pending
                            .as_ref()
                            .unwrap()
                            .receipt
                            .summary()
                            .is_some()
                    );
                    assert_eq!(checked.state.model.completed_sequence(), 0);
                }
            }
        }
    }
}

#[test]
fn entry_proof_matches_reference_across_receipt_kinds_and_bypasses() {
    for k in [10, 1000] {
        for order in [[0, 1], [1, 0]] {
            for mode in 0..4 {
                for bypasses in 0..3 {
                    let mut checked = Fixture::new(k, order);
                    let mut original = Fixture::new(k, order);
                    let mut generations =
                        Generations::new(checked.epoch.generation(), original.epoch.generation());
                    if mode != 0 {
                        checked.controller.arm(&checked.epoch).unwrap();
                        original.controller.arm(&original.epoch).unwrap();
                    }
                    if mode == 1 {
                        checked.controller.disarm(&checked.epoch).unwrap();
                        original.controller.disarm(&original.epoch).unwrap();
                    }
                    if mode == 3 {
                        // Two invocations per function/batch exhaust each real
                        // fixed bank; no synthetic closed receipt is invented.
                        for _ in 0..k / 2 {
                            checked.physical.begin(&checked.state).unwrap();
                            original.physical.begin(&original.state).unwrap();
                            for _ in 0..4 {
                                compare_visit(&mut checked, &mut original, &generations, true);
                                compare_visit(&mut checked, &mut original, &generations, false);
                            }
                            compare_finish(&mut checked, &mut original, &generations);
                        }
                    }
                    checked.physical.begin(&checked.state).unwrap();
                    original.physical.begin(&original.state).unwrap();
                    compare_visit(&mut checked, &mut original, &generations, true);
                    compare_visit(&mut checked, &mut original, &generations, false);
                    let raw = checked.state.pending.as_ref().unwrap().returned.unwrap();
                    match mode {
                        0 => assert!(matches!(raw.owner, RawIntervalOwner::InitialDisarmed)),
                        1 => assert!(
                            matches!(raw.owner, RawIntervalOwner::Removed { generation } if generation == checked.epoch.generation().get())
                        ),
                        2 => assert!(
                            matches!(raw.owner, RawIntervalOwner::Sampled { generation, .. } if generation == checked.epoch.generation().get())
                        ),
                        3 => assert!(
                            matches!(raw.owner, RawIntervalOwner::FunctionClosed { generation } if generation == checked.epoch.generation().get())
                        ),
                        _ => unreachable!(),
                    }
                    if mode >= 2 {
                        checked.controller.disarm(&checked.epoch).unwrap();
                        original.controller.disarm(&original.epoch).unwrap();
                    }
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
                    let held = normal_image(&checked.state);
                    for _ in 0..bypasses {
                        compare_visit(&mut checked, &mut original, &generations, false);
                        assert_eq!(normal_image(&checked.state), held);
                        assert_eq!(
                            checked.physical.active.as_ref().unwrap().pending_position,
                            Some(0)
                        );
                    }
                    compare_visit(&mut checked, &mut original, &generations, true);
                    assert_eq!(checked.state.records[0].unwrap().raw, raw);
                    assert_eq!(checked.state.len, 1);
                    assert_eq!(
                        checked.physical.active.as_ref().unwrap().pending_position,
                        Some(1 + bypasses)
                    );
                    assert!(matches!(checked.state.pending.as_ref().unwrap().summary,
                        Some(IntervalEntrySummary::Admitted { generation, .. }) if generation == a.generation()));
                    compare_visit(&mut checked, &mut original, &generations, false);
                    for _ in 0..2 - bypasses {
                        compare_visit(&mut checked, &mut original, &generations, false);
                    }
                    compare_finish(&mut checked, &mut original, &generations);
                    checked.controller.disarm(&a).unwrap();
                    original.controller.disarm(&b).unwrap();
                    assert_eq!(
                        checked
                            .controller
                            .report(&a)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        1
                    );
                    assert_eq!(
                        original
                            .controller
                            .report(&b)
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
fn ret_normal_proof_matches_full_postshape_for_changed_fields() {
    for order in [[0, 1], [1, 0]] {
        for observed in [false, true] {
            for bypasses in 0..3 {
                // Real commit at each possible later position, with an actual
                // older Returned owner retained while another epoch is current.
                for fault in 0..6 {
                    let mut f = Fixture::new(10, order);
                    f.controller.arm(&f.epoch).unwrap();
                    f.physical.begin(&f.state).unwrap();
                    f.call(true);
                    let older_raw = f.state.pending.as_ref().unwrap().returned.unwrap();
                    f.controller.disarm(&f.epoch).unwrap();
                    let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
                    f.controller.arm(&next).unwrap();
                    let held = normal_image(&f.state);
                    for _ in 0..bypasses {
                        f.call(false);
                        assert_eq!(normal_image(&f.state), held);
                        assert_eq!(
                            f.physical.active.as_ref().unwrap().pending_position,
                            Some(0)
                        );
                    }
                    if observed {
                        f.visit(true).unwrap();
                    }
                    let normal_before = normal_image(&f.state);
                    let owners = identities(&f.state, &f.physical);
                    let Visit {
                        selected,
                        pc,
                        rsp,
                        word,
                        stamp,
                        ..
                    } = f.input(false);
                    let committed = CheckedRet::new(&mut f.physical, &mut f.state)
                        .unwrap()
                        .commit(selected, pc, rsp, word, stamp)
                        .unwrap();
                    committed
                        .checked
                        .physical
                        .shape(committed.checked.state)
                        .unwrap();
                    if !observed {
                        assert_eq!(normal_image(committed.checked.state), normal_before);
                    }
                    let raw = committed
                        .checked
                        .state
                        .pending
                        .as_ref()
                        .unwrap()
                        .returned
                        .unwrap();
                    let count = committed.checked.state.totals.ret_observed;
                    let generation = if observed {
                        next.generation()
                    } else {
                        f.epoch.generation()
                    };
                    assert!(
                        matches!(raw.owner, RawIntervalOwner::Sampled { generation: g, .. }
                        if g == generation.get())
                    );
                    match fault {
                        0 => {}
                        1 => committed.checked.state.pending.as_mut().unwrap().returned = None,
                        2 => {
                            committed.checked.state.totals.ret_observed =
                                count.checked_sub(1).unwrap()
                        }
                        3 => {
                            committed.checked.state.totals.ret_observed =
                                count.checked_add(1).unwrap()
                        }
                        4 => committed.checked.state.totals.ret_observed = u64::MAX,
                        5 => {
                            // Full shape checks presence, not the RawInterval
                            // payload. Preserve that acceptance exactly;
                            // observation and later confirmation stay unchanged.
                            let mut altered = raw;
                            altered.end.ticks += 1;
                            committed.checked.state.pending.as_mut().unwrap().returned =
                                Some(altered);
                        }
                        _ => unreachable!(),
                    }
                    let at_postcheck = (
                        normal_image(committed.checked.state),
                        physical_image(committed.checked.physical),
                    );
                    assert_eq!(
                        at_postcheck.1.active.as_ref().unwrap().position,
                        2 + bypasses
                    );
                    assert_eq!(
                        at_postcheck.1.active.as_ref().unwrap().rows[1 + bypasses],
                        Some(committed.row)
                    );
                    let expected = if matches!(fault, 0 | 5) {
                        Ok(())
                    } else {
                        Err(error(Cause::Invariant))
                    };
                    // This is the unchanged full physical + normal checker on
                    // the same actual committed state and real receipt identity.
                    assert_eq!(
                        committed.checked.physical.shape(committed.checked.state),
                        expected
                    );
                    assert_eq!(committed.finish(), expected);
                    assert_eq!(
                        (normal_image(&f.state), physical_image(&f.physical)),
                        at_postcheck
                    );
                    assert_eq!(identities(&f.state, &f.physical), owners);
                    // Restore only the deliberate changed-field fault, then
                    // consume the actual owner without rollback or second RET.
                    f.state.pending.as_mut().unwrap().returned = Some(raw);
                    f.state.totals.ret_observed = count;
                    f.physical.shape(&f.state).unwrap();
                    for _ in 0..(2 - bypasses) {
                        f.call(false);
                    }
                    let batch = f.finish().0.unwrap();
                    assert_eq!(batch.records().len(), if observed { 2 } else { 1 });
                    assert_eq!(batch.records()[0].record.raw, older_raw);
                    assert_eq!(batch.records().last().unwrap().record.raw, raw);
                    assert!(f.state.pending.is_none());
                    assert_eq!(
                        f.controller
                            .report(&f.epoch)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        1
                    );
                    f.controller.disarm(&next).unwrap();
                    assert_eq!(
                        f.controller
                            .report(&next)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        usize::from(observed)
                    );
                }
            }
        }
    }
}

#[test]
fn ret_normal_proof_keeps_combined_late_failure_order_and_committed_state() {
    for order in [[0, 1], [1, 0]] {
        for observed in [false, true] {
            // All combinations: shared Identity precedes changed-normal or
            // volatile Invariant, which precedes missing-active Outstanding.
            for faults in 0..16 {
                let bad_shared = faults & 1 != 0;
                let bad_count = faults & 2 != 0;
                let bad_used = faults & 4 != 0;
                let no_active = faults & 8 != 0;
                let mut f = Fixture::new(10, order);
                f.controller.arm(&f.epoch).unwrap();
                f.physical.begin(&f.state).unwrap();
                if observed {
                    f.visit(true).unwrap();
                }
                let normal_before = normal_image(&f.state);
                let owners = identities(&f.state, &f.physical);
                let Visit {
                    selected,
                    pc,
                    rsp,
                    word,
                    stamp,
                    ..
                } = f.input(false);
                let committed = CheckedRet::new(&mut f.physical, &mut f.state)
                    .unwrap()
                    .commit(selected, pc, rsp, word, stamp)
                    .unwrap();
                committed
                    .checked
                    .physical
                    .shape(committed.checked.state)
                    .unwrap();
                if !observed {
                    // An all-bypass batch has no pending owner or model frame.
                    assert_eq!(normal_image(committed.checked.state), normal_before);
                    assert!(committed.checked.state.pending.is_none());
                }
                let count = committed.checked.state.totals.ret_observed;
                let used = committed.checked.state.journal.used();
                let row = committed.row;
                if bad_shared {
                    committed
                        .checked
                        .physical
                        .shared
                        .failed
                        .store(true, Ordering::Release);
                }
                if bad_count {
                    committed.checked.state.totals.ret_observed = count.checked_add(1).unwrap();
                }
                if bad_used {
                    committed.checked.state.journal.word(0, used as u64 + 1);
                }
                // Child-only access exercises the retained active guard; no
                // production mutation hook or escaping borrow is introduced.
                let active = if no_active {
                    committed.checked.physical.active.take()
                } else {
                    None
                };
                let at_postcheck = (
                    normal_image(committed.checked.state),
                    physical_image(committed.checked.physical),
                );
                let expected = if bad_shared {
                    Err(error(Cause::Identity))
                } else if bad_count || bad_used {
                    Err(error(Cause::Invariant))
                } else if no_active {
                    Err(error(Cause::Outstanding))
                } else {
                    Ok(())
                };
                assert_eq!(
                    committed.checked.physical.shape(committed.checked.state),
                    expected
                );
                assert_eq!(committed.finish(), expected);
                assert_eq!(
                    (normal_image(&f.state), physical_image(&f.physical)),
                    at_postcheck
                );
                assert_eq!(identities(&f.state, &f.physical), owners);
                f.physical.shared.failed.store(false, Ordering::Release);
                f.state.totals.ret_observed = count;
                f.state.journal.word(0, used as u64);
                if let Some(active) = active {
                    f.physical.active = Some(active);
                }
                let b = f.physical.active.as_ref().unwrap();
                assert_eq!(b.position, 1);
                assert_eq!(b.rows[0], Some(row));
                f.physical.shape(&f.state).unwrap();
                for _ in 0..3 {
                    f.call(false);
                }
                let batch = f.finish().0;
                assert_eq!(
                    batch.as_ref().map(|b| b.records().len()),
                    observed.then_some(1)
                );
                f.controller.disarm(&f.epoch).unwrap();
                assert_eq!(
                    f.controller
                        .report(&f.epoch)
                        .unwrap()
                        .unwrap()
                        .records()
                        .count(),
                    usize::from(observed)
                );
            }
        }
    }
}

#[test]
fn entry_normal_proof_matches_full_postshape_across_receipts_and_rearm() {
    for order in [[0, 1], [1, 0]] {
        for mode in 0..4 {
            // No Pending, an older Returned, or that owner across rearm.
            for prior in 0..3 {
                let mut f = Fixture::new(10, order);
                if mode != 0 {
                    f.controller.arm(&f.epoch).unwrap();
                }
                if mode == 1 {
                    f.controller.disarm(&f.epoch).unwrap();
                }
                if mode == 3 {
                    // Actual fixed-bank exhaustion, not a forged closed receipt.
                    for _ in 0..5 {
                        f.physical.begin(&f.state).unwrap();
                        for _ in 0..4 {
                            f.call(true);
                        }
                        assert_eq!(f.finish().0.unwrap().records().len(), 4);
                    }
                }
                f.physical.begin(&f.state).unwrap();
                let older = if prior != 0 {
                    f.call(true);
                    let raw = f.state.pending.as_ref().unwrap().returned.unwrap();
                    let held = normal_image(&f.state);
                    for _ in 0..2 {
                        f.call(false);
                        assert_eq!(normal_image(&f.state), held);
                        assert_eq!(
                            f.physical.active.as_ref().unwrap().pending_position,
                            Some(0)
                        );
                    }
                    Some(raw)
                } else {
                    None
                };
                let next = if prior == 2 {
                    if mode >= 2 {
                        f.controller.disarm(&f.epoch).unwrap();
                    }
                    let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
                    f.controller.arm(&next).unwrap();
                    Some(next)
                } else {
                    None
                };
                let owners = identities(&f.state, &f.physical);
                let Visit {
                    selected,
                    pc,
                    rsp,
                    word,
                    stamp,
                    ..
                } = f.input(true);
                let committed = CheckedEntry::new(&mut f.physical, &mut f.state)
                    .unwrap()
                    .commit(selected, pc, rsp, word, stamp)
                    .unwrap();
                let pending = committed.checked.state.pending.as_ref().unwrap();
                let summary = pending.summary.unwrap();
                assert_eq!(pending.receipt.summary(), Some(summary));
                match if prior == 2 { 2 } else { mode } {
                    0 => assert!(matches!(
                        summary,
                        IntervalEntrySummary::Unsampled {
                            reason: UnsampledSummary::InitialDisarmed,
                            ..
                        }
                    )),
                    1 => assert!(
                        matches!(summary, IntervalEntrySummary::Unsampled { reason: UnsampledSummary::Removed { generation }, .. } if generation == f.epoch.generation())
                    ),
                    2 => assert!(
                        matches!(summary, IntervalEntrySummary::Admitted { generation, .. } if generation == next.as_ref().unwrap_or(&f.epoch).generation())
                    ),
                    3 => assert!(
                        matches!(summary, IntervalEntrySummary::Unsampled { reason: UnsampledSummary::FunctionClosed { generation, function }, .. } if generation == f.epoch.generation() && function == selected.function)
                    ),
                    _ => unreachable!(),
                }
                assert!(pending.returned.is_none());
                assert_eq!(committed.checked.state.len, usize::from(prior != 0));
                if let Some(raw) = older {
                    assert_eq!(committed.checked.state.records[0].unwrap().raw, raw);
                }
                let at_postcheck = (
                    normal_image(committed.checked.state),
                    physical_image(committed.checked.physical),
                );
                assert_eq!(
                    committed.checked.physical.shape(committed.checked.state),
                    Ok(())
                );
                assert_eq!(committed.finish(), Ok(()));
                assert_eq!(
                    (normal_image(&f.state), physical_image(&f.physical)),
                    at_postcheck
                );
                assert_eq!(identities(&f.state, &f.physical), owners);
                f.visit(false).unwrap();
                let raw = f.state.pending.as_ref().unwrap().returned.unwrap();
                assert_eq!(raw.owner, timing::owner(summary));
                if prior == 0 {
                    for _ in 0..3 {
                        f.call(false);
                    }
                }
                let batch = f.finish().0.unwrap();
                assert_eq!(batch.records().len(), 1 + usize::from(prior != 0));
                if let Some(raw) = older {
                    assert_eq!(batch.records()[0].record.raw, raw);
                }
                assert_eq!(batch.records().last().unwrap().record.raw, raw);
                assert!(f.state.pending.is_none());
                assert_eq!(f.state.model.depth(), 0);
                assert_eq!(f.state.model.completed_sequence(), f.state.totals.completed);
                if let Some(next) = next {
                    f.controller.disarm(&next).unwrap();
                    assert_eq!(
                        f.controller
                            .report(&next)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        1
                    );
                } else if mode >= 2 {
                    f.controller.disarm(&f.epoch).unwrap();
                }
                if mode == 2 {
                    let count = if prior == 2 {
                        1
                    } else {
                        1 + usize::from(prior != 0)
                    };
                    assert_eq!(
                        f.controller
                            .report(&f.epoch)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        count
                    );
                } else if mode == 3 {
                    assert_eq!(
                        f.controller
                            .report(&f.epoch)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        20
                    );
                }
            }
        }
    }
}

#[test]
fn entry_normal_proof_keeps_changed_fields_depth_and_late_error_order() {
    const ENTERED: u16 = 1;
    const RET_COUNT: u16 = 2;
    const NEXT: u16 = 4;
    const RETURNED: u16 = 8;
    const DEPTH: u16 = 16;
    const USED: u16 = 32;
    const WORD: u16 = 64;
    const SHARED: u16 = 128;
    const CONFIRMED: u16 = 256;
    const COMBINED: u16 = ENTERED | NEXT | RETURNED | DEPTH | USED | WORD;
    for order in [[0, 1], [1, 0]] {
        for prior in [false, true] {
            for fault in [
                0,
                ENTERED,
                RET_COUNT,
                NEXT,
                RETURNED,
                DEPTH,
                USED,
                WORD,
                SHARED,
                CONFIRMED,
                COMBINED,
                COMBINED | SHARED,
                USED | WORD,
                DEPTH | WORD,
                RET_COUNT | WORD,
                SHARED | WORD,
            ] {
                let mut f = Fixture::new(10, order);
                f.controller.arm(&f.epoch).unwrap();
                f.physical.begin(&f.state).unwrap();
                let (next, older) = if prior {
                    f.call(true);
                    let older = f.state.pending.as_ref().unwrap().returned.unwrap();
                    for _ in 0..2 {
                        f.call(false);
                    }
                    f.controller.disarm(&f.epoch).unwrap();
                    let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
                    f.controller.arm(&next).unwrap();
                    (Some(next), Some(older))
                } else {
                    (None, None)
                };
                let owners = identities(&f.state, &f.physical);
                let Visit {
                    selected,
                    pc,
                    rsp,
                    word,
                    stamp,
                    ..
                } = f.input(true);
                let committed = CheckedEntry::new(&mut f.physical, &mut f.state)
                    .unwrap()
                    .commit(selected, pc, rsp, word, stamp)
                    .unwrap();
                committed
                    .checked
                    .physical
                    .shape(committed.checked.state)
                    .unwrap();
                let totals = committed.checked.state.totals;
                let next_ordinal = committed.checked.state.next;
                let used = committed.checked.state.journal.used();
                let sequence = committed.checked.state.model.completed_sequence();
                let has = |bit| fault & bit != 0;
                if has(ENTERED) {
                    committed.checked.state.totals.entered += 1;
                }
                if has(RET_COUNT) {
                    committed.checked.state.totals.ret_observed += 1;
                }
                if has(CONFIRMED) {
                    committed.checked.state.totals.confirmed += 1;
                }
                if has(NEXT) {
                    committed.checked.state.next += 1;
                }
                if has(RETURNED) {
                    let p = committed.checked.state.pending.as_mut().unwrap();
                    p.returned = Some(RawInterval {
                        ordinal: p.ordinal,
                        entry_pc: p.entry_pc,
                        return_pc: pc + 16,
                        owner: timing::owner(p.summary.unwrap()),
                        start: p.start,
                        end: stamp,
                    });
                }
                if has(WORD) {
                    committed.checked.state.pending.as_mut().unwrap().word += 8;
                }
                // A real cancellation changes depth without forging a model
                // frame or owner, and does not advance completed_sequence.
                let cancelled = if has(DEPTH) {
                    let state = &mut *committed.checked.state;
                    let p = state.pending.as_mut().unwrap();
                    let payload = state.model.cancel(&mut p.slot).unwrap();
                    assert_eq!(
                        payload.outcome,
                        crate::frontend::PayloadOutcome::Cancelled(
                            crate::generation::CancelReason::Explicit
                        )
                    );
                    assert_eq!(state.model.completed_sequence(), sequence);
                    assert_eq!(state.model.depth(), 0);
                    Some(payload)
                } else {
                    None
                };
                if has(USED) {
                    committed.checked.state.journal.word(0, used as u64 + 1);
                }
                if has(SHARED) {
                    committed
                        .checked
                        .physical
                        .shared
                        .failed
                        .store(true, Ordering::Release);
                }
                let at_postcheck = (
                    normal_image(committed.checked.state),
                    physical_image(committed.checked.physical),
                );
                let expected = if has(SHARED) {
                    Err(error(Cause::Identity))
                } else if fault & (ENTERED | RET_COUNT | NEXT | RETURNED | DEPTH | USED | CONFIRMED)
                    != 0
                {
                    Err(error(Cause::Invariant))
                } else if has(WORD) {
                    Err(error(Cause::Return))
                } else {
                    Ok(())
                };
                assert_eq!(
                    committed.checked.physical.shape(committed.checked.state),
                    expected
                );
                assert_eq!(committed.finish(), expected);
                assert_eq!(
                    (normal_image(&f.state), physical_image(&f.physical)),
                    at_postcheck
                );
                assert_eq!(identities(&f.state, &f.physical), owners);
                // Repair only diagnostic faults. A real cancellation is never
                // rolled back, retried as completion, or replaced by a new owner.
                f.physical.shared.failed.store(false, Ordering::Release);
                f.state.totals = totals;
                f.state.next = next_ordinal;
                f.state.journal.word(0, used as u64);
                let p = f.state.pending.as_mut().unwrap();
                p.returned = None;
                p.word = word;
                if let Some(payload) = cancelled {
                    assert!(p.receipt.summary().is_some());
                    assert_eq!(p.slot.word, TOKEN);
                    assert_eq!(f.state.shape(), Err(error(Cause::Invariant)));
                    let current = next.as_ref().unwrap_or(&f.epoch);
                    f.controller.disarm(current).unwrap();
                    let report = f.controller.report(current).unwrap().unwrap();
                    let records: Vec<_> = report.records().collect();
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0].payload, Some(payload));
                    assert_eq!(records[0].record.admission, payload.admission);
                } else {
                    f.physical.shape(&f.state).unwrap();
                    f.visit(false).unwrap();
                    if !prior {
                        for _ in 0..3 {
                            f.call(false);
                        }
                    }
                    assert_eq!(
                        f.finish().0.unwrap().records().len(),
                        1 + usize::from(prior)
                    );
                    let current = next.as_ref().unwrap_or(&f.epoch);
                    f.controller.disarm(current).unwrap();
                    assert_eq!(
                        f.controller
                            .report(current)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        1
                    );
                }
                if prior {
                    assert_eq!(
                        f.controller
                            .report(&f.epoch)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        1
                    );
                    assert_eq!(
                        f.state.records[0].map(|r| r.raw),
                        if has(DEPTH) { older } else { None }
                    );
                }
            }
        }
    }
}

// Literal complete pre-occupancy shape, renamed only. Both methods inspect the same
// real fixture, so no generation renaming or simulated model can hide a change.
impl PhysicalState {
    fn shape_before_occupancy(&self, state: &NormalState) -> Result<(), BridgeError> {
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

fn compare_occupancy_shape_unchanged(f: &Fixture, expected: Result<(), BridgeError>) {
    let before = (
        normal_image(&f.state),
        physical_image(&f.physical),
        identities(&f.state, &f.physical),
    );
    let original = f.physical.shape_before_occupancy(&f.state);
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
fn physical_occupancy_matches_original_for_all_6480_metadata_patterns() {
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
                let mut digits = row_pattern;
                for (index, original_row) in rows.iter().enumerate() {
                    b.seen.set(
                        index,
                        (seen_mask & (1 << index) != 0).then_some(index as u64 + 1),
                    );
                    let kind = digits % 3;
                    digits /= 3;
                    let mut row = *original_row;
                    row.observed_ordinal = (kind == 2).then_some(index as u64 + 1);
                    b.rows.set(index, (kind != 0).then_some(row));
                }
                assert_eq!(digits, 0);
                // Prove these cases reach physical checks, not NormalState's
                // earlier refusal path. The five accepted shapes are exactly
                // the empty/one/two/three/four all-bypass return prefixes.
                assert_eq!(f.physical.matches(&f.state), Ok(()));
                assert_eq!(f.state.shape(), Ok(()));
                let bypass_prefix = (3usize.pow(position as u32) - 1) / 2;
                if seen_mask == 0 && row_pattern == bypass_prefix {
                    compare_occupancy_shape_unchanged(&f, Ok(()));
                    accepted += 1;
                } else {
                    compare_occupancy_shape_unchanged(&f, Err(error(Cause::Invariant)));
                    refused += 1;
                }
            }
        }
    }
    assert_eq!((accepted, refused), (5, 6475));
    let b = f.physical.active.as_mut().unwrap();
    b.position = 4;
    b.rsp = Some(rows[0].entry_rsp);
    for (index, row) in rows.iter().enumerate() {
        b.seen.set(index, None);
        b.rows.set(index, Some(*row));
    }
    compare_occupancy_shape_unchanged(&f, Ok(()));
    assert!(f.finish().0.is_none());
    physical_occupancy_keeps_exact_error_precedence_and_underflow();
}

#[test]
fn physical_occupancy_matches_original_live_prefixes_and_rearm() {
    let mut batches = 0;
    for k in [10, 1000] {
        for order in [[0, 1], [1, 0]] {
            for mask in 0u8..16 {
                let mut f = Fixture::new(k, order);
                f.controller.arm(&f.epoch).unwrap();
                compare_occupancy_shape_unchanged(&f, Err(error(Cause::Outstanding)));
                f.physical.begin(&f.state).unwrap();
                compare_occupancy_shape_unchanged(&f, Ok(()));
                let mut second = None;
                for index in 0..4 {
                    let observed = mask & (1 << index) != 0;
                    if observed {
                        f.visit(true).unwrap();
                        compare_occupancy_shape_unchanged(&f, Ok(()));
                    }
                    let before_return = normal_image(&f.state);
                    f.visit(false).unwrap();
                    if !observed {
                        // A bypass must not consume/replace an older Returned,
                        // including after controller rearm and two bypasses.
                        assert_eq!(normal_image(&f.state), before_return);
                    }
                    compare_occupancy_shape_unchanged(&f, Ok(()));
                    if index == 0 {
                        let prior_pending = normal_image(&f.state).pending;
                        f.controller.disarm(&f.epoch).unwrap();
                        let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
                        f.controller.arm(&next).unwrap();
                        assert_eq!(normal_image(&f.state).pending, prior_pending);
                        compare_occupancy_shape_unchanged(&f, Ok(()));
                        second = Some(next);
                    }
                }
                let second = second.unwrap();
                let (sparse, rows) = f.finish();
                let count = mask.count_ones() as usize;
                assert_eq!(
                    rows.iter().filter(|r| r.observed_ordinal.is_some()).count(),
                    count
                );
                assert_eq!(sparse.as_ref().map_or(0, |s| s.records().len()), count);
                if let Some(sparse) = sparse {
                    for (record, row) in sparse
                        .records()
                        .iter()
                        .zip(rows.iter().filter(|r| r.observed_ordinal.is_some()))
                    {
                        let generation = if row.position == 0 {
                            f.epoch.generation()
                        } else {
                            second.generation()
                        };
                        assert!(
                            matches!(record.record.raw.owner, RawIntervalOwner::Sampled { generation: owner, .. } if owner == generation.get())
                        );
                        assert_eq!(Some(record.record.raw.ordinal), row.observed_ordinal);
                        assert_eq!(record.function, row.function);
                        assert_eq!(record.record.raw.return_pc, row.return_pc);
                        assert_eq!(record.record.entry_rsp, row.entry_rsp);
                        assert_eq!(record.record.return_word, row.return_word);
                    }
                }
                compare_occupancy_shape_unchanged(&f, Err(error(Cause::Outstanding)));
                let first_count = usize::from(mask & 1 != 0);
                assert_eq!(
                    f.controller
                        .report(&f.epoch)
                        .unwrap()
                        .unwrap()
                        .records()
                        .count(),
                    first_count
                );
                f.controller.disarm(&second).unwrap();
                assert_eq!(
                    f.controller
                        .report(&second)
                        .unwrap()
                        .unwrap()
                        .records()
                        .count(),
                    count - first_count
                );
                batches += 1;
            }
        }
    }
    assert_eq!(batches, 64);
}

// The exhaustive physical-query control also exercises the surrounding old
// first-error boundaries; these are not capsule-local predicate tests.
fn physical_occupancy_keeps_exact_error_precedence_and_underflow() {
    for order in [[0, 1], [1, 0]] {
        let mut f = Fixture::new(10, order);
        f.physical.begin(&f.state).unwrap();
        compare_occupancy_shape_unchanged(&f, Ok(()));
        // The initial overflow is after matches/normal/active, but before any
        // physical occupancy or cursor check. Restore each fault explicitly.
        f.physical.batches = u64::MAX;
        f.physical.shared.failed.store(true, Ordering::Release);
        compare_occupancy_shape_unchanged(&f, Err(error(Cause::Identity)));
        f.physical.shared.failed.store(false, Ordering::Release);
        f.state.len = CALLS + 1;
        compare_occupancy_shape_unchanged(&f, Err(error(Cause::Invariant)));
        f.state.len = 0;
        let active = f.physical.active.take();
        compare_occupancy_shape_unchanged(&f, Err(error(Cause::Outstanding)));
        f.physical.active = active;
        assert_eq!(f.state.shape(), Ok(()));
        for position in [5, usize::MAX] {
            f.physical.active.as_mut().unwrap().position = position;
            compare_occupancy_shape_unchanged(&f, Err(error(Cause::Capacity)));
            f.physical.batches = 0;
            compare_occupancy_shape_unchanged(&f, Err(error(Cause::Invariant)));
            f.physical.batches = u64::MAX;
        }
        f.physical.active.as_mut().unwrap().position = 0;
        f.physical.active.as_mut().unwrap().seen.set(3, Some(1));
        compare_occupancy_shape_unchanged(&f, Err(error(Cause::Capacity)));
        f.physical.batches = 0;
        compare_occupancy_shape_unchanged(&f, Err(error(Cause::Invariant)));
        f.physical.active.as_mut().unwrap().seen.set(3, None);
        compare_occupancy_shape_unchanged(&f, Ok(()));
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
            compare_occupancy_shape_unchanged(&f, Err(error(Cause::Invariant)));
        }
        f.state.cursor = cursor;
        f.physical.active.as_mut().unwrap().before.cursor = cursor;
        compare_occupancy_shape_unchanged(&f, Ok(()));
        f.controller.arm(&f.epoch).unwrap();
        f.call(true);
        compare_occupancy_shape_unchanged(&f, Ok(()));
        let old_next = f.physical.active.as_ref().unwrap().before.next;
        let old_seen = f.physical.active.as_ref().unwrap().seen[0];
        let old_row = f.physical.active.as_ref().unwrap().rows[0];
        let b = f.physical.active.as_mut().unwrap();
        b.before.next = u64::MAX;
        b.seen.set(0, Some(u64::MAX));
        let mut changed = b.rows[0].unwrap();
        changed.observed_ordinal = Some(u64::MAX);
        b.rows.set(0, Some(changed));
        assert_eq!(f.state.shape(), Ok(()));
        // Counts/prefix are valid: later ordinal overflow must remain Capacity.
        compare_occupancy_shape_unchanged(&f, Err(error(Cause::Capacity)));
        let row = f.physical.active.as_ref().unwrap().rows[0];
        f.physical.active.as_mut().unwrap().rows.set(0, None);
        compare_occupancy_shape_unchanged(&f, Err(error(Cause::Invariant)));
        let mut changed = row.unwrap();
        changed.return_pc += 1;
        f.physical
            .active
            .as_mut()
            .unwrap()
            .rows
            .set(0, Some(changed));
        compare_occupancy_shape_unchanged(&f, Err(error(Cause::Capacity)));
        let b = f.physical.active.as_mut().unwrap();
        b.before.next = old_next;
        b.seen.set(0, old_seen);
        let mut changed = b.rows[0].unwrap();
        changed.observed_ordinal = old_row.unwrap().observed_ordinal;
        b.rows.set(0, Some(changed));
        compare_occupancy_shape_unchanged(&f, Err(error(Cause::Identity)));
        f.physical.active.as_mut().unwrap().rows.set(0, old_row);
        compare_occupancy_shape_unchanged(&f, Ok(()));
        for _ in 0..3 {
            f.call(false);
        }
        assert_eq!(f.finish().0.unwrap().records().len(), 1);
    }
}

// The old full-shape oracle examines the same real receipt/model state. Include
// the new capsule's complete test-only image, so a query cannot repair facts,
// replace their retained owner, or mutate masks while returning the right error.
fn geometry_shape_unchanged(f: &Fixture, expected: Result<(), BridgeError>) {
    let rows = f.physical.active.as_ref().map(|b| b.rows.clone());
    compare_occupancy_shape_unchanged(f, expected);
    assert_eq!(f.physical.active.as_ref().map(|b| b.rows.clone()), rows);
}

fn geometry_hit(f: &Fixture, index: usize, pc: u64) -> bool {
    let selected = f.physical.order[index % 2];
    f.physical.active.as_ref().unwrap().rows.geometry_matches(
        index,
        &f.state,
        selected,
        ENTRIES[selected.index],
        pc,
    )
}

#[test]
fn geometry_facts_match_original_across_masks_rearm_and_reset() {
    let mut batches = 0;
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
                let mut next = None;
                for index in 0..4 {
                    let observed = mask & (1 << index) != 0;
                    if observed {
                        compare_visit(&mut checked, &mut original, &generations, true);
                    }
                    let prior = normal_image(&checked.state);
                    let pc = checked.input(false).pc;
                    assert!(!geometry_hit(&checked, index, pc));
                    compare_visit(&mut checked, &mut original, &generations, false);
                    assert!(geometry_hit(&checked, index, pc));
                    // The original transition uses the generic write, which
                    // must not accidentally mint a geometry proof.
                    assert!(!geometry_hit(&original, index, pc));
                    if !observed {
                        assert_eq!(normal_image(&checked.state), prior);
                    }
                    geometry_shape_unchanged(&checked, Ok(()));
                    geometry_shape_unchanged(&original, Ok(()));
                    if index == 0 {
                        let older = normal_image(&checked.state).pending;
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
                        assert_eq!(normal_image(&checked.state).pending, older);
                        assert!(geometry_hit(&checked, index, pc));
                        geometry_shape_unchanged(&checked, Ok(()));
                        next = Some((a, b));
                    }
                }
                compare_finish(&mut checked, &mut original, &generations);
                geometry_shape_unchanged(&checked, Err(error(Cause::Outstanding)));
                let (a, b) = next.unwrap();
                checked.controller.disarm(&a).unwrap();
                original.controller.disarm(&b).unwrap();
                let first = usize::from(mask & 1 != 0);
                for (f, second) in [(&checked, &a), (&original, &b)] {
                    assert_eq!(
                        f.controller
                            .report(&f.epoch)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        first
                    );
                    assert_eq!(
                        f.controller
                            .report(second)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        mask.count_ones() as usize - first
                    );
                }
                // A new batch has no prior fact even though owner, selected
                // function, entry and return-PC numbers are all reused.
                checked.physical.begin(&checked.state).unwrap();
                original.physical.begin(&original.state).unwrap();
                for index in 0..4 {
                    let selected = checked.physical.order[index % 2];
                    for pc in [ENTRIES[selected.index] + 16, ENTRIES[selected.index] + 24] {
                        assert!(!geometry_hit(&checked, index, pc));
                    }
                }
                for index in 0..4 {
                    let pc = checked.input(false).pc;
                    compare_visit(&mut checked, &mut original, &generations, false);
                    assert!(geometry_hit(&checked, index, pc));
                    geometry_shape_unchanged(&checked, Ok(()));
                }
                compare_finish(&mut checked, &mut original, &generations);
                batches += 2;
            }
        }
    }
    assert_eq!(batches, 128);
}

#[test]
fn geometry_facts_require_exact_owner_and_key_and_invalidate_on_replacement() {
    geometry_fact_owner_is_retained_until_the_batch_drops();
    for k in [10, 1000] {
        for order in [[0, 1], [1, 0]] {
            let mut a = Fixture::new(k, order);
            let mut b = Fixture::new(k, order);
            for f in [&mut a, &mut b] {
                f.physical.begin(&f.state).unwrap();
                f.call(false);
                geometry_shape_unchanged(f, Ok(()));
            }
            assert!(!Arc::ptr_eq(&a.state.binding, &b.state.binding));
            let selected = a.physical.order[0];
            let row = a.physical.active.as_ref().unwrap().rows[0].unwrap();
            let entry = ENTRIES[selected.index];
            assert_eq!(
                a.physical.active.as_ref().unwrap().rows[0],
                b.physical.active.as_ref().unwrap().rows[0]
            );
            assert!(geometry_hit(&a, 0, row.return_pc));
            let rows = &a.physical.active.as_ref().unwrap().rows;
            let before = rows.clone();
            let mut wrong_index = selected;
            wrong_index.index = 1 - selected.index;
            let mut wrong_function = selected;
            wrong_function.function = IDS[1 - selected.index];
            for (index, key, start, pc) in [
                (1, selected, entry, row.return_pc),
                (0, wrong_index, entry, row.return_pc),
                (0, wrong_function, entry, row.return_pc),
                (0, selected, entry + 1, row.return_pc),
                (0, selected, entry, row.return_pc + 1),
            ] {
                assert!(!rows.geometry_matches(index, &a.state, key, start, pc));
                assert_eq!(rows, &before);
            }
            assert!(!rows.geometry_matches(0, &b.state, selected, entry, row.return_pc));
            assert_eq!(rows, &before);
            // Identical replacement is still a mutation boundary: it drops the
            // fact, while the literal geometry fallback accepts the raw row.
            a.physical.active.as_mut().unwrap().rows.set(0, Some(row));
            assert!(!geometry_hit(&a, 0, row.return_pc));
            geometry_shape_unchanged(&a, Ok(()));
            a.physical
                .active
                .as_mut()
                .unwrap()
                .rows
                .checked_return(&a.state, selected, row.return_pc)
                .unwrap()
                .set(0, row);
            assert!(geometry_hit(&a, 0, row.return_pc));
            for index in [4, usize::MAX] {
                let before = a.physical.active.as_ref().unwrap().rows.clone();
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        a.physical
                            .active
                            .as_mut()
                            .unwrap()
                            .rows
                            .set(index, Some(row));
                    }))
                    .is_err()
                );
                assert_eq!(a.physical.active.as_ref().unwrap().rows, before);
            }
            a.physical.active.as_mut().unwrap().rows.set(0, None);
            assert!(!geometry_hit(&a, 0, row.return_pc));
            geometry_shape_unchanged(&a, Err(error(Cause::Invariant)));
            a.physical.active.as_mut().unwrap().rows.set(0, Some(row));
            assert!(!geometry_hit(&a, 0, row.return_pc));
            geometry_shape_unchanged(&a, Ok(()));
            let mut invalid = row;
            invalid.return_pc += 1;
            a.physical
                .active
                .as_mut()
                .unwrap()
                .rows
                .set(0, Some(invalid));
            assert!(!geometry_hit(&a, 0, invalid.return_pc));
            geometry_shape_unchanged(&a, Err(error(Cause::Identity)));
            a.physical
                .active
                .as_mut()
                .unwrap()
                .rows
                .checked_return(&a.state, selected, row.return_pc)
                .unwrap()
                .set(0, row);
            assert!(geometry_hit(&a, 0, row.return_pc));
            // Move the entire capsule. All numeric geometry and raw rows stay
            // equal, but its retained Arc still belongs to the other fixture.
            std::mem::swap(
                &mut a.physical.active.as_mut().unwrap().rows,
                &mut b.physical.active.as_mut().unwrap().rows,
            );
            assert!(!geometry_hit(&a, 0, row.return_pc));
            assert!(!geometry_hit(&b, 0, row.return_pc));
            geometry_shape_unchanged(&a, Ok(()));
            geometry_shape_unchanged(&b, Ok(()));
            b.physical
                .active
                .as_mut()
                .unwrap()
                .rows
                .checked_return(&b.state, selected, row.return_pc)
                .unwrap()
                .set(0, row);
            assert!(!geometry_hit(&b, 0, row.return_pc));
            geometry_shape_unchanged(&b, Ok(()));
            std::mem::swap(
                &mut a.physical.active.as_mut().unwrap().rows,
                &mut b.physical.active.as_mut().unwrap().rows,
            );
            // A capsule with no owner also uses only the original fallback,
            // even when the actual checked-return API successfully writes it.
            a.physical.active.as_mut().unwrap().rows = RowSlots::empty();
            a.physical
                .active
                .as_mut()
                .unwrap()
                .rows
                .checked_return(&a.state, selected, row.return_pc)
                .unwrap()
                .set(0, row);
            assert!(!geometry_hit(&a, 0, row.return_pc));
            geometry_shape_unchanged(&a, Ok(()));
            for f in [&mut a, &mut b] {
                for _ in 0..3 {
                    f.call(false);
                }
                assert!(f.finish().0.is_none());
                f.physical.begin(&f.state).unwrap();
                f.call(false);
                assert!(geometry_hit(f, 0, row.return_pc));
                geometry_shape_unchanged(f, Ok(()));
                for _ in 0..3 {
                    f.call(false);
                }
                assert!(f.finish().0.is_none());
            }
        }
    }
}

#[test]
fn geometry_facts_preserve_original_geometry_error_precedence() {
    for order in [[0, 1], [1, 0]] {
        let mut f = Fixture::new(10, order);
        f.controller.arm(&f.epoch).unwrap();
        f.physical.begin(&f.state).unwrap();
        f.call(true);
        f.visit(true).unwrap();
        // Geometry succeeds, then a changed pending position refuses the
        // observed transition. Dropping its checked-row token must install
        // neither the raw row nor a geometry fact; the real receipt remains
        // available for its original RET after the deliberate fault is repaired.
        let Visit {
            selected,
            pc,
            rsp,
            word,
            stamp,
            ..
        } = f.input(false);
        let checked = CheckedRet::new(&mut f.physical, &mut f.state).unwrap();
        let pending_position = checked.physical.active.as_ref().unwrap().pending_position;
        assert_eq!(pending_position, Some(1));
        checked.physical.active.as_mut().unwrap().pending_position = Some(0);
        let refusal_image = (
            normal_image(checked.state),
            physical_image(checked.physical),
            identities(checked.state, checked.physical),
        );
        let refusal_rows = checked.physical.active.as_ref().unwrap().rows.clone();
        assert_eq!(
            checked.commit(selected, pc, rsp, word, stamp).map(|_| ()),
            Err(error(Cause::Return))
        );
        assert_eq!(
            (
                normal_image(&f.state),
                physical_image(&f.physical),
                identities(&f.state, &f.physical)
            ),
            refusal_image,
        );
        assert_eq!(f.physical.active.as_ref().unwrap().rows, refusal_rows);
        assert!(!geometry_hit(&f, 1, pc));
        f.physical.active.as_mut().unwrap().pending_position = pending_position;
        f.visit(false).unwrap();
        assert!(geometry_hit(&f, 1, pc));
        assert_eq!(f.state.len, 1);
        assert_eq!(f.state.shape(), Ok(()));
        let row = f.physical.active.as_ref().unwrap().rows[0].unwrap();
        assert!(geometry_hit(&f, 0, row.return_pc));
        geometry_shape_unchanged(&f, Ok(()));
        let mut invalid = row;
        invalid.return_pc += 1;
        f.physical
            .active
            .as_mut()
            .unwrap()
            .rows
            .set(0, Some(invalid));
        geometry_shape_unchanged(&f, Err(error(Cause::Identity)));
        let len = f.state.len;
        f.state.len = CALLS + 1;
        geometry_shape_unchanged(&f, Err(error(Cause::Invariant)));
        f.state.len = len;
        f.physical.batches = u64::MAX;
        geometry_shape_unchanged(&f, Err(error(Cause::Capacity)));
        f.physical.batches = 0;
        let mut bad_word = invalid;
        bad_word.return_word += 8;
        f.physical
            .active
            .as_mut()
            .unwrap()
            .rows
            .set(0, Some(bad_word));
        geometry_shape_unchanged(&f, Err(error(Cause::Invariant)));
        f.physical
            .active
            .as_mut()
            .unwrap()
            .rows
            .set(0, Some(invalid));
        let pending_word = f.state.pending.as_ref().unwrap().word;
        f.state.pending.as_mut().unwrap().word += 8;
        assert_eq!(f.state.shape(), Ok(()));
        geometry_shape_unchanged(&f, Err(error(Cause::Identity)));
        f.physical.active.as_mut().unwrap().rows.set(0, Some(row));
        geometry_shape_unchanged(&f, Err(error(Cause::Return)));
        f.state.pending.as_mut().unwrap().word = pending_word;
        // Another valid RET address must reach the later confirmed-record join,
        // rather than use a stale fact to skip that independent relation.
        let mut different_valid_pc = row;
        different_valid_pc.return_pc = ENTRIES[f.physical.order[0].index] + 24;
        assert_ne!(different_valid_pc.return_pc, row.return_pc);
        f.physical
            .active
            .as_mut()
            .unwrap()
            .rows
            .set(0, Some(different_valid_pc));
        assert_eq!(f.state.shape(), Ok(()));
        geometry_shape_unchanged(&f, Err(error(Cause::Invariant)));
        f.physical.active.as_mut().unwrap().rows.set(0, Some(row));
        let selected = f.physical.order[0];
        f.physical
            .active
            .as_mut()
            .unwrap()
            .rows
            .checked_return(&f.state, selected, row.return_pc)
            .unwrap()
            .set(0, row);
        assert!(geometry_hit(&f, 0, row.return_pc));
        // Preserve the original unchecked canonical site-index panic even with
        // a previously valid cached row. Neither shape may mutate on refusal.
        for index in [2, usize::MAX] {
            f.physical.order[0].index = index;
            let before = (
                normal_image(&f.state),
                physical_image(&f.physical),
                identities(&f.state, &f.physical),
            );
            let facts = f.physical.active.as_ref().unwrap().rows.clone();
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f
                    .physical
                    .shape_before_occupancy(&f.state)))
                .is_err()
            );
            assert_eq!(
                (
                    normal_image(&f.state),
                    physical_image(&f.physical),
                    identities(&f.state, &f.physical)
                ),
                before
            );
            assert_eq!(f.physical.active.as_ref().unwrap().rows, facts);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f
                    .physical
                    .shape(&f.state)))
                .is_err()
            );
            assert_eq!(
                (
                    normal_image(&f.state),
                    physical_image(&f.physical),
                    identities(&f.state, &f.physical)
                ),
                before
            );
            assert_eq!(f.physical.active.as_ref().unwrap().rows, facts);
        }
        f.physical.order[0] = selected;
        geometry_shape_unchanged(&f, Ok(()));
        for _ in 0..2 {
            f.call(false);
        }
        assert_eq!(f.finish().0.unwrap().records().len(), 2);
        f.controller.disarm(&f.epoch).unwrap();
        assert_eq!(
            f.controller
                .report(&f.epoch)
                .unwrap()
                .unwrap()
                .records()
                .count(),
            2
        );
    }
}

// Deliberately move one private capsule beyond its source fixture in the test.
// The retained binding prevents ABA; a foreign live attachment still falls back.
// Production never moves this storage outside its own active PhysicalState.
fn geometry_fact_owner_is_retained_until_the_batch_drops() {
    let mut source = Fixture::new(10, [0, 1]);
    let mut target = Fixture::new(10, [0, 1]);
    for f in [&mut source, &mut target] {
        f.physical.begin(&f.state).unwrap();
        f.call(false);
    }
    let owner = Arc::downgrade(&source.state.binding);
    let pc = source.physical.active.as_ref().unwrap().rows[0]
        .unwrap()
        .return_pc;
    std::mem::swap(
        &mut source.physical.active.as_mut().unwrap().rows,
        &mut target.physical.active.as_mut().unwrap().rows,
    );
    drop(source);
    assert!(owner.upgrade().is_some());
    assert!(!geometry_hit(&target, 0, pc));
    geometry_shape_unchanged(&target, Ok(()));
    for _ in 0..3 {
        target.call(false);
    }
    assert!(target.finish().0.is_none());
    assert!(owner.upgrade().is_none());
}

// Literal original transition, renamed only. The paired candidate uses the real
// private current-RET capability; this reference still performs full geometry.
impl NormalState {
    fn observe_transition_before_current_ret(
        &mut self,
        selected: SelectedFunction,
        pc: u64,
        rsp: u64,
        word: u64,
        end: RawTimestamp,
    ) -> Result<(), BridgeError> {
        let pending = self.pending.as_ref().ok_or(error(Cause::Return))?;
        self.selected_geometry(selected, pending.entry_pc, Some(pc))?;
        let p = self.pending.as_mut().ok_or(error(Cause::Return))?;
        if p.selected != selected
            || p.returned.is_some()
            || p.rsp != rsp
            || p.word != word
            || p.slot.identity != p.ordinal
        {
            return Err(error(Cause::Return));
        }
        let summary = p.summary.ok_or(error(Cause::Invariant))?;
        let (kind, generation, bits) =
            history::packed_for_function(&self.binding.session, p.selected.function, summary)?;
        let observed = self
            .totals
            .ret_observed
            .checked_add(1)
            .ok_or(error(Cause::Capacity))?;
        if self.journal.used() >= EVENTS || self.len >= CALLS {
            return Err(error(Cause::Capacity));
        }
        if let Some(accuracy) = &mut self.accuracy {
            accuracy.end(self.len, selected, p.ordinal)?;
        }
        let raw = RawInterval {
            ordinal: p.ordinal,
            entry_pc: p.entry_pc,
            return_pc: pc,
            owner: timing::owner(summary),
            start: p.start,
            end,
        };
        self.journal
            .row([kind + 1, p.ordinal, pc, rsp, word, generation, bits]);
        p.returned = Some(raw);
        self.totals.ret_observed = observed;
        // Receipt, sampled frame and FunctionClosed owner remain untouched.
        Ok(())
    }
}

// Inject after the real full precheck/current geometry, while the test child
// holds the production token. Production exposes no mutable-state capability.
fn current_ret_fault(state: &mut NormalState, fault: usize) -> Option<Pending> {
    if matches!(fault, 0 | 1 | 2 | 3 | 4 | 12 | 15) {
        state.pending.as_mut().unwrap().entry_pc += 1;
    }
    if matches!(fault, 2 | 5 | 6 | 16) {
        state.pending.as_mut().unwrap().word += 8;
    }
    match fault {
        1 | 5 => state.journal.word(0, state.journal.used() as u64 + 1),
        3 | 7 => state.pending.as_mut().unwrap().summary = None,
        4 | 8 => state.totals.ret_observed = u64::MAX,
        9 | 10 => {
            let removed = state.pending.take();
            state
                .journal
                .word(0, (state.len * 2 + usize::from(fault == 10)) as u64);
            return removed;
        }
        11 | 12 => {
            state.len = CALLS;
            state.journal.word(0, (CALLS * 2 + 1) as u64);
        }
        13 => state.pending.as_mut().unwrap().selected.function = FunctionId(u64::MAX),
        _ => {}
    }
    if matches!(fault, 14..=16) {
        match state.pending.as_mut().unwrap().summary.as_mut().unwrap() {
            IntervalEntrySummary::Admitted { history_len, .. }
            | IntervalEntrySummary::Unsampled { history_len, .. } => *history_len = usize::MAX,
        }
    }
    None
}

fn current_ret_expected(fault: usize) -> Cause {
    match fault {
        0 | 2 | 3 | 4 | 12 | 15 => Cause::Identity,
        1 | 5 | 7 | 10 => Cause::Invariant,
        6 | 9 | 13 | 16 => Cause::Return,
        8 | 11 | 14 => Cause::Capacity,
        _ => unreachable!(),
    }
}

fn current_ret_refusal(f: &mut Fixture, fault: usize, original: bool) {
    let Visit {
        selected,
        pc,
        rsp,
        word,
        stamp,
        ..
    } = f.input(false);
    let before = normal_image(&f.state);
    let physical = physical_image(&f.physical);
    let owners = identities(&f.state, &f.physical);
    let rows = f.physical.active.as_ref().unwrap().rows.clone();
    let checked = CheckedVisit::new(&f.physical, &mut f.state).unwrap();
    let proof = checked
        .return_geometry(&mut f.physical.active.as_mut().unwrap().rows, selected, pc)
        .unwrap();
    let removed = current_ret_fault(proof.checked.state, fault);
    let damaged = normal_image(proof.checked.state);
    let result = if original {
        let CheckedCurrentReturn {
            checked,
            row: _row,
            selected,
            pc,
        } = proof;
        checked.journal_shape().and_then(|()| {
            checked
                .state
                .observe_transition_before_current_ret(selected, pc, rsp, word, stamp)
        })
    } else {
        proof.observe(rsp, word, stamp).map(|_| ())
    };
    assert_eq!(result, Err(error(current_ret_expected(fault))));
    assert_eq!(normal_image(&f.state), damaged);
    assert_eq!(physical_image(&f.physical), physical);
    assert_eq!(identities(&f.state, &f.physical), owners);
    assert_eq!(f.physical.active.as_ref().unwrap().rows, rows);
    assert!(!geometry_hit(
        f,
        f.physical.active.as_ref().unwrap().position,
        pc
    ));
    // Restore only the injected values after comparing every damaged image.
    // In particular an absent Pending keeps and restores the actual receipt.
    if let Some(pending) = removed {
        assert!(f.state.pending.is_none());
        f.state.pending = Some(pending);
    }
    let prior = before.pending.as_ref().unwrap();
    let pending = f.state.pending.as_mut().unwrap();
    pending.entry_pc = prior.entry_pc;
    pending.word = prior.word;
    pending.summary = prior.summary;
    pending.selected = prior.selected;
    f.state.len = before.len;
    f.state.totals.ret_observed = before.totals.ret_observed;
    f.state.journal.word(0, before.journal[0]);
    assert_eq!(normal_image(&f.state), before);
    assert_eq!(f.state.shape(), Ok(()));
}

#[test]
fn current_ret_geometry_preserves_paired_late_refusals_and_receipts() {
    let mut cases = 0;
    for k in [10, 1000] {
        for order in [[0, 1], [1, 0]] {
            for armed in [false, true] {
                for fault in 0..17 {
                    let mut checked = Fixture::new(k, order);
                    let mut original = Fixture::new(k, order);
                    let generations =
                        Generations::new(checked.epoch.generation(), original.epoch.generation());
                    for f in [&mut checked, &mut original] {
                        if armed {
                            f.controller.arm(&f.epoch).unwrap();
                        }
                        f.physical.begin(&f.state).unwrap();
                    }
                    compare_visit(&mut checked, &mut original, &generations, true);
                    current_ret_refusal(&mut checked, fault, false);
                    current_ret_refusal(&mut original, fault, true);
                    assert_eq!(
                        Some(normal_image(&checked.state)),
                        generations.image(normal_image(&original.state))
                    );
                    assert_eq!(
                        physical_image(&checked.physical),
                        physical_image(&original.physical)
                    );
                    // The exact original receipt still completes through the
                    // actual callback commit/postcheck and full old reference.
                    compare_visit(&mut checked, &mut original, &generations, false);
                    for _ in 0..3 {
                        compare_visit(&mut checked, &mut original, &generations, false);
                    }
                    compare_finish(&mut checked, &mut original, &generations);
                    for f in [&mut checked, &mut original] {
                        // Close an initially unpublished prepared epoch only
                        // after all old InitialDisarmed receipts are consumed.
                        if !armed {
                            f.controller.arm(&f.epoch).unwrap();
                        }
                        f.controller.disarm(&f.epoch).unwrap();
                        assert_eq!(
                            f.controller
                                .report(&f.epoch)
                                .unwrap()
                                .unwrap()
                                .records()
                                .count(),
                            usize::from(armed)
                        );
                    }
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 136);
}

#[test]
fn current_ret_geometry_uses_actual_validation_with_foreign_rows_and_rearm() {
    // Existing unchanged controls cover all16 masks at both K values and all
    // old prefix/error paths. Here a foreign equal-numeric row owner forces
    // fact=None while actual current validation must still certify the RET.
    let mut batches = 0;
    for (k, mode) in [(10, 0), (10, 1), (10, 2), (1000, 0), (1000, 1)] {
        for order in [[0, 1], [1, 0]] {
            let mut checked = Fixture::new(k, order);
            let mut original = Fixture::new(k, order);
            let mut generations =
                Generations::new(checked.epoch.generation(), original.epoch.generation());
            if mode != 0 {
                checked.controller.arm(&checked.epoch).unwrap();
                original.controller.arm(&original.epoch).unwrap();
            }
            if mode == 2 {
                for _ in 0..5 {
                    checked.physical.begin(&checked.state).unwrap();
                    original.physical.begin(&original.state).unwrap();
                    for _ in 0..4 {
                        compare_visit(&mut checked, &mut original, &generations, true);
                        compare_visit(&mut checked, &mut original, &generations, false);
                    }
                    compare_finish(&mut checked, &mut original, &generations);
                }
            }
            checked.physical.begin(&checked.state).unwrap();
            original.physical.begin(&original.state).unwrap();
            assert!(!Arc::ptr_eq(
                &checked.state.binding,
                &original.state.binding
            ));
            std::mem::swap(
                &mut checked.physical.active.as_mut().unwrap().rows,
                &mut original.physical.active.as_mut().unwrap().rows,
            );
            compare_visit(&mut checked, &mut original, &generations, true);
            let summary = checked.state.pending.as_ref().unwrap().summary.unwrap();
            match mode {
                0 => assert!(matches!(
                    summary,
                    IntervalEntrySummary::Unsampled {
                        reason: UnsampledSummary::InitialDisarmed,
                        ..
                    }
                )),
                1 => assert!(matches!(summary, IntervalEntrySummary::Admitted { .. })),
                2 => assert!(matches!(
                    summary,
                    IntervalEntrySummary::Unsampled {
                        reason: UnsampledSummary::FunctionClosed { .. },
                        ..
                    }
                )),
                _ => unreachable!(),
            }
            let pc = checked.input(false).pc;
            compare_visit(&mut checked, &mut original, &generations, false);
            assert!(!geometry_hit(&checked, 0, pc));
            assert!(!geometry_hit(&original, 0, pc));
            let older_pending = normal_image(&checked.state).pending;
            if mode != 0 {
                checked.controller.disarm(&checked.epoch).unwrap();
                original.controller.disarm(&original.epoch).unwrap();
            }
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
            assert_eq!(normal_image(&checked.state).pending, older_pending);
            let older = normal_image(&checked.state);
            compare_visit(&mut checked, &mut original, &generations, false);
            assert_eq!(normal_image(&checked.state), older);
            assert_eq!(
                checked.physical.active.as_ref().unwrap().pending_position,
                Some(0)
            );
            compare_visit(&mut checked, &mut original, &generations, true);
            compare_visit(&mut checked, &mut original, &generations, false);
            compare_visit(&mut checked, &mut original, &generations, false);
            compare_finish(&mut checked, &mut original, &generations);
            for (f, second) in [(&mut checked, &a), (&mut original, &b)] {
                f.controller.disarm(second).unwrap();
                assert_eq!(
                    f.controller
                        .report(second)
                        .unwrap()
                        .unwrap()
                        .records()
                        .count(),
                    1
                );
                if mode == 0 {
                    f.controller.arm(&f.epoch).unwrap();
                    f.controller.disarm(&f.epoch).unwrap();
                }
                assert_eq!(
                    f.controller
                        .report(&f.epoch)
                        .unwrap()
                        .unwrap()
                        .records()
                        .count(),
                    match mode {
                        0 => 0,
                        1 => 1,
                        2 => 20,
                        _ => unreachable!(),
                    }
                );
            }
            batches += 1;
        }
    }
    assert_eq!(batches, 10);
}

// Literal complete490c validator; only this method name differs.
impl PhysicalState {
    fn shape_before_row_prefix(&self, state: &NormalState) -> Result<(), BridgeError> {
        self.matches(state)?;
        state.shape()?;
        let b = self.active.as_ref().ok_or(error(Cause::Outstanding))?;
        if b.number != self.batches.checked_add(1).ok_or(error(Cause::Capacity))?
            || b.position > 4
            || state.cursor != b.before.cursor
            || !b.rows.is_prefix(b.position)
            || !b.seen.tail_is_empty(b.position.saturating_add(1).min(4))
            || state
                .totals
                .entered
                .checked_sub(b.before.cursor.totals.entered)
                != Some(b.seen.count() as u64)
            || state
                .totals
                .ret_observed
                .checked_sub(b.before.cursor.totals.ret_observed)
                != Some(b.rows.observed_count() as u64)
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
                // Preserve canonical-entry indexing (including its original
                // panic) before consulting the exact immutable geometry fact.
                let selected = self.order[index % 2];
                let entry = site.functions()[selected.index].entry();
                if !b
                    .rows
                    .geometry_matches(index, state, selected, entry, row.return_pc)
                {
                    state.selected_geometry(selected, entry, Some(row.return_pc))?;
                }
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

// Compare both read-only validators on the same live receipt and immutable
// geometry owner. The complete slot images also include masks, counts and facts.
fn row_prefix_shape_unchanged(f: &Fixture, expected: Result<(), BridgeError>) {
    let before = (
        normal_image(&f.state),
        physical_image(&f.physical),
        identities(&f.state, &f.physical),
    );
    let slots = f.physical.active.as_ref().map(|b| (b.seen, b.rows.clone()));
    for shape in [PhysicalState::shape_before_row_prefix, PhysicalState::shape] {
        assert_eq!(shape(&f.physical, &f.state), expected);
        assert_eq!(
            (
                normal_image(&f.state),
                physical_image(&f.physical),
                identities(&f.state, &f.physical),
            ),
            before
        );
        assert_eq!(
            f.physical.active.as_ref().map(|b| (b.seen, b.rows.clone())),
            slots
        );
    }
}

#[test]
fn row_prefix_matches_full_shape_at_each_position_and_receipt_kind() {
    let mut cases = 0;
    // FunctionClosed uses the actual twenty-record fixed bank. The other modes
    // cover both supported K values without manufacturing any receipt owner.
    for (k, mode) in [
        (10, 0),
        (10, 1),
        (10, 2),
        (10, 3),
        (10, 4),
        (1000, 0),
        (1000, 1),
        (1000, 2),
        (1000, 4),
    ] {
        for order in [[0, 1], [1, 0]] {
            for mask in [0b0101u8, 0b1111] {
                let mut f = Fixture::new(k, order);
                if mode != 0 {
                    f.controller.arm(&f.epoch).unwrap();
                }
                if mode == 1 {
                    f.controller.disarm(&f.epoch).unwrap();
                }
                if mode == 3 {
                    for _ in 0..5 {
                        f.physical.begin(&f.state).unwrap();
                        for _ in 0..4 {
                            f.call(true);
                        }
                        assert_eq!(f.finish().0.unwrap().records().len(), 4);
                    }
                }
                row_prefix_shape_unchanged(&f, Err(error(Cause::Outstanding)));
                f.physical.begin(&f.state).unwrap();
                let mut second = None;
                for position in 0..4 {
                    assert_eq!(f.physical.active.as_ref().unwrap().position, position);
                    assert!(f.physical.active.as_ref().unwrap().seen[position].is_none());
                    row_prefix_shape_unchanged(&f, Ok(()));
                    let observed = mask & (1 << position) != 0;
                    if observed {
                        f.visit(true).unwrap();
                        let p = f.state.pending.as_ref().unwrap();
                        let summary = p.summary.unwrap();
                        assert_eq!(p.receipt.summary(), Some(summary));
                        match mode {
                            0 => assert!(matches!(
                                summary,
                                IntervalEntrySummary::Unsampled {
                                    reason: UnsampledSummary::InitialDisarmed,
                                    ..
                                }
                            )),
                            1 => assert!(matches!(summary, IntervalEntrySummary::Unsampled {
                                reason: UnsampledSummary::Removed { generation }, ..
                            } if generation == f.epoch.generation())),
                            2 | 4 => assert!(matches!(summary, IntervalEntrySummary::Admitted {
                                generation, ..
                            } if generation == second.as_ref().unwrap_or(&f.epoch).generation())),
                            3 => assert!(matches!(summary, IntervalEntrySummary::Unsampled {
                                reason: UnsampledSummary::FunctionClosed { generation, function }, ..
                            } if generation == f.epoch.generation() && function == p.selected.function)),
                            _ => unreachable!(),
                        }
                        assert_eq!(
                            f.physical.active.as_ref().unwrap().seen[position],
                            Some(p.ordinal)
                        );
                        row_prefix_shape_unchanged(&f, Ok(()));
                    }
                    let before_return = normal_image(&f.state);
                    f.visit(false).unwrap();
                    if !observed {
                        assert_eq!(normal_image(&f.state), before_return);
                        assert_eq!(
                            f.physical.active.as_ref().unwrap().pending_position,
                            Some(position - 1)
                        );
                    }
                    row_prefix_shape_unchanged(&f, Ok(()));
                    if mode == 4 && position == 0 {
                        let pending = normal_image(&f.state).pending;
                        f.controller.disarm(&f.epoch).unwrap();
                        let next = f.controller.stage_prepared(f.banks.pop().unwrap()).unwrap();
                        f.controller.arm(&next).unwrap();
                        assert_eq!(normal_image(&f.state).pending, pending);
                        row_prefix_shape_unchanged(&f, Ok(()));
                        second = Some(next);
                    }
                }
                assert_eq!(f.physical.active.as_ref().unwrap().position, 4);
                // This succeeds without ever indexing seen[4].
                row_prefix_shape_unchanged(&f, Ok(()));
                let count = mask.count_ones() as usize;
                let (batch, rows) = f.finish();
                assert_eq!(batch.unwrap().records().len(), count);
                assert_eq!(
                    rows.iter().filter(|r| r.observed_ordinal.is_some()).count(),
                    count
                );
                assert!(f.state.pending.is_none());
                assert_eq!(f.state.model.depth(), 0);
                row_prefix_shape_unchanged(&f, Err(error(Cause::Outstanding)));
                if let Some(next) = second {
                    f.controller.disarm(&next).unwrap();
                    assert_eq!(
                        f.controller
                            .report(&next)
                            .unwrap()
                            .unwrap()
                            .records()
                            .count(),
                        count - 1
                    );
                } else if mode >= 2 {
                    f.controller.disarm(&f.epoch).unwrap();
                }
                if mode == 0 {
                    f.controller.arm(&f.epoch).unwrap();
                    f.controller.disarm(&f.epoch).unwrap();
                }
                assert_eq!(
                    f.controller
                        .report(&f.epoch)
                        .unwrap()
                        .unwrap()
                        .records()
                        .count(),
                    match mode {
                        0 | 1 => 0,
                        2 => count,
                        3 => 20,
                        4 => 1,
                        _ => unreachable!(),
                    }
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 36);
}

#[test]
fn row_prefix_preserves_current_overflow_and_earlier_row_error_order() {
    for order in [[0, 1], [1, 0]] {
        for position in 0..4 {
            let mut f = Fixture::new(10, order);
            f.controller.arm(&f.epoch).unwrap();
            f.physical.begin(&f.state).unwrap();
            if position != 0 {
                f.call(true);
                for _ in 1..position {
                    f.call(false);
                }
            }
            f.visit(true).unwrap();
            assert_eq!(f.physical.active.as_ref().unwrap().position, position);
            assert_eq!(f.state.len, usize::from(position != 0));
            row_prefix_shape_unchanged(&f, Ok(()));
            let original_seen = f.physical.active.as_ref().unwrap().seen;
            let original_rows = f.physical.active.as_ref().unwrap().rows.clone();
            let original_next = f.physical.active.as_ref().unwrap().before.next;
            let original_record = f.state.records[0];
            let original_word = f.state.pending.as_ref().unwrap().word;
            f.state.pending.as_mut().unwrap().word += 8;
            assert_eq!(f.state.shape(), Ok(()));
            row_prefix_shape_unchanged(&f, Err(error(Cause::Return)));
            // Current ordinal mismatch precedes the final Pending refusal.
            f.physical
                .active
                .as_mut()
                .unwrap()
                .seen
                .set(position, Some(0));
            row_prefix_shape_unchanged(&f, Err(error(Cause::Invariant)));
            let b = f.physical.active.as_mut().unwrap();
            b.before.next = u64::MAX - u64::from(position != 0);
            b.seen.set(position, Some(u64::MAX));
            if position != 0 {
                b.seen.set(0, Some(u64::MAX - 1));
                let mut row = b.rows[0].unwrap();
                row.observed_ordinal = Some(u64::MAX - 1);
                b.rows.set(0, Some(row));
                let mut record = original_record.unwrap();
                record.raw.ordinal = u64::MAX - 1;
                f.state.records.set(0, Some(record));
            }
            // NormalState does not inspect these raw ordinal/content values;
            // the physical count/prefix guards also succeed in this fixture.
            assert_eq!(f.state.shape(), Ok(()));
            row_prefix_shape_unchanged(&f, Err(error(Cause::Capacity)));
            if position != 0 {
                let row = f.physical.active.as_ref().unwrap().rows[0].unwrap();
                let record = f.state.records[0].unwrap();
                let mut bad_record = record;
                bad_record.raw.return_pc += 1;
                f.state.records.set(0, Some(bad_record));
                assert_eq!(f.state.shape(), Ok(()));
                row_prefix_shape_unchanged(&f, Err(error(Cause::Invariant)));
                let mut bad_row = row;
                bad_row.return_pc += 1;
                f.physical
                    .active
                    .as_mut()
                    .unwrap()
                    .rows
                    .set(0, Some(bad_row));
                // Earlier geometry precedes both the earlier record join and
                // the current-position overflow, even with bad Pending too.
                row_prefix_shape_unchanged(&f, Err(error(Cause::Identity)));
                f.physical.active.as_mut().unwrap().rows.set(0, None);
                row_prefix_shape_unchanged(&f, Err(error(Cause::Invariant)));
                f.physical.active.as_mut().unwrap().rows.set(0, Some(row));
                f.state.records.set(0, Some(record));
                row_prefix_shape_unchanged(&f, Err(error(Cause::Capacity)));
            }
            if position < 3 {
                f.physical
                    .active
                    .as_mut()
                    .unwrap()
                    .seen
                    .set(position + 1, Some(9));
                row_prefix_shape_unchanged(&f, Err(error(Cause::Invariant)));
                f.physical
                    .active
                    .as_mut()
                    .unwrap()
                    .seen
                    .set(position + 1, None);
                row_prefix_shape_unchanged(&f, Err(error(Cause::Capacity)));
            }
            // Repair only the deliberate faults, then consume the same actual
            // receipt through RET, confirmation, transfer and epoch report.
            let b = f.physical.active.as_mut().unwrap();
            b.seen = original_seen;
            b.rows = original_rows;
            b.before.next = original_next;
            f.state.records.set(0, original_record);
            row_prefix_shape_unchanged(&f, Err(error(Cause::Return)));
            f.state.pending.as_mut().unwrap().word = original_word;
            row_prefix_shape_unchanged(&f, Ok(()));
            f.visit(false).unwrap();
            for _ in position + 1..4 {
                f.call(false);
            }
            row_prefix_shape_unchanged(&f, Ok(()));
            let count = 1 + usize::from(position != 0);
            assert_eq!(f.finish().0.unwrap().records().len(), count);
            f.controller.disarm(&f.epoch).unwrap();
            assert_eq!(
                f.controller
                    .report(&f.epoch)
                    .unwrap()
                    .unwrap()
                    .records()
                    .count(),
                count
            );
        }
    }
}
