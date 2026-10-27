//! Pure supplied-record controls. No live owner or successful native seal is
//! constructed. Model association and copied-data checks are not eligibility.
use super::*;
use crate::lifecycle::LifecycleRegistry;
use crate::linux::remote::dynamic::owner::trusted::AdmissionStop;
use liteinst2::contracts::SourceIdentity;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;
const PANIC: u32 = 0x5348_5231;
const PC: u64 = 0x401000;

struct Model {
    prior: ObservedStop,
    binding: Binding,
    owner: OriginId,
    before: TaskStateSnapshot,
    step: TaskStateSnapshot,
    stops: [AdmissionStop; 8],
    trace: NativeTrace,
}
impl Model {
    fn new() -> Self {
        let registry =
            LifecycleRegistry::new(crate::lifecycle::Limits::default(), 101, PC).unwrap();
        let row = registry.task(registry.root_task()).unwrap();
        let registers = RegisterSnapshot {
            r15: 15,
            r14: 14,
            r13: 13,
            r12: 12,
            rbp: 11,
            rbx: 10,
            r11: 9,
            r10: 8,
            r9: 7,
            r8: 6,
            rax: 5,
            rcx: 4,
            rdx: 3,
            rsi: 2,
            rdi: 1,
            orig_rax: u64::MAX,
            rip: PC,
            cs: 0x33,
            eflags: 0x202,
            rsp: 0x600000,
            ss: 0x2b,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        };
        let prior = ObservedStop {
            token: DynamicStop {
                session: 91,
                sequence: 10,
                tid: 101,
                task: Some(row.id),
            },
            task: DynamicTask {
                task: row.id,
                process: row.process,
                address_space: row.address_space,
                generation: 0,
            },
            logical_pc: PC,
            registers,
            xstate: vec![0x5a; 832],
            signal_mask: 0x200,
            phase: StopPhase::UserCheckpoint,
            signal: None,
        };
        let before = TaskStateSnapshot {
            registers,
            xstate: prior.xstate.clone(),
            mask: prior.signal_mask,
        };
        let mut step = before.clone();
        step.registers.rip += 4;
        step.registers.rax += 1;
        let origin = OriginId {
            census: 31,
            serial: 2,
        };
        let owner = OriginId {
            census: 31,
            serial: 4,
        };
        let binding = Binding {
            census: 31,
            reservation: Reservation {
                census: 31,
                serial: 3,
            },
            candidate_serial: 4,
            origin,
            execution: ExecutionId::from_owner(91, 7).unwrap(),
            source: SourceRecord {
                identity: CodeIdentity {
                    source: SourceIdentity([0x31; 32]),
                    mapping: 17,
                    generation: 0,
                },
                index: 2,
            },
            encoding: Encoding::new(PC, &[0x48, 0x83, 0xc0, 1]).unwrap(),
            until: Instant::now() + Duration::from_secs(60),
        };
        let stops = std::array::from_fn(|index| {
            let mut token = prior.token.clone();
            token.sequence += index as u64;
            AdmissionStop {
                token,
                identity: prior.task,
                phase: if index == 0 {
                    AdmissionPhase::EntryReady
                } else if index == 4 {
                    AdmissionPhase::NativeCompleted
                } else {
                    AdmissionPhase::Restored
                },
                signal: None,
            }
        });
        let mut signal = [0; 128];
        signal[..4].copy_from_slice(&libc::SIGTRAP.to_ne_bytes());
        signal[8..12].copy_from_slice(&libc::TRAP_TRACE.to_ne_bytes());
        signal[16..24].copy_from_slice(&step.registers.rip.to_ne_bytes());
        let trace = NativeTrace {
            ordinal: 3,
            tid: 101,
            status: (libc::SIGTRAP << 8) | 0x7f,
            signal,
            dr6: TRACE_DR6,
        };
        Self {
            prior,
            binding,
            owner,
            before,
            step,
            stops,
            trace,
        }
    }
    fn view(&self) -> CompletionModel<'_> {
        CompletionModel {
            source: self.binding.source,
            origin: self.binding.origin,
            execution: self.binding.execution,
            until: self.binding.until,
            encoding: self.binding.encoding.bytes(),
            logical: NativeCheckpoint {
                stop: &self.stops[0],
                state: &self.before,
            },
            opening: std::array::from_fn(|i| NativeCheckpoint {
                stop: &self.stops[i + 1],
                state: &self.before,
            }),
            step: NativeCheckpoint {
                stop: &self.stops[4],
                state: &self.step,
            },
            closing: std::array::from_fn(|i| NativeCheckpoint {
                stop: &self.stops[i + 5],
                state: &self.step,
            }),
            trace: self.trace,
        }
    }
    fn prepared(&self) -> PreparedOrdinaryHistory {
        let mut out = PreparedOrdinaryHistory::empty();
        out.allocate_payloads(self.binding, self.owner).unwrap();
        out
    }
    fn complete(&self) -> PreparedOrdinaryHistory {
        let mut out = self.prepared();
        out.stage_prior(&self.prior).unwrap();
        out.stage_model(&self.view()).unwrap();
        out
    }
    fn owner_row(&self) -> OriginRow {
        OriginRow {
            id: self.owner,
            kind: OriginKind::CurrentHeldPc,
            pc: self.step.registers.rip,
            created_generation: 0,
            initial: copy_checkpoint(
                self.view().step,
                Vec::new(),
                StopPhase::OwnedOrdinaryComplete {
                    execution: self.binding.execution,
                },
                Some(DynamicSignalInfo {
                    raw: self.trace.signal,
                }),
            ),
        }
    }
    fn evidence(&self) -> OrdinaryEvidence {
        OrdinaryEvidence {
            binding: self.binding,
            trace: Some(self.trace),
        }
    }
}

#[test]
fn ordinary_shared_allocation_error_and_unwind_retain_every_installed_prefix() {
    let model = Model::new();
    assert_eq!(
        PreparedOrdinaryHistory::reservation_bytes().unwrap(),
        size_of::<PreparedOrdinaryHistory>()
            + size_of::<OrdinaryHistoryPayloads>()
            + 3 * MAX_XSTATE_BYTES
    );
    for ordinal in 0..4 {
        for unwind in [false, true] {
            let mut out = PreparedOrdinaryHistory::empty();
            let result = catch_unwind(AssertUnwindSafe(|| {
                out.allocate_with(
                    model.binding,
                    model.owner,
                    |i| {
                        if !unwind && i == ordinal {
                            Err(SharedError::Allocation)
                        } else {
                            Ok(())
                        }
                    },
                    |i| {
                        if unwind && i == ordinal {
                            std::panic::panic_any(PANIC);
                        }
                    },
                )
            }));
            if unwind {
                assert_eq!(*result.unwrap_err().downcast::<u32>().unwrap(), PANIC);
            } else {
                assert_eq!(result.unwrap(), Err(SharedError::Allocation));
            }
            let installed = ordinal + usize::from(unwind);
            let expected = if installed == 0 {
                0
            } else {
                size_of::<OrdinaryHistoryPayloads>() + (installed - 1) * MAX_XSTATE_BYTES
            };
            assert_eq!(out.allocation.filled, installed);
            assert_eq!(out.installed_bytes(), expected);
            assert_eq!(
                out.allocated_bytes().unwrap(),
                size_of::<PreparedOrdinaryHistory>() + expected
            );
            assert!(!out.allocation.complete);
            out.mark_aborted();
            assert_eq!(
                out.allocation.first_failure,
                Some(if unwind {
                    SharedError::Aborted
                } else {
                    SharedError::Allocation
                })
            );
            let saved = out.test_snapshot();
            if let Some(archive) = out.archive.as_deref() {
                let cloned = archive.clone();
                assert_eq!(cloned, *archive);
                for i in 0..3 {
                    assert_eq!(
                        cloned.payloads[i].bytes.capacity(),
                        archive.payloads[i].bytes.capacity()
                    );
                    assert_eq!(cloned.payloads[i].copy, archive.payloads[i].copy);
                    if archive.payloads[i].bytes.capacity() != 0 {
                        assert_ne!(
                            cloned.payloads[i].bytes.as_ptr(),
                            archive.payloads[i].bytes.as_ptr()
                        );
                    }
                }
            }
            assert_eq!(
                out.allocate_payloads(model.binding, model.owner),
                Err(SharedError::Reused)
            );
            out.mark_aborted();
            assert_eq!(out.test_snapshot(), saved);
            if let Some(archive) = out.partial_view().archive {
                for (i, p) in archive.payloads.iter().enumerate() {
                    assert_eq!(
                        p.identity.capacity,
                        if i + 1 < installed {
                            MAX_XSTATE_BYTES
                        } else {
                            0
                        }
                    );
                    assert_eq!(p.bytes.len(), 0);
                    assert!(!p.progress.started);
                }
            }
        }
    }
    assert_eq!(checked(usize::MAX, 1), Err(SharedError::Capacity));
    assert!(shared_temporary_bytes().unwrap() > size_of::<OrdinaryHistoryPayloads>());
}
#[test]
fn ordinary_shared_prior_is_the_single_pre_effect_payload_owner() {
    let model = Model::new();
    let mut out = model.prepared();
    out.stage_prior(&model.prior).unwrap();
    assert_eq!(out.prior().unwrap(), ObservationView::of(&model.prior));
    let view = out.partial_view().archive.unwrap();
    assert_eq!(view.prior.filled, 1);
    assert!(view.prior.complete);
    assert!(!view.native.started);
    assert_eq!(view.headers.iter().filter(|v| v.is_some()).count(), 1);
    for (i, p) in view.payloads.iter().enumerate() {
        assert_eq!(p.identity.capacity, MAX_XSTATE_BYTES);
        assert_eq!(p.bytes.len(), if i == 0 { 832 } else { 0 });
        assert_eq!(p.progress.complete, i == 0);
    }
    assert_ne!(
        view.payloads[0].identity.pointer,
        model.prior.xstate.as_ptr() as usize
    );
    assert!(out.archive().unwrap().records().is_err());
}
#[test]
fn ordinary_shared_semantic_rows_preserve_all_headers_and_role_aliases() {
    let model = Model::new();
    let out = model.complete();
    let archive = out.archive().unwrap();
    let owner = model.owner_row();
    let evidence = model.evidence();
    let context =
        ResolutionContext::for_owner(model.binding.census, &owner, &evidence, archive).unwrap();
    let rows = archive.records().unwrap();
    let mut roles = [0; 3];
    let partial = archive.partial_view();
    for reference in partial.references.into_iter().map(Option::unwrap) {
        roles[reference.role.index()] += 1;
        let actual = context.resolve(reference).unwrap();
        let expected = if reference.endpoint == 0 {
            model.prior.clone()
        } else {
            let index = reference.endpoint;
            let checkpoint = match index {
                1 | 2 => model.view().opening[0],
                3 | 4 => model.view().opening[1],
                5 | 6 => model.view().opening[2],
                7 | 8 => model.view().step,
                9 | 10 => model.view().closing[0],
                11 | 12 => model.view().closing[1],
                13 => model.view().closing[2],
                _ => unreachable!(),
            };
            copy_checkpoint(
                checkpoint,
                Vec::new(),
                if index == 7 || index == 8 {
                    StopPhase::OwnedOrdinaryComplete {
                        execution: model.binding.execution,
                    }
                } else {
                    StopPhase::UserCheckpoint
                },
                (index == 7 || index == 8).then_some(DynamicSignalInfo {
                    raw: model.trace.signal,
                }),
            )
        };
        assert_eq!(actual, ObservationView::of(&expected));
        assert_eq!(
            actual.xstate.as_ptr() as usize,
            partial.payloads[reference.role.index()].identity.pointer
        );
    }
    assert_eq!(roles, [1, 6, 7]);
    for a in 0..3 {
        for b in a + 1..3 {
            assert_ne!(
                partial.payloads[a].identity.pointer,
                partial.payloads[b].identity.pointer
            );
        }
    }
    assert_eq!(partial.payloads[0].bytes, partial.payloads[1].bytes); // Equal bytes stay separately owned.
    for (index, row) in rows.iter().enumerate() {
        match context.resolve_row(row).unwrap() {
            SharedRowView::Refreshed {
                origin,
                before,
                after,
            } => {
                assert_ne!(index, 3);
                assert_eq!(
                    origin,
                    if index < 3 {
                        model.binding.origin
                    } else {
                        model.owner
                    }
                );
                assert!(after.token.sequence > before.token.sequence);
            }
            SharedRowView::Consumed {
                origin,
                before,
                successor,
                evidence: actual,
            } => {
                assert_eq!(index, 3);
                assert_eq!(origin, model.binding.origin);
                assert_eq!(actual, &evidence);
                assert!(successor.token.sequence > before.token.sequence);
            }
        }
    }
}
#[test]
fn ordinary_shared_equal_bytes_do_not_substitute_for_canonical_provenance() {
    let model = Model::new();
    for case in 0..3 {
        let mut out = model.prepared();
        out.stage_prior(&model.prior).unwrap();
        let independent = model.before.clone();
        let independent_step = model.step.clone();
        let mut view = model.view();
        match case {
            0 => view.opening[1].state = &independent,
            1 => view.closing[2].state = &independent_step,
            _ => {
                view.step.state = &model.before;
                for checkpoint in &mut view.closing {
                    checkpoint.state = &model.before;
                }
            }
        }
        assert_eq!(
            out.native_with(&view, &mut |_| Ok(())),
            Err(SharedError::Provenance)
        );
        let archive = out.partial_view().archive.unwrap();
        assert_eq!(archive.native.first_failure, Some(SharedError::Provenance));
        assert!(archive.payloads[1].bytes.is_empty());
        assert!(archive.payloads[2].bytes.is_empty());
        assert_eq!(archive.headers.iter().filter(|v| v.is_some()).count(), 1);
    }
}
#[test]
fn ordinary_shared_resolver_rejects_foreign_identity_role_and_endpoint() {
    let model = Model::new();
    let out = model.complete();
    let archive = out.archive().unwrap();
    let owner = model.owner_row();
    let evidence = model.evidence();
    assert!(matches!(
        ResolutionContext::for_owner(32, &owner, &evidence, archive),
        Err(SharedError::Identity)
    ));
    let context = ResolutionContext::for_owner(31, &owner, &evidence, archive).unwrap();
    let original = archive.partial_view().references[6].unwrap();
    for index in 0..5 {
        let mut reference = original;
        match index {
            0 => reference.census ^= 1,
            1 => reference.owner.serial ^= 1,
            2 => reference.execution.serial ^= 1,
            3 => reference.role = CaptureRole::Step,
            _ => reference.endpoint = ENDPOINTS,
        }
        assert_ne!(reference, original);
        assert!(context.resolve(reference).is_err());
    }
    assert!(context.resolve(original).is_ok());
    for index in 0..4 {
        let mut changed = evidence.clone();
        match index {
            0 => changed.binding.source.index += 1,
            1 => changed.binding.until += Duration::from_nanos(1),
            2 => changed.binding.reservation.serial += 1,
            _ => changed.trace.as_mut().unwrap().dr6 ^= 1,
        }
        assert_ne!(changed, evidence);
        assert!(matches!(
            ResolutionContext::for_owner(31, &owner, &changed, archive),
            Err(SharedError::Identity)
        ));
    }
}
#[test]
fn ordinary_shared_row_grammar_is_exact_and_resolution_failure_is_not_skipped() {
    let model = Model::new();
    let out = model.complete();
    let archive = out.archive().unwrap();
    let owner = model.owner_row();
    let evidence = model.evidence();
    let context = ResolutionContext::for_owner(31, &owner, &evidence, archive).unwrap();
    let rows = archive.records().unwrap();
    let refs = archive.partial_view().references.map(Option::unwrap);
    let invalid = [
        SharedHistoryRecord::Refreshed {
            origin: model.binding.origin,
            before: refs[0],
            after: refs[3],
        },
        SharedHistoryRecord::Refreshed {
            origin: model.owner,
            before: refs[0],
            after: refs[1],
        },
        SharedHistoryRecord::Consumed {
            origin: model.binding.origin,
            before: refs[5],
            successor: refs[7],
        },
    ];
    for bad in invalid {
        assert!(context.resolve_row(&bad).is_err());
    }
    let mut foreign = refs[1];
    foreign.owner.serial ^= 1;
    assert_eq!(
        SharedHistoryRecord::Refreshed {
            origin: model.binding.origin,
            before: refs[0],
            after: foreign
        }
        .owner(),
        Err(SharedError::Identity)
    );
    for row in rows {
        assert_eq!(row.owner().unwrap(), model.owner);
    }
    let mut changed = rows;
    changed[2] = invalid[0];
    let result: Result<Vec<_>, _> = changed.iter().map(|row| context.resolve_row(row)).collect();
    assert!(result.is_err());
    assert_eq!(
        rows.iter()
            .map(|row| context.resolve_row(row))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        7
    );
}
#[test]
fn ordinary_shared_incomplete_and_corrupted_payload_extents_cannot_resolve() {
    let model = Model::new();
    for index in 0..5 {
        let mut out = model.complete();
        let archive = out.archive.as_mut().unwrap();
        match index {
            0 => archive.headers[12] = None,
            1 => archive.payloads[1].copy.complete = false,
            2 => archive.payloads[2].copy.filled += 1,
            3 => {
                archive.payloads[0].bytes.pop();
            }
            _ => {
                let mut bytes = exact_storage::empty_bytes(MAX_XSTATE_BYTES - 1).unwrap();
                bytes.extend_from_slice(&archive.payloads[1].bytes);
                archive.payloads[1].bytes = bytes;
            }
        }
        // The safe exact-storage helper guarantees a capacity unequal to MAX.
        if index == 4 {
            assert_ne!(archive.payloads[1].bytes.capacity(), MAX_XSTATE_BYTES);
        }
        assert!(archive.records().is_err());
        assert!(out.take_complete().is_err());
        assert!(out.archive.is_some());
    }
}
#[test]
fn ordinary_shared_stage_errors_and_unwinds_retain_every_initialized_prefix() {
    let model = Model::new();
    // 4 chunks +1 prior header; then 8 native chunks +13 native headers.
    for native in [false, true] {
        let points = if native { 21 } else { 5 };
        for target in 0..points {
            for unwind in [false, true] {
                let mut out = model.prepared();
                if native {
                    out.stage_prior(&model.prior).unwrap();
                }
                let mut seen = 0;
                let mut hook = |point: CopyPoint| {
                    assert!(point.1 <= ENDPOINTS || point.0.is_some());
                    let at = seen;
                    seen += 1;
                    if at == target {
                        if unwind {
                            std::panic::panic_any(PANIC);
                        }
                        return Err(SharedError::Endpoint);
                    }
                    Ok(())
                };
                let result = catch_unwind(AssertUnwindSafe(|| {
                    if native {
                        out.native_with(&model.view(), &mut hook)
                    } else {
                        out.prior_with(&model.prior, &mut hook)
                    }
                }));
                if unwind {
                    assert_eq!(*result.unwrap_err().downcast::<u32>().unwrap(), PANIC);
                } else {
                    assert_eq!(result.unwrap(), Err(SharedError::Endpoint));
                }
                assert_eq!(seen, target + 1);
                assert_eq!(
                    out.allocated_bytes().unwrap(),
                    PreparedOrdinaryHistory::reservation_bytes().unwrap()
                );
                out.mark_aborted();
                let snapshot = out.test_snapshot();
                let archive = snapshot.archive.as_ref().unwrap();
                let progress = if native {
                    archive.native
                } else {
                    archive.prior
                };
                assert_eq!(
                    progress.first_failure,
                    Some(if unwind {
                        SharedError::Aborted
                    } else {
                        SharedError::Endpoint
                    })
                );
                assert!(!progress.complete);
                for i in 0..3 {
                    assert_eq!(archive.identities[i].length, archive.bytes[i].len());
                    assert_eq!(archive.progress[i].filled, archive.bytes[i].len());
                    assert_eq!(archive.identities[i].capacity, MAX_XSTATE_BYTES);
                }
                assert!(out.take_complete().is_err());
                out.mark_aborted();
                assert_eq!(out.test_snapshot(), snapshot);
            }
        }
    }
}
#[test]
fn ordinary_shared_snapshot_compares_every_byte_and_header_separately_from_identity() {
    let model = Model::new();
    let mut out = model.complete();
    let original = out.archive().unwrap().test_snapshot();
    for role in 0..3 {
        let archive = out.archive.as_mut().unwrap();
        archive.payloads[role].bytes[0] ^= 1;
        assert_ne!(archive.test_snapshot(), original);
        assert_eq!(archive.test_snapshot().identities, original.identities);
        archive.payloads[role].bytes[0] ^= 1;
        assert_eq!(archive.test_snapshot(), original);
    }
    for field in 0..8 {
        let header = out.archive.as_mut().unwrap().headers[3].as_mut().unwrap();
        let saved = header.clone();
        match field {
            0 => header.token.sequence ^= 1,
            1 => header.task.generation ^= 1,
            2 => header.logical_pc ^= 1,
            3 => header.registers.rax ^= 1,
            4 => header.signal_mask ^= 1,
            5 => header.phase = StopPhase::OriginalSignal,
            6 => header.signal = Some(DynamicSignalInfo { raw: [0; 128] }),
            _ => header.token.tid += 1,
        }
        assert_ne!(*header, saved);
        assert_ne!(out.archive().unwrap().test_snapshot(), original);
        out.archive.as_mut().unwrap().headers[3] = Some(saved);
        assert_eq!(out.archive().unwrap().test_snapshot(), original);
    }
    let mut copied = original.clone();
    copied.identities[0].pointer ^= 1;
    assert_ne!(copied, original);
    copied = original.clone();
    copied.bytes[2][0] ^= 1;
    assert_ne!(copied, original);
    let archive = out.archive.as_mut().unwrap();
    let mut bytes = exact_storage::empty_bytes(MAX_XSTATE_BYTES).unwrap();
    bytes.extend_from_slice(&archive.payloads[2].bytes);
    let previous = std::mem::replace(&mut archive.payloads[2].bytes, bytes);
    let changed = archive.test_snapshot();
    assert_eq!(changed.bytes, original.bytes);
    assert_ne!(changed.identities, original.identities);
    assert_ne!(changed, original);
    archive.payloads[2].bytes = previous;
    assert_eq!(archive.test_snapshot(), original);
    let cloned = (**archive).clone();
    assert_eq!(cloned, **archive);
    for i in 0..3 {
        assert_eq!(
            cloned.payloads[i].bytes.capacity(),
            archive.payloads[i].bytes.capacity()
        );
        assert_ne!(
            cloned.payloads[i].bytes.as_ptr(),
            archive.payloads[i].bytes.as_ptr()
        );
    }
    for ordinal in 0..3 {
        assert!(matches!(
            archive.try_clone_with(|i| if i == ordinal {
                Err(SharedError::Allocation)
            } else {
                Ok(())
            }),
            Err(SharedError::Allocation)
        ));
        assert_eq!(archive.test_snapshot(), original);
    }
}
#[test]
fn ordinary_shared_box_move_preserves_bytes_and_historical_owner_resolution() {
    let model = Model::new();
    let mut out = model.complete();
    let before = out.archive().unwrap().test_snapshot();
    let installed = out.installed_bytes();
    let owner = model.owner_row();
    let evidence = model.evidence();
    let archive = out.take_complete().unwrap();
    assert_eq!(archive.test_snapshot(), before);
    assert_eq!(
        out.allocated_bytes().unwrap(),
        size_of::<PreparedOrdinaryHistory>()
    );
    assert_eq!(out.installed_bytes(), installed);
    assert!(out.partial_view().transferred);
    assert_eq!(archive.allocated_bytes().unwrap(), installed);
    let moved = Some(archive);
    let archive = moved.as_deref().unwrap();
    let context = ResolutionContext::for_owner(31, &owner, &evidence, archive).unwrap();
    for row in archive.records().unwrap() {
        context.resolve_row(&row).unwrap();
    }
    assert_eq!(archive.test_snapshot(), before);
    assert!(matches!(
        ResolutionContext::for_owner(32, &owner, &evidence, archive),
        Err(SharedError::Identity)
    ));
    assert!(out.take_complete().is_err());
    out.mark_aborted();
    assert_eq!(archive.test_snapshot(), before);
    // No actual census retirement is performed by this supplied ownership model.
}
#[test]
fn ordinary_shared_invalid_prior_extent_and_binding_keep_first_error() {
    for length in [0, 511, MAX_XSTATE_BYTES] {
        let model = Model::new();
        let mut out = model.prepared();
        let mut prior = model.prior.clone();
        prior.xstate.resize(length, 0);
        assert_eq!(out.stage_prior(&prior), Err(SharedError::Extent));
        let before = out.test_snapshot();
        assert_eq!(out.stage_prior(&model.prior), Err(SharedError::Reused));
        out.mark_aborted();
        assert_eq!(out.test_snapshot(), before);
    }
    let model = Model::new();
    let mut out = PreparedOrdinaryHistory::empty();
    let mut owner = model.owner;
    owner.census ^= 1;
    assert_eq!(
        out.allocate_payloads(model.binding, owner),
        Err(SharedError::Identity)
    );
    assert!(out.archive.is_none());
    assert_eq!(out.installed_bytes(), 0);
    assert_eq!(
        out.allocated_bytes().unwrap(),
        size_of::<PreparedOrdinaryHistory>()
    );
}
#[test]
fn ordinary_shared_complete_storage_refuses_reuse_without_overwriting_records() {
    let model = Model::new();
    let mut out = model.complete();
    let before = out.test_snapshot();
    assert_eq!(
        out.allocate_payloads(model.binding, model.owner),
        Err(SharedError::Reused)
    );
    assert_eq!(out.stage_prior(&model.prior), Err(SharedError::Reused));
    assert_eq!(
        out.native_with(&model.view(), &mut |_| Ok(())),
        Err(SharedError::Reused)
    );
    out.mark_aborted();
    assert_eq!(out.test_snapshot(), before);
}
