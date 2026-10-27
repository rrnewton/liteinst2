//! Test-only atomic interval entry seam. No native pair, TLS, control, or code
//! authority is created here; those remain a separate, unimplemented bridge.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BindingChange {
    Initial,
    Published {
        action_index: usize,
        generation: GenerationId,
    },
    Removed {
        action_index: usize,
        generation: GenerationId,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EntryStamp {
    history_len: usize,
    binding: BindingChange,
}

// Not Clone and no constructor or extraction of a frame, ticket or epoch.
pub(crate) struct IntervalEntry {
    spec: Arc<Spec>,
    thread: u64,
    original_slot: ModelReturnSlot,
    stamp: EntryStamp,
    state: Option<Entered>,
}
enum Entered {
    Admitted {
        admission: Admission,
        start_sequence: u64,
    },
    Unsampled(UnsampledOwner),
}
enum UnsampledOwner {
    Disarmed {
        observed: BindingChange,
    },
    FunctionClosed {
        owner: Arc<FrontendEpoch>,
        function: FunctionId,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntervalEntryError {
    Model(EntryError),
    ControllerBusy,
    ControllerPoisoned,
    ControllerTerminal,
    BindingInconsistent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnsampledSummary {
    InitialDisarmed,
    Removed {
        generation: GenerationId,
    },
    FunctionClosed {
        generation: GenerationId,
        function: FunctionId,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntervalExit {
    Completed {
        completion: Completion,
        payload: Payload,
        stamp: EntryStamp,
    },
    Unsampled {
        reason: UnsampledSummary,
        stamp: EntryStamp,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntervalExitError {
    Model(ExitError),
    ForeignEntry,
    Consumed,
    TokenMismatch,
    CompletionMismatch,
}

fn stamp(
    session: &SessionInner,
    writer: &Controller,
    registry: &Registry,
) -> Result<EntryStamp, IntervalEntryError> {
    if writer.status != ControllerStatus::Ready {
        return Err(IntervalEntryError::ControllerTerminal);
    }
    if writer.actions.len() > session.spec.limits.actions
        || writer.actions.len() > MAX_ACTIONS
        || registry.current.as_ref().map(|o| o.epoch.id()) != writer.current
        || registry
            .current
            .as_ref()
            .is_some_and(|o| !Arc::ptr_eq(&o.spec, &session.spec))
    {
        return Err(IntervalEntryError::BindingInconsistent);
    }
    let mut binding = BindingChange::Initial;
    for (action_index, action) in writer.actions.iter().enumerate().rev() {
        if matches!(action.kind, ActionKind::Published | ActionKind::Removed) {
            if action.function.is_some() || action.group.is_some() {
                return Err(IntervalEntryError::BindingInconsistent);
            }
            binding = if action.kind == ActionKind::Published {
                if action.current != Some(action.generation) {
                    return Err(IntervalEntryError::BindingInconsistent);
                }
                BindingChange::Published {
                    action_index,
                    generation: action.generation,
                }
            } else {
                if action.current.is_some() {
                    return Err(IntervalEntryError::BindingInconsistent);
                }
                BindingChange::Removed {
                    action_index,
                    generation: action.generation,
                }
            };
            break;
        }
    }
    let agrees = match (writer.current, binding) {
        (Some(current), BindingChange::Published { generation, .. }) => current == generation,
        (None, BindingChange::Initial | BindingChange::Removed { .. }) => true,
        _ => false,
    };
    if !agrees {
        return Err(IntervalEntryError::BindingInconsistent);
    }
    Ok(EntryStamp {
        history_len: writer.actions.len(),
        binding,
    })
}

impl ThreadModel {
    pub(crate) fn interval_depth_limit(&self) -> usize {
        self.session.spec.limits.depth
    }

    pub(crate) fn enter_interval(
        &mut self,
        install: u64,
        function: FunctionId,
        value: u64,
        slot: &mut ModelReturnSlot,
    ) -> Result<IntervalEntry, IntervalEntryError> {
        self.preflight(slot).map_err(IntervalEntryError::Model)?;
        self.in_callback = true;
        let session = Arc::clone(&self.session);
        let original_slot = *slot;
        // This internal closure only scopes ordinary Result propagation. No
        // caller callback, allocation or physical publisher runs under locks.
        let result = (|| {
            if install != session.spec.install {
                return Err(IntervalEntryError::Model(EntryError::WrongInstall));
            }
            let writer = match session.writer.try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::WouldBlock) => return Err(IntervalEntryError::ControllerBusy),
                Err(TryLockError::Poisoned(_)) => {
                    return Err(IntervalEntryError::ControllerPoisoned);
                }
            };
            let registry = match session.registry.try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::WouldBlock) => {
                    return Err(IntervalEntryError::Model(EntryError::RegistryBusy));
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(IntervalEntryError::Model(EntryError::RegistryPoisoned));
                }
            };
            if !registry.threads.contains(&self.identity) {
                return Err(IntervalEntryError::Model(EntryError::UnknownThread));
            }
            if !session.spec.ids.contains(&function) {
                return Err(IntervalEntryError::Model(EntryError::Generation(
                    AdmissionRefusal::UnknownFunction,
                )));
            }
            let stamp = stamp(&session, &writer, &registry)?;
            let state = match &registry.current {
                Some(owner) => {
                    let handle = AdmissionHandle {
                        owner: Arc::clone(owner),
                        thread: self.identity,
                    };
                    let start_sequence = self.completed_sequence;
                    // Both guards remain live through the unchanged reservation,
                    // preallocated frame push and original continuation write.
                    match self.enter_inner(&handle, function, value, slot) {
                        Ok(admission) => Entered::Admitted {
                            admission,
                            start_sequence,
                        },
                        Err(EntryError::Generation(AdmissionRefusal::FunctionClosed)) => {
                            Entered::Unsampled(UnsampledOwner::FunctionClosed {
                                owner: Arc::clone(owner),
                                function,
                            })
                        }
                        Err(error) => return Err(IntervalEntryError::Model(error)),
                    }
                }
                None => Entered::Unsampled(UnsampledOwner::Disarmed {
                    observed: stamp.binding,
                }),
            };
            Ok(IntervalEntry {
                spec: Arc::clone(&session.spec),
                thread: self.identity,
                original_slot,
                stamp,
                state: Some(state),
            })
        })();
        self.in_callback = false;
        result
    }

    // The eventual bridge must first authenticate its mixed pair stack and
    // native return/control identity. This seam owns only the model receipt.
    pub(crate) fn finish_interval(
        &mut self,
        entry: &mut IntervalEntry,
        slot: &mut ModelReturnSlot,
        end: Observation,
    ) -> Result<IntervalExit, IntervalExitError> {
        let state = entry.state.as_ref().ok_or(IntervalExitError::Consumed)?;
        if !Arc::ptr_eq(&entry.spec, &self.session.spec) || entry.thread != self.identity {
            return Err(IntervalExitError::ForeignEntry);
        }
        match state {
            Entered::Admitted {
                admission,
                start_sequence,
            } => {
                if slot.identity != entry.original_slot.identity || slot.word != MODEL_CONTINUATION
                {
                    return Err(IntervalExitError::TokenMismatch);
                }
                let frame = self
                    .frames
                    .last()
                    .ok_or(IntervalExitError::Model(ExitError::Empty))?;
                if frame.slot != entry.original_slot
                    || frame.thread != entry.thread
                    || !Arc::ptr_eq(&frame.owner.spec, &entry.spec)
                    || frame.owner.epoch.id() != admission.generation
                    || frame.ticket.as_ref().map(OwnedTicket::admission) != Some(*admission)
                    || frame.start_sequence != *start_sequence
                {
                    return Err(IntervalExitError::ForeignEntry);
                }
                let (children, _) = self.exit_check(slot).map_err(IntervalExitError::Model)?;
                let expected = Payload {
                    admission: *admission,
                    thread: entry.thread,
                    start_sequence: *start_sequence,
                    outcome: PayloadOutcome::Completed {
                        end,
                        completed_children: children,
                    },
                };
                let (completion, payload) =
                    self.finish(slot, end).map_err(IntervalExitError::Model)?;
                // Consumption precedes the impossible postcondition failure:
                // no rollback/retry may invent a second completion.
                entry.state = None;
                if completion.admission != expected.admission
                    || payload != expected
                    || *slot != entry.original_slot
                {
                    self.exhausted = true;
                    return Err(IntervalExitError::CompletionMismatch);
                }
                Ok(IntervalExit::Completed {
                    completion,
                    payload,
                    stamp: entry.stamp,
                })
            }
            Entered::Unsampled(owner) => {
                if *slot != entry.original_slot {
                    return Err(IntervalExitError::TokenMismatch);
                }
                let reason = match owner {
                    UnsampledOwner::Disarmed {
                        observed: BindingChange::Initial,
                    } => UnsampledSummary::InitialDisarmed,
                    UnsampledOwner::Disarmed {
                        observed: BindingChange::Removed { generation, .. },
                    } => UnsampledSummary::Removed {
                        generation: *generation,
                    },
                    UnsampledOwner::FunctionClosed { owner, function } => {
                        UnsampledSummary::FunctionClosed {
                            generation: owner.epoch.id(),
                            function: *function,
                        }
                    }
                    UnsampledOwner::Disarmed {
                        observed: BindingChange::Published { .. },
                    } => {
                        return Err(IntervalExitError::ForeignEntry);
                    }
                };
                entry.state = None;
                Ok(IntervalExit::Unsampled {
                    reason,
                    stamp: entry.stamp,
                })
            }
        }
    }
}

mod tests;
