use super::*;

fn entry_phase(identity: &RuntimeKernelIdentity) -> StopPhase {
    StopPhase::SyscallEntry {
        syscall: identity.number(),
    }
}
fn exit_phase(identity: &RuntimeKernelIdentity, state: &TaskStateSnapshot) -> StopPhase {
    StopPhase::ParentSyscallExit {
        syscall: identity.number(),
        result: state.registers.rax as i64,
        is_error: false,
    }
}

impl ResumeCensus {
    pub(in super::super::super) fn commit_runtime_kernel_return<'a>(
        &mut self,
        reservation: Reservation,
        actual: OwnedRuntimeKernelReturn<'_>,
        prepared: &'a mut PreparedRuntimeKernelCensus,
    ) -> Result<RuntimeKernelCensusResult<'a>, CensusError> {
        let model = Model {
            identity: actual.binding(),
            logical: actual.logical_before(),
            opening: actual.opening(),
            entry: actual.entry(),
            outcome: Outcome {
                returned: Some(ReturnModel {
                    exit: actual.exit(),
                    bridge: actual.bridge(),
                    closing: actual.closing(),
                    trace: actual.trace(),
                }),
                terminal: None,
            },
        };
        self.commit_kernel_model(reservation, &model, prepared)
    }

    pub(in super::super::super) fn commit_runtime_kernel_terminal<'a>(
        &mut self,
        reservation: Reservation,
        actual: OwnedRuntimeKernelTerminal<'_>,
        prepared: &'a mut PreparedRuntimeKernelCensus,
    ) -> Result<RuntimeKernelCensusResult<'a>, CensusError> {
        let model = Model {
            identity: actual.binding(),
            logical: actual.logical_before(),
            opening: actual.opening(),
            entry: actual.entry(),
            outcome: Outcome {
                returned: None,
                terminal: Some(TerminalModel {
                    pre_exit: actual.pre_exit(),
                    exiting: actual.exiting_event(),
                    terminal: actual.terminal_event(),
                    trace: actual.trace(),
                }),
            },
        };
        self.commit_kernel_model(reservation, &model, prepared)
    }

    fn commit_kernel_model<'a>(
        &mut self,
        reservation: Reservation,
        actual: &Model<'_>,
        prepared: &'a mut PreparedRuntimeKernelCensus,
    ) -> Result<RuntimeKernelCensusResult<'a>, CensusError> {
        // Every binding, full observation, capacity, prospective serial and
        // six-axis debit is checked before taking any payload. The remainder
        // contains only checked-capacity moves, inline copies and pushes.
        let (old, next, remaining, used) = validate::model(self, reservation, actual, prepared)?;
        let identity = prepared.binding.identity.clone();
        let origin = identity.origin();
        let mut slot = 0;
        let entry = copy_state(
            actual.entry.event.stop_token().unwrap(),
            identity.task(),
            actual.entry.state,
            next_buffer(prepared, &mut slot),
            entry_phase(&identity),
        );
        let mut records = prepared.evidence.take().unwrap();
        records[0].entry = Some(entry);
        for index in 0..3 {
            let before = if index == 0 {
                ObservedStop {
                    token: prepared.before.token.clone(),
                    task: prepared.before.task,
                    logical_pc: prepared.before.logical_pc,
                    registers: prepared.before.registers,
                    xstate: std::mem::take(&mut prepared.before.xstate),
                    signal_mask: prepared.before.signal_mask,
                    phase: prepared.before.phase,
                    signal: prepared.before.signal.clone(),
                }
            } else {
                copy_checkpoint(actual.opening[index - 1], next_buffer(prepared, &mut slot))
            };
            let after = copy_checkpoint(actual.opening[index], next_buffer(prepared, &mut slot));
            self.state.history.push(HistoryRecord::Refreshed {
                origin,
                before,
                after,
            });
        }
        // Complete state stayed identical through all three actual opening
        // checkpoints. The existing current payload stays owned in its row.
        self.state.origins[old].current.token = actual.opening[2].stop.token.clone();
        let before = copy_checkpoint(actual.opening[2], next_buffer(prepared, &mut slot));
        let (current, outcome) = match (&actual.outcome.returned, &actual.outcome.terminal) {
            (
                Some(ReturnModel {
                    exit,
                    bridge,
                    closing,
                    trace,
                }),
                None,
            ) => {
                let phase = exit_phase(&identity, exit.state);
                let exit_token = exit.event.stop_token().unwrap();
                let successor = copy_state(
                    exit_token,
                    identity.task(),
                    exit.state,
                    next_buffer(prepared, &mut slot),
                    phase,
                );
                let id = OriginId {
                    census: self.identity,
                    serial: self.state.next_serial,
                };
                records[0].outcome = Some(RetainedOutcome {
                    returned: Some((id, *trace)),
                    terminal: None,
                });
                self.state.history.push(HistoryRecord::Consumed {
                    origin,
                    evidence: OwnerConsumption {
                        before,
                        successor,
                        evidence: Consumption::RuntimeKernel(records),
                    },
                });
                self.state.origins[old].active = false;
                let initial = copy_state(
                    exit_token,
                    identity.task(),
                    exit.state,
                    next_buffer(prepared, &mut slot),
                    phase,
                );
                let current = copy_checkpoint(closing[2], next_buffer(prepared, &mut slot));
                self.state.origins.push(StoredOrigin {
                    row: OriginRow {
                        id,
                        kind: OriginKind::CurrentHeldPc,
                        pc: initial.logical_pc,
                        created_generation: self.state.generation,
                        initial,
                    },
                    current,
                    active: true,
                    frame: None,
                    runtime_kernel: Some(KernelOriginLineage {
                        returned: id,
                        parent: None,
                    }),
                });
                for index in 0..4 {
                    let before = if index == 0 {
                        copy_state(
                            exit_token,
                            identity.task(),
                            exit.state,
                            next_buffer(prepared, &mut slot),
                            phase,
                        )
                    } else {
                        let checkpoint = if index == 1 {
                            *bridge
                        } else {
                            closing[index - 2]
                        };
                        copy_checkpoint(checkpoint, next_buffer(prepared, &mut slot))
                    };
                    let checkpoint = if index == 0 {
                        *bridge
                    } else {
                        closing[index - 1]
                    };
                    let after = copy_checkpoint(checkpoint, next_buffer(prepared, &mut slot));
                    self.state.history.push(HistoryRecord::Refreshed {
                        origin: id,
                        before,
                        after,
                    });
                }
                (
                    Some(id),
                    CommittedOutcome {
                        returned: Some((id, closing[2].stop.token.clone())),
                        terminal: None,
                    },
                )
            }
            (
                None,
                Some(TerminalModel {
                    exiting,
                    terminal,
                    trace,
                    ..
                }),
            ) => {
                // These already-validated variants contain only inline fields.
                // No EntryEvidence or other heap-bearing event is copied.
                records[0].outcome = Some(RetainedOutcome {
                    returned: None,
                    terminal: Some(RetainedTerminal {
                        exiting: (*exiting).clone(),
                        terminal: (*terminal).clone(),
                        trace: *trace,
                    }),
                });
                self.state
                    .history
                    .push(HistoryRecord::RuntimeKernelTerminal {
                        origin,
                        before,
                        evidence: records,
                    });
                self.state.origins[old].active = false;
                (
                    None,
                    CommittedOutcome {
                        returned: None,
                        terminal: Some(((*terminal).clone(), *trace)),
                    },
                )
            }
            _ => unreachable!("validated one native kernel outcome"),
        };
        self.state.next_serial = next;
        self.commit_debit(reservation, remaining, used);
        prepared.receipt = Some(RuntimeKernelCommitReceipt { identity, outcome });
        Ok(RuntimeKernelCensusResult {
            current,
            receipt: prepared.receipt.as_ref().unwrap(),
        })
    }
}
