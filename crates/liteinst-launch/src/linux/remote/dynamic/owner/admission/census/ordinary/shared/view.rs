use super::*;

/// Full semantic observation; construction borrows owned or shared bytes and
/// carries no control permission. Equality includes every field and full bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) struct ObservationView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) token: &'a DynamicStop,
    pub(in crate::linux::remote::dynamic::owner::admission) task: DynamicTask,
    pub(in crate::linux::remote::dynamic::owner::admission) logical_pc: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) registers: &'a RegisterSnapshot,
    pub(in crate::linux::remote::dynamic::owner::admission) xstate: &'a [u8],
    pub(in crate::linux::remote::dynamic::owner::admission) signal_mask: u64,
    pub(in crate::linux::remote::dynamic::owner::admission) phase: StopPhase,
    pub(in crate::linux::remote::dynamic::owner::admission) signal: Option<&'a DynamicSignalInfo>,
}
impl<'a> ObservationView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) fn of(value: &'a ObservedStop) -> Self {
        Self {
            token: &value.token,
            task: value.task,
            logical_pc: value.logical_pc,
            registers: &value.registers,
            xstate: &value.xstate,
            signal_mask: value.signal_mask,
            phase: value.phase,
            signal: value.signal.as_ref(),
        }
    }
}
impl ObservationHeader {
    pub(super) fn view<'a>(&'a self, xstate: &'a [u8]) -> ObservationView<'a> {
        ObservationView {
            token: &self.token,
            task: self.task,
            logical_pc: self.logical_pc,
            registers: &self.registers,
            xstate,
            signal_mask: self.signal_mask,
            phase: self.phase,
            signal: self.signal.as_ref(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct SharedObservationRef {
    pub(super) census: u64,
    pub(super) owner: OriginId,
    pub(super) execution: ExecutionId,
    pub(super) role: CaptureRole,
    pub(super) endpoint: usize,
}
fn role(endpoint: usize) -> Result<CaptureRole, SharedError> {
    match endpoint {
        0 => Ok(CaptureRole::Prior),
        1..=6 => Ok(CaptureRole::Before),
        7..=13 => Ok(CaptureRole::Step),
        _ => Err(SharedError::Endpoint),
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) enum SharedHistoryRecord {
    Refreshed {
        origin: OriginId,
        before: SharedObservationRef,
        after: SharedObservationRef,
    },
    Consumed {
        origin: OriginId,
        before: SharedObservationRef,
        successor: SharedObservationRef,
    },
}
impl SharedHistoryRecord {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn owner(
        self,
    ) -> Result<OriginId, SharedError> {
        let (before, after) = match self {
            Self::Refreshed { before, after, .. } => (before, after),
            Self::Consumed {
                before, successor, ..
            } => (before, successor),
        };
        require(
            before.owner == after.owner
                && before.census == after.census
                && before.census == before.owner.census
                && before.census != 0
                && before.execution == after.execution,
            SharedError::Identity,
        )?;
        Ok(before.owner)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) enum SharedRowView<'a> {
    Refreshed {
        origin: OriginId,
        before: ObservationView<'a>,
        after: ObservationView<'a>,
    },
    Consumed {
        origin: OriginId,
        before: ObservationView<'a>,
        successor: ObservationView<'a>,
        evidence: &'a OrdinaryEvidence,
    },
}
/// Only census code may build this context from the actually retained owner and
/// evidence. Historical resolution deliberately does not require an active row
/// or the new live census generation; retired callers supply the old identity.
pub(in crate::linux::remote::dynamic::owner::admission::census) struct ResolutionContext<'a> {
    census: u64,
    owner: &'a OriginRow,
    evidence: &'a OrdinaryEvidence,
    archive: &'a OrdinaryHistoryPayloads,
}
impl<'a> ResolutionContext<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn for_owner(
        census: u64,
        owner: &'a OriginRow,
        evidence: &'a OrdinaryEvidence,
        archive: &'a OrdinaryHistoryPayloads,
    ) -> Result<Self, SharedError> {
        archive.require_complete()?;
        require(
            census != 0
                && census == archive.binding.census
                && owner.id == archive.owner
                && owner.id.census == census
                && owner.id.serial == archive.binding.candidate_serial
                && evidence.binding == archive.binding
                && evidence.trace == archive.trace,
            SharedError::Identity,
        )?;
        let step = archive.headers[7].as_ref().ok_or(SharedError::Incomplete)?;
        require(
            owner.kind == OriginKind::CurrentHeldPc
                && owner.pc == step.logical_pc
                && owner.created_generation == step.task.generation
                && ObservationView::of(&owner.initial) == step.view(&archive.payloads[2].bytes),
            SharedError::Identity,
        )?;
        Ok(Self {
            census,
            owner,
            evidence,
            archive,
        })
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn resolve(
        &self,
        reference: SharedObservationRef,
    ) -> Result<ObservationView<'a>, SharedError> {
        // This is validation of an immutable already-complete owner, never a
        // cache of a prior active-generation check or an authority constructor.
        self.archive.require_complete()?;
        require(
            reference.census == self.census
                && reference.owner == self.owner.id
                && reference.execution == self.archive.binding.execution
                && reference.role == role(reference.endpoint)?,
            SharedError::Identity,
        )?;
        let payload = &self.archive.payloads[reference.role.index()];
        let header = self
            .archive
            .headers
            .get(reference.endpoint)
            .and_then(Option::as_ref)
            .ok_or(SharedError::Incomplete)?;
        Ok(header.view(&payload.bytes))
    }
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn resolve_row(
        &self,
        row: &SharedHistoryRecord,
    ) -> Result<SharedRowView<'a>, SharedError> {
        match *row {
            SharedHistoryRecord::Refreshed {
                origin,
                before,
                after,
            } => {
                let pair = (before.endpoint, after.endpoint);
                require(
                    matches!(
                        pair,
                        (0, 1) | (2, 3) | (4, 5) | (8, 9) | (10, 11) | (12, 13)
                    ),
                    SharedError::Endpoint,
                )?;
                let expected = if before.endpoint < 7 {
                    self.archive.binding.origin
                } else {
                    self.archive.owner
                };
                require(origin == expected, SharedError::Identity)?;
                Ok(SharedRowView::Refreshed {
                    origin,
                    before: self.resolve(before)?,
                    after: self.resolve(after)?,
                })
            }
            SharedHistoryRecord::Consumed {
                origin,
                before,
                successor,
            } => {
                require(
                    origin == self.archive.binding.origin
                        && before.endpoint == 6
                        && successor.endpoint == 7,
                    SharedError::Endpoint,
                )?;
                Ok(SharedRowView::Consumed {
                    origin,
                    before: self.resolve(before)?,
                    successor: self.resolve(successor)?,
                    evidence: self.evidence,
                })
            }
        }
    }
}
impl OrdinaryHistoryPayloads {
    fn reference(&self, endpoint: usize) -> Result<SharedObservationRef, SharedError> {
        Ok(SharedObservationRef {
            census: self.binding.census,
            owner: self.owner,
            execution: self.binding.execution,
            role: role(endpoint)?,
            endpoint,
        })
    }
    /// Construct before the integration's no-fail publication tail. These
    /// records alone cannot resolve without the actual retained owning context.
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn records(
        &self,
    ) -> Result<[SharedHistoryRecord; 7], SharedError> {
        self.require_complete()?;
        let refresh = |origin, a, b| -> Result<SharedHistoryRecord, SharedError> {
            Ok(SharedHistoryRecord::Refreshed {
                origin,
                before: self.reference(a)?,
                after: self.reference(b)?,
            })
        };
        Ok([
            refresh(self.binding.origin, 0, 1)?,
            refresh(self.binding.origin, 2, 3)?,
            refresh(self.binding.origin, 4, 5)?,
            SharedHistoryRecord::Consumed {
                origin: self.binding.origin,
                before: self.reference(6)?,
                successor: self.reference(7)?,
            },
            refresh(self.owner, 8, 9)?,
            refresh(self.owner, 10, 11)?,
            refresh(self.owner, 12, 13)?,
        ])
    }
}

/// Complete fixed descriptive binding, with no private source handle or seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct BindingView {
    pub(in crate::linux::remote::dynamic::owner::admission::census) census: u64,
    pub(in crate::linux::remote::dynamic::owner::admission::census) reservation: Reservation,
    pub(in crate::linux::remote::dynamic::owner::admission::census) candidate_serial: u64,
    pub(in crate::linux::remote::dynamic::owner::admission::census) origin: OriginId,
    pub(in crate::linux::remote::dynamic::owner::admission::census) execution: ExecutionId,
    pub(in crate::linux::remote::dynamic::owner::admission::census) source: CodeIdentity,
    pub(in crate::linux::remote::dynamic::owner::admission::census) source_index: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::census) pc: u64,
    pub(in crate::linux::remote::dynamic::owner::admission::census) next: u64,
    pub(in crate::linux::remote::dynamic::owner::admission::census) encoding: [u8; 15],
    pub(in crate::linux::remote::dynamic::owner::admission::census) encoding_len: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::census) until: Instant,
}
impl BindingView {
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    fn of(b: Binding) -> Self {
        Self {
            census: b.census,
            reservation: b.reservation,
            candidate_serial: b.candidate_serial,
            origin: b.origin,
            execution: b.execution,
            source: b.source.identity,
            source_index: b.source.index,
            pc: b.encoding.pc,
            next: b.encoding.next,
            encoding: b.encoding.bytes,
            encoding_len: b.encoding.length,
            until: b.until,
        }
    }
}
// Keep every diagnostic field in the unconditional temporary-layout bound.
#[cfg_attr(
    not(any(test, feature = "dev-exec-backing-cleanup")),
    expect(
        dead_code,
        reason = "The full diagnostic payload layout is charged even when snapshot readers are absent."
    )
)]
#[derive(Clone, Copy, Debug)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct PayloadView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission::census) role: CaptureRole,
    pub(in crate::linux::remote::dynamic::owner::admission::census) identity: PayloadIdentity,
    pub(in crate::linux::remote::dynamic::owner::admission::census) progress: Progress,
    pub(in crate::linux::remote::dynamic::owner::admission::census) bytes: &'a [u8],
}
// Keep every diagnostic field in the unconditional temporary-layout bound.
#[cfg_attr(
    not(any(test, feature = "dev-exec-backing-cleanup")),
    expect(
        dead_code,
        reason = "The full diagnostic archive layout is charged even when snapshot readers are absent."
    )
)]
#[derive(Clone, Copy, Debug)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct ArchivePartialView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission::census) address: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::census) binding: BindingView,
    pub(in crate::linux::remote::dynamic::owner::admission::census) owner: OriginId,
    pub(in crate::linux::remote::dynamic::owner::admission::census) trace: Option<NativeTrace>,
    pub(in crate::linux::remote::dynamic::owner::admission::census) prior: Progress,
    pub(in crate::linux::remote::dynamic::owner::admission::census) native: Progress,
    pub(in crate::linux::remote::dynamic::owner::admission::census) payloads:
        [PayloadView<'a>; PAYLOADS],
    pub(in crate::linux::remote::dynamic::owner::admission::census) headers:
        [Option<ObservationView<'a>>; ENDPOINTS],
    pub(in crate::linux::remote::dynamic::owner::admission::census) references:
        [Option<SharedObservationRef>; ENDPOINTS],
}
// Keep every diagnostic field in the unconditional temporary-layout bound.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "The full preparation diagnostic layout is charged even when test readers are absent."
    )
)]
#[derive(Clone, Copy, Debug)]
pub(in crate::linux::remote::dynamic::owner::admission::census) struct PartialView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission::census) allocation: Progress,
    pub(in crate::linux::remote::dynamic::owner::admission::census) installed_bytes: usize,
    pub(in crate::linux::remote::dynamic::owner::admission::census) transferred: bool,
    pub(in crate::linux::remote::dynamic::owner::admission::census) archive:
        Option<ArchivePartialView<'a>>,
}
impl OrdinaryHistoryPayloads {
    #[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn partial_view(
        &self,
    ) -> ArchivePartialView<'_> {
        ArchivePartialView {
            address: self as *const Self as usize,
            binding: BindingView::of(self.binding),
            owner: self.owner,
            trace: self.trace,
            prior: self.prior,
            native: self.native,
            payloads: std::array::from_fn(|index| {
                let p = &self.payloads[index];
                PayloadView {
                    role: [CaptureRole::Prior, CaptureRole::Before, CaptureRole::Step][index],
                    identity: PayloadIdentity::of(&p.bytes),
                    progress: p.copy,
                    bytes: &p.bytes,
                }
            }),
            headers: std::array::from_fn(|index| {
                self.headers[index].as_ref().map(|header| {
                    header.view(
                        &self.payloads[if index == 0 {
                            0
                        } else if index < 7 {
                            1
                        } else {
                            2
                        }]
                        .bytes,
                    )
                })
            }),
            references: std::array::from_fn(|index| {
                self.headers[index].as_ref().map(|_| SharedObservationRef {
                    census: self.binding.census,
                    owner: self.owner,
                    execution: self.binding.execution,
                    role: if index == 0 {
                        CaptureRole::Prior
                    } else if index < 7 {
                        CaptureRole::Before
                    } else {
                        CaptureRole::Step
                    },
                    endpoint: index,
                })
            }),
        }
    }
}
impl PreparedOrdinaryHistory {
    #[cfg(test)]
    pub(in crate::linux::remote::dynamic::owner::admission::census) fn partial_view(
        &self,
    ) -> PartialView<'_> {
        PartialView {
            allocation: self.allocation,
            installed_bytes: self.installed_bytes,
            transferred: self.transferred,
            archive: self
                .archive
                .as_deref()
                .map(OrdinaryHistoryPayloads::partial_view),
        }
    }
}
