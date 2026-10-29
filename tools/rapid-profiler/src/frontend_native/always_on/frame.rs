use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Returned {
    pub(super) pc: u64,
    pub(super) rsp: u64,
    pub(super) word: u64,
    pub(super) value: u64,
    pub(super) end: RawTimestamp,
}
pub(super) struct Frame<G> {
    pub(super) key: Arc<()>,
    pub(super) function: FunctionId,
    pub(super) registration: u64,
    pub(super) ordinal: u64,
    pub(super) rsp: u64,
    pub(super) word: u64,
    pub(super) slot: ModelReturnSlot,
    pub(super) receipt: IntervalEntry,
    pub(super) summary: Option<IntervalEntrySummary>,
    pub(super) gate: G,
    pub(super) start: RawTimestamp,
    pub(super) start_sequence: Option<u64>,
    pub(super) entry_pc: u64,
    pub(super) returned: Option<Returned>,
}
pub(super) struct Identity<'a> {
    pub(super) key: &'a Arc<()>,
    pub(super) function: FunctionId,
    pub(super) registration: u64,
}
impl<G> Frame<G> {
    pub(super) fn observe(
        &mut self,
        c: &HookContext,
        word: u64,
        end: RawTimestamp,
        pc: u64,
        identity: Identity<'_>,
    ) -> Result<(), BridgeError> {
        let Identity {
            key,
            function,
            registration,
        } = identity;
        if self.returned.is_some()
            || self.rsp != c.stack_pointer
            || self.word != word
            || c.instruction_pointer != pc
            || !Arc::ptr_eq(&self.key, key)
            || self.function != function
            || self.registration != registration
            || self.slot.identity != self.ordinal
        {
            return Err(error(Cause::Return));
        }
        self.returned = Some(Returned {
            pc,
            rsp: c.stack_pointer,
            word,
            value: c.rax,
            end,
        });
        Ok(())
    }
}

// Both paths consume the actual core receipt exactly once. Caller-specific
// preflight and irreversible full-payload postconditions remain in their wrappers.
pub(super) fn finish<G>(
    pair: &mut Frame<G>,
    model: &mut ThreadModel,
    observation: Observation,
    summary: IntervalEntrySummary,
) -> Result<IntervalExit, BridgeError> {
    let exit = model
        .finish_interval(&mut pair.receipt, &mut pair.slot, observation)
        .map_err(|e| error(Cause::Exit(e)))?;
    if exit.summary() != summary
        || pair.slot
            != (ModelReturnSlot {
                identity: pair.ordinal,
                word: TOKEN,
            })
    {
        return Err(error(Cause::Invariant));
    }
    Ok(exit)
}
