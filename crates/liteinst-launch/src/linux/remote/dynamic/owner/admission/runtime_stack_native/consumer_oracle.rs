//! Read-only borrowed native prefixes. These are historical observations,
//! never completion seals or permission to query/release a task.
use super::*;
use acquire::consumer_oracle::WordConsumerView;

pub(in crate::linux::remote::dynamic::owner::admission) struct StackNativeConsumerView<'a> {
    pub(in crate::linux::remote::dynamic::owner::admission) shape: Option<(u64, u64)>,
    pub(in crate::linux::remote::dynamic::owner::admission) until: Option<Instant>,
    pub(in crate::linux::remote::dynamic::owner::admission) states: &'a [StateSlot; STATES],
    pub(in crate::linux::remote::dynamic::owner::admission) maps: [Option<&'a MapBuffer>; MAPS],
    pub(in crate::linux::remote::dynamic::owner::admission) membership: &'a Vec<u8>,
    pub(in crate::linux::remote::dynamic::owner::admission) signals: &'a [SignalObservation; WAITS],
    pub(in crate::linux::remote::dynamic::owner::admission) debug: &'a [DebugRead; WAITS],
    pub(in crate::linux::remote::dynamic::owner::admission) profile: &'a ControlProfile,
    pub(in crate::linux::remote::dynamic::owner::admission) memory: &'a MemoryObservation,
    pub(in crate::linux::remote::dynamic::owner::admission) words: [WordConsumerView<'a>; 3],
    pub(in crate::linux::remote::dynamic::owner::admission) progress: &'a StackProgress,
    pub(in crate::linux::remote::dynamic::owner::admission) effects:
        &'a [Option<InstructionEffectRecord>; EFFECTS],
    pub(in crate::linux::remote::dynamic::owner::admission) effects_len: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) initial: Option<&'a AdmissionStop>,
    pub(in crate::linux::remote::dynamic::owner::admission) stops:
        &'a [Option<AdmissionStop>; WAITS],
    pub(in crate::linux::remote::dynamic::owner::admission) source: Option<SourceWindowId>,
    pub(in crate::linux::remote::dynamic::owner::admission) origin: Option<OriginId>,
    pub(in crate::linux::remote::dynamic::owner::admission) execution: Option<ExecutionId>,
    pub(in crate::linux::remote::dynamic::owner::admission) encoding: &'a [u8; 5],
    pub(in crate::linux::remote::dynamic::owner::admission) encoding_len: usize,
    pub(in crate::linux::remote::dynamic::owner::admission) identity:
        Option<&'a RuntimeStackIdentity>,
    pub(in crate::linux::remote::dynamic::owner::admission) trace: Option<NativeTrace>,
    pub(in crate::linux::remote::dynamic::owner::admission) call_id: Option<PotentialCallId>,
    pub(in crate::linux::remote::dynamic::owner::admission) claimed: bool,
    pub(in crate::linux::remote::dynamic::owner::admission) native_payload_bytes: usize,
}
impl PreparedStackNative {
    pub(in crate::linux::remote::dynamic::owner::admission) fn consumer_view(
        &self,
    ) -> StackNativeConsumerView<'_> {
        StackNativeConsumerView {
            shape: self.shape.map(|v| (v.start, v.end)),
            until: self.until,
            states: &self.states,
            maps: std::array::from_fn(|i| self.maps[i].consumer_retained()),
            membership: &self.membership,
            signals: &self.signals,
            debug: &self.debug,
            profile: &self.profile,
            memory: &self.peek,
            words: std::array::from_fn(|i| self.words[i].consumer_view()),
            progress: &self.progress,
            effects: &self.progress.effects,
            effects_len: self.progress.effects_len,
            initial: self.initial.as_ref(),
            stops: &self.stops,
            source: self.source,
            origin: self.origin,
            execution: self.execution,
            encoding: &self.encoding,
            encoding_len: self.encoding_len,
            identity: self.identity.as_ref(),
            trace: self.trace,
            call_id: self.call_id,
            claimed: self.claimed,
            native_payload_bytes: self.native_payload_bytes,
        }
    }
}

/// Borrowed-view stack metadata only; all payloads remain in their original
/// native/acquisition owners and are not charged as new copies here.
pub(in crate::linux::remote::dynamic::owner::admission) fn temporary_bytes()
-> Result<usize, LaunchError> {
    size_of::<StackNativeConsumerView<'_>>()
        .checked_add(acquire::consumer_oracle::temporary_bytes()?)
        .ok_or(LaunchError::Invalid("consumer native view size overflows"))
}
