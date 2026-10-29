//! Full function-set history identity; no receipt, executable or export authority.
use super::*;
use crate::frontend::{Action, HistoryChunk, HistoryView};
use std::ops::Range;

/// Opaque in-process identity. Clones retain only a key, not Session/epoch/code.
#[derive(Clone, Debug)]
pub struct NormalCallPairHistoryStream {
    key: Arc<()>,
    pid: u32,
    install: u64,
    identity: CodeIdentity,
    functions: [FunctionId; 2],
    entries: [u64; 2],
    edge: [u64; 3],
}
impl PartialEq for NormalCallPairHistoryStream {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.key, &other.key)
            && self.pid == other.pid
            && self.install == other.install
            && self.identity == other.identity
            && self.functions == other.functions
            && self.entries == other.entries
            && self.edge == other.edge
    }
}
impl Eq for NormalCallPairHistoryStream {}
impl NormalCallPairHistoryStream {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn install(&self) -> u64 {
        self.install
    }
    pub fn identity(&self) -> CodeIdentity {
        self.identity
    }
    pub fn functions(&self) -> &[FunctionId; 2] {
        &self.functions
    }
    pub fn entries(&self) -> &[u64; 2] {
        &self.entries
    }
    pub fn edge(&self) -> [u64; 3] {
        self.edge
    }
    pub fn format(&self) -> HistoryFormat {
        HistoryFormat::AbsoluteV1
    }
}
pub(super) fn stream_for(binding: &Binding) -> Option<NormalCallPairHistoryStream> {
    if !session::binding_matches(binding) {
        return None;
    }
    let BindingProfile::CallPair { site, functions } = &binding.profile else {
        return None;
    };
    Some(NormalCallPairHistoryStream {
        key: Arc::clone(&binding.key),
        pid: binding.pid,
        install: binding.install,
        identity: site.identity(),
        functions: *functions,
        entries: [site.functions()[0].entry(), site.functions()[1].entry()],
        edge: [
            site.edge().call_pc(),
            site.edge().callee_entry(),
            site.edge().continuation(),
        ],
    })
}

/// Contiguous immutable action transfer. A complete stream starts at 1/0/Initial.
#[derive(Debug, Eq, PartialEq)]
pub struct NormalCallPairHistoryBatch {
    stream: NormalCallPairHistoryStream,
    chunk: HistoryChunk,
}
impl NormalCallPairHistoryBatch {
    pub(super) fn from_checked(stream: NormalCallPairHistoryStream, chunk: HistoryChunk) -> Self {
        Self { stream, chunk }
    }
    pub fn stream(&self) -> &NormalCallPairHistoryStream {
        &self.stream
    }
    pub fn number(&self) -> u64 {
        self.chunk.number
    }
    pub fn range(&self) -> Range<u64> {
        self.chunk.range.clone()
    }
    pub fn before(&self) -> HistoryBinding {
        self.chunk.before
    }
    pub fn after(&self) -> HistoryBinding {
        self.chunk.after
    }
    pub fn actions(&self) -> &[Action] {
        &self.chunk.actions
    }
    pub fn follows(&self, previous: &Self) -> bool {
        self.stream == previous.stream
            && previous.number().checked_add(1) == Some(self.number())
            && previous.chunk.range.end == self.chunk.range.start
            && previous.after() == self.before()
    }
    /// Replay an absolute prefix in this chunk. Consumers join its generation
    /// with each saved entry owner; timestamps/current state are not selectors.
    pub fn binding_at(&self, prefix: u64) -> Option<HistoryBinding> {
        history::replay(&self.chunk, prefix)
    }
}

/// Bounded resident suffix with carry-in and status; not a complete-history claim.
#[derive(Debug, Eq, PartialEq)]
pub struct NormalCallPairHistoryWindow {
    stream: NormalCallPairHistoryStream,
    view: HistoryView,
}
impl NormalCallPairHistoryWindow {
    pub(super) fn from_checked(stream: NormalCallPairHistoryStream, view: HistoryView) -> Self {
        Self { stream, view }
    }
    pub fn stream(&self) -> &NormalCallPairHistoryStream {
        &self.stream
    }
    pub fn range(&self) -> Range<u64> {
        self.view.chunk.range.clone()
    }
    pub fn last_batch_number(&self) -> u64 {
        self.view.chunk.number
    }
    pub fn before(&self) -> HistoryBinding {
        self.view.chunk.before
    }
    pub fn after(&self) -> HistoryBinding {
        self.view.chunk.after
    }
    pub fn actions(&self) -> &[Action] {
        &self.view.chunk.actions
    }
    pub fn status(&self) -> ControllerStatus {
        self.view.status
    }
    pub fn current(&self) -> Option<GenerationId> {
        self.view.current
    }
    pub fn enabled(&self) -> &[bool] {
        &self.view.enabled
    }
    pub fn retained_failed_generation(&self) -> Option<GenerationId> {
        self.view.retained_failed_generation
    }
}
