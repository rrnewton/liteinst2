//! Full function-set history identity; no receipt, executable or export authority.
use super::*;
use crate::frontend::{Action, HistoryChunk, HistoryView};
use std::ops::Range;

/// Opaque in-process identity. Clones retain only a key, not Session/epoch/code.
#[derive(Clone, Debug)]
pub struct NormalLeafSetHistoryStream {
    key: Arc<()>,
    pid: u32,
    install: u64,
    identity: CodeIdentity,
    accuracy: Option<Policy>,
    pub(super) functions: LeafFunctions,
    pub(super) entries: [u64; 4],
}
impl PartialEq for NormalLeafSetHistoryStream {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.key, &other.key)
            && self.pid == other.pid
            && self.install == other.install
            && self.identity == other.identity
            && self.accuracy == other.accuracy
            && self.functions == other.functions
            && self.entries == other.entries
    }
}
impl Eq for NormalLeafSetHistoryStream {}
impl NormalLeafSetHistoryStream {
    /// Exact constructor policy carried by this opaque stream; no clock authority.
    pub fn accuracy_policy(&self) -> Option<Policy> {
        self.accuracy
    }
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn install(&self) -> u64 {
        self.install
    }
    pub fn identity(&self) -> CodeIdentity {
        self.identity
    }
    pub fn functions(&self) -> &[FunctionId] {
        self.functions.as_slice()
    }
    pub fn entries(&self) -> &[u64] {
        &self.entries[..self.functions.as_slice().len()]
    }
    pub fn format(&self) -> HistoryFormat {
        HistoryFormat::AbsoluteV1
    }
}
pub(super) fn stream_for(binding: &Binding) -> Option<NormalLeafSetHistoryStream> {
    if !binding_matches(binding) {
        return None;
    }
    let BindingProfile::LeafSet {
        site,
        functions,
        accuracy,
    } = &binding.profile
    else {
        return None;
    };
    let mut entries = [0; 4];
    for (entry, function) in entries.iter_mut().zip(site.functions()) {
        *entry = function.entry();
    }
    Some(NormalLeafSetHistoryStream {
        key: Arc::clone(&binding.key),
        pid: binding.pid,
        install: binding.install,
        identity: site.identity(),
        accuracy: *accuracy,
        functions: *functions,
        entries,
    })
}

/// Contiguous immutable action transfer. A complete stream starts at 1/0/Initial.
#[derive(Debug, Eq, PartialEq)]
pub struct NormalLeafSetHistoryBatch {
    stream: NormalLeafSetHistoryStream,
    chunk: HistoryChunk,
}
impl NormalLeafSetHistoryBatch {
    pub(super) fn from_checked(stream: NormalLeafSetHistoryStream, chunk: HistoryChunk) -> Self {
        Self { stream, chunk }
    }
    pub fn stream(&self) -> &NormalLeafSetHistoryStream {
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
        super::super::history::replay(&self.chunk, prefix)
    }
}

/// Bounded resident suffix with carry-in and status; not a complete-history claim.
#[derive(Debug, Eq, PartialEq)]
pub struct NormalLeafSetHistoryWindow {
    stream: NormalLeafSetHistoryStream,
    view: HistoryView,
}
impl NormalLeafSetHistoryWindow {
    pub(super) fn from_checked(stream: NormalLeafSetHistoryStream, view: HistoryView) -> Self {
        Self { stream, view }
    }
    pub fn stream(&self) -> &NormalLeafSetHistoryStream {
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

#[cfg(test)]
mod tests;
