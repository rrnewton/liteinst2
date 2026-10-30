//! Accuracy-only raw evidence over the existing worker/loop ownership path.
//! No scaling, correction, PMU qualification or failure-to-success conversion.
use super::*;
use rapid_profiler::frontend_native::{
    NormalAccuracyRecord, NormalCounterAcquisition, NormalCounterClose, NormalCounterEndpoint,
    NormalCounterOperation, NormalCounterRead, NormalLeafSetAccuracyBatch,
    NormalLeafSetAccuracyThread, NormalLeafSetClient, NormalLeafSetThread,
};

#[derive(Default)]
pub(super) struct Custody {
    acquisition: OnceLock<NormalCounterAcquisition>,
    close: OnceLock<NormalCounterClose>,
}
pub(super) enum Thread {
    Legacy(NormalLeafSetThread),
    Accuracy(NormalLeafSetAccuracyThread),
}
pub(super) struct Sidecars {
    pub(super) rows: Vec<NormalAccuracyRecord>,
    pub(super) acquisition: NormalCounterAcquisition,
}
pub(in crate::normal) struct Batch {
    pub(super) normal: NormalLeafSetBatch,
    pub(super) sidecars: Option<Sidecars>,
}
impl Batch {
    fn legacy(normal: NormalLeafSetBatch) -> Self {
        Self {
            normal,
            sidecars: None,
        }
    }
    fn accuracy(batch: NormalLeafSetAccuracyBatch) -> Self {
        let (normal, rows, acquisition) = batch.into_parts();
        Self {
            normal,
            sidecars: Some(Sidecars { rows, acquisition }),
        }
    }
    pub(super) fn normal(&self) -> &NormalLeafSetBatch {
        &self.normal
    }
}
impl Thread {
    /// # Safety
    /// Exactly the unchanged actual worker attach contract; accuracy additionally
    /// uses the SDK's admitted clock/counter sidecar profile on this same thread.
    pub(super) unsafe fn attach(
        client: &NormalLeafSetClient,
        readable: ReadableStack,
        evidence: Option<&Custody>,
    ) -> Self {
        assert_eq!(client.accuracy_policy().is_some(), evidence.is_some());
        if let Some(evidence) = evidence {
            let attached =
                unsafe { client.attach_accuracy(1, readable, IntervalJournal::allocate()) }
                    .unwrap();
            evidence
                .acquisition
                .set(attached.acquisition().unwrap())
                .unwrap();
            Self::Accuracy(attached)
        } else {
            Self::Legacy(
                unsafe { client.attach(1, readable, IntervalJournal::allocate()) }.unwrap(),
            )
        }
    }
    pub(super) fn totals(&self) -> NormalTotals {
        match self {
            Self::Legacy(t) => t.totals(),
            Self::Accuracy(t) => t.totals(),
        }
        .unwrap()
    }
    /// # Safety
    /// Complete physical returns and original input/code/thread postflight precede
    /// this call; the raw PMU evidence confers no acknowledgement authority.
    pub(super) unsafe fn checkpoint(&mut self) -> Option<Batch> {
        match self {
            Self::Legacy(t) => unsafe { t.checkpoint_after_returns() }
                .unwrap()
                .map(Batch::legacy),
            Self::Accuracy(t) => unsafe { t.checkpoint_after_returns() }
                .unwrap()
                .map(Batch::accuracy),
        }
    }
    pub(super) fn detach(self, evidence: Option<&Custody>) -> NormalTotals {
        match self {
            Self::Legacy(mut t) => {
                assert!(evidence.is_none());
                t.detach().unwrap()
            }
            Self::Accuracy(mut t) => {
                let detached = t.detach().unwrap();
                let evidence = evidence.expect("accuracy evidence owner");
                assert_eq!(
                    evidence.acquisition.get(),
                    Some(&detached.counter.acquisition)
                );
                evidence.close.set(detached.counter).unwrap();
                detached.totals
            }
        }
    }
}

pub(super) struct Evidence {
    pub(super) custody: Arc<Custody>,
    rows: Vec<NormalAccuracyRecord>,
    limit: usize,
    ready: bool,
    finished: bool,
}
impl Evidence {
    pub(super) fn new(calls: usize) -> Self {
        assert!(calls <= 4096);
        Self {
            custody: Arc::new(Custody::default()),
            rows: Vec::with_capacity(calls),
            limit: calls,
            ready: false,
            finished: false,
        }
    }
    pub(super) fn ready(&mut self, id: pair_worker::Identity, io: &mut Io) -> Result<(), String> {
        assert!(!self.ready);
        let a = *self
            .custody
            .acquisition
            .get()
            .expect("acquisition precedes worker Ready");
        assert_eq!((a.owner.pid, a.owner.tid), (id.pid, id.tid));
        self.ready = true; // retained acquisition precedes every fallible output
        for line in acquisition_lines(a) {
            emit(io, line)?;
        }
        Ok(())
    }
    pub(super) fn retain(
        &mut self,
        normal: &NormalLeafSetBatch,
        rows: Vec<NormalAccuracyRecord>,
        acquisition: NormalCounterAcquisition,
    ) -> std::ops::Range<usize> {
        assert!(self.ready && !self.finished);
        assert_eq!(self.custody.acquisition.get(), Some(&acquisition));
        assert_eq!(
            (acquisition.owner.pid, acquisition.owner.tid),
            (normal.pid(), normal.tid())
        );
        assert_eq!(normal.records().len(), rows.len());
        assert!(self.rows.len() + rows.len() <= self.limit);
        for (i, (raw, record)) in rows.iter().zip(normal.records()).enumerate() {
            assert_eq!(raw.function(), record.function);
            assert_eq!(raw.normal(), record.record);
            assert_eq!(raw.ordinal(), self.rows.len() as u64 + i as u64 + 1);
        }
        let start = self.rows.len();
        self.rows.extend(rows); // retain complete raw buffers, including refusals
        start..self.rows.len()
    }
    pub(super) fn emit_rows(
        &self,
        range: std::ops::Range<usize>,
        functions: &[FunctionId],
        io: &mut Io,
    ) -> Result<(), String> {
        for row in &self.rows[range] {
            let index = functions
                .iter()
                .position(|&f| f == row.function())
                .expect("immutable full roster");
            emit(io, endpoint_line(row.ordinal(), index, 0, row.start()))?;
            emit(io, endpoint_line(row.ordinal(), index, 1, row.end()))?;
        }
        Ok(())
    }
    pub(super) fn finish(&mut self, totals: NormalTotals, io: &mut Io) -> Result<(), String> {
        assert!(self.ready && !self.finished);
        assert_eq!(self.rows.len() as u64, totals.entered);
        let close = *self
            .custody
            .close
            .get()
            .expect("explicit worker detach before Finished");
        assert_eq!(self.custody.acquisition.get(), Some(&close.acquisition));
        self.finished = true;
        for line in close_lines(close) {
            emit(io, line)?;
        }
        Ok(())
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}
fn optional(value: Option<impl std::fmt::Display>) -> String {
    value.map_or_else(|| "-".into(), |v| v.to_string())
}
fn operation(op: NormalCounterOperation) -> u8 {
    match op {
        NormalCounterOperation::Id => 0,
        NormalCounterOperation::Enable => 1,
        NormalCounterOperation::Read => 2,
        NormalCounterOperation::Disable => 3,
        NormalCounterOperation::Close => 4,
    }
}
fn read_fields(read: Option<NormalCounterRead>) -> String {
    match read {
        None => "0,-,-,-,-,-".into(),
        Some(r) => {
            assert!(r.data_len <= 32);
            format!(
                "1,{},{},{},{},{}",
                operation(r.operation),
                r.syscall.result,
                optional(r.syscall.errno),
                r.data_len,
                hex(&r.data)
            )
        }
    }
}
fn acquisition_lines(a: NormalCounterAcquisition) -> Vec<String> {
    assert_eq!(a.requested_attributes.len(), 128);
    assert_eq!(a.attributes_after_open.len(), 128);
    let mut lines = vec![format!(
        "PMUOPEN,{},{},{},{}\n",
        a.owner.pid,
        a.owner.tid,
        a.open.result,
        optional(a.open.errno)
    )];
    for (kind, bytes) in [(0, &a.requested_attributes), (1, &a.attributes_after_open)] {
        for (i, chunk) in bytes.chunks_exact(64).enumerate() {
            lines.push(format!("PMUATTR,{kind},{},{}\n", i * 64, hex(chunk)));
        }
    }
    lines.push(format!("PMUCTL,0,{}\n", read_fields(a.id)));
    lines.push(format!("PMUCTL,1,{}\n", read_fields(a.enable)));
    for line in &lines {
        validate_line(line);
    }
    lines
}
fn close_lines(c: NormalCounterClose) -> Vec<String> {
    let lines = vec![
        format!("PMUCLOSE,{},{}\n", c.observer.pid, c.observer.tid),
        format!("PMUCTL,3,{}\n", read_fields(c.disable)),
        format!("PMUCTL,4,{}\n", read_fields(c.close)),
    ];
    for line in &lines {
        validate_line(line);
    }
    lines
}
fn endpoint_line(ordinal: u64, index: usize, side: u8, e: NormalCounterEndpoint) -> String {
    assert!(index < 4 && side < 2);
    let line = format!(
        "PMU,{ordinal},{index},{side},{},{},{},{},{},{},{},{},{}\n",
        e.observer.pid,
        e.observer.tid,
        e.before.ticks,
        e.before.aux,
        e.after.ticks,
        e.after.aux,
        u8::from(e.owner_matches),
        optional(e.event_id_matches.map(u8::from)),
        read_fields(e.read)
    );
    validate_line(&line);
    line
}

#[cfg(test)]
mod tests;
