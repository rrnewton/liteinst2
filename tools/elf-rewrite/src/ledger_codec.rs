//! Explicit lossless ExpectedBytes storage. Integrity is not semantic admission.
//! Legacy writers and semantic consumers retain their own checks and defaults.
use crate::model::{Error, Selection};
use formats::{ContentHasher, ContentId};
use li2core::contracts::ExpectedBytes;
use std::fmt::Write as _;
use std::io::Write;

pub const PROFILE: &str = "read-chunks256-v1";
pub const CHUNK_BYTES: usize = 256;
pub const MEMBER_BYTES: usize = 64 * 1024 * 1024;
pub const ENVELOPE_BYTES: usize = 2 * MEMBER_BYTES;

fn fail(reason: &'static str) -> Error {
    Error::new("ledger-codec", reason)
}
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or_else(|| fail("size overflow"))
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or_else(|| fail("size overflow"))
}
fn require(ok: bool, reason: &'static str) -> Result<(), Error> {
    if ok { Ok(()) } else { Err(fail(reason)) }
}

/// Caller-authenticated supported-plan contract, not generic model limits.
/// Each actual step/read is checked; these maxima never authorize omissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadContract {
    pub max_steps: usize,
    pub max_reads_per_step: usize,
    pub max_read_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    contract: ReadContract,
    reads: usize,
    references: usize,
    unique: usize,
    expanded: usize,
    working: usize,
    staging: usize,
}
impl Limits {
    /// Working bounds codec-owned allocation requests, including transient
    /// replacement buffers. Borrowed inputs and allocator overhead remain under
    /// the unchanged external process-memory limit. Staging is the additional
    /// simultaneously retained encoding bytes outside the three supplied files.
    pub fn new(
        contract: ReadContract,
        working_bytes: usize,
        staging_bytes: usize,
    ) -> Result<Self, Error> {
        require(
            working_bytes <= ENVELOPE_BYTES && staging_bytes <= ENVELOPE_BYTES,
            "encoding envelope",
        )?;
        let reads = mul(contract.max_steps, contract.max_reads_per_step)?;
        let per_read = contract.max_read_bytes.div_ceil(CHUNK_BYTES);
        let references = mul(reads, per_read)?;
        let expanded = add(MEMBER_BYTES, mul(mul(reads, contract.max_read_bytes)?, 2)?)?;
        Ok(Self {
            contract,
            reads,
            references,
            unique: references.min(MEMBER_BYTES / 13),
            expanded,
            working: working_bytes,
            staging: staging_bytes,
        })
    }
    /// Call before adding/copying final carrier rows or publishing any member.
    pub const fn read_contract(&self) -> ReadContract {
        self.contract
    }
    pub const fn working_bytes(&self) -> usize {
        self.working
    }
    pub const fn staging_bytes(&self) -> usize {
        self.staging
    }
    pub fn check_storage_lengths(
        &self,
        plan: usize,
        final_ledger: usize,
        table: usize,
    ) -> Result<(), Error> {
        require(
            plan <= MEMBER_BYTES && final_ledger <= MEMBER_BYTES && table <= MEMBER_BYTES,
            "member byte limit",
        )?;
        require(
            add(add(add(plan, final_ledger)?, table)?, self.staging)? <= ENVELOPE_BYTES,
            "encoding envelope",
        )
    }
    fn memory(&self, bytes: usize) -> Result<(), Error> {
        // Fixed auxiliary headroom covers bounded codec format/hex temporaries;
        // the potentially large text, chunks and indices are charged separately.
        require(add(bytes, 4096)? <= self.working, "working byte limit")
    }
}

#[derive(Debug)]
pub struct EncodedPlan {
    pub ledger: Vec<u8>,
    pub table: Vec<u8>,
}

/// The existing single traversal, with compact read emission. This writes the
/// ordinary plan body only; shared veneer/group/fixed/carrier extensions remain
/// consumer integration work and must retain the finalized table and limits.
pub fn encode_plan(
    selection: &Selection,
    plans: &[(u64, &li2core::emission::ArtifactPlan)],
    composition: &li2core::composition::Composition,
    dependencies: &[crate::carrier::elf64::FileRange],
    limits: Limits,
) -> Result<EncodedPlan, Error> {
    crate::ledger::plans_view_encoded(selection, plans, composition, dependencies, Some(limits))
}

// Hash only selects a bucket. Byte equality, including length, decides identity.
fn bucket(bytes: &[u8]) -> usize {
    let mut h = 0xcbf29ce484222325u64;
    for b in bytes {
        h = (h ^ u64::from(*b)).wrapping_mul(0x100000001b3);
    }
    h as usize
}
fn slots_for(n: usize) -> Result<usize, Error> {
    if n == 0 {
        return Ok(0);
    }
    mul(n, 2)?
        .checked_next_power_of_two()
        .ok_or_else(|| fail("size overflow"))
}
fn reserved<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| fail("allocation failed"))?;
    // std may report a larger allocation; never subsequently use unbudgeted capacity.
    require(v.capacity() == n, "unexpected allocation capacity")?;
    Ok(v)
}

struct Interner<'a> {
    bytes: Vec<&'a [u8]>,
    slots: Vec<usize>,
}
impl<'a> Interner<'a> {
    fn memory(&self) -> Result<usize, Error> {
        add(
            mul(self.bytes.capacity(), std::mem::size_of::<&[u8]>())?,
            mul(self.slots.capacity(), std::mem::size_of::<usize>())?,
        )
    }
    fn intern(&mut self, bytes: &'a [u8], limits: Limits, buffer: usize) -> Result<usize, Error> {
        if !self.slots.is_empty() {
            let mut at = bucket(bytes) & (self.slots.len() - 1);
            while self.slots[at] != 0 {
                let id = self.slots[at] - 1;
                if self.bytes[id] == bytes {
                    return Ok(id);
                }
                at = (at + 1) & (self.slots.len() - 1);
            }
        }
        let needed = add(self.bytes.len(), 1)?;
        require(needed <= limits.unique, "unique chunk limit")?;
        if needed > self.bytes.capacity() {
            let capacity = needed
                .checked_next_power_of_two()
                .ok_or_else(|| fail("size overflow"))?
                .min(limits.unique);
            let slot_count = slots_for(capacity)?;
            let replacement = add(
                mul(capacity, std::mem::size_of::<&[u8]>())?,
                mul(slot_count, std::mem::size_of::<usize>())?,
            )?;
            limits.memory(add(add(buffer, self.memory()?)?, replacement)?)?;
            let mut entries = reserved(capacity)?;
            entries.extend_from_slice(&self.bytes);
            let mut slots = reserved(slot_count)?;
            slots.resize(slot_count, 0);
            for (id, chunk) in entries.iter().enumerate() {
                let mut at = bucket(chunk) & (slot_count - 1);
                while slots[at] != 0 {
                    at = (at + 1) & (slot_count - 1);
                }
                slots[at] = id + 1;
            }
            self.bytes = entries;
            self.slots = slots;
        }
        let id = self.bytes.len();
        let mut at = bucket(bytes) & (self.slots.len() - 1);
        while self.slots[at] != 0 {
            at = (at + 1) & (self.slots.len() - 1);
        }
        self.bytes.push(bytes);
        self.slots[at] = id + 1;
        Ok(id)
    }
}

fn append(text: &mut String, value: &str, limits: Limits, other: usize) -> Result<(), Error> {
    let needed = add(text.len(), value.len())?;
    require(needed <= MEMBER_BYTES, "member byte limit")?;
    if needed > text.capacity() {
        // Geometric growth avoids one reallocation per formatting fragment;
        // both old and replacement buffers count at the transient peak.
        let available = limits
            .working
            .checked_sub(add(add(other, text.capacity())?, 4096)?)
            .ok_or_else(|| fail("working byte limit"))?;
        let target = needed
            .checked_next_power_of_two()
            .unwrap_or(MEMBER_BYTES)
            .min(MEMBER_BYTES)
            .min(available);
        require(target >= needed, "working byte limit")?;
        limits.memory(add(add(other, text.capacity())?, target)?)?;
        text.try_reserve_exact(target - text.len())
            .map_err(|_| fail("allocation failed"))?;
    }
    limits.memory(add(other, text.capacity())?)?;
    text.push_str(value);
    Ok(())
}

pub(crate) struct PlanWriter<'a> {
    out: String,
    limits: Option<Limits>,
    interner: Interner<'a>,
    error: Option<Error>,
    steps: usize,
    reads: usize,
    references: usize,
}
impl<'a> PlanWriter<'a> {
    pub(crate) fn new(header: String, limits: Option<Limits>) -> Self {
        Self {
            out: header,
            limits,
            interner: Interner {
                bytes: Vec::new(),
                slots: Vec::new(),
            },
            error: None,
            steps: 0,
            reads: 0,
            references: 0,
        }
    }
    pub(crate) fn reads(&mut self, site: u64, step: usize, reads: &'a [ExpectedBytes]) {
        if self.limits.is_none() {
            for read in reads {
                writeln!(
                    self.out,
                    "step-read\t{site}\t{step}\t{}\t{}",
                    read.address,
                    crate::ledger::hex(&read.bytes)
                )
                .unwrap();
            }
        } else if self.error.is_none() {
            if let Err(error) = self.compact_reads(site, step, reads) {
                let _ = self.error.get_or_insert(error);
            }
        }
    }
    fn compact_reads(
        &mut self,
        site: u64,
        step: usize,
        reads: &'a [ExpectedBytes],
    ) -> Result<(), Error> {
        let limits = self.limits.unwrap();
        self.steps = add(self.steps, 1)?;
        self.reads = add(self.reads, reads.len())?;
        require(
            self.steps <= limits.contract.max_steps
                && reads.len() <= limits.contract.max_reads_per_step
                && self.reads <= limits.reads,
            "read contract",
        )?;
        writeln!(self, "step-reads\t{site}\t{step}\t{}", reads.len()).unwrap();
        for (ordinal, read) in reads.iter().enumerate() {
            require(
                read.bytes.len() <= limits.contract.max_read_bytes
                    && read.address.checked_add(read.bytes.len() as u64).is_some(),
                "read length/address",
            )?;
            self.references = add(self.references, read.bytes.chunks(CHUNK_BYTES).len())?;
            require(self.references <= limits.references, "reference limit")?;
            writeln!(
                self,
                "step-read-ref\t{site}\t{step}\t{ordinal}\t{}\t{}\t{}\t{}",
                read.address,
                read.bytes.len(),
                crate::ledger::hex(&ContentId::of(&read.bytes).0),
                if read.bytes.is_empty() { "-" } else { "" }
            )
            .unwrap();
            // Replace the just-written newline with the IDs, without a per-read Vec.
            if self.error.is_some() {
                return Ok(());
            }
            self.out.pop();
            for (i, chunk) in read.bytes.chunks(CHUNK_BYTES).enumerate() {
                let id = self.interner.intern(chunk, limits, self.out.capacity())?;
                if i != 0 {
                    write!(self, ",").unwrap();
                }
                write!(self, "{id}").unwrap();
                if self.error.is_some() {
                    return Ok(());
                }
            }
            writeln!(self).unwrap();
            if self.error.is_some() {
                return Ok(());
            }
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<EncodedPlan, Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let Some(limits) = self.limits else {
            return Ok(EncodedPlan {
                ledger: self.out.into_bytes(),
                table: Vec::new(),
            });
        };
        let other = add(self.out.capacity(), self.interner.memory()?)?;
        let mut table = String::new();
        append(
            &mut table,
            &format!("LI2READ-CHUNKS\t1\t256\t{}\n", self.interner.bytes.len()),
            limits,
            other,
        )?;
        for (id, chunk) in self.interner.bytes.iter().enumerate() {
            append(
                &mut table,
                &format!(
                    "chunk\t{id}\t{}\t{}\n",
                    chunk.len(),
                    crate::ledger::hex(chunk)
                ),
                limits,
                other,
            )?;
        }
        let binding = format!(
            "read-storage\t{PROFILE}\t{}\t{}\n",
            table.len(),
            crate::ledger::hex(&ContentId::of(table.as_bytes()).0)
        );
        let old_header = "LI2LEDGER\t1\n";
        require(self.out.starts_with(old_header), "producer header")?;
        let size = add(self.out.len(), binding.len())?;
        limits.check_storage_lengths(size, size, table.len())?;
        limits.memory(add(add(other, table.capacity())?, size)?)?;
        let mut ledger = reserved(size)?;
        ledger.extend_from_slice(b"LI2LEDGER\t2\n");
        ledger.extend_from_slice(binding.as_bytes());
        ledger.extend_from_slice(&self.out.as_bytes()[old_header.len()..]);
        Ok(EncodedPlan {
            ledger,
            table: table.into_bytes(),
        })
    }
}
impl std::fmt::Write for PlanWriter<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        if self.error.is_none() {
            if let Some(limits) = self.limits {
                let result = self
                    .interner
                    .memory()
                    .and_then(|other| append(&mut self.out, s, limits, other));
                if let Err(error) = result {
                    self.error = Some(error);
                }
            } else {
                self.out.push_str(s);
            }
        }
        // Existing traversal's semantic checks still run after a storage refusal.
        Ok(())
    }
}

fn fields<const N: usize>(line: &str) -> Result<[&str; N], Error> {
    let mut out = [""; N];
    let mut iter = line.split('\t');
    for value in &mut out {
        *value = iter.next().ok_or_else(|| fail("row shape"))?;
    }
    require(iter.next().is_none(), "row shape")?;
    Ok(out)
}
fn number(s: &str) -> Result<usize, Error> {
    require(
        !s.is_empty() && (s == "0" || !s.starts_with('0')) && s.bytes().all(|b| b.is_ascii_digit()),
        "noncanonical number",
    )?;
    s.parse().map_err(|_| fail("number overflow"))
}
fn address(s: &str) -> Result<u64, Error> {
    let n = number(s)?;
    u64::try_from(n).map_err(|_| fail("number overflow"))
}
fn nibble(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(fail("noncanonical hex")),
    }
}
fn decode_hex(s: &str, out: &mut [u8]) -> Result<(), Error> {
    require(s.len() == mul(out.len(), 2)?, "hex length")?;
    for (to, from) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        *to = (nibble(from[0])? << 4) | nibble(from[1])?;
    }
    Ok(())
}
fn digest(s: &str) -> Result<ContentId, Error> {
    let mut bytes = [0; 32];
    decode_hex(s, &mut bytes)?;
    Ok(ContentId(bytes))
}
fn text(bytes: &[u8]) -> Result<&str, Error> {
    require(
        bytes.ends_with(b"\n") && !bytes.contains(&b'\r'),
        "line envelope",
    )?;
    std::str::from_utf8(bytes).map_err(|_| fail("non-UTF8 ledger"))
}
struct Chunk {
    bytes: [u8; CHUNK_BYTES],
    len: usize,
}
impl Chunk {
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

pub struct LedgerView<'a> {
    text: &'a str,
    chunks: Vec<Chunk>,
    limits: Limits,
    counts: Counts,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    pub steps: usize,
    pub reads: usize,
    pub references: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalSummary {
    pub bytes: usize,
    pub sha256: ContentId,
    pub counts: Counts,
}

impl<'a> LedgerView<'a> {
    pub fn new(
        plan: &'a [u8],
        final_ledger: &'a [u8],
        table: &[u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.check_storage_lengths(plan.len(), final_ledger.len(), table.len())?;
        require(final_ledger.starts_with(plan), "physical plan prefix")?;
        let plan_text = text(plan)?;
        let final_text = text(final_ledger)?;
        let mut plan_lines = plan_text.lines();
        require(
            matches!(
                plan_lines.next(),
                Some("LI2LEDGER\t2" | "LI2GROUPED-LEDGER\t2")
            ),
            "ledger version",
        )?;
        let b = fields::<4>(plan_lines.next().ok_or_else(|| fail("table binding"))?)?;
        require(b[0] == "read-storage" && b[1] == PROFILE, "table binding")?;
        require(
            number(b[2])? == table.len() && digest(b[3])? == ContentId::of(table),
            "table identity",
        )?;
        require(
            !plan_text.contains("CARRIER-EXTENSION\t"),
            "carrier in plan",
        )?;
        require(
            final_ledger.len() == plan.len()
                || final_ledger[plan.len()..].starts_with(b"CARRIER-EXTENSION\t1\n"),
            "carrier tail",
        )?;
        let mut table_lines = text(table)?.lines();
        let h = fields::<4>(table_lines.next().ok_or_else(|| fail("table version"))?)?;
        require(h[..3] == ["LI2READ-CHUNKS", "1", "256"], "table version")?;
        let count = number(h[3])?;
        require(count <= limits.unique, "unique chunk limit")?;
        require(table_lines.clone().count() == count, "table count")?;
        let slots_len = slots_for(count)?;
        limits.memory(add(
            mul(count, std::mem::size_of::<Chunk>())?,
            mul(slots_len, std::mem::size_of::<usize>())?,
        )?)?;
        let mut chunks: Vec<Chunk> = reserved(count)?;
        let mut slots = reserved(slots_len)?;
        slots.resize(slots_len, 0usize);
        for id in 0..count {
            let r = fields::<4>(table_lines.next().ok_or_else(|| fail("table count"))?)?;
            require(r[0] == "chunk" && number(r[1])? == id, "chunk ID order")?;
            let len = number(r[2])?;
            require((1..=CHUNK_BYTES).contains(&len), "chunk length")?;
            let mut chunk = Chunk {
                bytes: [0; CHUNK_BYTES],
                len,
            };
            decode_hex(r[3], &mut chunk.bytes[..len])?;
            let mut at = bucket(chunk.bytes()) & (slots_len - 1);
            while slots[at] != 0 {
                require(
                    chunks[slots[at] - 1].bytes() != chunk.bytes(),
                    "duplicate chunk bytes",
                )?;
                at = (at + 1) & (slots_len - 1);
            }
            slots[at] = id + 1;
            chunks.push(chunk);
        }
        require(table_lines.next().is_none(), "table count")?;
        drop(slots);
        let mut view = Self {
            text: final_text,
            chunks,
            limits,
            counts: Counts::default(),
        };
        view.validate_rows(plan.len())?;
        Ok(view)
    }
    fn validate_rows(&mut self, plan_len: usize) -> Result<(), Error> {
        let mut step: Option<(u64, usize)> = None;
        let mut declaration = false;
        let mut before_reads = 0u8;
        let mut remaining = 0;
        let mut ordinal = 0;
        let mut next_chunk = 0;
        let mut expanded_read_bytes = 0usize;
        let mut offset = 0;
        // Site order belongs to the producer; no monotonic-PC assumption.
        // A bounded vector detects return to an already completed site.
        let mut sites: Vec<u64> = Vec::new();
        for (line_no, line) in self.text.lines().enumerate() {
            // Each newline consumes a member byte; this also bounds no-read
            // floods and line scanning independently of the read contract.
            require(
                line_no < MEMBER_BYTES && line.len() < MEMBER_BYTES,
                "record/line limit",
            )?;
            let in_plan = offset < plan_len;
            offset = add(offset, add(line.len(), 1)?)?;
            if line_no < 2 {
                continue;
            }
            let kind = line.split('\t').next().unwrap();
            if before_reads == 2 {
                let r = fields::<6>(line)?;
                require(
                    r[0] == "live-prerequisites-not-receipts"
                        && step == Some((address(r[1])?, number(r[2])?)),
                    "read declaration position",
                )?;
                before_reads = 1;
                continue;
            }
            if before_reads == 1 {
                require(kind == "step-reads", "read declaration position")?;
            }
            if kind == "step" {
                require(
                    remaining == 0 && (step.is_none() || declaration),
                    "read declaration/count",
                )?;
                require(in_plan, "step outside plan")?;
                let r = fields::<8>(line)?;
                let current = (address(r[1])?, number(r[2])?);
                self.counts.steps = add(self.counts.steps, 1)?;
                require(
                    self.counts.steps <= self.limits.contract.max_steps,
                    "read contract",
                )?;
                if step.is_some_and(|s| s.0 == current.0) {
                    require(current.1 == add(step.unwrap().1, 1)?, "step order")?;
                } else {
                    require(current.1 == 0 && !sites.contains(&current.0), "step order")?;
                    let wanted = add(sites.len(), 1)?;
                    self.limits.memory(add(
                        mul(self.chunks.capacity(), std::mem::size_of::<Chunk>())?,
                        mul(add(sites.capacity(), wanted)?, std::mem::size_of::<u64>())?,
                    )?)?;
                    sites
                        .try_reserve_exact(1)
                        .map_err(|_| fail("allocation failed"))?;
                    sites.push(current.0);
                }
                step = Some(current);
                declaration = false;
                ordinal = 0;
                before_reads = 2;
            } else if kind == "step-reads" {
                let r = fields::<4>(line)?;
                require(
                    in_plan && !declaration && step == Some((address(r[1])?, number(r[2])?)),
                    "read declaration/count",
                )?;
                remaining = number(r[3])?;
                require(
                    remaining <= self.limits.contract.max_reads_per_step,
                    "read contract",
                )?;
                declaration = true;
                before_reads = 0;
            } else if kind == "step-read-ref" {
                require(
                    in_plan && declaration && remaining != 0,
                    "read declaration/count",
                )?;
                let read = parse_read(line, &self.chunks, self.limits)?;
                require(
                    step == Some((read.site, read.step)) && read.ordinal == ordinal,
                    "read order",
                )?;
                self.counts.reads = add(self.counts.reads, 1)?;
                require(self.counts.reads <= self.limits.reads, "read contract")?;
                let count = if read.ids == "-" {
                    0
                } else {
                    add(read.ids.bytes().filter(|b| *b == b',').count(), 1)?
                };
                let expected = read.len.div_ceil(CHUNK_BYTES);
                require(count == expected, "read reference count")?;
                self.counts.references = add(self.counts.references, count)?;
                require(
                    self.counts.references <= self.limits.references,
                    "reference limit",
                )?;
                expanded_read_bytes = add(expanded_read_bytes, mul(read.len, 2)?)?;
                require(
                    add(self.text.len(), expanded_read_bytes)? <= self.limits.expanded,
                    "expanded byte limit",
                )?;
                let mut hash = ContentHasher::new();
                let mut left = read.len;
                if count != 0 {
                    for raw in read.ids.split(',') {
                        let id = number(raw)?;
                        require(id <= next_chunk, "chunk first-encounter order")?;
                        let chunk = self
                            .chunks
                            .get(id)
                            .ok_or_else(|| fail("missing chunk"))?
                            .bytes();
                        if id == next_chunk {
                            next_chunk = add(next_chunk, 1)?;
                        }
                        require(chunk.len() == left.min(CHUNK_BYTES), "read chunk tail")?;
                        left -= chunk.len();
                        hash.update(chunk);
                    }
                }
                require(left == 0 && hash.finish() == read.sha256, "read digest")?;
                remaining -= 1;
                ordinal += 1;
            } else {
                require(remaining == 0, "read declaration/count")?;
                require(
                    !matches!(
                        kind,
                        "step-read"
                            | "read-storage"
                            | "LI2LEDGER"
                            | "LI2GROUPED-LEDGER"
                            | "LI2READ-CHUNKS"
                    ),
                    "unexpected codec row",
                )?;
            }
        }
        require(
            remaining == 0 && (step.is_none() || declaration),
            "read declaration/count",
        )?;
        require(next_chunk == self.chunks.len(), "unreferenced chunk")?;
        Ok(())
    }
    pub fn records(&self) -> impl Iterator<Item = Record<'_>> {
        self.text.lines().filter_map(|line| {
            if line.starts_with("read-storage\t") || line.starts_with("step-reads\t") {
                None
            } else if line.starts_with("step-read-ref\t") {
                Some(Record::Read(
                    parse_read(line, &self.chunks, self.limits).expect("checked read"),
                ))
            } else {
                Some(Record::Other(match line {
                    "LI2LEDGER\t2" => "LI2LEDGER\t1",
                    "LI2GROUPED-LEDGER\t2" => "LI2GROUPED-LEDGER\t1",
                    _ => line,
                }))
            }
        })
    }
    pub fn write_inline(&self, writer: &mut impl Write) -> Result<CanonicalSummary, Error> {
        let mut hash = ContentHasher::new();
        let mut bytes = 0usize;
        let mut emit = |part: &[u8]| -> Result<(), Error> {
            bytes = add(bytes, part.len())?;
            require(bytes <= self.limits.expanded, "expanded byte limit")?;
            writer.write_all(part).map_err(|_| fail("output write"))?;
            hash.update(part);
            Ok(())
        };
        for row in self.records() {
            match row {
                Record::Other(line) => {
                    emit(line.as_bytes())?;
                    emit(b"\n")?;
                }
                Record::Read(read) => {
                    emit(
                        format!(
                            "step-read\t{}\t{}\t{}\t",
                            read.site, read.step, read.address
                        )
                        .as_bytes(),
                    )?;
                    let mut hex = [0; CHUNK_BYTES * 2];
                    for chunk in read.chunks() {
                        const DIGITS: &[u8; 16] = b"0123456789abcdef";
                        for (pair, b) in hex.chunks_exact_mut(2).zip(chunk) {
                            pair[0] = DIGITS[(b >> 4) as usize];
                            pair[1] = DIGITS[(b & 15) as usize];
                        }
                        emit(&hex[..chunk.len() * 2])?;
                    }
                    emit(b"\n")?;
                }
            }
        }
        Ok(CanonicalSummary {
            bytes,
            sha256: hash.finish(),
            counts: self.counts,
        })
    }
    pub fn summary(&self) -> Result<CanonicalSummary, Error> {
        self.write_inline(&mut std::io::sink())
    }
}
fn parse_read<'v>(
    line: &'v str,
    chunks: &'v [Chunk],
    limits: Limits,
) -> Result<ReadView<'v>, Error> {
    let r = fields::<8>(line)?;
    let len = number(r[5])?;
    let pc = address(r[4])?;
    require(
        len <= limits.contract.max_read_bytes && pc.checked_add(len as u64).is_some(),
        "read length/address",
    )?;
    Ok(ReadView {
        site: address(r[1])?,
        step: number(r[2])?,
        ordinal: number(r[3])?,
        address: pc,
        len,
        sha256: digest(r[6])?,
        ids: r[7],
        chunks,
    })
}

#[derive(Clone, Copy)]
pub enum Record<'a> {
    Other(&'a str),
    Read(ReadView<'a>),
}
#[derive(Clone, Copy)]
pub struct ReadView<'a> {
    pub site: u64,
    pub step: usize,
    pub ordinal: usize,
    pub address: u64,
    pub len: usize,
    pub sha256: ContentId,
    ids: &'a str,
    chunks: &'a [Chunk],
}
impl ReadView<'_> {
    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.ids
            .split(',')
            .filter(|s| *s != "-")
            .map(|s| self.chunks[number(s).expect("checked ID")].bytes())
    }
    /// Caller supplies the full mapped current-overlay slice, before writes.
    /// This does not replace any mapping, entry, foreign, router or owner check.
    pub fn compare_current(&self, current: &[u8]) -> Result<(), Error> {
        require(current.len() == self.len, "current read mismatch")?;
        let mut at = 0;
        for chunk in self.chunks() {
            require(
                &current[at..at + chunk.len()] == chunk,
                "current read mismatch",
            )?;
            at += chunk.len();
        }
        require(at == current.len(), "current read mismatch")
    }
}

#[cfg(test)]
mod tests;
