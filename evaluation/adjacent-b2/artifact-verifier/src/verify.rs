//! Read-only W01 artifact joins. No planning, binding, decode, or execution authority.
use formats::{Compatibility, ContentId, Metadata, Outcome, Site, Tactic};
use liteinst_rewrite::carrier::{
    self,
    elf64::{
        Elf64, ElfVaddr, FileOffset, FileRange, ObjectType, ParseLimits, SegmentType, Storage,
    },
};
use liteinst_rewrite::{model::Selection, selection};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

#[path = "verify/candidate.rs"]
mod candidate;
#[path = "verify/ledger.rs"]
mod ledger;
#[path = "verify/startup.rs"]
pub mod startup;
pub const PROFILE: &str = "elf-disassembly-null-jumps-adjacent-routed-jmp-short-t3-pending-v1";
pub const TEXT: usize = 1_048_576;
pub const FILE: usize = 16 * TEXT;
pub const OUTPUT: usize = 2 * TEXT;
pub type Result<T> = std::result::Result<T, String>;
pub const EXPECTED_FILES: [&str; 5] = [
    "disassembly-inventory.tsv",
    "disassembly-policy.txt",
    "disassembly.txt",
    "planning-profile.tsv",
    "selection.txt",
];
pub const STATIC: [&str; 14] = [
    "adjacent-routed-jmp-evidence.txt",
    "bundle-index.tsv",
    "candidate.elf",
    "disassembly-inventory.tsv",
    "disassembly-policy.txt",
    "disassembly.txt",
    "ledger.tsv",
    "metadata.li2meta",
    "plan-ledger.tsv",
    "planning-profile.tsv",
    "report.tsv",
    "selection.txt",
    "source.li2sparse",
    "target.tsv",
];

pub fn require(ok: bool, why: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
pub fn checked<T, E: std::fmt::Debug>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| format!("{e:?}"))
}
pub fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| "integer overflow".into())
}
pub fn host(n: u64) -> Result<usize> {
    checked(usize::try_from(n))
}
pub fn number(s: &str) -> Result<u64> {
    let n: u64 = checked(s.parse())?;
    require(n.to_string() == s, "noncanonical integer")?;
    Ok(n)
}
pub fn signed(s: &str) -> Result<i128> {
    let n: i128 = checked(s.parse())?;
    require(n.to_string() == s, "noncanonical signed integer")?;
    Ok(n)
}
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub fn digest(b: &[u8]) -> String {
    hex(&ContentId::of(b).0)
}
pub fn unhex(s: &str) -> Result<Vec<u8>> {
    require(
        (s.len() & 1) == 0
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "canonical hex",
    )?;
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| checked(u8::from_str_radix(checked(std::str::from_utf8(p))?, 16)))
        .collect()
}
pub fn lines(b: &[u8]) -> Result<Vec<&str>> {
    require(
        b.len() <= FILE && b.last() == Some(&b'\n') && !b.contains(&b'\r') && !b.contains(&0),
        "text envelope",
    )?;
    require(
        b.iter().filter(|&&c| c == b'\n').count() <= TEXT,
        "text row allocation limit",
    )?;
    let text = checked(std::str::from_utf8(b))?;
    Ok(text[..text.len() - 1].split('\n').collect())
}
pub fn fields(line: &str, count: usize) -> Result<Vec<&str>> {
    let f: Vec<_> = line.split('\t').collect();
    require(f.len() == count, "row arity")?;
    Ok(f)
}
pub fn slice(b: &[u8], start: u64, len: u64) -> Result<&[u8]> {
    b.get(host(start)?..host(add(start, len)?)?)
        .ok_or_else(|| "byte range".into())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}
impl Range {
    pub fn new(start: u64, end: u64) -> Result<Self> {
        require(start < end, "empty/inverted range")?;
        Ok(Self { start, end })
    }
    pub fn bytes(start: u64, len: usize) -> Result<Self> {
        Self::new(start, add(start, len as u64)?)
    }
    pub fn len(self) -> u64 {
        self.end - self.start
    }
    pub fn covers(self, r: Self) -> bool {
        self.start <= r.start && r.end <= self.end
    }
    pub fn contains(self, pc: u64) -> bool {
        self.start <= pc && pc < self.end
    }
    pub fn overlaps(self, r: Self) -> bool {
        self.start < r.end && r.start < self.end
    }
}
pub fn page(n: u64) -> Result<u64> {
    Ok(add(n, 4095)? & !4095)
}
pub fn hull(address: u64, len: usize) -> Result<Range> {
    Range::new(address & !4095, page(add(address, len as u64)?)?)
}
pub fn merge(mut ranges: Vec<Range>, touching: bool) -> Vec<Range> {
    ranges.sort_unstable();
    let mut out: Vec<Range> = Vec::new();
    for r in ranges {
        if let Some(last) = out.last_mut() {
            if r.start < last.end || (touching && r.start == last.end) {
                last.end = last.end.max(r.end);
                continue;
            }
        }
        out.push(r);
    }
    out
}
pub fn original_offset(elf: &Elf64<'_>, r: Range) -> Result<u64> {
    let mapping = checked(elf.virtual_to_storage(ElfVaddr(r.start), r.len()))?;
    require(
        mapping.flags.0 == 5,
        "source must have unique original RX owner",
    )?;
    let Storage::FileBacked(file) = mapping.storage else {
        return Err("source is zero-fill".into());
    };
    let inverse = checked(elf.file_to_virtual(file.start(), file.len()))?;
    require(
        inverse.virtual_range.start().0 == r.start
            && inverse.program_header == mapping.program_header,
        "source inverse mapping",
    )?;
    Ok(file.start().0)
}

/// Implementations must bind every read to the closed directory's exact index.
pub trait Files {
    fn read(&self, name: &str, cap: usize) -> Result<Vec<u8>>;
    fn names(&self) -> BTreeSet<String>;
}
#[derive(Clone)]
pub struct Expected {
    pub program: String,
    pub files: BTreeMap<String, Vec<u8>>,
}
pub struct Facts {
    pub selection: Selection,
    pub heads: BTreeMap<u64, Vec<u8>>,
    pub snapshots: Vec<Range>,
    pub full_selection: Vec<u8>,
    pub target: Vec<u8>,
}
pub fn denominator(program: &str) -> Result<(usize, usize)> {
    match program {
        "checksum" => Ok((80, 16)),
        "rle-roundtrip" => Ok((107, 26)),
        _ => Err("fixed program roster".into()),
    }
}

impl Expected {
    pub fn facts(&self, original: &[u8], product: &dyn Files) -> Result<Facts> {
        let (head_count, count) = denominator(&self.program)?;
        require(
            self.files.keys().map(String::as_str).collect::<Vec<_>>() == EXPECTED_FILES,
            "exact independent expected files",
        )?;
        for (name, expected) in &self.files {
            require(expected.len() <= TEXT, "expected text size")?;
            require(
                product.read(name, TEXT)? == *expected,
                "full independent expected bytes differ",
            )?;
        }
        let full = self.files["selection.txt"].clone();
        let rows = lines(&full)?;
        require(
            rows.len() >= 8 && rows[0] == "LI2TOOL 1",
            "full manifest header",
        )?;
        require(
            rows[2..7]
                == [
                    "neighbor-victims short-only",
                    "neighbor-ownership inherited-t3",
                    "pending-selected full-instruction-ownership",
                    "adjacent-pairs original-geometry-jcc-or-routed-jmp-v1",
                    "adjacent-pair-budgets 2 1 2",
                ],
            "exact five identity rows",
        )?;
        let mut projected = format!("{}\n{}\n", rows[0], rows[1]);
        for row in &rows[7..] {
            writeln!(&mut projected, "{row}").unwrap();
        }
        let mut selected = checked(selection::parse(projected.as_bytes()))?;
        selected.manifest = full.clone();
        require(
            selected.original == ContentId::of(original) && selected.sites.len() == count,
            "expected original/denominator",
        )?;
        require(
            selected.bias_domain == 1 && selected.carrier_pc == 0x480000,
            "frozen domain/carrier",
        )?;
        let l = selected.limits;
        require(
            (
                l.input_bytes,
                l.sites,
                l.images,
                l.image_bytes,
                l.new_load_pages,
                l.output_bytes,
                l.added_file_bytes,
                l.program_headers,
                l.virtual_span,
            ) == (TEXT, 32, 32, 131072, 128, 2097152, 1048576, 128, 2147483648),
            "frozen limits",
        )?;
        require(
            original.len() <= TEXT
                && selected.hooks.len() == 1
                && selected.hooks[0].id == 1
                && selected.hooks[0].pc == 0x403000
                && selected.hooks[0].length == 1
                && selected.hooks[0].expected == ContentId::of(&[0xc3]),
            "frozen hook",
        )?;
        let elf = checked(Elf64::parse(
            original,
            ParseLimits {
                max_program_headers: 128,
            },
        ))?;
        candidate::original_shape(&elf)?;
        let ledger = lines(&self.files["disassembly.txt"])?;
        require(
            ledger.len() >= 5
                && ledger[0] == "LI2DISASM 1"
                && ledger[1] == format!("original {}", digest(original))
                && ledger[2] == "contract complete-code no-overlap no-code-as-data private-image",
            "independent source ledger prefix",
        )?;
        let mut heads = BTreeMap::new();
        let mut regions = Vec::new();
        let mut at = 3;
        while at < ledger.len() {
            let f: Vec<_> = ledger[at].split(' ').collect();
            require(f.len() == 4 && f[0] == "region", "region row")?;
            let start = number(f[1])?;
            let offset = number(f[2])?;
            let length = number(f[3])?;
            let r = Range::new(start, add(start, length)?)?;
            require(
                original_offset(&elf, r)? == offset
                    && regions.last().is_none_or(|old: &Range| old.end <= r.start),
                "region ownership/order",
            )?;
            at += 1;
            let mut pc = start;
            while at < ledger.len() && ledger[at].starts_with("head ") {
                let f: Vec<_> = ledger[at].split(' ').collect();
                require(
                    f.len() == 3 && number(f[1])? == pc,
                    "complete original head ordering",
                )?;
                let bytes = unhex(f[2])?;
                require((1..=15).contains(&bytes.len()), "instruction length")?;
                let h = Range::bytes(pc, bytes.len())?;
                require(
                    r.covers(h) && slice(original, original_offset(&elf, h)?, h.len())? == bytes,
                    "original head bytes",
                )?;
                require(heads.insert(pc, bytes).is_none(), "duplicate head")?;
                pc = h.end;
                at += 1;
            }
            require(pc == r.end, "complete head coverage")?;
            regions.push(r);
        }
        require(
            heads.len() == head_count
                && regions.len() == 3
                && regions[0].start == 0x401000
                && regions[1].start == 0x402000
                && regions[2] == Range::new(0x403000, 0x403001)?,
            "full original head denominator",
        )?;
        require(
            heads.range(regions[0].start..regions[0].end).count() == 61
                && heads.range(regions[1].start..regions[1].end).count() == head_count - 62,
            "full start/kernel head rosters",
        )?;
        require(
            heads.get(&0x403000) == Some(&vec![0xc3]),
            "original hook head",
        )?;
        require(
            selected.sites.windows(2).all(|w| w[0].pc < w[1].pc),
            "independent selected PC order",
        )?;
        for (i, s) in selected.sites.iter().enumerate() {
            require(
                s.id == i as u64 + 1
                    && heads
                        .get(&s.pc)
                        .is_some_and(|b| b.len() == usize::from(s.length)),
                "full expected selected roster",
            )?;
            let r = Range::new(s.snapshot.start(), s.snapshot.end())?;
            require(
                regions.contains(&r)
                    && original_offset(&elf, Range::bytes(s.pc, usize::from(s.length))?)?
                        == s.file_offset,
                "selected source ownership",
            )?;
            let expected_heads: Vec<_> = heads.range(r.start..r.end).map(|(pc, _)| *pc).collect();
            require(
                s.heads.iter().map(|h| h.address).collect::<Vec<_>>() == expected_heads
                    && s.heads.iter().all(|h| !h.requires_endbr),
                "full region heads",
            )?;
            require(
                s.completeness == li2core::contracts::EntryCompleteness::Complete
                    && s.provenance == ContentId::of(&self.files["disassembly.txt"]),
                "verified head provenance and textual entry contract",
            )?;
        }
        // The text parser preserves the caller's `complete` spelling. Only
        // after independently checking every original byte, contiguous head,
        // region roster, and selected region's exact head set above may W01
        // reconstruct the conservative all-heads mode used by the frontend.
        // This does not claim complete recovered function entries or decode
        // any producer output. Pair geometry retains its strict mode guard.
        for site in &mut selected.sites {
            site.completeness = li2core::contracts::EntryCompleteness::AllInstructionHeads;
        }
        let target = target_text(&selected);
        require(
            target == product.read("target.tsv", TEXT)?,
            "independent target compatibility text",
        )?;
        let snapshots = merge(
            selected
                .sites
                .iter()
                .map(|s| Range {
                    start: s.snapshot.start(),
                    end: s.snapshot.end(),
                })
                .collect(),
            false,
        );
        Ok(Facts {
            selection: selected,
            heads,
            snapshots,
            full_selection: full,
            target,
        })
    }
}
fn target_text(s: &Selection) -> Vec<u8> {
    let state = s.target;
    let kind = if state.format() == li2core::trampoline::SavedExtendedStateFormat::FXSAVE64 {
        "fxsave64"
    } else {
        "xsave64-standard"
    };
    let mut out = format!(
        "LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t{}\nformat\t{kind}\nallocation_bytes\t{}\nimage_bytes\t{}\nxcr0_mask\t{}\nqualification_complete\tfalse\n",
        s.bias_domain,
        state.len(),
        state.image_len(),
        state.mask()
    );
    for c in state.components() {
        writeln!(
            &mut out,
            "component\t{}\t{}\t{}",
            c.xfeature(),
            c.offset(),
            c.size()
        )
        .unwrap();
    }
    out.into_bytes()
}

pub struct Summary {
    pub program: String,
    pub selected: usize,
    pub images: usize,
    pub candidate_sha256: String,
}
pub fn verify(
    program: &str,
    original: &[u8],
    expected: &Expected,
    product: &dyn Files,
) -> Result<Summary> {
    verify_mode(program, original, expected, product, None).map(|(summary, _)| summary)
}
fn verify_mode(
    program: &str,
    original: &[u8],
    expected: &Expected,
    product: &dyn Files,
    startup: Option<&startup::Inputs>,
) -> Result<(Summary, Option<startup::Summary>)> {
    require(program == expected.program, "program expectation")?;
    let facts = expected.facts(original, product)?;
    let report = product.read("report.tsv", TEXT)?;
    let records = report_records(original, &facts, &report)?;
    let meta_bytes = product.read("metadata.li2meta", OUTPUT)?;
    metadata_join(original, &facts, &records, &meta_bytes)?;
    let ids: Vec<_> = (1..=records.len() as u64).collect();
    let plan = product.read("plan-ledger.tsv", FILE)?;
    let joined = ledger::join(original, &facts, &records, &plan, product)?;
    let mut names: BTreeSet<String> = STATIC.iter().map(|s| s.to_string()).collect();
    if startup.is_some() {
        for name in [
            "catalog.li2boot",
            "startup-policy.txt",
            "startup-profile.tsv",
        ] {
            names.insert(name.into());
        }
    } else {
        names.insert("COMPLETE".into());
    }
    for id in ids {
        names.insert(format!("site-{id}.diagnostics.txt"));
    }
    for i in 0..joined.images.len() {
        names.insert(format!("image-{i:04}.bin"));
    }
    require(
        product.names() == names,
        "complete actual artifact membership",
    )?;
    let candidate = product.read("candidate.elf", OUTPUT)?;
    let full_ledger = product.read("ledger.tsv", FILE)?;
    let startup_summary = if let Some(input) = startup {
        Some(startup::join(
            startup::Artifact {
                program,
                original,
                facts: &facts,
                joined: &joined,
                metadata: &meta_bytes,
                plan: &plan,
                candidate: &candidate,
                ledger: &full_ledger,
                product,
            },
            input,
        )?)
    } else {
        candidate::join(
            original,
            &facts,
            &joined,
            &meta_bytes,
            &plan,
            &candidate,
            &product.read("ledger.tsv", FILE)?,
        )?;
        None
    };
    let content = formats::sparse::Limits {
        edits: TEXT,
        edited_bytes: TEXT,
        pages: TEXT / 4096,
    };
    let sparse_limits = formats::sparse_wire::Limits {
        bytes: OUTPUT,
        content,
    };
    let wire = product.read("source.li2sparse", OUTPUT)?;
    let sparse = checked(formats::sparse_wire::decode(&wire, original, sparse_limits))?;
    let expected_edits = joined
        .edits
        .iter()
        .map(|e| formats::sparse::FileEdit {
            offset: e.offset.0,
            expected: e.expected.clone(),
            replacement: e.replacement.clone(),
        })
        .collect();
    let expected_sparse = checked(formats::sparse::SparsePages::build(
        original,
        expected_edits,
        content,
    ))?;
    require(
        sparse.edits() == expected_sparse.edits()
            && sparse.pages() == expected_sparse.pages()
            && checked(formats::sparse_wire::encode(
                &expected_sparse,
                sparse_limits,
            ))? == wire,
        "exact sparse/ledger source join",
    )?;
    evidence(
        &product.read("adjacent-routed-jmp-evidence.txt", FILE)?,
        &facts,
        &joined.associations,
    )?;
    Ok((
        Summary {
            program: program.into(),
            selected: records.len(),
            images: joined.images.len(),
            candidate_sha256: digest(&candidate),
        },
        startup_summary,
    ))
}
fn metadata_join(original: &[u8], f: &Facts, records: &[Site], meta_bytes: &[u8]) -> Result<()> {
    let compatibility = Compatibility {
        planner: 3,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&f.target),
        binding: ContentId::of(&f.full_selection),
    };
    let limits = formats::Limits {
        bytes: OUTPUT,
        chunks: TEXT / 65536,
        sites: 32,
    };
    let meta = checked(Metadata::decode(meta_bytes, &compatibility, limits))?;
    let ids: Vec<_> = (1..=records.len() as u64).collect();
    checked(meta.verify_selection(ContentId::of(&f.full_selection), &ids))?;
    checked(meta.verify_original(original))?;
    for (i, chunk) in original.chunks(65536).enumerate() {
        checked(meta.verify_chunk(original.len() as u64, i, chunk))?;
    }
    require(
        meta.sites() == records,
        "metadata/report/original roster join",
    )?;
    let rebuilt = checked(Metadata::new(
        original,
        ContentId::of(&f.full_selection),
        compatibility,
        records.to_vec(),
    ))?;
    require(
        checked(rebuilt.encode(limits))? == meta_bytes,
        "complete expected metadata bytes",
    )?;
    Ok(())
}
fn report_records(original: &[u8], f: &Facts, bytes: &[u8]) -> Result<Vec<Site>> {
    let prefix = format!(
        "LI2REPORT\t1\noriginal_sha256\t{}\nselection_sha256\t{}\ncandidate_complete\ttrue\nqualification_complete\tfalse\nsite\tpc\tfile_offset\tlength\tcore_tactic\tcandidate_emitted\trefusal_code\tstage\tdetail_hex\n",
        digest(original),
        digest(&f.full_selection)
    );
    require(
        bytes.starts_with(prefix.as_bytes()),
        "complete report prefix/refusal",
    )?;
    let rows = lines(&bytes[prefix.len()..])?;
    require(
        rows.len() == f.selection.sites.len(),
        "complete report count",
    )?;
    rows.iter()
        .zip(&f.selection.sites)
        .map(|(row, s)| {
            let r = fields(row, 9)?;
            require(
                number(r[0])? == s.id
                    && number(r[1])? == s.pc
                    && number(r[2])? == s.file_offset
                    && number(r[3])? == u64::from(s.length)
                    && r[5..] == ["true", "none", "none", ""],
                "complete report original coordinates/outcome",
            )?;
            let tactic = match r[4] {
                "B1" => Tactic::Relocation,
                "B2" => Tactic::GeneralizedPun,
                "T1" => Tactic::PrefixedPun,
                "T2" => Tactic::SuccessorEviction,
                "T3" => Tactic::NeighborEviction,
                _ => return Err("tactic".into()),
            };
            Ok(Site {
                id: s.id,
                original_pc: s.pc,
                file_offset: s.file_offset,
                length: s.length,
                outcome: Outcome::Rewritten(tactic),
            })
        })
        .collect()
}
fn evidence(bytes: &[u8], f: &Facts, accepted: &ledger::Associations) -> Result<()> {
    let at = bytes
        .windows(b"resources\t".len())
        .position(|w| w == b"resources\t")
        .ok_or("missing bounded diagnostic suffix")?;
    let r = lines(&bytes[..at])?;
    require(r.len() == 14, "evidence scalar count")?;
    require(
        r[0] == "LI2ADJACENT-ROUTED-JMP-EVIDENCE\t1"
            && r[1] == format!("selection_sha256\t{}", digest(&f.full_selection))
            && r[10] == "qualification_complete\tfalse"
            && r[11] == "classification_complete\tfalse",
        "evidence identity/flags",
    )?;
    let scalar = |i: usize, key: &str| -> Result<u64> {
        let v = fields(r[i], 2)?;
        require(v[0] == key, "evidence scalar key")?;
        number(v[1])
    };
    let counts = |i: usize, key: &str| -> Result<[u64; 3]> {
        let v = fields(r[i], 4)?;
        require(v[0] == key, "evidence counts key")?;
        Ok([number(v[1])?, number(v[2])?, number(v[3])?])
    };
    let n = scalar(2, "selected_count")?;
    let baseline = scalar(3, "baseline_calls")?;
    let pairs = scalar(4, "pair_calls")?;
    let total = counts(5, "adjacent_counts")?;
    let forward = scalar(6, "forward_jcc_calls")?;
    let fc = counts(7, "forward_jcc_counts")?;
    let routed = scalar(8, "routed_jmp_calls")?;
    let rc = counts(9, "routed_jmp_counts")?;
    let legacy = scalar(12, "legacy_image_slots")?;
    let combined = scalar(13, "combined_image_work_upper_bound")?;
    require(
        n == f.selection.sites.len() as u64
            && baseline == n
            && pairs == add(forward, routed)?
            && pairs <= n / 2
            && accepted.forward == forward
            && accepted.routed == routed
            && accepted.attempts.iter().copied().eq(0..pairs),
        "evidence full denominator and accepted pair counts",
    )?;
    for (c, calls, complete) in [
        (fc, forward, accepted.forward),
        (rc, routed, accepted.routed),
    ] {
        require(
            c[0] <= 2 * calls
                && c[1] <= calls
                && c[2] <= 2 * calls
                && c[2] <= c[0]
                && c.iter().all(|n| *n >= complete),
            "family fixed U2 L1 J2 and accepted work",
        )?;
    }
    for i in 0..3 {
        require(total[i] == add(fc[i], rc[i])?, "family total sum")?;
    }
    require(
        combined == add(add(legacy, total[0])?, total[1])?,
        "combined work sum",
    )
}

#[cfg(test)]
#[path = "verify/tests.rs"]
pub(crate) mod tests;
