//! Bounded static-ET_EXEC startup catalog. Integrity is not execution authority.
//!
//! Catalogs are compiler/package inputs. Only the unsafe core startup facade may
//! activate routes, under its additional semantic, loader and lifetime contract.
use crate::elf64::{Elf64, ElfVaddr, ObjectType, ParseLimits, SegmentType, Storage};
use crate::{ContentId, Metadata};
use std::collections::BTreeSet;

mod geometry;
mod wire;
use geometry::{near_target, validate_neighbors, validate_source_encoding};
#[cfg(test)]
mod tests;

pub const PROFILE: &str = "linux-x86-64-static-exec-router-bootstrap-v1";
pub const MAX_CATALOG: usize = 64 * 1024 * 1024;
pub const MAX_FILE: usize = 16 * 1024 * 1024;
pub const MAX_MAPPED: u64 = 64 * 1024 * 1024;
pub const MAX_RECORDS: usize = 65_536;
pub const PAGE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Limit,
    Shape,
    Identity,
    Selection,
    Source,
    Image,
    Route,
    Startup,
    Target,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blob {
    pub address: u64,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Span {
    pub start: u64,
    pub len: u64,
}
impl Span {
    pub fn end(self) -> Result<u64> {
        self.start
            .checked_add(self.len)
            .filter(|&end| self.len != 0 && end <= 1 << 47)
            .ok_or(Error::Shape)
    }
    pub fn covers(self, other: Self) -> Result<bool> {
        Ok(self.start <= other.start && other.end()? <= self.end()?)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Obligation {
    pub original: u64,
    pub generated: Option<u64>,
}
/// Exact accepted source-encoding geometry, separate from selected-image role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Relocation,
    GeneralizedPun(Pun),
    PrefixedPun(Pun),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pun {
    pub instruction_len: u64,
    pub prefixes: u64,
    pub consumed: Span,
    pub target_window: Span,
    pub store: Span,
}
/// Both members carry the same geometry derived from the opaque plan metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Neighbor {
    pub selected: u64,
    pub selected_len: u64,
    pub victim: u64,
    pub victim_len: u64,
    pub relay: u64,
    pub rel8: i8,
    pub selected_target: u64,
    pub victim_target: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Step {
    pub selected_id: u64,
    pub logical: u64,
    pub physical: u64,
    pub displaced: Span,
    pub kind: Kind,
    pub neighbor: Option<Neighbor>,
    pub reads: Vec<Blob>,
    pub writes: Vec<Blob>,
    pub dependencies: Vec<Span>,
    pub allocation: Span,
    pub image: u64,
    pub obligations: Vec<Obligation>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Image {
    pub body: Blob,
    pub entries: Vec<(u64, u64)>,
    // Exact source ArtifactRequirement vocabulary, not satisfied flags.
    pub requirements: Vec<(u64, u64)>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub domain: u64,
    pub format: u64,
    pub allocation: u64,
    pub image: u64,
    pub mask: u64,
    pub components: Vec<(u64, u64, u64)>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dependency {
    pub path: Vec<u8>,
    pub identity: ContentId,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub interpreter: Vec<u8>,
    pub bootstrap_dso: Vec<u8>,
    pub dependencies: Vec<Dependency>,
    pub app_stack: Span,
    pub hook_pc: u64,
    pub hook_id: u64,
    pub state: State,
    /// Independently reviewed semantic/ISA/ABI/unwind exclusion/package contract.
    /// This ID is not interpreted as a proof or boolean runtime verdict.
    pub qualification_contract: ContentId,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Input {
    /// 1 = checksum (80 heads,16 selected); 2 = RLE (107 heads,26 selected).
    pub program: u64,
    pub policy: Policy,
    pub original: Vec<u8>,
    pub main: Vec<u8>,
    pub selection: Vec<u8>,
    pub metadata: Vec<u8>,
    pub target: Vec<u8>,
    pub ledger: Vec<u8>,
    pub heads: Vec<u64>,
    pub steps: Vec<Step>,
    pub images: Vec<Image>,
}
/// Opaque structurally checked catalog. Still not a semantic or executable receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog(Input);
impl Catalog {
    /// Checks all cross-record joins, not the external semantic admission contract.
    pub fn new(input: Input) -> Result<Self> {
        validate(&input)?;
        Ok(Self(input))
    }
    pub fn input(&self) -> &Input {
        &self.0
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        wire::encode(&self.0)
    }
    /// Reject corruption, surplus data, noncanonical form, limits and bad joins.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::new(wire::decode(bytes)?)
    }
    pub fn main_id(&self) -> ContentId {
        ContentId::of(&self.0.main)
    }
    /// Entire exact route set, derived from step obligations, including auxiliaries.
    pub fn routes(&self) -> Vec<(u64, u64)> {
        self.0
            .steps
            .iter()
            .flat_map(|s| s.obligations.iter())
            .filter_map(|o| o.generated.map(|g| (o.original, g)))
            .collect()
    }
}

pub fn parse(bytes: &[u8]) -> Result<Elf64<'_>> {
    if bytes.len() > MAX_FILE {
        return Err(Error::Limit);
    }
    Elf64::parse(
        bytes,
        ParseLimits {
            max_program_headers: 256,
        },
    )
    .map_err(|_| Error::Shape)
}
pub fn file_range(
    elf: &Elf64<'_>,
    address: u64,
    len: u64,
    flags: u32,
) -> Result<std::ops::Range<usize>> {
    let m = elf
        .virtual_to_storage(ElfVaddr(address), len)
        .map_err(|_| Error::Source)?;
    if m.flags.0 != flags {
        return Err(Error::Source);
    }
    match m.storage {
        Storage::FileBacked(r) => Ok(r.start().0 as usize..r.end().0 as usize),
        _ => Err(Error::Source),
    }
}
pub fn target_bytes(state: &State) -> Result<Vec<u8>> {
    use std::fmt::Write as _;
    let kind = match state.format {
        1 => "fxsave64",
        2 => "xsave64-standard",
        _ => return Err(Error::Target),
    };
    let mut s = format!(
        "LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t{}\nformat\t{}\nallocation_bytes\t{}\nimage_bytes\t{}\nxcr0_mask\t{}\nqualification_complete\tfalse\n",
        state.domain, kind, state.allocation, state.image, state.mask
    );
    for &(f, o, n) in &state.components {
        writeln!(&mut s, "component\t{f}\t{o}\t{n}").map_err(|_| Error::Shape)?;
    }
    Ok(s.into_bytes())
}
fn path_ok(p: &[u8]) -> bool {
    p.len() > 1
        && p.len() <= 4095
        && p[0] == b'/'
        && p.iter().all(|&b| (0x21..=0x7e).contains(&b))
        && !p
            .split(|&b| b == b'/')
            .skip(1)
            .any(|s| s.is_empty() || s == b"." || s == b"..")
}
fn exactly_one<'a>(
    elf: &'a Elf64<'_>,
    kind: SegmentType,
) -> Result<&'a crate::elf64::ProgramHeader> {
    let mut it = elf.segments(kind);
    let item = it.next().ok_or(Error::Startup)?;
    if it.next().is_some() {
        return Err(Error::Startup);
    }
    Ok(item)
}
/// Validate exact child-carrier startup grammar independently from its writer.
pub fn validate_startup(elf: &Elf64<'_>, policy: &Policy) -> Result<u64> {
    if elf.header().object_type != ObjectType::Executable
        || elf.header().flags != 0
        || !path_ok(&policy.interpreter)
        || !path_ok(&policy.bootstrap_dso)
    {
        return Err(Error::Startup);
    }
    let ph = exactly_one(elf, SegmentType::ProgramHeaders)?;
    let interp = exactly_one(elf, SegmentType::Interpreter)?;
    let dynamic = exactly_one(elf, SegmentType::Dynamic)?;
    let stack = exactly_one(elf, SegmentType::GnuStack)?;
    if stack.flags.0 != 6
        || stack.file_size != 0
        || stack.memory_size != 0
        || ph.flags.0 != 4
        || ph.offset != elf.header().program_offset
        || ph.file_size != u64::from(elf.header().program_count) * 56
        || ph.memory_size != ph.file_size
        || interp.index <= ph.index
        || interp.flags.0 != 4
        || dynamic.flags.0 != 4
        || interp.file_size != policy.interpreter.len() as u64 + 1
        || interp.memory_size != interp.file_size
        || interp.alignment != 1
        || dynamic.alignment != 8
        || dynamic.file_size != 112
        || dynamic.memory_size != 112
    {
        return Err(Error::Startup);
    }
    let loads: Vec<_> = elf.segments(SegmentType::Load).collect();
    if loads
        .iter()
        .any(|p| p.index <= interp.index || p.index >= dynamic.index)
    {
        return Err(Error::Startup);
    }
    let ir = file_range(elf, interp.vaddr.0, interp.file_size, 4)?;
    if ir.start != interp.offset.0 as usize
        || elf.bytes()[ir.clone()] != [policy.interpreter.as_slice(), &[0]].concat()
    {
        return Err(Error::Startup);
    }
    let str_start = ir.end;
    let str_bytes = [&[0][..], policy.bootstrap_dso.as_slice(), &[0]].concat();
    let str_end = str_start.checked_add(str_bytes.len()).ok_or(Error::Limit)?;
    let sym_start = (str_end + 7) & !7;
    let sym_end = sym_start + 24;
    let hash_start = (sym_end + 3) & !3;
    let hash_end = hash_start + 16;
    let dyn_start = (hash_end + 7) & !7;
    let delta = interp
        .vaddr
        .0
        .checked_sub(interp.offset.0)
        .ok_or(Error::Startup)?;
    let va = |at: usize| delta.checked_add(at as u64).ok_or(Error::Startup);
    if dynamic.offset.0 != dyn_start as u64 || dynamic.vaddr.0 != va(dyn_start)? {
        return Err(Error::Startup);
    }
    let all = file_range(elf, interp.vaddr.0, (dyn_start + 112 - ir.start) as u64, 4)?;
    if all.start != ir.start
        || all.end != dyn_start + 112
        || elf.bytes().get(str_start..str_end) != Some(str_bytes.as_slice())
    {
        return Err(Error::Startup);
    }
    if elf.bytes()[str_end..hash_start].iter().any(|&b| b != 0)
        || elf.bytes()[hash_end..dyn_start].iter().any(|&b| b != 0)
    {
        return Err(Error::Startup);
    }
    let expected_hash = [1u32, 1, 0, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    if elf.bytes()[hash_start..hash_end] != expected_hash {
        return Err(Error::Startup);
    }
    let tags = [
        (1, 1),
        (5, va(str_start)?),
        (10, str_bytes.len() as u64),
        (6, va(sym_start)?),
        (11, 24),
        (4, va(hash_start)?),
        (0, 0),
    ];
    let expected = tags
        .into_iter()
        .flat_map(|(a, b): (u64, u64)| a.to_le_bytes().into_iter().chain(b.to_le_bytes()))
        .collect::<Vec<_>>();
    if elf.bytes()[dyn_start..dyn_start + 112] != expected {
        return Err(Error::Startup);
    }
    if file_range(elf, ph.vaddr.0, ph.file_size, 4)?.start != ph.offset.0 as usize {
        return Err(Error::Startup);
    }
    let owner = elf
        .virtual_to_storage(ph.vaddr, ph.file_size)
        .map_err(|_| Error::Startup)?
        .program_header;
    if elf
        .virtual_to_storage(interp.vaddr, (dyn_start + 112 - ir.start) as u64)
        .map_err(|_| Error::Startup)?
        .program_header
        != owner
    {
        return Err(Error::Startup);
    }
    let load = &elf.program_headers()[owner];
    if ph.offset != load.offset
        || ph.vaddr != load.vaddr
        || ph.alignment != 8
        || load.file_size != load.memory_size
        || load.offset.0.checked_add(load.file_size) != Some((dyn_start + 112) as u64)
    {
        return Err(Error::Startup);
    }
    Ok(ph.vaddr.0)
}

fn validate(x: &Input) -> Result<()> {
    bounded_shape(x)?;
    let (nh, ns) = match x.program {
        1 => (80, 16),
        2 => (107, 26),
        _ => return Err(Error::Selection),
    };
    if x.heads.len() != nh
        || x.heads.windows(2).any(|w| w[0] >= w[1])
        || x.steps.len() > 4096
        || x.images.len() > 4096
        || x.selection.len() > 1024 * 1024
        || x.metadata.len() > 1024 * 1024
        || x.target.len() > 65536
        || x.ledger.len() > 16 * 1024 * 1024
        || x.policy.qualification_contract.0 == [0; 32]
    {
        return Err(Error::Limit);
    }
    if x.target != target_bytes(&x.policy.state)? {
        return Err(Error::Target);
    }
    let old = parse(&x.original)?;
    let main = parse(&x.main)?;
    if old.header().object_type != ObjectType::Executable
        || old.header().entry != main.header().entry
        || x.main.len() < x.original.len()
    {
        return Err(Error::Source);
    }
    let expected_compatibility = crate::Compatibility {
        planner: 3,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&x.target),
        binding: ContentId::of(&x.selection),
    };
    let meta = Metadata::decode(
        &x.metadata,
        &expected_compatibility,
        crate::Limits {
            bytes: 1024 * 1024,
            chunks: 256,
            sites: ns,
        },
    )
    .map_err(|_| Error::Identity)?;
    meta.verify_original(&x.original)
        .map_err(|_| Error::Identity)?;
    let ids: Vec<_> = meta.sites().iter().map(|s| s.id).collect();
    meta.verify_selection(ContentId::of(&x.selection), &ids)
        .map_err(|_| Error::Selection)?;
    let compatibility = meta.compatibility();
    if compatibility.planner != 3
        || compatibility.encoder != 1
        || compatibility.hook_abi != 1
        || compatibility.arena != 1
        || compatibility.binding != ContentId::of(&x.selection)
    {
        return Err(Error::Identity);
    }
    if ids.len() != ns
        || !meta.declares_complete_trampoline_coverage()
        || meta.compatibility().target != ContentId::of(&x.target)
    {
        return Err(Error::Selection);
    }
    for &h in &x.heads {
        file_range(&old, h, 1, 5)?;
    }
    for s in meta.sites() {
        if x.heads.binary_search(&s.original_pc).is_err()
            || file_range(&old, s.original_pc, u64::from(s.length), 5)?.start as u64
                != s.file_offset
        {
            return Err(Error::Selection);
        }
    }
    for p in old.program_headers() {
        if matches!(
            p.kind,
            SegmentType::Dynamic
                | SegmentType::Interpreter
                | SegmentType::Tls
                | SegmentType::GnuProperty
                | SegmentType::GnuRelro
                | SegmentType::Other(_)
        ) {
            return Err(Error::Startup);
        }
    }
    let old_records: Vec<_> = old
        .program_headers()
        .iter()
        .filter(|p| p.kind != SegmentType::ProgramHeaders)
        .collect();
    let mut cursor = 0;
    for p in &old_records {
        let pos = main.program_headers()[cursor..]
            .iter()
            .position(|q| same_header(p, q))
            .ok_or(Error::Source)?;
        cursor += pos + 1;
    }
    if main.program_headers().len()
        != old_records.len()
            + 4
            + x.images.len()
            + usize::from(old.segments(SegmentType::GnuStack).next().is_none())
    {
        return Err(Error::Startup);
    }
    main.check_load_page_congruence(PAGE)
        .map_err(|_| Error::Shape)?;
    let mut end = 0;
    let mut mapped = 0u64;
    let loads: Vec<_> = main
        .segments(SegmentType::Load)
        .filter(|p| p.memory_size != 0)
        .collect();
    for p in &loads {
        let start = p.vaddr.0 & !(PAGE - 1);
        let stop = p
            .vaddr
            .0
            .checked_add(p.memory_size)
            .and_then(|v| v.checked_add(PAGE - 1))
            .ok_or(Error::Limit)?
            & !(PAGE - 1);
        if p.flags.0 != 4 && p.flags.0 != 5 && p.flags.0 != 6 {
            return Err(Error::Shape);
        }
        if start < end || start == 0 || stop > 1 << 47 {
            return Err(Error::Shape);
        }
        mapped = mapped.checked_add(stop - start).ok_or(Error::Limit)?;
        end = stop;
    }
    if loads
        .first()
        .is_none_or(|p| end - (p.vaddr.0 & !(PAGE - 1)) > 1 << 31)
    {
        return Err(Error::Limit);
    }
    if mapped > MAX_MAPPED {
        return Err(Error::Limit);
    }
    validate_startup(&main, &x.policy)?;
    for p in main.program_headers() {
        if !matches!(
            p.kind,
            SegmentType::Null
                | SegmentType::Load
                | SegmentType::Interpreter
                | SegmentType::Dynamic
                | SegmentType::Note
                | SegmentType::ProgramHeaders
                | SegmentType::GnuStack
        ) {
            return Err(Error::Startup);
        }
    }
    let carrier = main
        .virtual_to_storage(exactly_one(&main, SegmentType::ProgramHeaders)?.vaddr, 1)
        .map_err(|_| Error::Startup)?
        .program_header;
    if old_records
        .iter()
        .any(|o| same_header(o, &main.program_headers()[carrier]))
    {
        return Err(Error::Startup);
    }
    for p in main.program_headers() {
        if old_records.iter().any(|o| same_header(o, p)) {
            continue;
        }
        match p.kind {
            SegmentType::ProgramHeaders | SegmentType::Interpreter | SegmentType::Dynamic => {}
            SegmentType::GnuStack if old.segments(SegmentType::GnuStack).next().is_none() => {}
            SegmentType::Load if p.flags.0 == 5 => {}
            SegmentType::Load
                if p.index == carrier
                    && p.flags.0 == 4
                    && p.file_size == p.memory_size
                    && p.vaddr.0 % PAGE == 0 => {}
            _ => return Err(Error::Startup),
        }
    }
    if main.executable_bytes(main.header().entry, 1).is_err()
        || main
            .executable_bytes(ElfVaddr(x.policy.hook_pc), 1)
            .map_err(|_| Error::Target)?
            != [0xc3]
    {
        return Err(Error::Target);
    }
    if x.policy.app_stack.len != 65536 || x.policy.app_stack.start % 16 != 0 {
        return Err(Error::Target);
    }
    let stack = main
        .virtual_to_storage(ElfVaddr(x.policy.app_stack.start), x.policy.app_stack.len)
        .map_err(|_| Error::Target)?;
    let old_stack = old
        .virtual_to_storage(ElfVaddr(x.policy.app_stack.start), x.policy.app_stack.len)
        .map_err(|_| Error::Target)?;
    if stack.flags.0 != 6
        || old_stack.flags.0 != 6
        || !same_header(
            &old.program_headers()[old_stack.program_header],
            &main.program_headers()[stack.program_header],
        )
    {
        return Err(Error::Target);
    }
    match (old_stack.storage, stack.storage) {
        (Storage::ZeroFill, Storage::ZeroFill) => {}
        (Storage::FileBacked(a), Storage::FileBacked(b)) if a == b => {
            // This named two-program profile admits the authored PROGBITS data
            // owner, not an arbitrary RW slice relabelled as an application stack.
            let owner = &old.program_headers()[old_stack.program_header];
            let original_stack = &old.bytes()[a.start().0 as usize..a.end().0 as usize];
            if owner.vaddr.0 != 0x404000
                || owner.offset.0 != 0x4000
                || owner.file_size != 335872
                || owner.memory_size != 335872
                || x.policy.app_stack.start != 0x446000
                || original_stack.iter().any(|&v| v != 0x5a)
                || original_stack != &main.bytes()[b.start().0 as usize..b.end().0 as usize]
            {
                return Err(Error::Target);
            }
        }
        _ => return Err(Error::Target),
    }
    let selected: BTreeSet<_> = x
        .steps
        .iter()
        .filter_map(|s| {
            meta.sites()
                .iter()
                .find(|m| m.id == s.selected_id && m.original_pc == s.logical)
                .map(|m| m.id)
        })
        .collect();
    if selected.into_iter().collect::<Vec<_>>() != ids
        || meta.sites().iter().any(|m| {
            x.steps
                .iter()
                .filter(|s| s.selected_id == m.id && s.logical == m.original_pc)
                .count()
                != 1
        })
    {
        return Err(Error::Selection);
    }
    for &id in &ids {
        let count = x.steps.iter().filter(|s| s.selected_id == id).count();
        if !(1..=2).contains(&count) {
            return Err(Error::Selection);
        }
    }
    validate_neighbors(x, &meta)?;
    let mut reconstructed = x.original.clone();
    let mut physical = BTreeSet::new();
    let mut image_owners = BTreeSet::new();
    let mut route_heads = BTreeSet::new();
    for s in &x.steps {
        if !ids.contains(&s.selected_id)
            || !physical.insert(s.physical)
            || s.reads.is_empty()
            || s.writes.is_empty()
            || s.dependencies.is_empty()
            || !s.displaced.covers(Span {
                start: s.physical,
                len: 1,
            })?
        {
            return Err(Error::Source);
        }
        file_range(&old, s.displaced.start, s.displaced.len, 5)?;
        for d in &s.dependencies {
            file_range(&old, d.start, d.len, 5)?;
        }
        for r in &s.reads {
            let range = file_range(&old, r.address, r.bytes.len() as u64, 5)?;
            if reconstructed[range] != r.bytes {
                return Err(Error::Source);
            }
        }
        let extent = validate_source_encoding(s, &old, &reconstructed, &main)?;
        for w in &s.writes {
            let range = file_range(&old, w.address, w.bytes.len() as u64, 5)?;
            reconstructed[range].copy_from_slice(&w.bytes);
        }
        if s.allocation.start % PAGE != 0
            || s.allocation.len % PAGE != 0
            || !s.allocation.covers(Span {
                start: s.image,
                len: 1,
            })?
            || !image_owners.insert(s.image)
        {
            return Err(Error::Image);
        }
        let im = x
            .images
            .iter()
            .find(|i| i.body.address == s.image)
            .ok_or(Error::Image)?;
        let image_end = s
            .image
            .checked_add(im.body.bytes.len() as u64)
            .ok_or(Error::Image)?;
        let hull_end = image_end.checked_add(PAGE - 1).ok_or(Error::Image)? & !(PAGE - 1);
        if s.allocation.start != (s.image & !(PAGE - 1))
            || s.allocation.end()? != hull_end
            || im.body.bytes.is_empty()
        {
            return Err(Error::Image);
        }
        let owner = loads
            .iter()
            .find(|p| {
                p.vaddr.0 == s.allocation.start
                    && p.memory_size == image_end - s.allocation.start
                    && p.file_size == p.memory_size
                    && p.flags.0 == 5
            })
            .ok_or(Error::Image)?;
        if main.bytes()
            [owner.offset.0 as usize..(owner.offset.0 + s.image - s.allocation.start) as usize]
            .iter()
            .any(|&b| b != 0)
        {
            return Err(Error::Image);
        }
        if old
            .segments(SegmentType::Load)
            .any(|p| same_header(p, owner))
        {
            return Err(Error::Image);
        }
        if main
            .executable_bytes(ElfVaddr(s.image), im.body.bytes.len() as u64)
            .map_err(|_| Error::Image)?
            != im.body.bytes
        {
            return Err(Error::Image);
        }
        let mut heads = BTreeSet::new();
        for &(h, g) in &im.entries {
            if x.heads.binary_search(&h).is_err()
                || !heads.insert(h)
                || g < s.image
                || g >= s.image + im.body.bytes.len() as u64
            {
                return Err(Error::Route);
            }
        }
        let extent_end = extent.end()?;
        let expected_heads: Vec<_> = x
            .heads
            .iter()
            .copied()
            .filter(|&h| h >= extent.start && h < extent_end)
            .collect();
        let actual_heads: Vec<_> = s.obligations.iter().map(|o| o.original).collect();
        if expected_heads != actual_heads {
            return Err(Error::Route);
        }
        for o in &s.obligations {
            if x.heads.binary_search(&o.original).is_err() {
                return Err(Error::Route);
            }
            if let Some(g) = o.generated {
                if !route_heads.insert(o.original) || !im.entries.contains(&(o.original, g)) {
                    return Err(Error::Route);
                }
                validate_marker(&main, o.original)?;
            } else if o.original == s.physical {
                if let Some(n) = s.neighbor {
                    if s.physical == n.selected {
                        if main
                            .executable_bytes(ElfVaddr(n.selected), 2)
                            .map_err(|_| Error::Route)?
                            != [0xeb, n.rel8 as u8]
                        {
                            return Err(Error::Route);
                        }
                        near_target(&main, n.relay, 0, n.selected_target)?;
                    } else {
                        near_target(&main, n.victim, 0, n.victim_target)?;
                    }
                } else {
                    let prefixes = match s.kind {
                        Kind::Relocation => 0,
                        Kind::GeneralizedPun(p) | Kind::PrefixedPun(p) => p.prefixes,
                    };
                    near_target(&main, o.original, prefixes, s.image)?;
                }
            } else {
                // Pun successor obligations use the already authenticated current
                // consumed tail, which can contain an earlier auxiliary redirect.
                match s.kind {
                    Kind::GeneralizedPun(_) | Kind::PrefixedPun(_)
                        if o.original >= s.displaced.end()? => {}
                    _ => return Err(Error::Route),
                }
            }
        }
        let selected_pc = meta
            .sites()
            .iter()
            .find(|m| m.id == s.selected_id)
            .ok_or(Error::Selection)?
            .original_pc;
        let mut expected = vec![(1, 0), (2, 0), (3, 0), (4, 0), (7, 0), (8, 0)];
        if s.logical == selected_pc {
            expected.push((5, x.policy.hook_id));
        }
        if x.steps
            .iter()
            .filter(|t| t.selected_id == s.selected_id)
            .any(|t| t.obligations.iter().any(|o| o.generated.is_some()))
        {
            expected.push((6, 0));
        }
        if im.requirements != expected {
            return Err(Error::Image);
        }
    }
    if image_owners.len() != x.images.len() {
        return Err(Error::Image);
    }
    // No omitted/extra RX LOAD can hide an image outside the complete plan inventory.
    for p in &loads {
        if p.flags.0 == 5
            && !old.segments(SegmentType::Load).any(|o| same_header(o, p))
            && x.steps
                .iter()
                .filter(|s| {
                    s.allocation.start == p.vaddr.0
                        && s.allocation.end().ok()
                            == p.vaddr
                                .0
                                .checked_add(p.memory_size)
                                .and_then(|v| v.checked_add(PAGE - 1))
                                .map(|v| v & !(PAGE - 1))
                })
                .count()
                != 1
        {
            return Err(Error::Image);
        }
    }
    reconstructed[32..40].copy_from_slice(&x.main[32..40]);
    reconstructed[56..58].copy_from_slice(&x.main[56..58]);
    if x.main[..reconstructed.len()] != reconstructed {
        return Err(Error::Source);
    }
    Ok(())
}
fn same_header(a: &crate::elf64::ProgramHeader, b: &crate::elf64::ProgramHeader) -> bool {
    a.raw_type == b.raw_type
        && a.flags == b.flags
        && a.offset == b.offset
        && a.vaddr == b.vaddr
        && a.physical_address == b.physical_address
        && a.file_size == b.file_size
        && a.memory_size == b.memory_size
        && a.alignment == b.alignment
}
/// Only the existing production marker families; full 15-byte EVEX fetch retained.
pub fn validate_marker(elf: &Elf64<'_>, pc: u64) -> Result<()> {
    let first = elf
        .executable_bytes(ElfVaddr(pc), 1)
        .map_err(|_| Error::Route)?[0];
    if matches!(
        first,
        0x06 | 0x07
            | 0x0e
            | 0x16
            | 0x17
            | 0x1e
            | 0x1f
            | 0x27
            | 0x2f
            | 0x37
            | 0x3f
            | 0x60
            | 0x61
            | 0xce
    ) {
        return Ok(());
    }
    if first == 0x62 {
        let b = elf
            .executable_bytes(ElfVaddr(pc), 15)
            .map_err(|_| Error::Route)?;
        if b[2] & 4 == 0 {
            return Ok(());
        }
    }
    Err(Error::Route)
}

fn bounded_shape(x: &Input) -> Result<()> {
    let mut used = 1024usize;
    let mut records = x.heads.len()
        + x.steps.len()
        + x.images.len()
        + x.policy.dependencies.len()
        + x.policy.state.components.len();
    let mut add = |n: usize| {
        used = used.checked_add(n).ok_or(Error::Limit)?;
        if used > MAX_CATALOG - 32 {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    };
    for b in [
        &x.original,
        &x.main,
        &x.selection,
        &x.metadata,
        &x.target,
        &x.ledger,
    ] {
        add(b.len())?;
    }
    if x.policy.dependencies.is_empty()
        || x.policy.dependencies.len() > 16
        || x.policy.state.components.len() > 64
        || x.steps.len() > 4096
        || x.images.len() > 4096
    {
        return Err(Error::Limit);
    }
    let mut paths = BTreeSet::new();
    for d in &x.policy.dependencies {
        if !path_ok(&d.path)
            || !paths.insert(&d.path)
            || d.path == x.policy.bootstrap_dso
            || d.identity.0 == [0; 32]
        {
            return Err(Error::Startup);
        }
        add(d.path.len() + 40)?;
    }
    if !paths.contains(&x.policy.interpreter) {
        return Err(Error::Startup);
    }
    for s in &x.steps {
        if s.reads.len() > MAX_RECORDS
            || s.writes.len() > MAX_RECORDS
            || s.dependencies.len() > MAX_RECORDS
            || s.obligations.len() > MAX_RECORDS
        {
            return Err(Error::Limit);
        }
        records = records
            .checked_add(
                s.reads.len() + s.writes.len() + s.dependencies.len() + s.obligations.len(),
            )
            .ok_or(Error::Limit)?;
        add(256 + s.dependencies.len() * 16 + s.obligations.len() * 24)?;
        for b in s.reads.iter().chain(&s.writes) {
            add(16 + b.bytes.len())?;
        }
    }
    for i in &x.images {
        records = records
            .checked_add(i.entries.len() + i.requirements.len())
            .ok_or(Error::Limit)?;
        if i.entries.len() > MAX_RECORDS || i.requirements.len() > 8 {
            return Err(Error::Limit);
        }
        add(32 + i.body.bytes.len() + 16 * (i.entries.len() + i.requirements.len()))?;
    }
    if records > MAX_RECORDS {
        return Err(Error::Limit);
    }
    Ok(())
}
