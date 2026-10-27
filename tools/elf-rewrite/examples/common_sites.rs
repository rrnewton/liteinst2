//! Finite, source-owned common-corpus inventory and LI2TOOL selection.
//! No planning, rewriting, mapping, or execution occurs in this example.
#![forbid(unsafe_code)]

use formats::ContentId;
use iced_x86::{
    Code, CodeSize, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register, UsedMemory,
};
use li2core::scanner::InstructionScanner;
use liteinst_rewrite::carrier::elf64::{
    Elf64, ElfVaddr, ObjectType, ParseLimits, SegmentType, Storage,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

type Result<T> = std::result::Result<T, String>;
const INPUT_LIMIT: usize = 16 * 1024 * 1024;
const TEXT_LIMIT: u64 = 1024 * 1024;
const KERNEL_LIMIT: u64 = 65536;
const HEAD_LIMIT: usize = 4096;
const SITE_LIMIT: usize = 1024;
const STACK_LIMIT: i64 = 65536;
const NAMES: [&str; 3] = ["li2_array_store", "li2_sift_down", "li2_heap_sort"];
const STORE: [u8; 5] = [0x48, 0x89, 0x14, 0xf7, 0xc3];

fn check(ok: bool, reason: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(reason.to_owned()) }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(bytes: &[u8]) -> String {
    hex(&ContentId::of(bytes).0)
}
fn number(s: &str) -> Result<u64> {
    liteinst_rewrite::selection::num(s).map_err(|e| e.to_string())
}
fn sha(s: &str) -> Result<String> {
    check(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase SHA-256 required",
    )?;
    Ok(s.to_owned())
}
fn end(start: u64, length: u64) -> Result<u64> {
    check(length != 0, "empty range")?;
    start
        .checked_add(length)
        .ok_or_else(|| "range overflow".to_owned())
}
fn bytes_at(bytes: &[u8], start: u64, length: u64) -> Result<&[u8]> {
    let stop = end(start, length)?;
    bytes
        .get(
            usize::try_from(start).map_err(|e| e.to_string())?
                ..usize::try_from(stop).map_err(|e| e.to_string())?,
        )
        .ok_or_else(|| "file range outside original".to_owned())
}
fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

#[derive(Clone, Debug)]
struct Owner {
    name: String,
    pc: u64,
    length: u64,
    hash: String,
}
#[derive(Clone, Copy, Debug)]
struct Arena {
    base: u64,
    stride: u64,
    bytes: u64,
    candidates: u64,
}
#[derive(Clone, Copy, Debug)]
struct Placement {
    domain: (u64, u64),
}
#[derive(Clone, Copy, Debug)]
struct Permit {
    range: (u64, u64),
    preferred: u64,
}
#[derive(Clone, Debug)]
struct Policy {
    original: String,
    target: String,
    provenance: String,
    text: Owner,
    text_offset: u64,
    functions: Vec<Owner>,
    hooks: Vec<Owner>,
    carrier: u64,
    placement: Option<Placement>,
    arenas: [Arena; 2],
    limits: [u64; 9],
    search: [u64; 5],
}
struct Lines<'a>(std::str::Lines<'a>);
impl<'a> Lines<'a> {
    fn row(&mut self, tag: &str, length: usize) -> Result<Vec<&'a str>> {
        let line = self.0.next().ok_or_else(|| format!("missing {tag}"))?;
        let row: Vec<_> = line.split(' ').collect();
        check(
            row.len() == length && row[0] == tag && row.iter().all(|s| !s.is_empty()),
            "policy order/field count/spacing",
        )?;
        Ok(row)
    }
}
fn policy(bytes: &[u8]) -> Result<Policy> {
    check(
        bytes.len() <= 65536 && bytes.last() == Some(&b'\n'),
        "policy bound/final newline",
    )?;
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    check(
        text.is_ascii() && !text.contains('\r'),
        "ASCII LF policy required",
    )?;
    let mut lines = Lines(text.lines());
    let version = lines.row("LI2COMMON", 2)?[1];
    check(matches!(version, "1" | "2"), "policy version")?;
    let original = sha(lines.row("original", 2)?[1])?;
    let target = sha(lines.row("target", 2)?[1])?;
    let provenance = sha(lines.row("provenance", 2)?[1])?;
    let t = lines.row("text", 5)?;
    let text = Owner {
        name: ".text".to_owned(),
        pc: number(t[1])?,
        length: number(t[3])?,
        hash: sha(t[4])?,
    };
    let text_offset = number(t[2])?;
    check(text.length <= TEXT_LIMIT, "text bound")?;
    end(text.pc, text.length)?;
    let mut functions = Vec::new();
    for name in NAMES {
        let r = lines.row("function", 5)?;
        check(r[1] == name, "exact three function names/order required")?;
        functions.push(Owner {
            name: name.to_owned(),
            pc: number(r[2])?,
            length: number(r[3])?,
            hash: sha(r[4])?,
        });
    }
    let mut hooks = Vec::new();
    for id in ["2", "3"] {
        let r = lines.row("hook", 5)?;
        check(r[1] == id, "exact hook IDs 2/3 required")?;
        hooks.push(Owner {
            name: id.to_owned(),
            pc: number(r[2])?,
            length: number(r[3])?,
            hash: sha(r[4])?,
        });
    }
    let carrier = number(lines.row("carrier", 2)?[1])?;
    let placement = if version == "2" {
        let r = lines.row("placement", 4)?;
        check(r[1] == "original-derived-v1", "placement profile")?;
        let low = number(r[2])?;
        let bytes = number(r[3])?;
        let high = end(low, bytes)?;
        check(
            low & 4095 == 0 && bytes & 4095 == 0 && high <= 0x0000_8000_0000_0000,
            "placement domain",
        )?;
        Some(Placement {
            domain: (low, high),
        })
    } else {
        None
    };
    let mut arenas = Vec::new();
    for kind in ["selected", "victim"] {
        let r = lines.row("arena", if placement.is_some() { 4 } else { 6 })?;
        check(r[1] == kind, "arena order")?;
        let a = if placement.is_some() {
            check(
                number(r[2])? == 65536 && number(r[3])? == 65536,
                "original-derived-v1 requires unchanged 64KiB/65536 caps",
            )?;
            Arena {
                base: 0,
                stride: 65536,
                bytes: 65536,
                candidates: 65536,
            }
        } else {
            Arena {
                base: number(r[2])?,
                stride: number(r[3])?,
                bytes: number(r[4])?,
                candidates: number(r[5])?,
            }
        };
        check(
            a.base & 4095 == 0
                && a.stride & 4095 == 0
                && a.bytes & 4095 == 0
                && (4096..=65536).contains(&a.bytes)
                && a.stride >= a.bytes
                && (1..=65536).contains(&a.candidates),
            "bounded page-aligned arena",
        )?;
        arenas.push(a);
    }
    let r = lines.row("limits", 10)?;
    let mut limits = [0; 9];
    for (to, from) in limits.iter_mut().zip(&r[1..]) {
        *to = number(from)?;
    }
    check(
        limits.iter().all(|&v| v > 0)
            && limits[0] <= INPUT_LIMIT as u64
            && limits[1] <= SITE_LIMIT as u64
            && limits[2] <= 4096
            && limits[3] <= 64 * 1024 * 1024
            && limits[4] <= 65536
            && limits[5] <= 512 * 1024 * 1024
            && limits[6] <= 512 * 1024 * 1024
            && limits[7] <= 4096
            && limits[8] <= 1_u64 << 32,
        "finite aggregate limits",
    )?;
    if let Some(v) = placement {
        check(
            v.domain.1 - v.domain.0 <= limits[8],
            "placement exceeds virtual span",
        )?;
    }
    let r = lines.row("search", 6)?;
    let mut search = [0; 5];
    for (to, from) in search.iter_mut().zip(&r[1..]) {
        *to = number(from)?;
    }
    check(
        search.iter().all(|&v| v > 0)
            && search[0] <= 65536
            && search[1] <= 65536
            && search[2] <= 4096
            && search[3] <= 65536
            && search[4] <= 1048576,
        "finite search limits",
    )?;
    lines.row("END", 1)?;
    check(lines.0.next().is_none(), "extra policy record")?;
    Ok(Policy {
        original,
        target,
        provenance,
        text,
        text_offset,
        functions,
        hooks,
        carrier,
        placement,
        arenas: [arenas[0], arenas[1]],
        limits,
        search,
    })
}

fn u64_at(bytes: &[u8], start: usize) -> u64 {
    u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap())
}
fn u32_at(bytes: &[u8], start: usize) -> u32 {
    u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap())
}
// The original ELF parser intentionally does not interpret sections. This
// bounded, local check authenticates the one .text owner used by both lanes.
fn text_section(original: &[u8], elf: &Elf64<'_>, p: &Policy) -> Result<()> {
    let h = elf.header();
    check(
        h.section_entry_size == 64
            && (1..=4096).contains(&h.section_count)
            && h.section_name_index > 0
            && h.section_name_index < h.section_count,
        "ordinary bounded ELF section table",
    )?;
    let table = bytes_at(
        original,
        h.section_offset.0,
        u64::from(h.section_count) * 64,
    )?;
    let shstr = &table[usize::from(h.section_name_index) * 64..][..64];
    check(u32_at(shstr, 4) == 3, "section string table type")?;
    let names = bytes_at(original, u64_at(shstr, 24), u64_at(shstr, 32))?;
    let mut found = 0;
    for s in table.chunks_exact(64) {
        let offset = u32_at(s, 0) as usize;
        let suffix = names
            .get(offset..)
            .ok_or_else(|| "section name outside string table".to_owned())?;
        let n = suffix
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| "unterminated section name".to_owned())?;
        if &suffix[..n] == b".text" {
            found += 1;
            check(
                u32_at(s, 4) == 1 && u64_at(s, 8) == 6,
                "text must be uncompressed ALLOC/EXEC PROGBITS",
            )?;
            check(
                (u64_at(s, 16), u64_at(s, 24), u64_at(s, 32))
                    == (p.text.pc, p.text_offset, p.text.length),
                "text section policy identity",
            )?;
        }
    }
    check(found == 1, "one exact .text section")
}
fn owned_bytes<'a>(original: &'a [u8], elf: &Elf64<'_>, owner: &Owner) -> Result<(&'a [u8], u64)> {
    end(owner.pc, owner.length)?;
    let mapping = elf
        .virtual_to_storage(ElfVaddr(owner.pc), owner.length)
        .map_err(|e| e.to_string())?;
    check(mapping.flags.0 == 5, "unique RX nonwritable LOAD required")?;
    let Storage::FileBacked(range) = mapping.storage else {
        return Err("owner not file-backed".to_owned());
    };
    let bytes = bytes_at(original, range.start().0, range.len())?;
    check(digest(bytes) == owner.hash, "whole owner SHA mismatch")?;
    Ok((bytes, range.start().0))
}

#[derive(Clone)]
struct Function {
    owner: Owner,
    file_offset: u64,
    bytes: Vec<u8>,
    instructions: Vec<Instruction>,
}
fn decode(bytes: &[u8], pc: u64) -> Result<Vec<Instruction>> {
    let scan = InstructionScanner::default()
        .scan(bytes, pc)
        .map_err(|e| e.to_string())?;
    check(
        !scan.instructions().is_empty() && scan.instructions().len() <= HEAD_LIMIT,
        "complete nonempty head bound",
    )?;
    Ok(scan
        .instructions()
        .iter()
        .map(|s| *s.instruction())
        .collect())
}
fn load_functions(original: &[u8], elf: &Elf64<'_>, p: &Policy) -> Result<(Vec<Function>, String)> {
    let (text, offset) = owned_bytes(original, elf, &p.text)?;
    check(
        offset == p.text_offset && text.len() as u64 == p.text.length,
        "text LOAD/file identity",
    )?;
    text_section(original, elf, p)?;
    let mut functions = Vec::new();
    for owner in &p.functions {
        check(
            owner.length <= KERNEL_LIMIT
                && owner.pc >= p.text.pc
                && end(owner.pc, owner.length)? <= end(p.text.pc, p.text.length)?,
            "function in exact text",
        )?;
        let (bytes, file_offset) = owned_bytes(original, elf, owner)?;
        functions.push(Function {
            owner: owner.clone(),
            file_offset,
            bytes: bytes.to_vec(),
            instructions: decode(bytes, owner.pc)?,
        });
    }
    functions.sort_by_key(|f| f.owner.pc);
    let first = functions.first().unwrap().owner.pc;
    let last = functions.last().unwrap();
    let stop = end(last.owner.pc, last.owner.length)?;
    check(
        stop - first <= KERNEL_LIMIT
            && functions
                .iter()
                .map(|f| f.instructions.len())
                .sum::<usize>()
                <= HEAD_LIMIT,
        "whole kernel byte/head bound",
    )?;
    let mut padding = "pc\tlength\tbytes\n".to_owned();
    for pair in functions.windows(2) {
        let start = end(pair[0].owner.pc, pair[0].owner.length)?;
        check(start <= pair[1].owner.pc, "overlapping function owners")?;
        if start != pair[1].owner.pc {
            let gap = elf
                .executable_bytes(ElfVaddr(start), pair[1].owner.pc - start)
                .map_err(|e| e.to_string())?;
            for i in decode(gap, start)? {
                check(
                    i.mnemonic() == Mnemonic::Nop,
                    "inter-function span contains non-NOP unowned code",
                )?;
                let n = (i.ip() - start) as usize;
                writeln!(
                    padding,
                    "0x{:x}\t{}\t{}",
                    i.ip(),
                    i.len(),
                    hex(&gap[n..n + i.len()])
                )
                .unwrap();
            }
        }
    }
    let mut intervals = vec![(first, stop)];
    for hook in &p.hooks {
        check(hook.length <= 65536, "hook byte bound")?;
        owned_bytes(original, elf, hook)?;
        let range = (hook.pc, end(hook.pc, hook.length)?);
        check(
            intervals.iter().all(|&v| !overlaps(v, range)),
            "hook/kernel owners overlap",
        )?;
        intervals.push(range);
    }
    Ok((functions, padding))
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}
fn jump(i: &Instruction) -> bool {
    // This is the finite shared E9 asm=j.* rule, not all control flow.
    format!("{:?}", i.mnemonic())
        .to_ascii_lowercase()
        .starts_with('j')
}
fn direct(i: &Instruction) -> Option<u64> {
    if i.op_count() > 0 && i.op0_kind() == OpKind::NearBranch64 {
        Some(i.near_branch_target())
    } else {
        None
    }
}
fn rsp_delta(i: &Instruction) -> Result<i64> {
    match i.code() {
        Code::Push_r64 => Ok(-8),
        Code::Pop_r64 if i.op0_register() != Register::RSP => Ok(8),
        Code::Call_rel32_64 | Code::Retnq => Ok(0),
        Code::Add_rm64_imm8 | Code::Sub_rm64_imm8 | Code::Add_rm64_imm32 | Code::Sub_rm64_imm32
            if i.op0_kind() == OpKind::Register && i.op0_register() == Register::RSP =>
        {
            let v = if i.op1_kind() == OpKind::Immediate8to64 {
                i.immediate8to64()
            } else {
                i.immediate32to64()
            };
            Ok(
                if matches!(i.code(), Code::Sub_rm64_imm8 | Code::Sub_rm64_imm32) {
                    -v
                } else {
                    v
                },
            )
        }
        _ => {
            let mut factory = InstructionInfoFactory::new();
            let info = factory.info(i);
            check(
                !info
                    .used_registers()
                    .iter()
                    .any(|r| r.register().full_register() == Register::RSP && writes(r.access())),
                "unproven RSP change",
            )?;
            Ok(0)
        }
    }
}
fn stack_owner(m: &UsedMemory, depth: i64) -> bool {
    if m.base() != Register::RSP
        || m.index() != Register::None
        || m.segment() != Register::SS
        || m.address_size() != CodeSize::Code64
        || m.vsib_size() != 0
    {
        return false;
    }
    let size = m.memory_size().size();
    if size == 0 {
        return false;
    }
    let Some(start) = depth.checked_add(m.displacement() as i64) else {
        return false;
    };
    let Some(stop) = start.checked_add(size as i64) else {
        return false;
    };
    start >= -STACK_LIMIT && start >= depth - 128 && stop <= 0
}
fn heap_owner(i: &Instruction, m: &UsedMemory, exact_store: bool, entry: u64) -> bool {
    exact_store
        && i.ip() == entry
        && m.base() == Register::RDI
        && m.index() == Register::RSI
        && m.scale() == 8
        && m.displacement() == 0
        && m.segment() == Register::DS
        && m.address_size() == CodeSize::Code64
        && m.memory_size().size() == 8
        && m.access() == OpAccess::Write
}

struct Graph {
    edges: BTreeMap<u64, Vec<u64>>,
    blocks: Vec<(u64, u64)>,
    calls: BTreeSet<u64>,
    errors: BTreeSet<String>,
}
fn graph(f: &Function, entries: &BTreeSet<u64>) -> Graph {
    let heads: BTreeSet<_> = f.instructions.iter().map(Instruction::ip).collect();
    let stop = f.owner.pc + f.owner.length;
    let mut boundaries = BTreeSet::from([f.owner.pc, stop]);
    let mut edges = BTreeMap::new();
    let mut calls = BTreeSet::new();
    let mut errors = BTreeSet::new();
    for i in &f.instructions {
        let mut successors = Vec::new();
        let next = i.next_ip();
        if i.flow_control() != FlowControl::Next && next < stop {
            boundaries.insert(next);
        }
        match i.flow_control() {
            FlowControl::Next => successors.push(next),
            FlowControl::Call if i.code() == Code::Call_rel32_64 => {
                let target = i.near_branch_target();
                if !entries.contains(&target) {
                    errors.insert(format!("0x{:x}:external-call", i.ip()));
                }
                calls.insert(target);
                successors.push(next);
            }
            FlowControl::Return if i.code() == Code::Retnq => {}
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if let Some(target) = direct(i) {
                    successors.push(target);
                    boundaries.insert(target);
                } else {
                    errors.insert(format!("0x{:x}:non-near-branch", i.ip()));
                }
                if i.flow_control() == FlowControl::ConditionalBranch {
                    successors.push(next);
                }
            }
            _ => {
                errors.insert(format!("0x{:x}:unsupported-control-flow", i.ip()));
            }
        }
        for target in &successors {
            if !heads.contains(target) {
                errors.insert(format!(
                    "0x{:x}:target-not-function-head:0x{target:x}",
                    i.ip()
                ));
            }
        }
        edges.insert(i.ip(), successors);
    }
    // Foreign branch coordinates remain explicit errors; never expand the
    // function/block owner to accommodate them.
    boundaries.retain(|p| *p == stop || heads.contains(p));
    let bounds: Vec<_> = boundaries.into_iter().collect();
    let blocks = bounds.windows(2).map(|p| (p[0], p[1])).collect();
    Graph {
        edges,
        blocks,
        calls,
        errors,
    }
}
fn depths(f: &Function, g: &Graph) -> Result<BTreeMap<u64, i64>> {
    check(g.errors.is_empty(), "invalid function CFG")?;
    let instructions: BTreeMap<_, _> = f.instructions.iter().map(|i| (i.ip(), i)).collect();
    let mut result: BTreeMap<u64, i64> = BTreeMap::from([(f.owner.pc, 0)]);
    let mut queue = VecDeque::from([f.owner.pc]);
    while let Some(pc) = queue.pop_front() {
        let i = instructions[&pc];
        let depth = result[&pc];
        if i.code() == Code::Retnq {
            check(depth == 0, "RET with unbalanced stack")?;
        }
        let after = depth
            .checked_add(rsp_delta(i)?)
            .ok_or_else(|| "stack depth overflow".to_owned())?;
        check(
            (-STACK_LIMIT..=0).contains(&after),
            "stack exceeds finite owned frame",
        )?;
        for next in &g.edges[&pc] {
            if let Some(old) = result.get(next) {
                check(*old == after, "conflicting RSP depths at CFG join")?;
            } else {
                result.insert(*next, after);
                queue.push_back(*next);
            }
        }
    }
    Ok(result)
}
fn acyclic(graphs: &BTreeMap<u64, BTreeSet<u64>>) -> bool {
    fn visit(
        pc: u64,
        graphs: &BTreeMap<u64, BTreeSet<u64>>,
        stack: &mut BTreeSet<u64>,
        done: &mut BTreeSet<u64>,
    ) -> bool {
        if done.contains(&pc) {
            return true;
        }
        if !stack.insert(pc) {
            return false;
        }
        let Some(calls) = graphs.get(&pc) else {
            return false;
        };
        if calls.iter().any(|&to| !visit(to, graphs, stack, done)) {
            return false;
        }
        stack.remove(&pc);
        done.insert(pc);
        true
    }
    let mut done = BTreeSet::new();
    graphs
        .keys()
        .all(|&pc| visit(pc, graphs, &mut BTreeSet::new(), &mut done))
}

struct Selected {
    id: usize,
    function: usize,
    instruction: Instruction,
    block: (u64, u64),
}
struct Inventory {
    instructions: String,
    memory: String,
    sites: String,
    blocks: String,
    selected: Vec<Selected>,
    errors: BTreeSet<String>,
    heads: usize,
}
fn inventory(functions: &[Function], style: &str) -> Result<Inventory> {
    check(matches!(style, "jump-site" | "heap-write"), "style")?;
    let entries = functions.iter().map(|f| f.owner.pc).collect();
    let graphs: Vec<_> = functions.iter().map(|f| graph(f, &entries)).collect();
    let calls = functions
        .iter()
        .zip(&graphs)
        .map(|(f, g)| (f.owner.pc, g.calls.clone()))
        .collect();
    let mut errors = BTreeSet::new();
    if !acyclic(&calls) {
        errors.insert("recursive-or-foreign-call-graph".to_owned());
    }
    let mut out = Inventory {
        instructions: "id\tpc\tlength\tfile_offset\tfunction\tbytes\tmnemonic\tflow\tdirect_target\tblock_start\tblock_end\tjump_site\theap_write\trsp_depth\n".to_owned(),
        memory: "id\tpc\twrite_index\taccess\tsegment\tbase\tindex\tscale\tdisplacement\tbytes\taddress_size\towner\n".to_owned(),
        sites: "id\tpc\tlength\tfile_offset\tfunction\tstyle\n".to_owned(),
        blocks: "function\tstart\tend\n".to_owned(), selected: Vec::new(), errors, heads: 0,
    };
    for (fi, (f, g)) in functions.iter().zip(&graphs).enumerate() {
        out.errors.extend(g.errors.iter().cloned());
        let depth = match depths(f, g) {
            Ok(d) => d,
            Err(e) => {
                out.errors.insert(format!("{}:{e}", f.owner.name));
                BTreeMap::new()
            }
        };
        let exact_store = f.owner.name == NAMES[0] && f.bytes == STORE;
        if f.owner.name == NAMES[0] && !exact_store {
            out.errors
                .insert("li2_array_store:exact-MOV-RET-body-required".to_owned());
        }
        for &(start, stop) in &g.blocks {
            writeln!(out.blocks, "{}\t0x{start:x}\t0x{stop:x}", f.owner.name).unwrap();
        }
        for i in &f.instructions {
            out.heads += 1;
            let id = out.heads;
            let block = *g
                .blocks
                .iter()
                .find(|&&(a, b)| a <= i.ip() && i.ip() < b)
                .ok_or_else(|| "missing block owner".to_owned())?;
            let mut factory = InstructionInfoFactory::new();
            let info = factory.info(i);
            let mut heap = false;
            let memory_writes: Vec<_> = info
                .used_memory()
                .iter()
                .filter(|m| writes(m.access()))
                .collect();
            for (memory_index, m) in memory_writes.iter().enumerate() {
                let owner = if heap_owner(i, m, exact_store, f.owner.pc) {
                    heap = true;
                    "array-store-ABI-requires-runtime-witness"
                } else if depth.get(&i.ip()).is_some_and(|&d| stack_owner(m, d)) {
                    "RSP-frame"
                } else {
                    out.errors.insert(format!(
                        "0x{:x}:unproven-memory-writer:{memory_index}",
                        i.ip()
                    ));
                    "unsupported"
                };
                writeln!(out.memory, "{id}\t0x{:x}\t{memory_index}\t{:?}\t{:?}\t{:?}\t{:?}\t{}\t0x{:x}\t{}\t{:?}\t{owner}", i.ip(), m.access(), m.segment(), m.base(), m.index(), m.scale(), m.displacement(), m.memory_size().size(), m.address_size()).unwrap();
            }
            if exact_store && i.ip() == f.owner.pc && (!heap || memory_writes.len() != 1) {
                out.errors
                    .insert("store-memory-effect-denominator".to_owned());
            }
            if !depth.contains_key(&i.ip()) && i.mnemonic() != Mnemonic::Nop {
                out.errors
                    .insert(format!("0x{:x}:unreachable-nonpadding-head", i.ip()));
            }
            let offset = (i.ip() - f.owner.pc) as usize;
            let target = direct(i).map_or_else(|| "none".to_owned(), |pc| format!("0x{pc:x}"));
            let rsp = depth
                .get(&i.ip())
                .map_or_else(|| "unproven".to_owned(), ToString::to_string);
            writeln!(out.instructions, "{id}\t0x{:x}\t{}\t{}\t{}\t{}\t{:?}\t{:?}\t{target}\t0x{:x}\t0x{:x}\t{}\t{heap}\t{rsp}", i.ip(), i.len(), f.file_offset + offset as u64, f.owner.name, hex(&f.bytes[offset..offset + i.len()]), i.mnemonic(), i.flow_control(), block.0, block.1, jump(i)).unwrap();
            if (style == "jump-site" && jump(i)) || (style == "heap-write" && heap) {
                writeln!(
                    out.sites,
                    "{id}\t0x{:x}\t{}\t{}\t{}\t{style}",
                    i.ip(),
                    i.len(),
                    f.file_offset + offset as u64,
                    f.owner.name
                )
                .unwrap();
                out.selected.push(Selected {
                    id,
                    function: fi,
                    instruction: *i,
                    block,
                });
            }
        }
    }
    if out.selected.is_empty() {
        out.errors.insert("empty-complete-selection".to_owned());
    }
    Ok(out)
}

fn allocation_ranges(elf: &Elf64<'_>, p: &Policy, count: usize) -> Result<Vec<[(u64, u64); 2]>> {
    check(
        count <= SITE_LIMIT && count as u64 <= p.limits[1],
        "complete site count exceeds fixed policy",
    )?;
    let mut occupied = Vec::new();
    for h in elf
        .program_headers()
        .iter()
        .filter(|h| h.kind == SegmentType::Load && h.memory_size != 0)
    {
        let stop = end(h.vaddr.0, h.memory_size)?
            .checked_add(4095)
            .ok_or_else(|| "LOAD page overflow".to_owned())?
            & !4095;
        check(
            stop <= 0x0000_8000_0000_0000,
            "original LOAD outside low canonical user range",
        )?;
        occupied.push((h.vaddr.0 & !4095, stop));
    }
    check(p.carrier & 4095 == 0, "carrier page alignment")?;
    let carrier_bytes = (p.limits[7] * 56 + 128).div_ceil(4096) * 4096;
    let carrier = (p.carrier, end(p.carrier, carrier_bytes)?);
    check(
        carrier.1 <= 0x0000_8000_0000_0000,
        "carrier outside low canonical user range",
    )?;
    check(
        occupied.iter().all(|&r| !overlaps(r, carrier)),
        "carrier intersects original LOAD page",
    )?;
    occupied.push(carrier);
    let mut result = Vec::new();
    for n in 0..count {
        let mut pair = [(0, 0); 2];
        for (k, a) in p.arenas.iter().enumerate() {
            let delta = a
                .stride
                .checked_mul(n as u64)
                .ok_or_else(|| "arena stride overflow".to_owned())?;
            let start = a
                .base
                .checked_add(delta)
                .ok_or_else(|| "arena address overflow".to_owned())?;
            let range = (start, end(start, a.bytes)?);
            check(
                range.1 <= 0x0000_8000_0000_0000 && occupied.iter().all(|&r| !overlaps(r, range)),
                "noncanonical or overlapping allocation permit",
            )?;
            occupied.push(range);
            pair[k] = range;
        }
        result.push(pair);
    }
    Ok(result)
}
// These are the unchanged B1 forbidden-entry opcode bytes, not an emission
// oracle. The core still qualifies instructions, emits images and checks fit.
const ENTRY_BYTES: [u8; 14] = [
    0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce,
];
#[derive(Clone, Copy, Debug)]
struct TargetPattern {
    next: u64,
    fixed: [Option<u8>; 4],
    entries: [bool; 4],
}
impl TargetPattern {
    fn plain(next: u64) -> Self {
        Self {
            next,
            fixed: [None; 4],
            entries: [false; 4],
        }
    }
    fn allows(self, digit: usize, byte: u8) -> bool {
        self.fixed[digit].is_none_or(|b| b == byte)
            && (!self.entries[digit] || ENTRY_BYTES.contains(&byte))
    }
}

// A four-byte digit successor, not a walk over address-space bytes. A tight
// prefix can recurse once at each digit; a larger digit takes the minimum
// legal suffix. Thus no loop is proportional to the domain's byte length.
fn encoded_at_least(pattern: TargetPattern, lower: u32) -> Option<u32> {
    if (0..4).any(|n| !(0..=255).any(|b| pattern.allows(n, b))) {
        return None;
    }
    fn digit(p: TargetPattern, lower: u32, n: i32, tight: bool, prefix: u32) -> Option<u32> {
        if n < 0 {
            return Some(prefix);
        }
        let shift = n as u32 * 8;
        let floor = if tight { (lower >> shift) & 255 } else { 0 };
        for byte in floor..=255 {
            if !p.allows(n as usize, byte as u8) {
                continue;
            }
            if let Some(value) = digit(
                p,
                lower,
                n - 1,
                tight && byte == floor,
                prefix | (byte << shift),
            ) {
                return Some(value);
            }
        }
        None
    }
    digit(pattern, lower, 3, true, 0)
}

fn first_target(pattern: TargetPattern, range: (u64, u64)) -> Option<u64> {
    if range.0 >= range.1 {
        return None;
    }
    let low = (i128::from(range.0) - i128::from(pattern.next)).max(i128::from(i32::MIN));
    let high = (i128::from(range.1 - 1) - i128::from(pattern.next)).min(i128::from(i32::MAX));
    if low > high {
        return None;
    }
    // Signed order: negative encodings first, then nonnegative encodings.
    for (a, b) in [(low, high.min(-1)), (low.max(0), high)] {
        if a > b {
            continue;
        }
        let encoded = encoded_at_least(pattern, a as i32 as u32);
        if let Some(value) = encoded.filter(|&v| v <= b as i32 as u32) {
            return u64::try_from(i128::from(pattern.next) + i128::from(value as i32)).ok();
        }
    }
    None
}

fn pun_pattern(f: &Function, s: &Selected, prefixes: usize, p: &Policy) -> Option<TargetPattern> {
    let pc = s.instruction.ip();
    let len = s.instruction.len();
    let displaced_end = pc.checked_add(len as u64)?;
    let consumed_end = pc.checked_add(5 + prefixes as u64)?;
    if !(1..=4).contains(&len)
        || prefixes >= len
        || len as u64 > p.search[1]
        || pc < s.block.0
        || displaced_end > s.block.1
        || consumed_end > end(f.owner.pc, f.owner.length).ok()?
        || pc / 64 != (displaced_end - 1) / 64
    {
        return None;
    }
    let store_len = len.next_power_of_two() as u64;
    let store_pc = pc.min((pc | 63).checked_sub(store_len - 1)?);
    if store_pc < f.owner.pc
        || store_pc.checked_add(store_len)? > end(f.owner.pc, f.owner.length).ok()?
    {
        return None;
    }
    let offset = usize::try_from(pc - f.owner.pc).ok()?;
    let free = len - prefixes - 1;
    let suffix = f.bytes.get(offset + len..offset + 5 + prefixes)?;
    let mut raw = [0; 4];
    raw[free..].copy_from_slice(suffix);
    // Match the core's checked lower-bound conversion BEFORE intersection.
    let low = u64::try_from(i128::from(consumed_end) + i128::from(i32::from_le_bytes(raw))).ok()?;
    low.checked_add(1_u64 << (8 * free))?;
    let mut result = TargetPattern::plain(consumed_end);
    for (slot, byte) in result.fixed.iter_mut().zip(raw).skip(free) {
        *slot = Some(byte);
    }
    Some(result)
}

fn original_patterns(f: &Function, s: &Selected, p: &Policy) -> Vec<TargetPattern> {
    let logical = s.instruction.ip();
    let mut patterns = Vec::new();
    if let Some(pattern) = pun_pattern(f, s, 0, p) {
        patterns.push(pattern);
    }
    let mut physical: Vec<_> = f
        .instructions
        .iter()
        .filter(|i| {
            s.block.0 <= i.ip()
                && i.ip() < s.block.1
                && i.ip() <= logical
                && logical - i.ip() <= p.search[0]
        })
        .map(Instruction::ip)
        .collect();
    physical.sort_by_key(|&pc| (pc != logical, pc % 64 > 56, logical - pc));
    // The core spends max_sites on physical heads, even on invalid windows.
    for pc in physical.into_iter().take(p.search[2] as usize) {
        let mut window = Vec::new();
        let mut stop = pc;
        let mut valid = true;
        for i in f.instructions.iter().filter(|i| i.ip() >= pc) {
            if i.ip() >= s.block.1 {
                break;
            }
            stop = i.next_ip();
            if stop > s.block.1 || stop - pc > p.search[1] {
                valid = false;
                break;
            }
            window.push(i);
            if stop - pc >= 5 && stop > logical {
                break;
            }
        }
        if !valid
            || stop - pc < 5
            || stop <= logical
            || window.iter().any(|i| {
                matches!(
                    i.flow_control(),
                    FlowControl::Call | FlowControl::IndirectCall
                ) || (i.flow_control() != FlowControl::Next && i.next_ip() != stop)
            })
        {
            continue;
        }
        let Some(next) = pc.checked_add(5) else {
            continue;
        };
        let mut pattern = TargetPattern::plain(next);
        for head in &f.instructions {
            if pc < head.ip() && head.ip() < next {
                pattern.entries[(head.ip() - pc - 1) as usize] = true;
            }
        }
        patterns.push(pattern);
    }
    for prefixes in 1..s.instruction.len().min(4) {
        if let Some(pattern) = pun_pattern(f, s, prefixes, p) {
            patterns.push(pattern);
        }
    }
    patterns
}

fn free_permit(
    domain: (u64, u64),
    occupied: &[(u64, u64)],
    pattern: TargetPattern,
    reach: (u64, u64),
    bytes: u64,
) -> Option<Permit> {
    let mut rows = occupied.to_vec();
    rows.sort_unstable();
    rows.push((domain.1, domain.1));
    let mut cursor = domain.0;
    for (start, stop) in rows {
        if start > cursor && start - cursor >= bytes {
            // Any byte in the final eligible page is a legal preferred PC;
            // the entire page-rounded slot must fit, not only that byte.
            let hi = start - bytes + 4096;
            let range = (cursor.max(reach.0), hi.min(reach.1));
            if let Some(target) = first_target(pattern, range) {
                let base = target & !4095;
                return Some(Permit {
                    range: (base, base + bytes),
                    preferred: target,
                });
            }
        }
        cursor = cursor.max(stop);
    }
    None
}

fn neutral_reach(origins: impl Iterator<Item = u64>) -> Result<(u64, u64)> {
    let mut low = 0_i128;
    let mut high = 0x0000_8000_0000_0000_i128;
    for pc in origins {
        let next = i128::from(pc.checked_add(5).ok_or("neutral origin overflow")?);
        low = low.max(next + i128::from(i32::MIN));
        high = high.min(next + i128::from(i32::MAX) + 1);
    }
    check(low < high, "empty neutral rel32 intersection")?;
    Ok((low as u64, high as u64))
}

fn original_permits(
    elf: &Elf64<'_>,
    p: &Policy,
    functions: &[Function],
    inv: &Inventory,
) -> Result<Vec<[Permit; 2]>> {
    if p.placement.is_none() {
        return allocation_ranges(elf, p, inv.selected.len()).map(|rows| {
            rows.into_iter()
                .map(|pair| {
                    pair.map(|range| Permit {
                        range,
                        preferred: range.0,
                    })
                })
                .collect()
        });
    }
    // Keep every v1 LOAD/carrier check, including its checked arithmetic.
    allocation_ranges(elf, p, 0)?;
    check(
        inv.selected.len() <= SITE_LIMIT && inv.selected.len() as u64 <= p.limits[1],
        "complete site count exceeds fixed policy",
    )?;
    let domain = p.placement.unwrap().domain;
    let mut occupied = Vec::new();
    for h in elf
        .program_headers()
        .iter()
        .filter(|h| h.kind == SegmentType::Load && h.memory_size != 0)
    {
        occupied.push((
            h.vaddr.0 & !4095,
            (end(h.vaddr.0, h.memory_size)? + 4095) & !4095,
        ));
    }
    let carrier_bytes = (p.limits[7] * 56 + 128).div_ceil(4096) * 4096;
    occupied.push((p.carrier, end(p.carrier, carrier_bytes)?));
    check(
        occupied
            .iter()
            .all(|&(a, b)| domain.0 <= a && b <= domain.1),
        "placement domain must contain every original LOAD page and carrier",
    )?;
    let empty = Permit {
        range: (0, 0),
        preferred: 0,
    };
    let mut result = vec![[empty; 2]; inv.selected.len()];
    let mut neutral = Vec::new();
    // Reserve constrained selected slots before any neutral reservation.
    for (n, s) in inv.selected.iter().enumerate() {
        let patterns = original_patterns(&functions[s.function], s, p);
        let found = patterns
            .into_iter()
            .find_map(|pattern| free_permit(domain, &occupied, pattern, domain, p.arenas[0].bytes));
        if let Some(permit) = found {
            occupied.push(permit.range);
            result[n][0] = permit;
        } else {
            neutral.push(n);
        }
    }
    for n in neutral {
        let pc = inv.selected[n].instruction.ip();
        let reach = neutral_reach(std::iter::once(pc))?;
        let permit = free_permit(
            domain,
            &occupied,
            TargetPattern::plain(pc + 5),
            reach,
            p.arenas[0].bytes,
        )
        .ok_or("no disjoint neutral selected permit")?;
        occupied.push(permit.range);
        result[n][0] = permit;
    }
    for (n, s) in inv.selected.iter().enumerate() {
        let f = &functions[s.function];
        // All original function heads conservatively include every potential
        // victim origin. This does not solve any T2 overlay or T3 joint route.
        let reach = neutral_reach(f.instructions.iter().map(Instruction::ip))?;
        let permit = free_permit(
            domain,
            &occupied,
            TargetPattern::plain(s.instruction.ip() + 5),
            reach,
            p.arenas[1].bytes,
        )
        .ok_or("no disjoint neutral victim permit")?;
        occupied.push(permit.range);
        result[n][1] = permit;
    }
    Ok(result)
}

#[cfg(test)]
fn selection(
    p: &Policy,
    policy_bytes: &[u8],
    target: &[u8],
    functions: &[Function],
    inv: &Inventory,
    ranges: &[[(u64, u64); 2]],
    journal: bool,
) -> Result<Vec<u8>> {
    let permits: Vec<_> = ranges
        .iter()
        .map(|pair| {
            pair.map(|range| Permit {
                range,
                preferred: range.0,
            })
        })
        .collect();
    selection_with_permits(p, policy_bytes, target, functions, inv, &permits, journal)
}
fn selection_with_permits(
    p: &Policy,
    policy_bytes: &[u8],
    target: &[u8],
    functions: &[Function],
    inv: &Inventory,
    ranges: &[[Permit; 2]],
    journal: bool,
) -> Result<Vec<u8>> {
    let target = std::str::from_utf8(target).map_err(|e| e.to_string())?;
    check(
        target.starts_with("target ")
            && target.ends_with('\n')
            && target.lines().count() == 1
            && target.is_ascii()
            && !target.contains('\r'),
        "one compact target line required",
    )?;
    let mut out = format!(
        "LI2TOOL 1\noriginal {}\n{target}domain 1\ncarrier {}\nlimits",
        p.original, p.carrier
    );
    for n in p.limits {
        write!(out, " {n}").unwrap();
    }
    let hook = &p.hooks[usize::from(journal)];
    writeln!(
        out,
        "\nhook {} {} {} {}",
        hook.name, hook.pc, hook.length, hook.hash
    )
    .unwrap();
    for (s, permits) in inv.selected.iter().zip(ranges) {
        let f = &functions[s.function];
        let i = s.instruction;
        writeln!(
            out,
            "site {} {} {} {} {} {} {} {} {} {} {} observe original-decode",
            s.id,
            i.ip(),
            i.len(),
            f.file_offset + i.ip() - f.owner.pc,
            f.owner.pc,
            f.owner.length,
            f.owner.pc,
            f.owner.length,
            s.block.0,
            s.block.1 - s.block.0,
            hook.name
        )
        .unwrap();
        write!(out, "entries {} complete {}", s.id, digest(policy_bytes)).unwrap();
        for head in &f.instructions {
            write!(out, " {}:0", head.ip()).unwrap();
        }
        writeln!(
            out,
            "\nresumes {} none\nsearch {} preferred {} {} {} none {} {}",
            s.id, s.id, p.search[0], p.search[1], p.search[2], p.search[3], p.search[4]
        )
        .unwrap();
        for (k, kind) in ["selected", "victim"].iter().enumerate() {
            let Permit {
                range: (a, b),
                preferred,
            } = permits[k];
            writeln!(
                out,
                "allocation {} {kind} {preferred} {} {} {a}:{}",
                s.id,
                p.arenas[k].candidates,
                p.arenas[k].bytes,
                b - a
            )
            .unwrap();
        }
    }
    // Use the product's unchanged parser; complete original per-function heads
    // and every static selected instruction must survive this join literally.
    let parsed = liteinst_rewrite::selection::parse(out.as_bytes()).map_err(|e| e.to_string())?;
    check(
        parsed.sites.len() == inv.selected.len(),
        "selection site denominator",
    )?;
    for (actual, expected) in parsed.sites.iter().zip(&inv.selected) {
        check(
            actual.id == expected.id as u64
                && actual.pc == expected.instruction.ip()
                && usize::from(actual.length) == expected.instruction.len(),
            "selection site identity",
        )?;
        check(
            actual
                .heads
                .iter()
                .map(|h| h.address)
                .eq(functions[expected.function]
                    .instructions
                    .iter()
                    .map(Instruction::ip)),
            "selection lost original head",
        )?;
    }
    Ok(out.into_bytes())
}

fn read(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    check(
        file.metadata().map_err(|e| e.to_string())?.is_file(),
        "regular input file required",
    )?;
    let mut bytes = Vec::new();
    file.take((bound + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    check(
        !bytes.is_empty() && bytes.len() <= bound,
        "input byte bound",
    )?;
    Ok(bytes)
}
fn publish(directory: &Path, files: &BTreeMap<&str, Vec<u8>>) -> Result<()> {
    let parent = directory
        .parent()
        .ok_or_else(|| "output parent".to_owned())?;
    check(
        parent.is_absolute()
            && parent
                .canonicalize()
                .map_err(|e| e.to_string())?
                .as_os_str()
                == parent.as_os_str()
            && directory.file_name().is_some(),
        "canonical absolute existing output parent",
    )?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(directory)
        .map_err(|e| e.to_string())?;
    for (name, bytes) in files {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(name))
            .map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
    }
    // Complete marker comes last. A partial I/O failure is never complete.
    let index = files
        .iter()
        .map(|(name, bytes)| format!("{}\t{}\t{name}\n", digest(bytes), bytes.len()))
        .collect::<String>();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("COMPLETE"))
        .map_err(|e| e.to_string())?;
    write!(file, "LI2COMMONFILES\t1\n{index}").map_err(|e| e.to_string())
}
fn run(args: &[std::ffi::OsString]) -> Result<bool> {
    check(
        args.len() == 7,
        "common_sites ORIGINAL POLICY TARGET_RECORD jump-site|heap-write null|journal NEW_DIRECTORY",
    )?;
    let original = read(Path::new(&args[1]), INPUT_LIMIT)?;
    let policy_bytes = read(Path::new(&args[2]), 65536)?;
    let target = read(Path::new(&args[3]), 4096)?;
    let style = args[4].to_str().ok_or_else(|| "ASCII style".to_owned())?;
    let journal = match args[5].to_str() {
        Some("null") => false,
        Some("journal") => true,
        _ => return Err("hook mode".to_owned()),
    };
    let p = policy(&policy_bytes)?;
    check(
        digest(&original) == p.original
            && digest(&target) == p.target
            && original.len() as u64 <= p.limits[0],
        "whole original/target identity",
    )?;
    let elf = Elf64::parse(
        &original,
        ParseLimits {
            max_program_headers: 4096,
        },
    )
    .map_err(|e| e.to_string())?;
    check(
        elf.header().object_type == ObjectType::Executable,
        "ET_EXEC required",
    )?;
    let (functions, padding) = load_functions(&original, &elf, &p)?;
    let mut inv = inventory(&functions, style)?;
    let ranges = original_permits(&elf, &p, &functions, &inv);
    let mut chosen = None;
    match ranges {
        Ok(ranges) if inv.errors.is_empty() => match selection_with_permits(
            &p,
            &policy_bytes,
            &target,
            &functions,
            &inv,
            &ranges,
            journal,
        ) {
            Ok(bytes) => chosen = Some(bytes),
            Err(e) => {
                inv.errors.insert(format!("selection:{e}"));
            }
        },
        Ok(_) => {}
        Err(e) => {
            inv.errors.insert(format!("allocation:{e}"));
        }
    }
    let complete = inv.errors.is_empty();
    let mut files = BTreeMap::from([
        ("policy.txt", policy_bytes),
        ("target.txt", target),
        ("instructions.tsv", inv.instructions.into_bytes()),
        ("memory-writes.tsv", inv.memory.into_bytes()),
        ("sites.tsv", inv.sites.into_bytes()),
        ("blocks.tsv", inv.blocks.into_bytes()),
        ("padding.tsv", padding.into_bytes()),
    ]);
    let mut status = format!(
        "LI2COMMONRESULT\t1\noriginal_sha256\t{}\npolicy_sha256\t{}\ncaller_provenance_sha256\t{}\ntarget_sha256\t{}\nstyle\t{style}\nhook\t{}\ninstruction_heads\t{}\nselected_sites\t{}\ncomplete_static_policy\t{complete}\nqualification_complete\tfalse\n",
        p.original,
        digest(&files["policy.txt"]),
        p.provenance,
        p.target,
        if journal { "journal" } else { "null" },
        inv.heads,
        inv.selected.len()
    );
    for error in &inv.errors {
        writeln!(status, "unsupported\t{error}").unwrap();
    }
    if let Some(bytes) = chosen {
        writeln!(status, "selection_sha256\t{}", digest(&bytes)).unwrap();
        files.insert("selection.txt", bytes);
    }
    files.insert("status.tsv", status.into_bytes());
    // Re-read the complete finite inputs before the first output write.
    check(
        read(Path::new(&args[1]), INPUT_LIMIT)? == original
            && read(Path::new(&args[2]), 65536)? == files["policy.txt"]
            && read(Path::new(&args[3]), 4096)? == files["target.txt"],
        "input bytes changed",
    )?;
    publish(Path::new(&args[6]), &files)?;
    println!(
        "common sites: heads={} selected={} style={} hook={} complete_static_policy={} qualification_complete=false",
        inv.heads,
        inv.selected.len(),
        style,
        if journal { "journal" } else { "null" },
        complete
    );
    Ok(complete)
}
fn main() {
    match run(&std::env::args_os().collect::<Vec<_>>()) {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(e) => {
            eprintln!("common sites refused: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str, pc: u64, bytes: &[u8]) -> Function {
        Function {
            owner: Owner {
                name: name.to_owned(),
                pc,
                length: bytes.len() as u64,
                hash: digest(bytes),
            },
            file_offset: pc,
            bytes: bytes.to_vec(),
            instructions: decode(bytes, pc).unwrap(),
        }
    }
    fn one(bytes: &[u8]) -> Instruction {
        decode(bytes, 0x1000).unwrap()[0]
    }
    fn corpus(other: &[u8]) -> Vec<Function> {
        vec![
            function(NAMES[0], 0x1000, &STORE),
            function(NAMES[1], 0x2000, other),
            function(NAMES[2], 0x3000, &[0xc3]),
        ]
    }
    fn policy_text() -> String {
        let h = "a".repeat(64);
        format!(
            "LI2COMMON 1\noriginal {h}\ntarget {h}\nprovenance {h}\ntext 4096 4096 8193 {h}\nfunction li2_array_store 4096 5 {h}\nfunction li2_sift_down 8192 4 {h}\nfunction li2_heap_sort 12288 1 {h}\nhook 2 16384 1 {h}\nhook 3 16416 19 {h}\ncarrier 32768\narena selected 65536 8192 4096 64\narena victim 131072 8192 4096 64\nlimits 1048576 64 128 1048576 256 4194304 3145728 256 16777216\nsearch 64 256 64 256 4096\nEND\n"
        )
    }
    fn elf_with_load(pc: u64, memory_bytes: u64) -> Vec<u8> {
        let mut bytes = vec![0_u8; 120];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&4_u32.to_le_bytes());
        bytes[80..88].copy_from_slice(&pc.to_le_bytes());
        bytes[96..104].copy_from_slice(&120_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&memory_bytes.to_le_bytes());
        bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        bytes
    }

    // Exact original bytes from the retained cbb 87-head inventory. This is a
    // source-only fixture, not a candidate or an execution result.
    fn original_corpus() -> Vec<Function> {
        vec![
            function(
                "li2_array_store",
                0x401840,
                &[b"\x48\x89\x14\xf7\xc3".as_slice()].concat(),
            ),
            function(
                "li2_sift_down",
                0x401850,
                &[
                    b"\x41\x56\x41\x55\x49\x89\xfd\x41\x54\x49\x89\xf4\x49\xd1\xec\x55".as_slice(),
                    b"\x48\x89\xf5\x48\x89\xd6\x53\x4c\x39\xe2\x72\x22\xeb\x58\x66\x90".as_slice(),
                    b"\x4c\x89\xef\xe8\xc8\xff\xff\xff\x4c\x89\xf2\x48\x89\xde\x4c\x89".as_slice(),
                    b"\xef\xe8\xba\xff\xff\xff\x4c\x39\xe3\x73\x3b\x48\x89\xde\x48\x8d".as_slice(),
                    b"\x04\x36\x48\x8d\x4e\x01\x48\x8d\x58\x01\x48\x83\xc0\x02\x49\x8b".as_slice(),
                    b"\x54\xdd\x00\x48\x39\xe8\x73\x14\x48\xc1\xe1\x04\x49\x8b\x4c\x0d".as_slice(),
                    b"\x00\x48\x39\xd1\x76\x06\x48\x89\xca\x48\x89\xc3\x4d\x8b\x74\xf5".as_slice(),
                    b"\x00\x49\x39\xd6\x72\xaa\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\xc3".as_slice(),
                ]
                .concat(),
            ),
            function(
                "li2_heap_sort",
                0x4018d0,
                &[
                    b"\x48\x83\xfe\x01\x76\x7a\x41\x54\x49\x89\xf4\x55\x49\xd1\xec\x48".as_slice(),
                    b"\x89\xfd\x53\x48\x89\xf3\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00".as_slice(),
                    b"\x49\x83\xec\x01\x48\x89\xde\x48\x89\xef\x4c\x89\xe2\xe8\x4e\xff".as_slice(),
                    b"\xff\xff\x4d\x85\xe4\x75\xe9\x66\x0f\x1f\x84\x00\x00\x00\x00\x00".as_slice(),
                    b"\x48\x8b\x54\xdd\xf8\x4c\x8b\x65\x00\x31\xf6\x48\x83\xeb\x01\x48".as_slice(),
                    b"\x89\xef\xe8\x19\xff\xff\xff\x4c\x89\xe2\x48\x89\xde\x48\x89\xef".as_slice(),
                    b"\xe8\x0b\xff\xff\xff\x31\xd2\x48\x89\xde\x48\x89\xef\xe8\x0e\xff".as_slice(),
                    b"\xff\xff\x48\x83\xfb\x01\x75\xc8\x5b\x5d\x41\x5c\xc3\x0f\x1f\x00".as_slice(),
                    b"\xc3".as_slice(),
                ]
                .concat(),
            ),
        ]
    }

    fn derived_policy_text() -> String {
        policy_text()
            .replace("LI2COMMON 1", "LI2COMMON 2")
            .replace(
                "carrier 32768",
                "carrier 536870912\nplacement original-derived-v1 65536 1073741824",
            )
            .replace(
                "arena selected 65536 8192 4096 64",
                "arena selected 65536 65536",
            )
            .replace(
                "arena victim 131072 8192 4096 64",
                "arena victim 65536 65536",
            )
            .replace(
                "limits 1048576 64 128 1048576 256 4194304 3145728 256 16777216",
                "limits 1048576 64 256 8388608 2048 16777216 12582912 512 1073741824",
            )
    }

    #[test]
    fn explicit_v2_grammar_keeps_exact_caps_and_v1_separate() {
        let text = derived_policy_text();
        let p = policy(text.as_bytes()).unwrap();
        assert_eq!(p.placement.unwrap().domain, (65536, 1073807360));
        assert!(
            policy(policy_text().as_bytes())
                .unwrap()
                .placement
                .is_none()
        );
        for bad in [
            text.replace("original-derived-v1", "automatic"),
            text.replace("65536 1073741824\n", "65537 1073741824\n"),
            text.replace("65536 1073741824\n", "65536 1073745920\n"),
            text.replace("arena selected 65536 65536", "arena selected 4096 65536"),
            text.replace("arena victim 65536 65536", "arena victim 65536 65537"),
            text.replace(
                "arena victim 65536 65536",
                "arena victim 0 65536 65536 65536",
            ),
            text.replace("LI2COMMON 2", "LI2COMMON 1"),
        ] {
            assert!(policy(bad.as_bytes()).is_err());
        }
    }

    #[test]
    fn signed_digit_successor_retains_negative_edges_and_entry_bytes() {
        let plain = TargetPattern::plain(0x8000_0000);
        assert_eq!(first_target(plain, (0, 1)), Some(0));
        assert_eq!(
            first_target(plain, (0xffff_ffff, 0x1_0000_0000)),
            Some(0xffff_ffff)
        );
        assert_eq!(first_target(plain, (0x1_0000_0000, 0x1_0000_0001)), None);
        let full = TargetPattern {
            entries: [true; 4],
            ..TargetPattern::plain(0x4000_0000)
        };
        assert_eq!(first_target(full, (0, 0x8000_0000)), Some(0x0e06_0606));
        let mut fixed = TargetPattern::plain(0x1000);
        fixed.fixed = [Some(0xff); 4];
        assert_eq!(first_target(fixed, (0, 0x2000)), Some(0xfff));
        fixed.fixed = [Some(0); 4];
        assert_eq!(first_target(fixed, (0x1001, 0x2000)), None);
    }

    #[test]
    fn digit_minimum_matches_bounded_independent_byte_enumeration() {
        let next = 0x8000_0000_u64;
        let starts = [
            0,
            127,
            255,
            65535,
            0x7fff_ffc0,
            0x8000_0000,
            0x8000_ffc0,
            0xffff_ff80,
            0x8606_05c0,
            0x4e06_05c0,
            0xcc90_65c0,
            0x8000_0001,
        ];
        let mut patterns: Vec<_> = (0..16)
            .map(|mask| TargetPattern {
                entries: std::array::from_fn(|n| mask & (1 << n) != 0),
                ..TargetPattern::plain(next)
            })
            .collect();
        for fixed in [
            [None, Some(0x66), Some(0x90), Some(0x4c)],
            [None, None, None, Some(0x80)],
            [Some(0xff), Some(0xff), Some(0xff), Some(0xff)],
            [Some(0), Some(0), Some(0), Some(0)],
        ] {
            patterns.push(TargetPattern {
                fixed,
                ..TargetPattern::plain(next)
            });
        }
        for pattern in patterns {
            for low in starts {
                let high = low + 129;
                let expected = (low..high).find(|&pc| {
                    let Ok(displacement) = i32::try_from(i128::from(pc) - i128::from(next)) else {
                        return false;
                    };
                    displacement
                        .to_le_bytes()
                        .iter()
                        .enumerate()
                        .all(|(n, &byte)| {
                            pattern.fixed[n].is_none_or(|b| b == byte)
                                && (!pattern.entries[n]
                                    || [
                                        0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37,
                                        0x3f, 0x60, 0x61, 0xce,
                                    ]
                                    .contains(&byte))
                        })
                });
                assert_eq!(
                    first_target(pattern, (low, high)),
                    expected,
                    "{pattern:?} {low:#x}"
                );
            }
        }
    }

    #[test]
    fn heap_store_uses_complete_ret_entry_and_unaligned_preferred_pc() {
        let p = policy(derived_policy_text().as_bytes()).unwrap();
        let functions = original_corpus();
        let inv = inventory(&functions, "heap-write").unwrap();
        let bytes = elf_with_load(0x400000, 0x25000);
        let elf = Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: 1,
            },
        )
        .unwrap();
        let permits = original_permits(&elf, &p, &functions, &inv).unwrap();
        assert_eq!(inv.heads, 87);
        assert_eq!(inv.selected.len(), 1);
        assert!(pun_pattern(&functions[0], &inv.selected[0], 0, &p).is_none());
        assert_eq!(permits[0][0].preferred, 0x0640_1845);
        assert_eq!(permits[0][0].range, (0x0640_1000, 0x0641_1000));
        let displacement = (permits[0][0].preferred - 0x401845) as u32;
        assert_eq!(displacement.to_le_bytes(), [0, 0, 0, 6]);
        assert_eq!(permits[0][1].range, (0x10000, 0x20000));
        // The old permit has high displacement byte 0x0f throughout; it still
        // cannot contain a B1 target retaining the RET head at source+4.
        let mask = TargetPattern {
            entries: [false, false, false, true],
            ..TargetPattern::plain(0x401845)
        };
        assert_eq!(first_target(mask, (0x1000_0000, 0x1001_0000)), None);
    }

    #[test]
    fn upstream_windows_use_original_head_budget_before_qualification() {
        let f = function(NAMES[1], 0x1000, &[0x48, 0x39, 0xc0, 0x75, 0xfb]);
        let s = Selected {
            id: 2,
            function: 0,
            instruction: f.instructions[1],
            block: (0x1000, 0x1005),
        };
        let mut p = policy(derived_policy_text().as_bytes()).unwrap();
        p.search[2] = 1;
        assert!(original_patterns(&f, &s, &p).is_empty());
        p.search[2] = 2;
        let patterns = original_patterns(&f, &s, &p);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].next, 0x1005);
        assert_eq!(patterns[0].entries, [false, false, true, false]);
        p.search[0] = 2;
        assert!(original_patterns(&f, &s, &p).is_empty());
        p.search[0] = 64;
        p.search[1] = 4;
        assert!(original_patterns(&f, &s, &p).is_empty());
    }

    #[test]
    fn complete_jump_cell_keeps_unplaceable_id15_as_neutral_permit() {
        let policy_bytes = derived_policy_text().into_bytes();
        let p = policy(&policy_bytes).unwrap();
        let functions = original_corpus();
        let inv = inventory(&functions, "jump-site").unwrap();
        let bytes = elf_with_load(0x400000, 0x25000);
        let elf = Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: 1,
            },
        )
        .unwrap();
        let s = inv.selected.iter().find(|s| s.id == 15).unwrap();
        assert_eq!(
            (s.instruction.ip(), s.block),
            (0x40186c, (0x40186c, 0x40186e))
        );
        let patterns = original_patterns(&functions[s.function], s, &p);
        assert_eq!(patterns.len(), 1);
        assert_eq!(
            patterns[0].fixed,
            [None, Some(0x66), Some(0x90), Some(0x4c)]
        );
        assert_eq!(
            first_target(patterns[0], (0, 0x8000_0000)),
            Some(1288732273)
        );
        assert_eq!(first_target(patterns[0], p.placement.unwrap().domain), None);
        assert!(pun_pattern(&functions[s.function], s, 1, &p).is_none());
        let permits = original_permits(&elf, &p, &functions, &inv).unwrap();
        let mut prior = Vec::new();
        for pair in &permits {
            for permit in pair {
                assert_eq!(permit.range.1 - permit.range.0, 65536);
                assert!(prior.iter().all(|&r| !overlaps(r, permit.range)));
                prior.push(permit.range);
            }
        }
        for journal in [false, true] {
            let output = selection_with_permits(
                &p,
                &policy_bytes,
                b"target fxsave64\n",
                &functions,
                &inv,
                &permits,
                journal,
            )
            .unwrap();
            let selection = liteinst_rewrite::selection::parse(&output).unwrap();
            assert_eq!(selection.sites.len(), 9);
            assert_eq!(
                selection.sites.iter().map(|s| s.id).collect::<Vec<_>>(),
                [14, 15, 24, 32, 36, 41, 49, 64, 81]
            );
            assert_eq!(selection.sites[1].pc, 0x40186c);
            assert_eq!(selection.sites[1].heads.len(), 45);
            assert_eq!(selection.sites[1].selected_allocation.max_candidates, 65536);
        }
    }

    #[test]
    fn full_page_slot_ownership_and_exhaustion_are_not_byte_only() {
        let pattern = TargetPattern::plain(0x1000);
        assert!(free_permit((0x10000, 0x1f000), &[], pattern, (0, 0x40000), 65536).is_none());
        let blocked = [(0x10000, 0x11000), (0x30000, 0x40000)];
        let permit =
            free_permit((0x10000, 0x40000), &blocked, pattern, (0, 0x40000), 65536).unwrap();
        assert_eq!(permit.range, (0x11000, 0x21000));
        let fixed = TargetPattern {
            fixed: [Some(0xff), Some(0x0f), Some(1), Some(0)],
            ..pattern
        };
        assert_eq!(
            free_permit((0x10000, 0x21000), &[], fixed, (0, 0x40000), 65536)
                .unwrap()
                .preferred,
            0x11fff
        );
        assert!(free_permit((0x10000, 0x20000), &[], fixed, (0, 0x40000), 65536).is_none());
    }

    #[test]
    fn derived_domain_must_own_loads_carrier_and_all_permits() {
        let functions = original_corpus();
        let inv = inventory(&functions, "heap-write").unwrap();
        let mut p = policy(derived_policy_text().as_bytes()).unwrap();
        let bytes = elf_with_load(0x400000, 0x25000);
        let elf = Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: 1,
            },
        )
        .unwrap();
        p.placement = Some(Placement {
            domain: (0x500000, 0x40010000),
        });
        assert!(
            original_permits(&elf, &p, &functions, &inv)
                .unwrap_err()
                .contains("every original LOAD")
        );
        p.placement = Some(Placement {
            domain: (0x10000, 0x20000000),
        });
        assert!(
            original_permits(&elf, &p, &functions, &inv)
                .unwrap_err()
                .contains("carrier")
        );
        p.carrier = 0x425000;
        p.placement = Some(Placement {
            domain: (0x400000, 0x42d000),
        });
        assert!(
            original_permits(&elf, &p, &functions, &inv)
                .unwrap_err()
                .contains("no disjoint")
        );
    }

    fn core_plan(
        f: &Function,
        s: &Selected,
        p: &Policy,
        pair: [Permit; 2],
        forced: Option<li2core::engine::Tactic>,
    ) -> std::result::Result<li2core::emission::ArtifactPlan, li2core::engine::EngineFailure> {
        use li2core::contracts::*;
        use li2core::emission::*;
        use li2core::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
        let range = |r: (u64, u64)| AddressRange::new(r.0, (r.1 - r.0) as usize).unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity(ContentId::of(&f.bytes).0),
            mapping: 1,
            generation: 1,
        };
        let function = AddressRange::new(f.owner.pc, f.bytes.len()).unwrap();
        let entries = LegalEntrySet {
            identity,
            scope: function,
            provenance: EntryProvenance::Declared("complete fixture heads".into()),
            completeness: EntryCompleteness::Complete,
            resumes: ResumeObligation::NoneExist,
            entries: f
                .instructions
                .iter()
                .map(|i| LegalEntry {
                    address: i.ip(),
                    requires_endbr: false,
                })
                .collect(),
        };
        let policies: Vec<_> = pair
            .iter()
            .map(|permit| AllocationPolicy {
                ranges: vec![range(permit.range)],
                preferred_address: Some(permit.preferred),
                max_candidates: 65536,
                max_mappings: 1,
                max_mapped_bytes: 65536,
            })
            .collect();
        let emission = ArtifactEmission::new(
            TargetProfile::linux_x86_64_legacy_evex(
                li2core::trampoline::SavedExtendedStateLayout::describe_target_fxsave64(),
                1,
            )
            .unwrap(),
            SymbolicHook {
                identity: 2,
                address: Some(0x401960),
            },
            vec![range((0x400000, 0x425000)), range((0x20000000, 0x20008000))],
        );
        let request = ArtifactRequest {
            site: PlanningSite {
                identity,
                code: &f.bytes,
                base_address: f.owner.pc,
                function,
                block: range(s.block),
                logical_pc: s.instruction.ip(),
                entries: &entries,
                semantics: li2core::planner::HookSemantics::Observe,
                allocation: &policies[0],
                search: SearchPolicy {
                    tactics: TacticPolicy::PreferGeneralizedPun,
                    max_upstream_bytes: p.search[0] as usize,
                    max_displaced_bytes: p.search[1] as usize,
                    max_sites: p.search[2] as usize,
                },
            },
            emission: &emission,
        };
        li2core::engine::plan_with_emission(
            &request,
            &policies[1],
            li2core::engine::EnginePolicy {
                forced,
                successor_puns: TacticPolicy::PreferGeneralizedPun,
                neighbor: li2core::neighbor::NeighborSearch {
                    forced_victim: None,
                    max_victims: p.search[3] as usize,
                    max_pairs: p.search[4] as usize,
                },
                bundle: li2core::bundle::BundleBudget {
                    max_steps: 2,
                    max_mappings: p.limits[2] as usize,
                    max_virtual_bytes: p.limits[4] * 4096,
                    max_backing_bytes: p.limits[4] * 4096,
                    max_virtual_span: p.limits[8],
                },
            },
        )
    }

    #[test]
    fn unchanged_core_accepts_heap_b1_but_retains_old_arena_and_id15_refusals() {
        use li2core::contracts::{EntryObligation, PlanKind, Refusal};
        use li2core::emission::ArtifactMetrics;
        use li2core::engine::Tactic;
        let p = policy(derived_policy_text().as_bytes()).unwrap();
        let functions = original_corpus();
        let bytes = elf_with_load(0x400000, 0x25000);
        let elf = Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: 1,
            },
        )
        .unwrap();
        let heap = inventory(&functions, "heap-write").unwrap();
        let permits = original_permits(&elf, &p, &functions, &heap).unwrap();
        let plan = core_plan(&functions[0], &heap.selected[0], &p, permits[0], None).unwrap();
        assert!(matches!(
            plan.metrics(),
            ArtifactMetrics::Engine(Tactic::Relocation, _, _)
        ));
        assert_eq!(plan.source_steps().len(), 1);
        let parts = plan.source_steps()[0].parts();
        assert_eq!(parts.kind, PlanKind::Relocation);
        assert_eq!(parts.writes[0].address, 0x401840);
        assert_eq!(parts.writes[0].bytes, [0xe9, 0, 0, 0, 6]);
        assert_eq!(
            parts
                .entries
                .entries
                .iter()
                .map(|e| e.address)
                .collect::<Vec<_>>(),
            [0x401840, 0x401844]
        );
        let ret_route = parts
            .obligations
            .iter()
            .find_map(|o| match o {
                EntryObligation::Routed(route) if route.original == 0x401844 => Some(*route),
                _ => None,
            })
            .expect("complete RET entry must be routed");
        assert!(plan.images().any(|image| {
            image
                .entry_routes()
                .contains(&(ret_route.original, ret_route.generated))
        }));
        let mut second = permits[0];
        second[0] = Permit {
            range: (0x07401000, 0x07411000),
            preferred: 0x07401845,
        };
        let plan = core_plan(
            &functions[0],
            &heap.selected[0],
            &p,
            second,
            Some(Tactic::Relocation),
        )
        .unwrap();
        let ArtifactMetrics::Engine(
            Tactic::Relocation,
            li2core::engine::SelectedMetrics::Single(metrics),
            _,
        ) = plan.metrics()
        else {
            panic!("expected unchanged B1 metric");
        };
        assert_eq!(metrics.allocation_attempts, 2);
        let mut old = permits[0];
        old[0] = Permit {
            range: (0x10000000, 0x10010000),
            preferred: 0x10000000,
        };
        assert_eq!(
            core_plan(
                &functions[0],
                &heap.selected[0],
                &p,
                old,
                Some(Tactic::Relocation)
            )
            .unwrap_err()
            .reason,
            Refusal::AllocationUnavailable
        );
        let jumps = inventory(&functions, "jump-site").unwrap();
        let permits = original_permits(&elf, &p, &functions, &jumps).unwrap();
        let n = jumps.selected.iter().position(|s| s.id == 15).unwrap();
        let failed =
            core_plan(&functions[1], &jumps.selected[n], &p, permits[n], None).unwrap_err();
        assert_eq!(failed.reason, Refusal::NoPatchWindow);
        assert_eq!(failed.attempts.len(), 5);
    }

    #[test]
    fn carrier_low_canonical_endpoint_is_admitted_but_crossing_refuses() {
        let bytes = elf_with_load(0x400000, 4096);
        let elf = Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: 1,
            },
        )
        .unwrap();
        let mut p = policy(policy_text().as_bytes()).unwrap();
        p.limits[7] = 1;
        p.carrier = 0x0000_7fff_ffff_f000;
        assert!(allocation_ranges(&elf, &p, 1).is_ok());
        p.limits[7] = 128;
        assert!(
            allocation_ranges(&elf, &p, 1)
                .unwrap_err()
                .contains("carrier outside low canonical")
        );
        p.limits[7] = 1;
        p.carrier = 0x0000_8000_0000_0000;
        assert!(
            allocation_ranges(&elf, &p, 1)
                .unwrap_err()
                .contains("carrier outside low canonical")
        );
    }
    #[test]
    fn original_load_low_canonical_endpoint_is_admitted_but_crossing_refuses() {
        let p = policy(policy_text().as_bytes()).unwrap();
        let bytes = elf_with_load(0x0000_7fff_ffff_f000, 4096);
        let elf = Elf64::parse(
            &bytes,
            ParseLimits {
                max_program_headers: 1,
            },
        )
        .unwrap();
        assert!(allocation_ranges(&elf, &p, 1).is_ok());
        for (pc, size) in [(0x0000_7fff_ffff_f000, 4097), (0x0000_8000_0000_0000, 4096)] {
            let bytes = elf_with_load(pc, size);
            let elf = Elf64::parse(
                &bytes,
                ParseLimits {
                    max_program_headers: 1,
                },
            )
            .unwrap();
            assert!(
                allocation_ranges(&elf, &p, 1)
                    .unwrap_err()
                    .contains("original LOAD outside low canonical")
            );
        }
    }
    #[test]
    fn strict_policy_keeps_three_ranges_and_all_bounds() {
        let text = policy_text();
        let p = policy(text.as_bytes()).unwrap();
        assert_eq!(
            p.functions
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            NAMES
        );
        assert_eq!(p.arenas[0].candidates, 64);
        for changed in [
            text.replace("LI2COMMON 1", "LI2COMMON 2"),
            text.replace("\nhook 3 ", "\nhook 2 "),
            text.replace("li2_sift_down", "foreign"),
            text.replace("arena selected 65536", "arena selected 65537"),
            text.replace("1048576 64 128", "1048576 1025 128"),
            text.replace("search 64 256 64 256 4096", "search 64 256 64 256 1048577"),
            format!("{text}END\n"),
            text.replace("provenance ", "provenance  "),
        ] {
            assert!(policy(changed.as_bytes()).is_err());
        }
    }
    #[test]
    fn selection_roundtrip_retains_every_head_and_exact_static_sites() {
        let bytes = policy_text().into_bytes();
        let p = policy(&bytes).unwrap();
        let functions = corpus(&[0x75, 1, 0x90, 0xc3]);
        let inv = inventory(&functions, "jump-site").unwrap();
        assert!(inv.errors.is_empty());
        let ranges = [[(65536, 69632), (131072, 135168)]];
        for journal in [false, true] {
            let result = selection(
                &p,
                &bytes,
                b"target fxsave64\n",
                &functions,
                &inv,
                &ranges,
                journal,
            )
            .unwrap();
            let parsed = liteinst_rewrite::selection::parse(&result).unwrap();
            assert_eq!(parsed.sites.len(), 1);
            assert_eq!(
                parsed.sites[0]
                    .heads
                    .iter()
                    .map(|h| h.address)
                    .collect::<Vec<_>>(),
                [0x2000, 0x2002, 0x2003]
            );
            assert_eq!(parsed.sites[0].hook, if journal { 3 } else { 2 });
            assert_eq!(parsed.sites[0].provenance, ContentId::of(&bytes));
        }
        assert!(
            selection(
                &p,
                &bytes,
                b"target fxsave64\ntarget fxsave64\n",
                &functions,
                &inv,
                &ranges,
                false
            )
            .is_err()
        );
    }
    #[test]
    fn rsp_red_zone_and_frame_bounds_are_checked_without_pointer_masks() {
        let make = |displacement, size, segment| {
            UsedMemory::new2(
                segment,
                Register::RSP,
                Register::None,
                1,
                displacement,
                size,
                OpAccess::Write,
                CodeSize::Code64,
                0,
            )
        };
        let inside = make(
            (-128_i64) as u64,
            iced_x86::MemorySize::UInt64,
            Register::SS,
        );
        assert!(stack_owner(&inside, 0));
        assert!(!stack_owner(
            &make(
                (-129_i64) as u64,
                iced_x86::MemorySize::UInt64,
                Register::SS
            ),
            0
        ));
        assert!(!stack_owner(
            &make(0, iced_x86::MemorySize::UInt64, Register::SS),
            0
        ));
        assert!(!stack_owner(
            &make((-8_i64) as u64, iced_x86::MemorySize::UInt64, Register::FS),
            0
        ));
        assert!(!stack_owner(&inside, -STACK_LIMIT));
    }
    #[test]
    fn jump_policy_retains_jumps_but_not_call_ret_or_loop() {
        for bytes in [
            &[0x75, 0][..],
            &[0xe9, 0, 0, 0, 0],
            &[0xe3, 0],
            &[0xff, 0xe0],
        ] {
            assert!(jump(&one(bytes)));
        }
        for bytes in [&[0xe8, 0, 0, 0, 0][..], &[0xc3], &[0xe2, 0], &[0x90]] {
            assert!(!jump(&one(bytes)));
        }
    }
    #[test]
    fn complete_heads_and_single_store_are_not_visit_filtered() {
        let inv = inventory(&corpus(&[0x75, 1, 0x90, 0xc3]), "heap-write").unwrap();
        assert!(inv.errors.is_empty(), "{:?}", inv.errors);
        assert_eq!(inv.heads, 6);
        assert_eq!(inv.selected.len(), 1);
        assert_eq!(inv.selected[0].instruction.ip(), 0x1000);
        assert_eq!(inv.memory.lines().count(), 2);
    }
    #[test]
    fn complete_jump_table_includes_unconditional_and_conditional() {
        let inv = inventory(&corpus(&[0x75, 2, 0xeb, 0, 0xc3]), "jump-site").unwrap();
        assert!(inv.errors.is_empty(), "{:?}", inv.errors);
        assert_eq!(
            inv.selected
                .iter()
                .map(|s| s.instruction.ip())
                .collect::<Vec<_>>(),
            [0x2000, 0x2002]
        );
        assert_eq!(inv.blocks.lines().count(), 6);
    }
    #[test]
    fn explicit_and_implicit_rsp_writes_are_owned() {
        // push rbx; sub rsp,16; mov [rsp+8],rax; call store;
        // add rsp,16; pop rbx; ret. CALL's implicit write is retained.
        let bytes = [
            0x53, 0x48, 0x83, 0xec, 16, 0x48, 0x89, 0x44, 0x24, 8, 0xe8, 0xf1, 0xef, 0xff, 0xff,
            0x48, 0x83, 0xc4, 16, 0x5b, 0xc3,
        ];
        let inv = inventory(&corpus(&bytes), "heap-write").unwrap();
        assert!(inv.errors.is_empty(), "{:?}", inv.errors);
        assert_eq!(
            inv.memory
                .lines()
                .filter(|l| l.ends_with("RSP-frame"))
                .count(),
            3
        );
    }
    #[test]
    fn unknown_writers_stay_visible_and_refuse_full_selection() {
        for bytes in [
            &[0x48, 0x89, 0x07, 0xc3][..],
            &[0x48, 0x89, 0x45, 0xf8, 0xc3],
            &[0x48, 0x89, 0x04, 0x0c, 0xc3],
            &[0xf3, 0x48, 0xab, 0xc3],
        ] {
            let inv = inventory(&corpus(bytes), "heap-write").unwrap();
            assert!(
                inv.errors
                    .iter()
                    .any(|s| s.contains("unproven-memory-writer"))
            );
            assert!(inv.memory.contains("unsupported"));
            assert_eq!(inv.selected.len(), 1);
        }
    }
    #[test]
    fn return_slot_and_unproven_stack_adjustments_refuse() {
        for bytes in [
            &[0x48, 0x89, 0x04, 0x24, 0xc3][..],
            &[0x48, 0x83, 0xe4, 0xf0, 0xc3],
            &[0x5c, 0xc3],
            &[0x53, 0xc3],
        ] {
            assert!(
                !inventory(&corpus(bytes), "heap-write")
                    .unwrap()
                    .errors
                    .is_empty()
            );
        }
    }
    #[test]
    fn inconsistent_join_depth_refuses() {
        let inv = inventory(&corpus(&[0x75, 1, 0x53, 0xc3]), "heap-write").unwrap();
        assert!(
            inv.errors
                .iter()
                .any(|s| s.contains("conflicting RSP depths"))
        );
    }
    #[test]
    fn foreign_middle_indirect_and_recursive_transfers_refuse_without_site_filtering() {
        for bytes in [
            &[0x75, 0x7f, 0xc3][..],
            &[0x75, 1, 0x48, 0x89, 0xc0, 0xc3],
            &[0xff, 0xe0],
            &[0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3],
        ] {
            let inv = inventory(&corpus(bytes), "jump-site").unwrap();
            assert!(!inv.errors.is_empty());
            assert_eq!(inv.selected.len(), usize::from(jump(&one(bytes))));
        }
    }
    #[test]
    fn changed_store_displacement_or_width_never_gets_heap_credit() {
        for bytes in [
            &[0x48, 0x89, 0x54, 0xf7, 8, 0xc3][..],
            &[0x89, 0x14, 0xf7, 0xc3],
            &[0x48, 0x89, 0x14, 0xf7, 0x90, 0xc3],
        ] {
            let mut functions = corpus(&[0xc3]);
            functions[0] = function(NAMES[0], 0x1000, bytes);
            let inv = inventory(&functions, "heap-write").unwrap();
            assert!(
                inv.errors
                    .contains("li2_array_store:exact-MOV-RET-body-required")
            );
            assert!(inv.selected.is_empty());
        }
    }
    #[test]
    fn scanner_rejects_invalid_and_truncated_tail() {
        assert!(decode(&[0x48], 0x1000).is_err());
        assert!(decode(&[0x90, 0x0f], 0x1000).is_err());
    }
}
