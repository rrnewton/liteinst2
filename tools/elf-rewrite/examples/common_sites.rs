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
    check(lines.row("LI2COMMON", 2)?[1] == "1", "policy version")?;
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
    let mut arenas = Vec::new();
    for kind in ["selected", "victim"] {
        let r = lines.row("arena", 6)?;
        check(r[1] == kind, "arena order")?;
        let a = Arena {
            base: number(r[2])?,
            stride: number(r[3])?,
            bytes: number(r[4])?,
            candidates: number(r[5])?,
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
fn selection(
    p: &Policy,
    policy_bytes: &[u8],
    target: &[u8],
    functions: &[Function],
    inv: &Inventory,
    ranges: &[[(u64, u64); 2]],
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
            let (a, b) = permits[k];
            writeln!(
                out,
                "allocation {} {kind} {a} {} {} {a}:{}",
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
    let ranges = allocation_ranges(&elf, &p, inv.selected.len());
    let mut chosen = None;
    match ranges {
        Ok(ranges) if inv.errors.is_empty() => match selection(
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
