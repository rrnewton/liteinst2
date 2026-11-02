//! One pinned whole-program material bridge, never a loader or native admission.
//!
//! The caller supplies the existing trusted complete-code/no-overlap/no-code-as-
//! data/private-image premise, including the non-code gaps outside SHF_EXECINSTR.
//! ELF flags and an E9 dump do not prove that premise. Every nonempty executable
//! section must be covered without holes; iced, through disassembly::import,
//! independently checks bytes/boundaries and derives all j* sites. No Python or
//! mnemonic display text participates. A READY result is only material output.
#![forbid(unsafe_code)]

use formats::ContentId;
use liteinst_rewrite::carrier::elf64::{Elf64, ElfVaddr, FileOffset, ParseLimits, SegmentType};
use liteinst_rewrite::disassembly;
use std::fmt::Write as _;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

const ORIGINAL_SHA: &str = "890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb";
const FILE_LIMIT: usize = 16 * 1024 * 1024;
const TEXT_LIMIT: usize = 1024 * 1024;
const SECTION_LIMIT: usize = 4096;
const SITE_LIMIT: usize = 1024;
const MESSAGE_LIMIT: usize = 4096;
const CONTEXT: u64 = 127 + 2 + 15;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Legacy,
    Whole4096,
}
impl Profile {
    fn name(self) -> &'static str {
        match self {
            Self::Legacy => "e9patch-full-sections-null-jumps-v1",
            Self::Whole4096 => disassembly::whole::MATERIAL_PROFILE,
        }
    }
}
type Result<T> = std::result::Result<T, String>;

#[path = "full_program_bridge/input.rs"]
mod input;
#[path = "full_program_bridge/policy_cli.rs"]
mod policy_cli;

fn need(condition: bool, reason: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(reason.to_owned())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    hex(&ContentId::of(bytes).0)
}
fn append(out: &mut String, text: &str, limit: usize, kind: &str) -> Result<()> {
    let size = out
        .len()
        .checked_add(text.len())
        .ok_or("text size overflow")?;
    need(
        size <= limit,
        &format!("{kind}: required {size}, limit {limit}"),
    )?;
    out.push_str(text);
    Ok(())
}
fn part(bytes: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let end = offset.checked_add(size).ok_or("file range overflow")?;
    need(end <= bytes.len() as u64, "file range outside original")?;
    Ok(&bytes[offset as usize..end as usize])
}
fn uint(bytes: &[u8], offset: u64, size: u64) -> Result<u64> {
    let mut value = 0;
    for (i, byte) in part(bytes, offset, size)?.iter().enumerate() {
        value |= u64::from(*byte) << (8 * i);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Region {
    section: usize,
    pc: u64,
    offset: u64,
    length: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Head {
    pc: u64,
    offset: u64,
    length: u64,
}

fn regions(original: &[u8]) -> Result<(Vec<Region>, String)> {
    need(original.len() <= FILE_LIMIT, "original exceeds 16 MiB")?;
    let elf = Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: SECTION_LIMIT,
        },
    )
    .map_err(|e| format!("ELF: {e}"))?;
    elf.check_load_page_congruence(4096)
        .map_err(|e| e.to_string())?;
    let table = uint(original, 40, 8)?;
    let width = uint(original, 58, 2)?;
    let count = uint(original, 60, 2)? as usize;
    need(
        table >= 64 && width == 64 && (1..=SECTION_LIMIT).contains(&count),
        "section table shape/extended numbering unsupported",
    )?;
    part(original, table, count as u64 * width)?;
    let mut regions = Vec::new();
    for index in 0..count {
        let at = table + index as u64 * width;
        let flags = uint(original, at + 8, 8)?;
        if flags & 4 == 0 {
            continue;
        }
        let length = uint(original, at + 32, 8)?;
        // No hidden non-allocated/writeable/compressed executable section.
        need(
            flags == 6 && uint(original, at + 4, 4)? == 1,
            "executable section must be allocated nonwrite PROGBITS, flags 6",
        )?;
        if length == 0 {
            continue;
        }
        let pc = uint(original, at + 16, 8)?;
        let offset = uint(original, at + 24, 8)?;
        need(
            pc.checked_add(length)
                .is_some_and(|end| end <= i64::MAX as u64),
            "executable section signed address overflow",
        )?;
        let bytes = part(original, offset, length)?;
        let owned = elf
            .executable_bytes(ElfVaddr(pc), length)
            .map_err(|e| e.to_string())?;
        let inverse = elf
            .file_to_virtual(FileOffset(offset), length)
            .map_err(|e| e.to_string())?;
        need(
            owned == bytes
                && inverse.virtual_range.start().0 == pc
                && inverse.flags.readable()
                && inverse.flags.executable()
                && !inverse.flags.writable(),
            "executable section exact bidirectional RX owner",
        )?;
        regions.push(Region {
            section: index,
            pc,
            offset,
            length,
        });
    }
    regions.sort_by_key(|r| r.pc); // Section table order is not instruction order.
    need(!regions.is_empty(), "no executable sections")?;
    for pair in regions.windows(2) {
        need(
            pair[0].pc + pair[0].length <= pair[1].pc
                && pair[0].offset + pair[0].length <= pair[1].offset,
            "section overlap or nonmonotonic file order",
        )?;
    }
    // Retain every RX LOAD gap instead of silently classifying it as padding.
    // Its no-code interpretation remains part of the caller's explicit premise.
    let mut inventory = String::from("kind\tindex\tpc\tfile_offset\tlength\tsha256\n");
    for r in &regions {
        writeln!(
            inventory,
            "section\t{}\t{}\t{}\t{}\t{}",
            r.section,
            r.pc,
            r.offset,
            r.length,
            sha(part(original, r.offset, r.length)?)
        )
        .unwrap();
    }
    for load in elf
        .segments(SegmentType::Load)
        .filter(|p| p.flags.executable())
    {
        need(
            load.flags.readable() && !load.flags.writable() && load.file_size == load.memory_size,
            "executable LOAD must be read-only and fully file backed",
        )?;
        let end = load.vaddr.0 + load.file_size;
        let mut cursor = load.vaddr.0;
        for r in regions
            .iter()
            .filter(|r| load.vaddr.0 <= r.pc && r.pc < end)
        {
            if cursor < r.pc {
                let off = load.offset.0 + cursor - load.vaddr.0;
                writeln!(
                    inventory,
                    "gap-caller-noncode\t{}\t{cursor}\t{off}\t{}\t{}",
                    load.index,
                    r.pc - cursor,
                    sha(part(original, off, r.pc - cursor)?)
                )
                .unwrap();
            }
            cursor = r.pc + r.length;
        }
        if cursor < end {
            let off = load.offset.0 + cursor - load.vaddr.0;
            writeln!(
                inventory,
                "gap-caller-noncode\t{}\t{cursor}\t{off}\t{}\t{}",
                load.index,
                end - cursor,
                sha(part(original, off, end - cursor)?)
            )
            .unwrap();
        }
    }
    need(
        inventory.len() <= TEXT_LIMIT,
        "region/gap inventory exceeds 1 MiB",
    )?;
    Ok((regions, inventory))
}

fn csv_heads(csv: &[u8]) -> Result<Vec<Head>> {
    need(
        !csv.is_empty() && csv.len() <= TEXT_LIMIT && csv.is_ascii() && csv.ends_with(b"\n"),
        "DISASM CSV ASCII/LF/1 MiB bound",
    )?;
    let text = std::str::from_utf8(csv).map_err(|e| e.to_string())?;
    let mut lines = text.split_terminator('\n');
    need(
        lines.next() == Some("address,offset,size"),
        "exact DISASM CSV header",
    )?;
    let mut heads: Vec<Head> = Vec::new();
    for line in lines {
        need(line.len() <= 96, "CSV row length")?;
        let fields: Vec<_> = line.split(',').collect();
        need(fields.len() == 3, "CSV has exactly three fields")?;
        let pc = u64::from_str_radix(
            fields[0].strip_prefix("0x").ok_or("CSV address prefix")?,
            16,
        )
        .map_err(|_| "CSV address")?;
        let offset: u64 = fields[1]
            .strip_prefix('+')
            .ok_or("CSV signed-positive offset")?
            .parse()
            .map_err(|_| "CSV offset")?;
        let length: u64 = fields[2].parse().map_err(|_| "CSV length")?;
        need(
            line == format!("0x{pc:x},+{offset},{length}"),
            "noncanonical CSV row",
        )?;
        need(
            (1..=15).contains(&length)
                && pc <= i64::MAX as u64 - length
                && offset <= FILE_LIMIT as u64 - length,
            "CSV instruction bounds",
        )?;
        if let Some(previous) = heads.last() {
            need(
                previous.pc + previous.length <= pc && previous.offset + previous.length <= offset,
                "CSV duplicate/overlap/order",
            )?;
        }
        heads.push(Head { pc, offset, length });
    }
    need(!heads.is_empty(), "empty CSV head population")?;
    Ok(heads)
}

fn ledger(original: &[u8], regions: &[Region], heads: &[Head]) -> Result<String> {
    let mut out = format!(
        "LI2DISASM 1\noriginal {}\ncontract complete-code no-overlap no-code-as-data private-image\n",
        sha(original)
    );
    let mut index = 0;
    for r in regions {
        append(
            &mut out,
            &format!("region {} {} {}\n", r.pc, r.offset, r.length),
            TEXT_LIMIT,
            "ledger",
        )?;
        let mut next = r.pc;
        while index < heads.len() && heads[index].pc < r.pc + r.length {
            let h = heads[index];
            need(
                h.pc == next
                    && h.offset == r.offset + next - r.pc
                    && h.pc + h.length <= r.pc + r.length,
                "CSV section coverage/offset",
            )?;
            append(
                &mut out,
                &format!(
                    "head {} {}\n",
                    h.pc,
                    hex(part(original, h.offset, h.length)?)
                ),
                TEXT_LIMIT,
                "ledger",
            )?;
            next += h.length;
            index += 1;
        }
        need(
            next == r.pc + r.length,
            "CSV omits executable section bytes",
        )?;
    }
    need(index == heads.len(), "CSV head outside executable sections")?;
    Ok(out)
}

#[derive(Debug, Eq, PartialEq)]
enum Event {
    Instruction(usize),
    Patch(usize),
}
fn events(heads: &[Head], selected: &[usize]) -> Result<Vec<Event>> {
    events_bounded(heads, selected, SITE_LIMIT, MESSAGE_LIMIT)
}
fn events_whole(heads: &[Head], selected: &[usize]) -> Result<Vec<Event>> {
    need(
        heads.len() <= disassembly::whole::HEAD_LIMIT,
        &format!(
            "head bound: required {}, limit {}",
            heads.len(),
            disassembly::whole::HEAD_LIMIT
        ),
    )?;
    events_bounded(
        heads,
        selected,
        disassembly::whole::SITE_LIMIT,
        disassembly::whole::MESSAGE_LIMIT,
    )
}
fn events_bounded(
    heads: &[Head],
    selected: &[usize],
    site_limit: usize,
    message_limit: usize,
) -> Result<Vec<Event>> {
    need(
        !selected.is_empty() && selected.len() <= site_limit,
        &format!(
            "site bound: required {}, limit {site_limit}",
            selected.len()
        ),
    )?;
    need(
        selected.iter().all(|i| *i < heads.len()) && selected.windows(2).all(|w| w[0] < w[1]),
        "selected head indices/order",
    )?;
    let mut emitted = vec![false; heads.len()];
    let mut events = Vec::new();
    // Same pinned e9tool loop: selected sites descending; backward from the
    // selected head, then forward, one global emitted bit, inclusive ±144 starts.
    for &index in selected.iter().rev() {
        let pc = heads[index].pc;
        for j in (0..=index).rev() {
            if pc - heads[j].pc > CONTEXT {
                break;
            }
            if !emitted[j] {
                events.push(Event::Instruction(j));
                emitted[j] = true;
            }
        }
        for j in index + 1..heads.len() {
            if heads[j].pc - pc > CONTEXT {
                break;
            }
            if !emitted[j] {
                events.push(Event::Instruction(j));
                emitted[j] = true;
            }
        }
        events.push(Event::Patch(index));
    }
    let required = events.len() + 3; // binary, trampoline, emit.
    need(
        required <= message_limit,
        &format!("RPC message bound: required {required}, limit {message_limit}"),
    )?;
    Ok(events)
}
fn integer(value: u64) -> String {
    if value <= i32::MAX as u64 {
        value.to_string()
    } else {
        format!("\"0x{value:x}\"")
    }
}
fn quoted_path(path: &str) -> Result<String> {
    need(
        path.starts_with('/')
            && path.len() <= 4096
            && path.bytes().all(|b| (32..=126).contains(&b)),
        "RPC original path must be bounded absolute printable ASCII",
    )?;
    Ok(format!(
        "\"{}\"",
        path.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
fn rpc(heads: &[Head], selected: &[usize], path: &str) -> Result<Vec<u8>> {
    rpc_profile(heads, selected, path, Profile::Legacy)
}
fn rpc_profile(
    heads: &[Head],
    selected: &[usize],
    path: &str,
    profile: Profile,
) -> Result<Vec<u8>> {
    let path = quoted_path(path)?;
    let events = match profile {
        Profile::Legacy => events(heads, selected)?,
        Profile::Whole4096 => events_whole(heads, selected)?,
    };
    let mut messages = vec![
        ("binary", format!("\"filename\":{path},\"mode\":\"exe\"")),
        (
            "trampoline",
            "\"name\":\"passthru\",\"template\":[\"$instruction\",\"$continue\"]".to_owned(),
        ),
    ];
    for event in events {
        match event {
            Event::Instruction(i) => {
                let h = heads[i];
                messages.push((
                    "instruction",
                    format!(
                        "\"address\":{},\"length\":{},\"offset\":{}",
                        integer(h.pc),
                        h.length,
                        integer(h.offset)
                    ),
                ));
            }
            Event::Patch(i) => messages.push((
                "patch",
                format!(
                    "\"trampoline\":\"passthru\",\"offset\":{}",
                    integer(heads[i].offset)
                ),
            )),
        }
    }
    messages.push((
        "emit",
        "\"filename\":\"a.out\",\"format\":\"binary\",\"mapping_size\":4096".to_owned(),
    ));
    let mut out = String::new();
    for (id, (method, params)) in messages.iter().enumerate() {
        append(
            &mut out,
            &format!(
                "{{\"jsonrpc\":\"2.0\",\"method\":\"{method}\",\"params\":{{{params}}},\"id\":{id}}}\n"
            ),
            FILE_LIMIT,
            "RPC bytes",
        )?;
    }
    Ok(out.into_bytes())
}

struct Materials {
    ledger: Vec<u8>,
    inventory: Vec<u8>,
    regions: Vec<u8>,
    heads: usize,
    sites: usize,
    rpc: Result<Vec<u8>>,
}
fn bridge(original: &[u8], csv: &[u8], path: &str) -> Result<Materials> {
    bridge_profile(original, csv, path, Profile::Legacy)
}
fn bridge_profile(original: &[u8], csv: &[u8], path: &str, profile: Profile) -> Result<Materials> {
    let (regions, region_inventory) = regions(original)?;
    let heads = csv_heads(csv)?;
    let ledger = ledger(original, &regions, &heads)?.into_bytes();
    // This is the existing independently checked decoder/classifier. CSV has
    // no mnemonic column, and there is no new decoder or selective head filter.
    let imported = disassembly::import(original, &ledger, ContentId::of(&ledger))
        .map_err(|e| format!("independent importer: {e}"))?;
    let selected = imported
        .jumps()
        .iter()
        .map(|site| {
            let i = heads
                .binary_search_by_key(&site.pc, |h| h.pc)
                .map_err(|_| "imported site missing head")?;
            need(
                heads[i].offset == site.file_offset && heads[i].length == site.length as u64,
                "imported selected geometry",
            )?;
            Ok(i)
        })
        .collect::<Result<Vec<_>>>()?;
    let inventory = match profile {
        Profile::Legacy => imported.inventory(),
        Profile::Whole4096 => imported.inventory_whole_program(),
    };
    need(
        inventory.len() <= FILE_LIMIT,
        "complete inventory exceeds 16 MiB",
    )?;
    Ok(Materials {
        ledger,
        inventory,
        regions: region_inventory.into_bytes(),
        heads: heads.len(),
        sites: selected.len(),
        rpc: match profile {
            Profile::Legacy => rpc(&heads, &selected, path),
            Profile::Whole4096 => rpc_profile(&heads, &selected, path, profile),
        },
    })
}

#[derive(Debug, Eq, PartialEq)]
struct Stamp(u64, u64, u32, u64, i64, i64, i64, i64);
fn stamp(m: &Metadata) -> Stamp {
    Stamp(
        m.dev(),
        m.ino(),
        m.mode(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read(path: &Path, cap: usize) -> Result<(Vec<u8>, Stamp)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    need(before.is_file(), "input not a regular file")?;
    need(
        before.len() <= cap as u64,
        &format!("input file bound: required {}, limit {cap}", before.len()),
    )?;
    let mut bytes = Vec::new();
    (&file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let held = stamp(&before);
    need(
        bytes.len() as u64 == before.len()
            && held == stamp(&file.metadata().map_err(|e| e.to_string())?)
            && held == stamp(&fs::symlink_metadata(path).map_err(|e| e.to_string())?),
        "input changed during capture",
    )?;
    Ok((bytes, held))
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}
fn arguments(args: &[String]) -> Result<(&[String], Profile)> {
    if args.get(1).is_some_and(|s| s == "--whole-program-4096") {
        need(
            args.len() == 7
                && args[2] == "--trusted-complete-code"
                && !args[2..].iter().any(|s| s == "--whole-program-4096"),
            "full_program_bridge --whole-program-4096 --trusted-complete-code ORIGINAL DISASM.csv CSV_SHA256 NEW_DIRECTORY",
        )?;
        Ok((&args[1..], Profile::Whole4096))
    } else {
        Ok((args, Profile::Legacy))
    }
}
fn run(args: &[String]) -> Result<bool> {
    if args.get(1).is_some_and(|s| s == "--policy-profile") {
        return policy_cli::run(args);
    }
    let explicit = input::arguments(args)?;
    let (args, profile) = match &explicit {
        Some(input) => (input.args.as_slice(), Profile::Whole4096),
        None => arguments(args)?,
    };
    need(
        args.len() == 6 && args[1] == "--trusted-complete-code",
        "full_program_bridge --trusted-complete-code ORIGINAL DISASM.csv CSV_SHA256 NEW_DIRECTORY",
    )?;
    let original_path = Path::new(&args[2]);
    let csv_path = Path::new(&args[3]);
    let original = read(original_path, FILE_LIMIT)?;
    let csv = read(csv_path, TEXT_LIMIT)?;
    if let Some(input) = &explicit {
        input.verify(&original.0)?;
    } else {
        need(
            sha(&original.0) == ORIGINAL_SHA,
            "not the pinned original e9patch",
        )?;
    }
    need(
        args[4].len() == 64
            && args[4]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && sha(&csv.0) == args[4],
        "CSV first pin mismatch",
    )?;
    let resolved = original_path.canonicalize().map_err(|e| e.to_string())?;
    let path = resolved.to_str().ok_or("non-UTF8 original path")?;
    let result = match profile {
        Profile::Legacy => bridge(&original.0, &csv.0, path),
        Profile::Whole4096 => bridge_profile(&original.0, &csv.0, path, profile),
    };
    need(
        read(original_path, FILE_LIMIT)? == original
            && read(&resolved, FILE_LIMIT)? == original
            && read(csv_path, TEXT_LIMIT)? == csv,
        "inputs changed before publication",
    )?;
    let mut files: Vec<(&str, Vec<u8>)> = Vec::new();
    let (ready, counts, refusal) = match result {
        Ok(m) => {
            files.extend([
                ("ledger.txt", m.ledger),
                ("sites.tsv", m.inventory),
                ("regions.tsv", m.regions),
            ]);
            let counts = format!("heads\t{}\nsites\t{}\n", m.heads, m.sites);
            match m.rpc {
                Ok(rpc) => {
                    files.push(("request.jsonl", rpc));
                    (true, counts, None)
                }
                Err(e) => (false, counts, Some(e)),
            }
        }
        Err(e) => (
            false,
            "heads\tunavailable\nsites\tunavailable\n".to_owned(),
            Some(e),
        ),
    };
    if let Some(e) = refusal {
        files.push(("refusal.txt", format!("{e}\n").into_bytes()));
    }
    let mut complete = format!(
        "LI2FULL-PROGRAM-MATERIALS\t1\nprofile\t{}\nstatus\t{}\noriginal_sha256\t{}\ncsv_sha256\t{}\n{counts}complete_code_premise\tcaller_supplied_not_proved\nplanning_attempted\tfalse\nqualification_complete\tfalse\n",
        if explicit.is_some() {
            input::PROFILE
        } else {
            profile.name()
        },
        if ready {
            "MATERIALS_READY"
        } else {
            "MATERIALS_REFUSED"
        },
        explicit
            .as_ref()
            .map_or_else(|| ORIGINAL_SHA.to_owned(), |i| hex(&i.expected.0)),
        args[4]
    );
    for (name, bytes) in &files {
        writeln!(complete, "file\t{name}\t{}\t{}", bytes.len(), sha(bytes)).unwrap();
    }
    let total = files.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() + complete.len();
    need(total <= FILE_LIMIT, "total material output exceeds 16 MiB")?;
    let output = Path::new(&args[5]);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| e.to_string())?;
    for (name, bytes) in files {
        write(&output.join(name), &bytes)?;
    }
    write(&output.join("COMPLETE"), complete.as_bytes())?;
    File::open(output)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!("materials_ready={ready} planning_attempted=false qualification_complete=false");
    Ok(ready)
}
fn main() {
    match run(&std::env::args().collect::<Vec<_>>()) {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
#[path = "full_program_bridge/tests.rs"]
mod tests;
