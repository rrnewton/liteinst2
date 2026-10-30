//! Independent byte layout and original startup-exclusion proof. No carrier
//! writer result, runtime validator, loader or candidate is invoked here.
use super::*;
#[derive(Debug)]
pub(in crate::verify) struct Bytes {
    pub start: u64,
    pub end: u64,
    pub interpreter: Range,
    pub dynamic: Range,
    pub bytes: Vec<u8>,
}
pub(in crate::verify) fn bytes(start: u64, carrier_offset: u64, policy: &Policy) -> Result<Bytes> {
    let interpreter = Range::bytes(start, policy.runtime.interpreter.len() + 1)?;
    let needed = policy.needed()?;
    let mut string_bytes = 1u64;
    let mut offsets = Vec::new();
    for name in &needed {
        offsets.push(string_bytes);
        string_bytes = add(string_bytes, name.len() as u64 + 1)?;
    }
    require(
        string_bytes <= policy.caps[2] && string_bytes - 1 <= policy.caps[1],
        "actual aggregate startup string charge",
    )?;
    let strings = Range::new(interpreter.end, add(interpreter.end, string_bytes)?)?;
    let symbols = Range::new(
        add(strings.end, 7)? & !7,
        add(add(strings.end, 7)? & !7, 24)?,
    )?;
    let hash = Range::new(
        add(symbols.end, 3)? & !3,
        add(add(symbols.end, 3)? & !3, 16)?,
    )?;
    let dynamic = Range::new(
        add(hash.end, 7)? & !7,
        add(add(hash.end, 7)? & !7, policy.mode().dynamic_bytes())?,
    )?;
    require(
        dynamic.end - start <= policy.caps[4],
        "actual startup metadata charge",
    )?;
    let va = |offset: u64| -> Result<u64> {
        add(
            0x480000,
            offset
                .checked_sub(carrier_offset)
                .ok_or("startup before carrier")?,
        )
    };
    let mut out = vec![0; host(dynamic.end - start)?];
    out[..policy.runtime.interpreter.len()].copy_from_slice(&policy.runtime.interpreter);
    for (name, offset) in needed.iter().zip(&offsets) {
        let at = host(add(strings.start - start, *offset)?)?;
        out[at..at + name.len()].copy_from_slice(name);
    }
    let at = host(hash.start - start)?;
    out[at..at + 16].copy_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut records: Vec<(u64, u64)> = offsets.into_iter().map(|offset| (1, offset)).collect();
    records.extend([
        (5, va(strings.start)?),
        (10, strings.len()),
        (6, va(symbols.start)?),
        (11, 24),
        (4, va(hash.start)?),
        (0, 0),
    ]);
    require(
        records.len() as u64 * 16 == dynamic.len(),
        "exact selected startup dynamic grammar",
    )?;
    for (index, (tag, value)) in records.into_iter().enumerate() {
        let at = host(dynamic.start - start)? + index * 16;
        out[at..at + 8].copy_from_slice(&u64::to_le_bytes(tag));
        out[at + 8..at + 16].copy_from_slice(&u64::to_le_bytes(value));
    }
    Ok(Bytes {
        start,
        end: dynamic.end,
        interpreter,
        dynamic,
        bytes: out,
    })
}
fn word(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(checked(
        b.get(at..at + 8).ok_or("section word")?.try_into(),
    )?))
}
fn half(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(checked(
        b.get(at..at + 4).ok_or("section halfword")?.try_into(),
    )?))
}
fn cstring(b: &[u8], offset: u32) -> Result<&[u8]> {
    let tail = b.get(offset as usize..).ok_or("section string offset")?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or("section string terminator")?;
    Ok(&tail[..end])
}
#[derive(Clone)]
struct Section {
    name: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
}
/// Check every original section/symbol and charge original caps independently.
/// Final-main preservation is separately byte-for-byte in candidate::direct.
pub(in crate::verify) fn original_sections(
    original: &[u8],
    policy: &Policy,
    edits: &[carrier::DeclaredEdit],
) -> Result<()> {
    let elf = checked(Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: 128,
        },
    ))?;
    let h = elf.header();
    for ph in elf.program_headers() {
        require(
            matches!(
                ph.kind,
                SegmentType::ProgramHeaders
                    | SegmentType::Load
                    | SegmentType::Note
                    | SegmentType::GnuStack
            ),
            "startup original segment exclusion",
        )?;
    }
    let stacks: Vec<_> = elf.segments(SegmentType::GnuStack).collect();
    require(
        stacks.len() == 1
            && stacks[0].flags.0 == 6
            && stacks[0].file_size == 0
            && stacks[0].memory_size == 0,
        "original exact non-executable stack header",
    )?;
    let stack = Range::new(0x446000, 0x456000)?;
    let storage = checked(elf.virtual_to_storage(ElfVaddr(stack.start), stack.len()))?;
    require(storage.flags.0 == 6, "authored stack unique RW owner")?;
    let Storage::FileBacked(file) = storage.storage else {
        return Err("authored stack must be file-backed".into());
    };
    require(
        slice(original, file.start().0, file.len())?
            .iter()
            .all(|&b| b == 0x5a),
        "authored stack exact 0x5a bytes",
    )?;
    let n = usize::from(h.section_count);
    require(n as u64 <= policy.caps[5], "actual startup section charge")?;
    if n == 0 {
        return require(
            h.section_offset.0 == 0 && h.section_name_index == 0,
            "absent section table canonical coordinates",
        );
    }
    require(
        h.section_entry_size == 64,
        "startup ELF64 section record width",
    )?;
    let bytes = slice(original, h.section_offset.0, n as u64 * 64)?;
    let table = Range::new(h.section_offset.0, add(h.section_offset.0, n as u64 * 64)?)?;
    for e in edits {
        require(
            !table.overlaps(Range::bytes(e.offset.0, e.replacement.len())?),
            "source edits preserve original section table",
        )?;
    }
    require(
        bytes[..64].iter().all(|&b| b == 0),
        "null original section exact",
    )?;
    let mut rows = Vec::new();
    for b in bytes.chunks_exact(64) {
        rows.push(Section {
            name: half(b, 0)?,
            kind: half(b, 4)?,
            flags: word(b, 8)?,
            address: word(b, 16)?,
            offset: word(b, 24)?,
            size: word(b, 32)?,
            link: half(b, 40)?,
            info: half(b, 44)?,
            alignment: word(b, 48)?,
            entry_size: word(b, 56)?,
        });
    }
    let data = |s: &Section| slice(original, s.offset, s.size);
    let mut strings = 0;
    let mut symbols = 0;
    for s in rows.iter().skip(1) {
        require(
            matches!(s.kind, 1 | 2 | 3 | 7 | 8) && s.flags & 0x400 == 0,
            "original has no TLS/dynamic/startup section kind",
        )?;
        require(
            s.alignment <= 1 || s.alignment.is_power_of_two(),
            "section alignment",
        )?;
        add(s.address, s.size)?;
        if s.kind != 8 {
            data(s)?;
            if s.size != 0 && s.flags & 4 == 0 {
                let protected = Range::new(s.offset, add(s.offset, s.size)?)?;
                for e in edits {
                    require(
                        !protected.overlaps(Range::bytes(e.offset.0, e.replacement.len())?),
                        "source edits preserve every non-executable original section",
                    )?;
                }
            }
        }
        if s.flags & 2 != 0 && s.size != 0 {
            let m = checked(elf.virtual_to_storage(ElfVaddr(s.address), s.size))?;
            require(
                (s.flags & 1 == 0 || m.flags.writable())
                    && (s.flags & 4 == 0 || m.flags.executable())
                    && match m.storage {
                        Storage::ZeroFill => s.kind == 8,
                        Storage::FileBacked(r) => s.kind != 8 && r.start().0 == s.offset,
                    },
                "original section unique compatible LOAD owner",
            )?;
        }
        if s.kind == 3 {
            strings = add(strings, s.size)?;
            let b = data(s)?;
            require(
                strings <= policy.caps[7]
                    && b.first() == Some(&0)
                    && b.last() == Some(&0)
                    && s.flags & 4 == 0,
                "actual startup string section charge/envelope",
            )?;
        }
        if s.kind == 2 {
            require(
                s.entry_size == 24 && s.size != 0 && s.size % 24 == 0 && s.flags & 4 == 0,
                "original symbol table shape",
            )?;
            symbols = add(symbols, s.size / 24)?;
            require(symbols <= policy.caps[6], "actual startup symbol charge")?;
        }
    }
    let names = if h.section_name_index == 0 {
        None
    } else {
        let s = rows
            .get(usize::from(h.section_name_index))
            .ok_or("section name owner")?;
        require(s.kind == 3, "section names are strings")?;
        Some(data(s)?)
    };
    for s in rows.iter().skip(1) {
        if let Some(names) = names {
            let name = cstring(names, s.name)?;
            for prefix in [
                b".init".as_slice(),
                b".fini",
                b".preinit_array",
                b".init_array",
                b".fini_array",
                b".ctors",
                b".dtors",
            ] {
                require(
                    name != prefix
                        && !name
                            .strip_prefix(prefix)
                            .is_some_and(|rest| rest.first() == Some(&b'.')),
                    "original startup function/array exclusion",
                )?;
            }
        } else {
            require(s.name == 0, "unnamed original sections")?;
        }
        if s.kind != 2 {
            continue;
        }
        let strings = rows.get(s.link as usize).ok_or("symbol string owner")?;
        require(
            strings.kind == 3 && u64::from(s.info) <= s.size / 24,
            "symbol links",
        )?;
        for (index, symbol) in data(s)?.chunks_exact(24).enumerate() {
            require(
                index != 0 || symbol.iter().all(|&b| b == 0),
                "null symbol exact",
            )?;
            let section = u16::from_le_bytes([symbol[6], symbol[7]]);
            require(
                section != 0xffff
                    && (section >= 0xff00 || usize::from(section) < n)
                    && symbol[4] & 15 != 10,
                "original symbol section and IFUNC exclusion",
            )?;
            let name = cstring(data(strings)?, half(symbol, 0)?)?;
            require(
                ![
                    b"_init".as_slice(),
                    b"_fini",
                    b"__libc_csu_init",
                    b"__libc_csu_fini",
                    b"__preinit_array_start",
                    b"__preinit_array_end",
                    b"__init_array_start",
                    b"__init_array_end",
                    b"__fini_array_start",
                    b"__fini_array_end",
                    b"__CTOR_LIST__",
                    b"__CTOR_END__",
                    b"__DTOR_LIST__",
                    b"__DTOR_END__",
                ]
                .contains(&name),
                "original startup symbol exclusion",
            )?;
        }
    }
    Ok(())
}
