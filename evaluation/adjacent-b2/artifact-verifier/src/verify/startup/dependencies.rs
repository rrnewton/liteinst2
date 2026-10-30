//! Hash, storage and static ELF resource joins only. Loader selection, actual
//! relocation, constructor order and runtime protections remain package/native
//! obligations, never inferred from the pathname or hash.
use super::*;
pub(super) fn join(policy: &Policy, inputs: &[Vec<u8>]) -> Result<String> {
    require(
        inputs.len() == policy.runtime.dependencies.len() && (1..=16).contains(&inputs.len()),
        "complete transported dependency roster",
    )?;
    let mut storage = 0usize;
    let mut pages = 0u64;
    let mut roster = String::new();
    for (declared, bytes) in policy.runtime.dependencies.iter().zip(inputs) {
        storage = storage
            .checked_add(bytes.len())
            .ok_or("dependency aggregate overflow")?;
        require(
            bytes.len() <= FILE && storage <= 128 * TEXT,
            "dependency input storage caps",
        )?;
        require(
            ContentId::of(bytes) == declared.identity,
            "dependency independent full-byte identity",
        )?;
        let elf = checked(Elf64::parse(
            bytes,
            ParseLimits {
                max_program_headers: 256,
            },
        ))?;
        require(
            elf.header().object_type == ObjectType::Dynamic,
            "dependency must be ELF64 ET_DYN",
        )?;
        checked(elf.check_load_page_congruence(4096))?;
        let relro: Vec<_> = elf.segments(SegmentType::GnuRelro).collect();
        require(
            relro.len() == 1 && relro[0].memory_size != 0,
            "dependency exact nonempty RELRO roster",
        )?;
        let stacks: Vec<_> = elf.segments(SegmentType::GnuStack).collect();
        require(
            stacks.len() == 1
                && stacks[0].flags.0 == 6
                && stacks[0].file_size == 0
                && stacks[0].memory_size == 0,
            "dependency explicit non-executable stack",
        )?;
        let loads: Vec<_> = elf
            .segments(SegmentType::Load)
            .filter(|p| p.memory_size != 0)
            .collect();
        require(
            !loads.is_empty() && loads.iter().any(|p| p.offset.0 == 0 && p.file_size != 0),
            "dependency file-zero LOAD owner",
        )?;
        let mut occupied: Vec<Range> = Vec::new();
        for p in loads {
            require(
                matches!(p.flags.0, 4..=6),
                "dependency readable non-WX LOAD permissions",
            )?;
            slice(bytes, p.offset.0, p.file_size)?;
            let r = Range::new(p.vaddr.0 & !4095, page(add(p.vaddr.0, p.memory_size)?)?)?;
            require(
                r.end <= 1u64 << 47 && occupied.iter().all(|old| !old.overlaps(r)),
                "dependency exclusive bounded LOAD pages",
            )?;
            pages = add(pages, r.len() / 4096)?;
            require(
                pages <= 65_536,
                "dependency aggregate runtime LOAD page charge",
            )?;
            occupied.push(r);
        }
        let rr = Range::new(
            relro[0].vaddr.0,
            add(relro[0].vaddr.0, relro[0].memory_size)?,
        )?;
        require(
            elf.segments(SegmentType::Load)
                .filter(|p| p.flags.0 == 6)
                .any(|p| {
                    p.vaddr.0 <= rr.start
                        && p.vaddr
                            .0
                            .checked_add(p.memory_size)
                            .is_some_and(|end| rr.end <= end)
                }),
            "dependency RELRO owns RW LOAD bytes",
        )?;
        let path = checked(std::str::from_utf8(&declared.path))?;
        writeln!(&mut roster, "{path}\t{}\t{}", bytes.len(), digest(bytes)).unwrap();
    }
    Ok(digest(roster.as_bytes()))
}
