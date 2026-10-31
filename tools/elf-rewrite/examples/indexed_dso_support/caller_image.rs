//! Separate view of the compiled caller DSO. The subject's required symbols
//! and acceptance rules are unchanged. This supplies bytes, CFG facts and raw
//! original CFI; it does not certify CFI semantics or permit native execution.
#![forbid(unsafe_code)]

use super::super::caller;
use super::*;

const NAMES: [[&str; 7]; 2] = [
    [
        "li2_uw_call_work",
        "li2_uw_caller_work_sample",
        "li2_uw_caller_work_configured",
        "li2_uw_caller_work_canary_before",
        "li2_uw_caller_work_pre",
        "li2_uw_caller_work_post",
        "li2_uw_caller_work_canary_after",
    ],
    [
        "li2_uw_call_reference",
        "li2_uw_caller_reference_sample",
        "li2_uw_caller_reference_configured",
        "li2_uw_caller_reference_canary_before",
        "li2_uw_caller_reference_pre",
        "li2_uw_caller_reference_post",
        "li2_uw_caller_reference_canary_after",
    ],
];

#[derive(Debug)]
pub enum Refusal {
    Elf(Error),
    Caller(caller::Error),
}
impl From<Error> for Refusal {
    fn from(value: Error) -> Self {
        Self::Elf(value)
    }
}

/// Immutable binding for one ordinary C function, not just its target CALL.
pub struct Function {
    symbol: Symbol,
    proof: caller::Proof,
    original_cfi: OriginalArtifactCfi,
}
impl Function {
    pub const fn symbol(&self) -> Symbol {
        self.symbol
    }
    pub const fn proof(&self) -> &caller::Proof {
        &self.proof
    }
    /// Raw original CIE/FDE bytes. Independently establish their complete
    /// recovery semantics before using them to predict any caller frame.
    pub const fn original_cfi(&self) -> &OriginalArtifactCfi {
        &self.original_cfi
    }
}

pub struct CallerImage<'a> {
    bytes: &'a [u8],
    identity: ContentId,
    functions: [Function; 2],
    original_fdes: Vec<(u64, u64, u64)>,
}

/// Owned module coordinate of one independent 64-byte return capture. Runtime
/// writable mappings and no-alias/single-writer custody are still required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawObject {
    pub address: u64,
    pub size: u64,
    pub program_header: usize,
}

impl<'a> CallerImage<'a> {
    pub fn inspect(bytes: &'a [u8]) -> std::result::Result<Self, Refusal> {
        if bytes.len() as u64 > BYTE_LIMIT {
            return Err(Error::Limit("input file bytes").into());
        }
        let elf = parse_elf(bytes)?;
        if elf.header().object_type != ObjectType::Dynamic || elf.header().entry.0 != 0 {
            return Err(Error::Format("ET_DYN with zero entry").into());
        }
        elf.check_load_page_congruence(PAGE).map_err(Error::Elf)?;
        load_ranges(&elf)?;
        let sections = sections(&elf)?;
        let (regular, dynamic) = symbol_tables(bytes, &sections)?;
        dynamic_symbols(&elf, &sections)?;
        let index =
            OriginalIndex::inspect(&elf, IndexLimits::default(), dynamic::Limits::default())
                .map_err(Error::Unwind)?;
        let get = |names: [&'static str; 7]| -> std::result::Result<Function, Refusal> {
            // The fixed build uses -fvisibility=hidden for ordinary caller C.
            // Localized and explicit HIDDEN forms retain their actual linkage.
            let symbol =
                required_symbol(&elf, &sections, &regular, &dynamic, names[0], true, false)?;
            let mut markers = Vec::new();
            for name in &names[1..] {
                markers.push(required_symbol(
                    &elf, &sections, &regular, &dynamic, name, false, false,
                )?);
            }
            let coordinates = coordinates(symbol, &markers)?;
            let code = owned_code(&elf, symbol.address, symbol.size)?;
            let proof =
                caller::prove(code.bytes, symbol.address, coordinates).map_err(Refusal::Caller)?;
            // Return PCs are interpreted by the unwinder at next_ip-1. The
            // checked ordinary CALL has nonzero length and is inside this owner.
            let point = proof.return_pc().checked_sub(1).ok_or(Error::Arithmetic)?;
            let original_cfi = index.source_record(point).map_err(Error::Unwind)?;
            Ok(Function {
                symbol,
                proof,
                original_cfi,
            })
        };
        let functions = [get(NAMES[0])?, get(NAMES[1])?];
        let a = functions[0].symbol;
        let b = functions[1].symbol;
        if a.address < add(b.address, b.size)? && b.address < add(a.address, a.size)? {
            return Err(Error::Symbol("overlapping caller functions").into());
        }
        Ok(Self {
            bytes,
            identity: ContentId::of(bytes),
            functions,
            original_fdes: index.intervals().collect(),
        })
    }
    pub const fn identity(&self) -> ContentId {
        self.identity
    }
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn named_function(&self, name: &'static str) -> std::result::Result<Symbol, Refusal> {
        let input = parse_elf(self.bytes)?;
        let sections = sections(&input)?;
        let (regular, dynamic) = symbol_tables(self.bytes, &sections)?;
        Ok(required_symbol(
            &input, &sections, &regular, &dynamic, name, true, false,
        )?)
    }
    pub const fn work(&self) -> &Function {
        &self.functions[0]
    }
    pub const fn reference(&self) -> &Function {
        &self.functions[1]
    }
    pub fn original_fdes(&self) -> &[(u64, u64, u64)] {
        &self.original_fdes
    }

    /// This additional gate deliberately refuses the historical caller which
    /// only exported observations through an RSP-relative pointer reload.
    /// Ordinary structural inspection of that earlier file remains unchanged.
    pub fn raw_return(&self, reference: bool) -> std::result::Result<RawObject, Refusal> {
        let name = if reference {
            "li2_uw_reference_raw"
        } else {
            "li2_uw_work_raw"
        };
        let input = parse_elf(self.bytes)?;
        let sections = sections(&input)?;
        let (regular, dynamic) = symbol_tables(self.bytes, &sections)?;
        let mut matches = regular.iter().filter(|s| s.name == name.as_bytes());
        let symbol = matches.next().ok_or(Error::Missing(name))?;
        if matches.next().is_some() {
            return Err(Error::Duplicate(name).into());
        }
        let section = sections.get(symbol.section).ok_or(Error::Symbol(name))?;
        if symbol.kind != 1
            || symbol.size != 64
            || symbol.address % 8 != 0
            || section.kind != 1
            || section.flags != 3
            || symbol.address < section.address
            || symbol.address.checked_add(symbol.size).is_none_or(|end| {
                section
                    .address
                    .checked_add(section.size)
                    .is_none_or(|limit| end > limit)
            })
            || !((symbol.binding == 0 && symbol.visibility == 0)
                || (symbol.binding <= 1 && symbol.visibility == 2))
            || dynamic.iter().any(|s| s.name == name.as_bytes())
        {
            return Err(Error::Symbol(name).into());
        }
        let owner = input
            .virtual_to_storage(ElfVaddr(symbol.address), symbol.size)
            .map_err(Error::Elf)?;
        let Storage::FileBacked(file) = owner.storage else {
            return Err(Error::Ownership.into());
        };
        let reverse = input
            .file_to_virtual(file.start(), file.len())
            .map_err(Error::Elf)?;
        if owner.flags.0 != 6
            || reverse.program_header != owner.program_header
            || reverse.virtual_range.start() != ElfVaddr(symbol.address)
            || file.start().0
                != section
                    .offset
                    .checked_add(symbol.address - section.address)
                    .ok_or(Error::Ownership)?
        {
            return Err(Error::Ownership.into());
        }
        Ok(RawObject {
            address: symbol.address,
            size: symbol.size,
            program_header: owner.program_header,
        })
    }

    pub const fn qualification_complete(&self) -> bool {
        false
    }
}

fn coordinates(symbol: Symbol, markers: &[Symbol]) -> Result<caller::Labels> {
    if markers.len() != 6 || symbol.size == 0 {
        return Err(Error::Symbol("caller markers"));
    }
    let end = add(symbol.address, symbol.size)?;
    for (i, marker) in markers.iter().enumerate() {
        if marker.section != symbol.section
            || marker.size != 0
            || marker.address < symbol.address
            || marker.address >= end
            || markers[..i].iter().any(|old| old.address == marker.address)
        {
            return Err(Error::Symbol("caller marker extent/identity"));
        }
    }
    Ok(caller::Labels {
        sample: markers[0].address,
        configured: markers[1].address,
        canary_before: markers[2].address,
        pre: markers[3].address,
        post: markers[4].address,
        canary_after: markers[5].address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_coordinates_refuse_another_function_section_alias_and_end_marker() {
        let function = Symbol {
            name: NAMES[0][0],
            address: 0x1000,
            size: 0x100,
            section: 3,
            binding: 0,
            visibility: 0,
            linkage: Linkage::Localized,
        };
        let markers: Vec<_> = (0..6)
            .map(|i| Symbol {
                name: NAMES[0][i + 1],
                address: 0x1010 + i as u64 * 8,
                size: 0,
                ..function
            })
            .collect();
        let labels = coordinates(function, &markers).unwrap();
        assert_eq!(labels.sample, 0x1010);
        assert_eq!(labels.canary_after, 0x1038);
        for i in 0..6 {
            for (address, section, size) in [
                (0xfff, 3, 0),
                (0x1100, 3, 0),
                (markers[i].address, 4, 0),
                (markers[i].address, 3, 1),
                (markers[(i + 1) % 6].address, 3, 0),
            ] {
                let mut bad = markers.clone();
                bad[i].address = address;
                bad[i].section = section;
                bad[i].size = size;
                assert!(matches!(
                    coordinates(function, &bad),
                    Err(Error::Symbol("caller marker extent/identity"))
                ));
            }
        }
    }
}
