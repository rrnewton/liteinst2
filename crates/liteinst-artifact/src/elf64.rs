//! Private A3 foundation: checked ELF64 metadata and byte ownership, not a loader.
//!
//! This module has no dependencies and does not use native struct casts. It does
//! not decode instructions, enumerate entries, interpret dynamic relocations,
//! certify bootstrap readiness, or create/rewrite an executable artifact.

use std::fmt;

const ELF_HEADER_SIZE: u64 = 64;
const PROGRAM_HEADER_SIZE: u64 = 56;
const PN_XNUM: u16 = 0xffff;

/// An offset in the original immutable file, never a process pointer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileOffset(#[doc = "Unsigned byte offset from the start of the file."] pub u64);

/// An ELF virtual address before any runtime load bias is applied.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ElfVaddr(#[doc = "Unsigned original ELF virtual address, without load bias."] pub u64);

/// A checked half-open file interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRange {
    start: FileOffset,
    end: FileOffset,
}

impl FileRange {
    /// Check addition without implying that the interval exists in any file.
    pub fn checked(start: FileOffset, length: u64) -> Result<Self, Error> {
        let end = checked_end(AddressDomain::File, start.0, length)?;
        Ok(Self {
            start,
            end: FileOffset(end),
        })
    }

    /// Inclusive start.
    pub fn start(self) -> FileOffset {
        self.start
    }
    /// Exclusive end.
    pub fn end(self) -> FileOffset {
        self.end
    }
    /// Number of bytes.
    pub fn len(self) -> u64 {
        self.end.0 - self.start.0
    }
    /// Whether the interval has no bytes.
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// A checked half-open interval in ELF virtual-address space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualRange {
    start: ElfVaddr,
    end: ElfVaddr,
}

impl VirtualRange {
    /// Check addition without implying load ownership or canonical runtime addresses.
    pub fn checked(start: ElfVaddr, length: u64) -> Result<Self, Error> {
        let end = checked_end(AddressDomain::Virtual, start.0, length)?;
        Ok(Self {
            start,
            end: ElfVaddr(end),
        })
    }

    /// Inclusive start.
    pub fn start(self) -> ElfVaddr {
        self.start
    }
    /// Exclusive end.
    pub fn end(self) -> ElfVaddr {
        self.end
    }
    /// Number of bytes.
    pub fn len(self) -> u64 {
        self.end.0 - self.start.0
    }
    /// Whether the interval has no bytes.
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// The address domain of a failed checked addition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressDomain {
    /// Original file offsets.
    File,
    /// Original ELF virtual addresses.
    Virtual,
}

/// ELF64 object kinds supported by this metadata reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectType {
    /// ET_EXEC, numeric value two.
    Executable,
    /// ET_DYN, numeric value three, including PIE and shared objects.
    Dynamic,
}

/// Header fields used in structured errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderField {
    /// The four ELF magic bytes, viewed as a little-endian integer.
    Magic,
    /// EI_CLASS.
    Class,
    /// EI_DATA.
    ByteOrder,
    /// EI_VERSION.
    IdentVersion,
    /// e_type.
    ObjectType,
    /// e_machine.
    Machine,
    /// e_version.
    Version,
    /// e_ehsize.
    HeaderSize,
    /// e_phentsize.
    ProgramHeaderSize,
    /// e_phnum.
    ProgramHeaderCount,
    /// e_phoff.
    ProgramHeaderOffset,
}

/// Which file structure failed a bounds check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRegion {
    /// The fixed 64-byte ELF header.
    Header,
    /// The complete program-header table.
    ProgramHeaderTable,
    /// A nonempty segment file image, identified by original program-header index.
    Segment(#[doc = "Original program-header index."] usize),
}

/// Typed refusals preserve the difference between malformed data and local limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A nonempty structure extends beyond the immutable file.
    Truncated {
        /// Original structure whose bytes are required.
        region: FileRegion,
        /// Requested or declared byte interval.
        range: FileRange,
        /// Actual immutable input length.
        file_len: u64,
    },
    /// An address interval cannot be represented without unsigned overflow.
    Overflow {
        /// Address space in which the addition overflowed.
        domain: AddressDomain,
        /// Original interval start.
        start: u64,
        /// Requested interval length.
        length: u64,
    },
    /// The reader deliberately does not implement this format variation.
    Unsupported {
        /// Header field whose format variation is unsupported.
        field: HeaderField,
        /// Original field value.
        value: u64,
    },
    /// A required fixed header value is inconsistent.
    InvalidHeader {
        /// Header field being checked.
        field: HeaderField,
        /// Original field value.
        value: u64,
        /// Required fixed field value.
        required: u64,
    },
    /// A nonempty program-header table overlaps the ELF header itself.
    ProgramTableOverlapsHeader {
        /// Original e_phoff.
        offset: FileOffset,
    },
    /// A caller-selected allocation limit was reached; this is not malformed ELF.
    ProgramHeaderLimit {
        /// Number of records declared by the input.
        required: usize,
        /// Caller-supplied maximum record count.
        limit: usize,
    },
    /// A meaningful program header has a non-power-of-two alignment greater than one.
    InvalidAlignment {
        /// Original program-header index.
        index: usize,
        /// Original p_align.
        alignment: u64,
    },
    /// A load segment's file and virtual offsets do not have the required residue.
    IncongruentLoad {
        /// Original program-header index.
        index: usize,
        /// Original p_offset.
        offset: FileOffset,
        /// Original p_vaddr.
        vaddr: ElfVaddr,
        /// Original p_align.
        alignment: u64,
    },
    /// An explicit target-page check requires a nonzero power-of-two page size.
    InvalidPageSize {
        /// Caller-supplied target page size.
        page_size: u64,
    },
    /// A load's offsets disagree modulo the caller-supplied target page size.
    IncongruentLoadPage {
        /// Original program-header index.
        index: usize,
        /// Original p_offset.
        offset: FileOffset,
        /// Original p_vaddr.
        vaddr: ElfVaddr,
        /// Caller-supplied target page size.
        page_size: u64,
    },
    /// A load or TLS initialization image exceeds its memory extent.
    FileSizeExceedsMemory {
        /// Original program-header index.
        index: usize,
        /// Original p_filesz.
        file_size: u64,
        /// Original p_memsz.
        memory_size: u64,
    },
    /// PT_LOAD records are not in ascending virtual-address order.
    InvalidLoadOrder {
        /// Earlier original PT_LOAD index, with a greater virtual start.
        before: usize,
        /// Later original PT_LOAD index, with a smaller virtual start.
        after: usize,
    },
    /// Translation of an empty interval would have ambiguous endpoint semantics.
    EmptyRange,
    /// No PT_LOAD memory extent intersects the requested virtual interval.
    UnmappedVirtual {
        /// Requested virtual interval.
        range: VirtualRange,
    },
    /// At least two PT_LOAD memory extents own a requested byte.
    AmbiguousVirtual {
        /// Requested or declared byte interval.
        range: VirtualRange,
        /// All intersecting PT_LOAD indexes in original table order.
        owners: Vec<usize>,
    },
    /// The requested interval is not wholly inside one load's memory extent.
    CrossesLoadBoundary {
        /// Requested or declared byte interval.
        range: VirtualRange,
        /// All intersecting PT_LOAD indexes in original table order.
        owners: Vec<usize>,
    },
    /// The request straddles one load's file-backed/zero-fill boundary.
    CrossesFileZeroBoundary {
        /// Original program-header index.
        index: usize,
        /// Requested or declared byte interval.
        range: VirtualRange,
        /// First zero-filled virtual address of the unique owner.
        boundary: ElfVaddr,
    },
    /// Unique ownership exists, but the containing load does not have PF_X.
    NotExecutable {
        /// Original program-header index.
        index: usize,
    },
    /// A request for original file bytes refers to zero-filled memory.
    NotFileBacked {
        /// Original program-header index.
        index: usize,
        /// Requested virtual interval.
        range: VirtualRange,
    },
    /// No nonempty PT_LOAD file image intersects the requested file interval.
    UnmappedFile {
        /// Requested file interval.
        range: FileRange,
    },
    /// Multiple load images contain at least one requested file byte.
    AmbiguousFile {
        /// Requested or declared byte interval.
        range: FileRange,
        /// All intersecting PT_LOAD indexes in original table order.
        owners: Vec<usize>,
    },
    /// The requested file interval does not fit wholly in one load image.
    CrossesFileLoadBoundary {
        /// Requested or declared byte interval.
        range: FileRange,
        /// All intersecting PT_LOAD indexes in original table order.
        owners: Vec<usize>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ELF64 metadata/ownership refusal: {self:?}")
    }
}

impl std::error::Error for Error {}

/// Resource policy, separate from structural ELF validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    /// Bound the allocation and inventory work before reading individual records.
    pub max_program_headers: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_program_headers: 1024,
        }
    }
}

/// Variable ELF header fields, including opaque section metadata; fixed values were validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// The complete original e_ident; OSABI, ABI version and padding are preserved.
    pub ident: [u8; 16],
    /// ET_EXEC or ET_DYN.
    pub object_type: ObjectType,
    /// Original e_entry, including zero for DSOs.
    pub entry: ElfVaddr,
    /// Original e_phoff.
    pub program_offset: FileOffset,
    /// Original e_phnum; PN_XNUM is explicitly unsupported.
    pub program_count: u16,
    /// Original e_phentsize.
    pub program_entry_size: u16,
    /// Original e_shoff, retained without section-table interpretation/validation.
    pub section_offset: FileOffset,
    /// Original e_shentsize, retained without section-table interpretation/validation.
    pub section_entry_size: u16,
    /// Original e_shnum, retained without resolving extended section counts.
    pub section_count: u16,
    /// Original e_shstrndx, retained without resolving extended section indexes.
    pub section_name_index: u16,
    /// Original e_flags; architecture/loader qualification is a separate layer.
    pub flags: u32,
}

/// Program-header types needed by later loader-layout/relocation qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentType {
    /// PT_NULL: unused fields are opaque.
    Null,
    /// PT_LOAD: an original load image.
    Load,
    /// PT_DYNAMIC: dynamic-table inventory only.
    Dynamic,
    /// PT_INTERP: interpreter-path payload inventory only.
    Interpreter,
    /// PT_NOTE: note payload inventory only.
    Note,
    /// PT_PHDR: program-header mapping inventory only.
    ProgramHeaders,
    /// PT_TLS: thread-local initialization and zero-fill inventory.
    Tls,
    /// PT_GNU_STACK: stack-permission inventory only.
    GnuStack,
    /// PT_GNU_RELRO: protection-range inventory only.
    GnuRelro,
    /// PT_GNU_PROPERTY: property payload inventory without CET qualification.
    GnuProperty,
    /// Unknown types remain visible in their original order.
    Other(#[doc = "Original p_type value."] u32),
}

impl SegmentType {
    fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Null,
            1 => Self::Load,
            2 => Self::Dynamic,
            3 => Self::Interpreter,
            4 => Self::Note,
            6 => Self::ProgramHeaders,
            7 => Self::Tls,
            0x6474_e551 => Self::GnuStack,
            0x6474_e552 => Self::GnuRelro,
            0x6474_e553 => Self::GnuProperty,
            value => Self::Other(value),
        }
    }
}

/// Original p_flags bits; unknown bits are preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentFlags(#[doc = "Original p_flags bit pattern."] pub u32);

impl SegmentFlags {
    /// PF_X is set.
    pub fn executable(self) -> bool {
        self.0 & 1 != 0
    }
    /// PF_W is set.
    pub fn writable(self) -> bool {
        self.0 & 2 != 0
    }
    /// PF_R is set.
    pub fn readable(self) -> bool {
        self.0 & 4 != 0
    }
}

/// One original record. PT_NULL's unused fields remain opaque and unvalidated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramHeader {
    /// Index in the original table; records are never reordered.
    pub index: usize,
    /// Interpreted type, preserving unknown numeric values.
    pub kind: SegmentType,
    /// Original p_type.
    pub raw_type: u32,
    /// Original p_flags.
    pub flags: SegmentFlags,
    /// Original p_offset; empty file images need not anchor within the file.
    pub offset: FileOffset,
    /// Original p_vaddr, before runtime load bias.
    pub vaddr: ElfVaddr,
    /// Original p_paddr; no physical-address semantics are inferred.
    pub physical_address: u64,
    /// Original p_filesz.
    pub file_size: u64,
    /// Original p_memsz.
    pub memory_size: u64,
    /// Original p_align; zero/one mean no alignment requirement.
    pub alignment: u64,
}

impl ProgramHeader {
    /// Compute the raw file interval, including an empty anchor for zero-size images.
    pub fn file_range(&self) -> Result<FileRange, Error> {
        FileRange::checked(self.offset, self.file_size)
    }

    /// Compute the raw memory interval; PT_NULL fields may be meaningless/overflowing.
    pub fn memory_range(&self) -> Result<VirtualRange, Error> {
        VirtualRange::checked(self.vaddr, self.memory_size)
    }
}

/// Storage classification for a uniquely owned virtual interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Storage {
    /// Original file bytes exist for the entire interval.
    FileBacked(#[doc = "Corresponding checked original file interval."] FileRange),
    /// The whole interval belongs to the load's zero-filled tail.
    ZeroFill,
}

/// A unique byte-level mapping; it makes no assertion about page-sharing or entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualMapping {
    /// Original owning program-header index.
    pub program_header: usize,
    /// Requested un-biased virtual interval.
    pub virtual_range: VirtualRange,
    /// Original load flags.
    pub flags: SegmentFlags,
    /// File-backed or zero-filled storage.
    pub storage: Storage,
}

/// A uniquely invertible file interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMapping {
    /// Original owning program-header index.
    pub program_header: usize,
    /// Requested file interval.
    pub file_range: FileRange,
    /// Corresponding un-biased virtual interval.
    pub virtual_range: VirtualRange,
    /// Original load flags.
    pub flags: SegmentFlags,
}

/// Borrowed immutable input with checked headers and explicit ownership queries.
#[derive(Clone, Debug)]
pub struct Elf64<'a> {
    bytes: &'a [u8],
    header: Header,
    program_headers: Vec<ProgramHeader>,
}

impl<'a> Elf64<'a> {
    /// Parse ELF64 little-endian x86-64 metadata within the caller's count budget.
    pub fn parse(bytes: &'a [u8], limits: ParseLimits) -> Result<Self, Error> {
        require_file_range(
            bytes,
            FileRange::checked(FileOffset(0), ELF_HEADER_SIZE)?,
            FileRegion::Header,
        )?;
        let magic = read_u32(bytes, 0);
        fixed(HeaderField::Magic, u64::from(magic), 0x464c_457f)?;
        supported(HeaderField::Class, u64::from(bytes[4]), 2)?;
        supported(HeaderField::ByteOrder, u64::from(bytes[5]), 1)?;
        fixed(HeaderField::IdentVersion, u64::from(bytes[6]), 1)?;
        let object_type = match read_u16(bytes, 16) {
            2 => ObjectType::Executable,
            3 => ObjectType::Dynamic,
            value => {
                return Err(Error::Unsupported {
                    field: HeaderField::ObjectType,
                    value: u64::from(value),
                });
            }
        };
        supported(HeaderField::Machine, u64::from(read_u16(bytes, 18)), 62)?;
        fixed(HeaderField::Version, u64::from(read_u32(bytes, 20)), 1)?;
        fixed(
            HeaderField::HeaderSize,
            u64::from(read_u16(bytes, 52)),
            ELF_HEADER_SIZE,
        )?;
        let program_count = read_u16(bytes, 56);
        if program_count == PN_XNUM {
            return Err(Error::Unsupported {
                field: HeaderField::ProgramHeaderCount,
                value: u64::from(program_count),
            });
        }
        let program_offset = FileOffset(read_u64(bytes, 32));
        let program_entry_size = read_u16(bytes, 54);
        if program_count == 0 {
            fixed(HeaderField::ProgramHeaderOffset, program_offset.0, 0)?;
            if program_entry_size != 0 && u64::from(program_entry_size) != PROGRAM_HEADER_SIZE {
                return Err(Error::InvalidHeader {
                    field: HeaderField::ProgramHeaderSize,
                    value: u64::from(program_entry_size),
                    required: PROGRAM_HEADER_SIZE,
                });
            }
        } else {
            fixed(
                HeaderField::ProgramHeaderSize,
                u64::from(program_entry_size),
                PROGRAM_HEADER_SIZE,
            )?;
            if program_offset.0 < ELF_HEADER_SIZE {
                return Err(Error::ProgramTableOverlapsHeader {
                    offset: program_offset,
                });
            }
        }
        let count = usize::from(program_count);
        if count > limits.max_program_headers {
            return Err(Error::ProgramHeaderLimit {
                required: count,
                limit: limits.max_program_headers,
            });
        }
        // u16 * the fixed 56-byte entry size is representable in u64. The table
        // offset addition below is still checked before any usize conversion.
        let table = FileRange::checked(
            program_offset,
            u64::from(program_count) * PROGRAM_HEADER_SIZE,
        )?;
        require_file_range(bytes, table, FileRegion::ProgramHeaderTable)?;
        let mut ident = [0; 16];
        ident.copy_from_slice(&bytes[..16]);
        let header = Header {
            ident,
            object_type,
            entry: ElfVaddr(read_u64(bytes, 24)),
            program_offset,
            program_count,
            program_entry_size,
            section_offset: FileOffset(read_u64(bytes, 40)),
            section_entry_size: read_u16(bytes, 58),
            section_count: read_u16(bytes, 60),
            section_name_index: read_u16(bytes, 62),
            flags: read_u32(bytes, 48),
        };
        let mut program_headers: Vec<ProgramHeader> = Vec::with_capacity(count);
        let mut previous_load: Option<usize> = None;
        for index in 0..count {
            // The whole table is bounded by bytes.len(), so both conversions
            // and each fixed-size read below are within the original slice.
            let base = table.start.0 as usize + index * PROGRAM_HEADER_SIZE as usize;
            let raw_type = read_u32(bytes, base);
            let item = ProgramHeader {
                index,
                kind: SegmentType::from_raw(raw_type),
                raw_type,
                flags: SegmentFlags(read_u32(bytes, base + 4)),
                offset: FileOffset(read_u64(bytes, base + 8)),
                vaddr: ElfVaddr(read_u64(bytes, base + 16)),
                physical_address: read_u64(bytes, base + 24),
                file_size: read_u64(bytes, base + 32),
                memory_size: read_u64(bytes, base + 40),
                alignment: read_u64(bytes, base + 48),
            };
            if item.kind != SegmentType::Null {
                if item.alignment > 1 && !item.alignment.is_power_of_two() {
                    return Err(Error::InvalidAlignment {
                        index,
                        alignment: item.alignment,
                    });
                }
                require_file_range(bytes, item.file_range()?, FileRegion::Segment(index))?;
                item.memory_range()?;
                if matches!(item.kind, SegmentType::Load | SegmentType::Tls)
                    && item.file_size > item.memory_size
                {
                    return Err(Error::FileSizeExceedsMemory {
                        index,
                        file_size: item.file_size,
                        memory_size: item.memory_size,
                    });
                }
                if item.kind == SegmentType::Load {
                    if item.alignment > 1
                        && item.offset.0 % item.alignment != item.vaddr.0 % item.alignment
                    {
                        return Err(Error::IncongruentLoad {
                            index,
                            offset: item.offset,
                            vaddr: item.vaddr,
                            alignment: item.alignment,
                        });
                    }
                    if let Some(before) = previous_load {
                        if program_headers[before].vaddr > item.vaddr {
                            return Err(Error::InvalidLoadOrder {
                                before,
                                after: index,
                            });
                        }
                    }
                    previous_load = Some(index);
                }
            }
            program_headers.push(item);
        }
        Ok(Self {
            bytes,
            header,
            program_headers,
        })
    }

    /// Original immutable file bytes; parsing never modifies them.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Original checked header.
    pub fn header(&self) -> &Header {
        &self.header
    }
    /// Every original program-header record, preserving order and index.
    pub fn program_headers(&self) -> &[ProgramHeader] {
        &self.program_headers
    }
    /// Enumerate one segment type without asserting uniqueness or loader readiness.
    pub fn segments(&self, kind: SegmentType) -> impl Iterator<Item = &ProgramHeader> {
        self.program_headers
            .iter()
            .filter(move |item| item.kind == kind)
    }

    /// Check the independent target-page congruence rule, including loads whose
    /// p_align is zero/one. The caller supplies an authenticated target page size;
    /// this does not qualify page-rounded overlap, permissions, or loader readiness.
    pub fn check_load_page_congruence(&self, page_size: u64) -> Result<(), Error> {
        if !page_size.is_power_of_two() {
            return Err(Error::InvalidPageSize { page_size });
        }
        for item in self.segments(SegmentType::Load) {
            if item.offset.0 % page_size != item.vaddr.0 % page_size {
                return Err(Error::IncongruentLoadPage {
                    index: item.index,
                    offset: item.offset,
                    vaddr: item.vaddr,
                    page_size,
                });
            }
        }
        Ok(())
    }

    /// Translate a nonempty interval only when one load owns every requested byte.
    /// All load permissions participate in ambiguity checks, including non-PF_X.
    pub fn virtual_to_storage(
        &self,
        start: ElfVaddr,
        length: u64,
    ) -> Result<VirtualMapping, Error> {
        let range = VirtualRange::checked(start, length)?;
        if range.is_empty() {
            return Err(Error::EmptyRange);
        }
        let owners: Vec<_> = self
            .segments(SegmentType::Load)
            .filter(|item| {
                intersects(
                    start.0,
                    range.end.0,
                    item.vaddr.0,
                    item.vaddr.0 + item.memory_size,
                )
            })
            .collect();
        let indices = || owners.iter().map(|item| item.index).collect();
        if owners.is_empty() {
            return Err(Error::UnmappedVirtual { range });
        }
        if overlapping_intersections(&owners, start.0, range.end.0, false) {
            return Err(Error::AmbiguousVirtual {
                range,
                owners: indices(),
            });
        }
        if owners.len() != 1
            || start.0 < owners[0].vaddr.0
            || range.end.0 > owners[0].vaddr.0 + owners[0].memory_size
        {
            return Err(Error::CrossesLoadBoundary {
                range,
                owners: indices(),
            });
        }
        let item = owners[0];
        let boundary = item.vaddr.0 + item.file_size;
        let storage = if range.end.0 <= boundary {
            Storage::FileBacked(FileRange::checked(
                FileOffset(item.offset.0 + (start.0 - item.vaddr.0)),
                length,
            )?)
        } else if start.0 >= boundary {
            Storage::ZeroFill
        } else {
            return Err(Error::CrossesFileZeroBoundary {
                index: item.index,
                range,
                boundary: ElfVaddr(boundary),
            });
        };
        Ok(VirtualMapping {
            program_header: item.index,
            virtual_range: range,
            flags: item.flags,
            storage,
        })
    }

    /// Return exact original executable file bytes, refusing BSS, ambiguity or crossings.
    pub fn executable_bytes(&self, start: ElfVaddr, length: u64) -> Result<&'a [u8], Error> {
        let mapping = self.virtual_to_storage(start, length)?;
        if !mapping.flags.executable() {
            return Err(Error::NotExecutable {
                index: mapping.program_header,
            });
        }
        match mapping.storage {
            Storage::FileBacked(range) => {
                Ok(&self.bytes[range.start.0 as usize..range.end.0 as usize])
            }
            Storage::ZeroFill => Err(Error::NotFileBacked {
                index: mapping.program_header,
                range: mapping.virtual_range,
            }),
        }
    }

    /// Invert a file interval only if one PT_LOAD owns it. Intentional file aliases
    /// remain valid inventory records but return an explicit ambiguity here.
    pub fn file_to_virtual(&self, start: FileOffset, length: u64) -> Result<FileMapping, Error> {
        let range = FileRange::checked(start, length)?;
        if range.is_empty() {
            return Err(Error::EmptyRange);
        }
        let owners: Vec<_> = self
            .segments(SegmentType::Load)
            .filter(|item| {
                intersects(
                    start.0,
                    range.end.0,
                    item.offset.0,
                    item.offset.0 + item.file_size,
                )
            })
            .collect();
        let indices = || owners.iter().map(|item| item.index).collect();
        if owners.is_empty() {
            return Err(Error::UnmappedFile { range });
        }
        if overlapping_intersections(&owners, start.0, range.end.0, true) {
            return Err(Error::AmbiguousFile {
                range,
                owners: indices(),
            });
        }
        if owners.len() != 1
            || start.0 < owners[0].offset.0
            || range.end.0 > owners[0].offset.0 + owners[0].file_size
        {
            return Err(Error::CrossesFileLoadBoundary {
                range,
                owners: indices(),
            });
        }
        let item = owners[0];
        let virtual_range =
            VirtualRange::checked(ElfVaddr(item.vaddr.0 + (start.0 - item.offset.0)), length)?;
        Ok(FileMapping {
            program_header: item.index,
            file_range: range,
            virtual_range,
            flags: item.flags,
        })
    }
}

fn checked_end(domain: AddressDomain, start: u64, length: u64) -> Result<u64, Error> {
    start.checked_add(length).ok_or(Error::Overflow {
        domain,
        start,
        length,
    })
}

fn require_file_range(bytes: &[u8], range: FileRange, region: FileRegion) -> Result<(), Error> {
    // No file byte exists to validate for a zero-sized segment, even when its
    // p_offset anchor is past EOF. Translation never indexes that empty anchor.
    if !range.is_empty() && range.end.0 > bytes.len() as u64 {
        Err(Error::Truncated {
            region,
            range,
            file_len: bytes.len() as u64,
        })
    } else {
        Ok(())
    }
}

fn fixed(field: HeaderField, value: u64, required: u64) -> Result<(), Error> {
    if value == required {
        Ok(())
    } else {
        Err(Error::InvalidHeader {
            field,
            value,
            required,
        })
    }
}

fn supported(field: HeaderField, value: u64, required: u64) -> Result<(), Error> {
    if value == required {
        Ok(())
    } else {
        Err(Error::Unsupported { field, value })
    }
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ])
}

fn intersects(a: u64, b: u64, c: u64, d: u64) -> bool {
    a < b && c < d && a < d && c < b
}

fn overlapping_intersections(owners: &[&ProgramHeader], start: u64, end: u64, file: bool) -> bool {
    let mut intervals: Vec<_> = owners
        .iter()
        .map(|item| {
            let (base, length) = if file {
                (item.offset.0, item.file_size)
            } else {
                (item.vaddr.0, item.memory_size)
            };
            (base.max(start), (base + length).min(end))
        })
        .collect();
    intervals.sort_unstable();
    let mut previous_end = 0;
    for (start, end) in intervals {
        if start < previous_end {
            return true;
        }
        previous_end = end;
    }
    false
}

#[cfg(test)]
#[path = "fixtures.rs"]
mod fixtures;
