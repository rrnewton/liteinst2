use liteinst2::generated_unwind::{OriginalCfi, Refusal, SourceOwner};
use std::path::PathBuf;
use std::sync::Arc;

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn name(bytes: &[u8], at: usize) -> &[u8] {
    let tail = &bytes[at..];
    &tail[..tail.iter().position(|b| *b == 0).unwrap()]
}

pub struct Elf {
    bytes: Vec<u8>,
    path: PathBuf,
    bias: u64,
    loads: Vec<(u64, u64, u64, u32)>,
    sections: Vec<[u64; 5]>, // name,type,flags,address,offset; size/link from original header
    shoff: usize,
    eh_frame: (u64, u64),
}
impl Elf {
    pub fn current(anchor: u64) -> Self {
        let path = std::fs::read_link("/proc/self/exe").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert!(metadata.len() < 128 * 1024 * 1024);
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() >= 64);
        assert_eq!(&bytes[..7], b"\x7fELF\x02\x01\x01");
        assert!(matches!(u16_at(&bytes, 16), 2 | 3));
        assert_eq!(u16_at(&bytes, 18), 62);
        assert_eq!(u16_at(&bytes, 52), 64);
        assert_eq!(u16_at(&bytes, 54), 56);
        assert_eq!(u16_at(&bytes, 58), 64);
        let phoff = usize::try_from(u64_at(&bytes, 32)).unwrap();
        let phnum = usize::from(u16_at(&bytes, 56));
        let shoff = usize::try_from(u64_at(&bytes, 40)).unwrap();
        let shnum = usize::from(u16_at(&bytes, 60));
        assert!(phnum > 0 && phnum <= 256 && shnum > 0 && shnum <= 4096);
        assert!(phoff.checked_add(phnum * 56).unwrap() <= bytes.len());
        assert!(shoff.checked_add(shnum * 64).unwrap() <= bytes.len());
        let mut loads = Vec::new();
        for n in 0..phnum {
            let p = phoff + n * 56;
            if u32_at(&bytes, p) == 1 {
                let file = u64_at(&bytes, p + 8);
                let start = u64_at(&bytes, p + 16);
                let size = u64_at(&bytes, p + 32);
                assert!(file.checked_add(size).unwrap() <= bytes.len() as u64);
                loads.push((
                    start,
                    start.checked_add(size).unwrap(),
                    file,
                    u32_at(&bytes, p + 4),
                ));
            }
        }
        let mut sections = Vec::new();
        for n in 0..shnum {
            let p = shoff + n * 64;
            sections.push([
                u64::from(u32_at(&bytes, p)),
                u64::from(u32_at(&bytes, p + 4)),
                u64_at(&bytes, p + 8),
                u64_at(&bytes, p + 16),
                u64_at(&bytes, p + 24),
            ]);
        }
        let strings = usize::from(u16_at(&bytes, 62));
        assert!(strings < shnum);
        let str_offset = usize::try_from(sections[strings][4]).unwrap();
        let str_size = usize::try_from(u64_at(&bytes, shoff + strings * 64 + 32)).unwrap();
        let names = &bytes[str_offset..str_offset.checked_add(str_size).unwrap()];
        let matching: Vec<_> = sections
            .iter()
            .enumerate()
            .filter(|(_, s)| name(names, s[0] as usize) == b".eh_frame")
            .collect();
        assert_eq!(matching.len(), 1);
        let (index, section) = matching[0];
        assert_eq!(section[1], 1);
        assert_eq!(section[2] & 3, 2);
        let eh_frame = (
            section[3],
            section[3]
                .checked_add(u64_at(&bytes, shoff + index * 64 + 32))
                .unwrap(),
        );
        let mut elf = Self {
            bytes,
            path,
            bias: 0,
            loads,
            sections,
            shoff,
            eh_frame,
        };
        let symbol = elf.symbol("uw_frameless");
        elf.bias = anchor.checked_sub(symbol).unwrap();
        if u16_at(&elf.bytes, 16) == 2 {
            assert_eq!(elf.bias, 0);
        }
        elf
    }
    pub fn symbol(&self, wanted: &str) -> u64 {
        let mut found = Vec::new();
        for (index, section) in self.sections.iter().enumerate() {
            if section[1] != 2 {
                continue;
            }
            let header = self.shoff + index * 64;
            assert_eq!(u64_at(&self.bytes, header + 56), 24);
            let size = usize::try_from(u64_at(&self.bytes, header + 32)).unwrap();
            assert_eq!(size % 24, 0);
            let link = usize::try_from(u32_at(&self.bytes, header + 40)).unwrap();
            assert!(link < self.sections.len());
            let names_offset = self.sections[link][4] as usize;
            let names_len = u64_at(&self.bytes, self.shoff + link * 64 + 32) as usize;
            let names = &self.bytes[names_offset..names_offset.checked_add(names_len).unwrap()];
            let entries =
                &self.bytes[section[4] as usize..(section[4] as usize).checked_add(size).unwrap()];
            for entry in entries.chunks_exact(24) {
                if name(names, u32_at(entry, 0) as usize) == wanted.as_bytes() {
                    assert_ne!(u16_at(entry, 6), 0);
                    found.push(u64_at(entry, 8));
                }
            }
        }
        assert_eq!(found.len(), 1, "unique actual symbol {wanted}");
        found[0]
    }
    pub fn address(&self, symbol: &str) -> u64 {
        self.bias.checked_add(self.symbol(symbol)).unwrap()
    }
    pub fn file_slice(&self, address: u64, length: usize, executable: bool) -> &[u8] {
        let virtual_address = address.checked_sub(self.bias).unwrap();
        let end = virtual_address.checked_add(length as u64).unwrap();
        let matches: Vec<_> = self
            .loads
            .iter()
            .filter(|&&(start, stop, _, flags)| {
                start <= virtual_address
                    && end <= stop
                    && flags & 4 != 0
                    && flags & 2 == 0
                    && (!executable || flags & 1 != 0)
            })
            .collect();
        assert_eq!(matches.len(), 1, "unique readable immutable PT_LOAD owner");
        let &(start, _, file, _) = matches[0];
        let offset = usize::try_from(file + virtual_address - start).unwrap();
        &self.bytes[offset..offset.checked_add(length).unwrap()]
    }
    pub fn authenticate_code(&self, start: u64, end: u64) {
        let expected = self.file_slice(start, usize::try_from(end - start).unwrap(), true);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(start as usize as *const u8, expected.len()) },
            expected
        );
    }
    pub fn cfi(&self, fde_address: u64) -> OriginalCfi {
        let record = |address: u64| {
            let virtual_address = address.checked_sub(self.bias).unwrap();
            assert!(virtual_address >= self.eh_frame.0);
            let length = usize::try_from(u32_at(self.file_slice(address, 4, false), 0)).unwrap();
            assert!((4..=65532).contains(&length));
            let total = length + 4;
            assert!(virtual_address.checked_add(total as u64).unwrap() <= self.eh_frame.1);
            let expected = self.file_slice(address, total, false);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(address as usize as *const u8, total) },
                expected
            );
            expected.to_vec()
        };
        let fde = record(fde_address);
        let cie_address = fde_address
            .checked_add(4)
            .unwrap()
            .checked_sub(u64::from(u32_at(&fde, 4)))
            .unwrap();
        OriginalCfi {
            cie_address,
            cie: record(cie_address),
            fde_address,
            fde,
        }
    }
    pub fn owner(self: &Arc<Self>, records: &[OriginalCfi]) -> Arc<dyn SourceOwner> {
        Arc::new(MainOwner {
            elf: self.clone(),
            records: records.to_vec(),
        })
    }
}
struct MainOwner {
    elf: Arc<Elf>,
    records: Vec<OriginalCfi>,
}
unsafe impl SourceOwner for MainOwner {
    fn revalidate(&self) -> Result<(), Refusal> {
        // This fixture pins the process's main executable, never a dlcloseable
        // DSO. Entire backing bytes and every live CFI byte remain exact.
        if std::fs::read(&self.elf.path).map_err(|_| Refusal::SourceIdentity)? != self.elf.bytes {
            return Err(Refusal::SourceIdentity);
        }
        for record in &self.records {
            for (address, bytes) in [
                (record.cie_address, &record.cie),
                (record.fde_address, &record.fde),
            ] {
                if unsafe { std::slice::from_raw_parts(address as usize as *const u8, bytes.len()) }
                    != bytes
                {
                    return Err(Refusal::SourceIdentity);
                }
            }
        }
        Ok(())
    }
}

// Independent finite CFI evaluator for the ORIGINAL authored fixture. Unlike
// the product parser it stops at one target, uses i128 LEB arithmetic and only
// accepts the assembler's declared opcode grammar. No generated-row code is used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointRow {
    pub cfa: (usize, i64),
    pub registers: [Option<i64>; 17],
}
fn leb(bytes: &[u8], at: &mut usize, signed: bool) -> i64 {
    let mut value = 0_i128;
    let mut bits = 0;
    loop {
        assert!(bits < 70);
        let byte = bytes[*at];
        *at += 1;
        value |= i128::from(byte & 127) << bits;
        bits += 7;
        if byte & 128 == 0 {
            if signed && byte & 64 != 0 {
                value -= 1_i128 << bits;
            }
            return i64::try_from(value).unwrap();
        }
    }
}
fn interpret(bytes: &[u8], mut row: PointRow, mut pc: u64, target: u64) -> PointRow {
    let mut at = 0;
    while at < bytes.len() {
        let op = bytes[at];
        at += 1;
        if op & 0xc0 == 0x40 {
            let next = pc.checked_add(u64::from(op & 63)).unwrap();
            if next > target {
                return row;
            }
            pc = next;
            continue;
        }
        if op & 0xc0 == 0x80 {
            let register = usize::from(op & 63);
            assert!(register < 17);
            row.registers[register] = Some(leb(bytes, &mut at, false).checked_mul(-8).unwrap());
            continue;
        }
        match op {
            0 => {}
            2 | 3 | 4 => {
                let width = 1_usize << (op - 2);
                let mut amount = 0_u64;
                for shift in 0..width {
                    amount |= u64::from(bytes[at + shift]) << (8 * shift);
                }
                at += width;
                let next = pc.checked_add(amount).unwrap();
                if next > target {
                    return row;
                }
                pc = next;
            }
            8 => {
                let register = usize::try_from(leb(bytes, &mut at, false)).unwrap();
                row.registers[register] = None;
            }
            0x0c => {
                row.cfa = (
                    usize::try_from(leb(bytes, &mut at, false)).unwrap(),
                    leb(bytes, &mut at, false),
                );
            }
            0x0d => row.cfa.0 = usize::try_from(leb(bytes, &mut at, false)).unwrap(),
            0x0e => row.cfa.1 = leb(bytes, &mut at, false),
            _ => panic!("unexpected original fixture CFI opcode {op:#x}"),
        }
    }
    row
}
pub fn prove_point(
    record: &OriginalCfi,
    target: u64,
    expected_start: u64,
    expected_end: u64,
) -> PointRow {
    let cie = &record.cie;
    assert_eq!(u32_at(cie, 4), 0);
    assert_eq!(cie[8], 1);
    assert_eq!(&cie[9..12], b"zR\0");
    let mut at = 12;
    assert_eq!(leb(cie, &mut at, false), 1);
    assert_eq!(leb(cie, &mut at, true), -8);
    assert_eq!(cie[at], 16);
    at += 1;
    assert_eq!(leb(cie, &mut at, false), 1);
    let encoding = cie[at];
    at += 1;
    assert!(encoding == 0 || encoding == 0x1b);
    let initial = interpret(
        &cie[at..],
        PointRow {
            cfa: (7, 8),
            registers: [None; 17],
        },
        0,
        0,
    );
    let fde = &record.fde;
    let (start, size, mut at) = if encoding == 0 {
        (u64_at(fde, 8), u64_at(fde, 16), 24)
    } else {
        (
            record
                .fde_address
                .checked_add(8)
                .unwrap()
                .checked_add_signed(i64::from(u32_at(fde, 8) as i32))
                .unwrap(),
            u64::try_from(u32_at(fde, 12) as i32).unwrap(),
            16,
        )
    };
    assert_eq!(
        (start, start.checked_add(size).unwrap()),
        (expected_start, expected_end)
    );
    assert!(start <= target && target < expected_end);
    assert_eq!(leb(fde, &mut at, false), 0);
    interpret(&fde[at..], initial, start, target)
}
