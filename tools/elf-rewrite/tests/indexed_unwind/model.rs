use super::*;
use liteinst_rewrite::carrier::elf64::Storage;

pub const SITE: u64 = 0x1100;
pub const HOOK: u64 = 0x1800;
pub const IMAGE: u64 = 0x10000;
const HEADER: u64 = 0x500;
pub const STREAM: u64 = 0x600;

fn put16(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn record(mut body: Vec<u8>) -> Vec<u8> {
    body.resize(body.len().next_multiple_of(4), 0);
    let mut out = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    out.extend(body);
    out
}
fn relative(target: u64, base: u64) -> [u8; 4] {
    i32::try_from(i128::from(target) - i128::from(base))
        .unwrap()
        .to_le_bytes()
}
fn fde(address: u64, start: u64, length: u32) -> Vec<u8> {
    let mut body = u32::try_from(address + 4 - STREAM)
        .unwrap()
        .to_le_bytes()
        .to_vec();
    body.extend(relative(start, address + 8));
    body.extend(length.to_le_bytes());
    body.push(0); // z augmentation is empty
    record(body)
}
pub fn input() -> Vec<u8> {
    let mut bytes = vec![0_u8; 8192];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut bytes, 16, 3);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 3);
    for (i, (kind, flags, offset, size, alignment)) in [
        (1_u32, 4_u32, 0_u64, 4096_u64, 4096_u64),
        (1, 5, 4096, 4096, 4096),
        (0x6474_e550, 4, HEADER, 28, 4),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + i * 56;
        put32(&mut bytes, at, kind);
        put32(&mut bytes, at + 4, flags);
        for (field, value) in [
            (8, offset),
            (16, offset),
            (24, offset),
            (32, size),
            (40, size),
            (48, alignment),
        ] {
            put64(&mut bytes, at + field, value);
        }
    }
    bytes[SITE as usize..SITE as usize + 6].copy_from_slice(&[0x0f, 0x1f, 0x44, 0, 0, 0xc3]);
    bytes[HOOK as usize] = 0xc3;
    let mut body = vec![
        0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0x0c, 7, 8, 0x90, 1,
    ];
    for column in [3, 6, 12, 13, 14, 15] {
        body.extend([8, column]);
    }
    let mut stream = record(body);
    let source_fde = STREAM + stream.len() as u64;
    stream.extend(fde(source_fde, SITE, 6));
    let hook_fde = STREAM + stream.len() as u64;
    stream.extend(fde(hook_fde, HOOK, 1));
    stream.extend([0; 4]);
    bytes[STREAM as usize..STREAM as usize + stream.len()].copy_from_slice(&stream);
    let mut header = vec![1, 0x1b, 3, 0x3b];
    header.extend(relative(STREAM, HEADER + 4));
    header.extend(2_u32.to_le_bytes());
    for (start, fde) in [(SITE, source_fde), (HOOK, hook_fde)] {
        header.extend(relative(start, HEADER));
        header.extend(relative(fde, HEADER));
    }
    bytes[HEADER as usize..HEADER as usize + header.len()].copy_from_slice(&header);
    bytes
}
pub fn parse(bytes: &[u8]) -> Elf64<'_> {
    Elf64::parse(bytes, ParseLimits::default()).unwrap()
}
pub fn policy() -> ImagePolicy {
    ImagePolicy {
        layout: CarrierPolicy {
            page_size: 4096,
            user_address_limit: 1 << 47,
            max_added_file_bytes: 0x10000,
            max_output_file_bytes: 0x20000,
            max_program_headers: 32,
            max_virtual_span: 0x20000,
        },
        dynamic: dynamic::Limits::default(),
        max_images: 4,
        max_new_load_pages: 8,
    }
}
fn view<'a>(elf: &Elf64<'a>, pc: u64, length: u64) -> &'a [u8] {
    let mapped = elf.virtual_to_storage(ElfVaddr(pc), length).unwrap();
    assert!(mapped.flags.readable() && !mapped.flags.writable());
    let Storage::FileBacked(file) = mapped.storage else {
        panic!("metadata file owner")
    };
    &elf.bytes()[file.start().0 as usize..file.end().0 as usize]
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn signed(base: u64, bytes: &[u8], at: usize) -> u64 {
    base.checked_add_signed(i64::from(word(bytes, at) as i32))
        .unwrap()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupError {
    Cie,
}

fn cie_encoding(
    elf: &Elf64<'_>,
    fde: u64,
    delta: u32,
    expected_cies: &[u64],
) -> Result<(), LookupError> {
    let cie = fde
        .checked_add(4)
        .and_then(|field| field.checked_sub(u64::from(delta)))
        .ok_or(LookupError::Cie)?;
    if delta == 0 || !expected_cies.contains(&cie) {
        return Err(LookupError::Cie);
    }
    let prefix = view(elf, cie, 17);
    let size = u64::from(word(prefix, 0))
        .checked_add(4)
        .ok_or(LookupError::Cie)?;
    if !(17..=65536).contains(&size)
        || word(prefix, 4) != 0
        || prefix[8..17] != [1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b]
    {
        return Err(LookupError::Cie);
    }
    // Require the entire exact CIE to have one immutable file owner, not only
    // an encoding byte at a possibly unrelated numeric address.
    view(elf, cie, size);
    Ok(())
}

/// Independent table lookup: no production unwind parser, certificate or
/// composer is used. `expected_cies` names exact CIE starts supplied by the
/// source-owned fixture. Resolve the backward CIE reference and assert its
/// actual zR/pcrel-sdata4 encoding before decoding either FDE field.
pub fn lookup(
    bytes: &[u8],
    header_address: u64,
    bias: u64,
    pc: u64,
    expected_cies: &[u64],
) -> Result<Option<u64>, LookupError> {
    let elf = parse(bytes);
    let prefix = view(&elf, header_address, 12);
    assert_eq!(&prefix[..4], &[1, 0x1b, 3, 0x3b]);
    let count = word(prefix, 8) as usize;
    assert!(count <= 256);
    let header = view(&elf, header_address, 12 + 8 * count as u64);
    let base = bias.checked_add(header_address).unwrap();
    let mut candidate = None;
    let mut previous = None;
    for row in 0..count {
        let start = signed(base, header, 12 + 8 * row);
        let fde = signed(base, header, 16 + 8 * row);
        assert!(previous.is_none_or(|last| last < start));
        previous = Some(start);
        if start <= pc {
            candidate = Some((start, fde));
        }
    }
    let Some((start, fde)) = candidate else {
        return Ok(None);
    };
    let envelope = view(&elf, fde - bias, 16);
    assert!(word(envelope, 0) >= 13);
    cie_encoding(&elf, fde - bias, word(envelope, 4), expected_cies)?;
    view(&elf, fde - bias, u64::from(word(envelope, 0)) + 4);
    assert_eq!(signed(fde + 8, envelope, 8), start);
    let range = u64::try_from(word(envelope, 12) as i32).unwrap();
    Ok((pc < start.checked_add(range).unwrap()).then_some(fde))
}
