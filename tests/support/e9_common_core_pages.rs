//! Pure materialization of the exact common-core LOAD page view.
//! Called by the native candidate reader and the standalone page-contract tests.
//! No ELF ownership, hash authority, mapping or native execution is supplied here.
use std::collections::BTreeSet;

pub(super) const PAGE: usize = 4096;
pub(super) const IMAGE_START: u64 = 0x400000;
pub(super) const IMAGE_END: u64 = 0x425000;
pub(super) const LOADS: [(u64, u64, u64, u64, u32); 4] = [
    (0, 0x400000, 0x8b0, 0x8b0, 4),
    (0x1000, 0x401000, 0xa51, 0xa51, 5),
    (0x2000, 0x402000, 0xe1c, 0xe1c, 4),
    (0x3e00, 0x403e00, 0x20358, 0x20390, 6),
];

#[derive(Clone)]
pub(super) struct Page {
    pub(super) address: u64,
    pub(super) flags: u32,
    pub(super) bytes: Vec<u8>,
}

fn page_end(value: u64) -> u64 {
    value.checked_add(4095).unwrap() & !4095
}

pub(super) fn materialize_load_pages(
    elf: &[u8],
    loads: Vec<(u64, u64, u64, u64, u32)>,
) -> (Vec<u8>, Vec<Page>) {
    assert!(loads.len() >= LOADS.len());
    // Preserve each complete original tuple in its original relative order.
    // Generated LOADs may precede or interleave them; do not sort page output.
    let original_loads: Vec<_> = loads
        .iter()
        .filter(|row| LOADS.iter().any(|old| old.1 == row.1))
        .copied()
        .collect();
    assert_eq!(&original_loads[..original_loads.len().min(4)], &LOADS);
    assert!(loads.len() <= 261);
    let mut pages = Vec::new();
    let mut seen = BTreeSet::new();
    let mut base = vec![0; (IMAGE_END - IMAGE_START) as usize];
    for &(offset, address, fs, ms, flags) in &loads {
        assert!(
            matches!(flags, 4..=6)
                && fs <= ms
                && offset.checked_add(fs).unwrap() <= elf.len() as u64
        );
        assert_eq!(offset % 4096, address % 4096);
        let lo = address & !4095;
        let hi = page_end(address.checked_add(ms).unwrap());
        assert!(hi <= 1 << 47);
        for page in (lo..hi).step_by(PAGE) {
            assert!(seen.insert(page));
            let mut data = vec![0; PAGE];
            let at = (offset & !4095) + page - lo;
            if page < page_end(address + fs) {
                let n = PAGE.min(elf.len().saturating_sub(at as usize));
                data[..n].copy_from_slice(&elf[at as usize..at as usize + n]);
            }
            if ms > fs && page + 4096 > address + fs {
                let at = (address + fs).saturating_sub(page) as usize;
                data[at..].fill(0);
            }
            if (IMAGE_START..IMAGE_END).contains(&page) {
                assert!(page >= IMAGE_START);
                let at = (page - IMAGE_START) as usize;
                base[at..at + PAGE].copy_from_slice(&data);
            } else {
                assert!(flags != 6);
                pages.push(Page {
                    address: page,
                    flags,
                    bytes: data,
                });
            }
        }
    }
    // Nonempty repeated originals already refuse at seen.insert(page).
    // Also reject a repeated original address with an empty page interval.
    assert_eq!(original_loads.len(), LOADS.len());
    assert!(pages.len() <= 2048);
    assert!(seen.last().unwrap() + 4096 - seen.first().unwrap() <= 1_073_741_824);
    (base, pages)
}
