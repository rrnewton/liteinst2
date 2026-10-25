//! Private fixture mapper. Every fixed map stays inside one owned reservation.
use super::{Mapping, NativeOracle, PAGE, STACK_BYTES};
use std::fs::File;
use std::os::fd::AsRawFd;

#[derive(Clone, Copy, Debug)]
pub struct FileLoad {
    pub vaddr: u64,
    pub offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: u32,
}

/// Source-page ownership and the remaining reservation are disjoint. No shared
/// borrowed Mapping can unmap a page owned by another guard.
pub struct FileModule {
    pub oracle: NativeOracle,
    before_source: Mapping,
    after_source: Mapping,
    start: u64,
    min_vaddr: u64,
    max_vaddr: u64,
    pub bias: u64,
    pub expected_pages: Vec<(u64, Vec<u8>)>,
}

fn end_page(address: u64) -> u64 {
    address.checked_add(PAGE as u64 - 1).unwrap() & !(PAGE as u64 - 1)
}

impl FileModule {
    pub fn new(
        min_vaddr: u64,
        max_vaddr: u64,
        source_page: u64,
        file: &File,
        file_bytes: &[u8],
        loads: &[FileLoad],
    ) -> Self {
        assert_eq!(min_vaddr % PAGE as u64, 0);
        assert_eq!(max_vaddr % PAGE as u64, 0);
        assert_eq!(source_page % PAGE as u64, 0);
        assert!(min_vaddr <= source_page && source_page < max_vaddr);
        let span = usize::try_from(max_vaddr.checked_sub(min_vaddr).unwrap()).unwrap();
        assert!(span > 0 && span <= 1024 * 1024);
        let reservation = Mapping::new(span.checked_add(2 * PAGE).unwrap());
        reservation.protect(libc::PROT_NONE);
        let start = reservation.address().checked_add(PAGE as u64).unwrap();
        let bias = start.checked_sub(min_vaddr).unwrap();
        let source_address = bias.checked_add(source_page).unwrap();
        let before_len = usize::try_from(source_address - reservation.address()).unwrap();
        let after_address = source_address.checked_add(PAGE as u64).unwrap();
        let reservation_end = reservation.address() + reservation.len as u64;
        let after_len = usize::try_from(reservation_end - after_address).unwrap();
        assert!(before_len >= PAGE && after_len >= PAGE);
        // All arithmetic/checks precede the infallible ownership split. Guards
        // own nonoverlapping ranges, including the outer inaccessible pages.
        let code = Mapping {
            address: source_address as usize as *mut u8,
            len: PAGE,
        };
        let before_source = Mapping {
            address: reservation.address,
            len: before_len,
        };
        let after_source = Mapping {
            address: after_address as usize as *mut u8,
            len: after_len,
        };
        std::mem::forget(reservation);
        let data = Mapping::new(PAGE);
        data.initialize(
            0,
            &(0..PAGE).map(|i| (i * 37 + 11) as u8).collect::<Vec<_>>(),
        );
        let stack = Mapping::new(STACK_BYTES + PAGE);
        stack.initialize(0, &vec![0x5a; STACK_BYTES + PAGE]);
        assert_eq!(
            unsafe { libc::mprotect(stack.writable().cast(), PAGE, libc::PROT_NONE) },
            0
        );
        let initial_rsp = stack.address() + STACK_BYTES as u64 - 8;
        // No manufactured instruction is placed here. RET stops before any
        // execution at this existing file-page byte, as in the old oracle.
        let return_pc = source_address + (PAGE / 2) as u64;
        stack.initialize(
            (initial_rsp - stack.address()) as usize,
            &return_pc.to_ne_bytes(),
        );
        let oracle = NativeOracle {
            code,
            data,
            stack,
            initial_rsp,
            return_pc,
            original_code: Vec::new(),
            seeded_arithmetic_flags: false,
        };
        let mut module = Self {
            oracle,
            before_source,
            after_source,
            start,
            min_vaddr,
            max_vaddr,
            bias,
            expected_pages: Vec::new(),
        };
        module.load(file, file_bytes, loads);
        module.oracle.original_code = module.oracle.code.bytes().to_vec();
        module
    }

    /// Called only between fully reaped cohorts. This is a manual file reload,
    /// not a live publisher transaction or an ELF dynamic-loader implementation.
    pub fn load(&mut self, file: &File, file_bytes: &[u8], loads: &[FileLoad]) {
        assert!(!loads.is_empty() && loads.len() <= 64);
        let span = usize::try_from(self.max_vaddr - self.min_vaddr).unwrap();
        assert_eq!(
            self.before_source.address() + self.before_source.len as u64,
            self.oracle.code.address()
        );
        assert_eq!(
            self.oracle.code.address() + PAGE as u64,
            self.after_source.address()
        );
        assert_eq!(
            self.start + span as u64 + PAGE as u64,
            self.after_source.address() + self.after_source.len as u64
        );
        // SAFETY: this exact interior range is already exclusively owned by
        // the three disjoint guards; outer guard pages are never remapped.
        let reset = unsafe {
            libc::mmap(
                self.start as usize as *mut _,
                span,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(reset as u64, self.start);
        let mut pages = Vec::new();
        let mut occupied = Vec::<std::ops::Range<u64>>::new();
        for load in loads {
            // This fixed input cohort has no BSS. Refuse broader loading rules
            // instead of silently inventing dynamic relocation/zero-fill logic.
            assert_eq!(load.file_size, load.memory_size);
            assert!(load.file_size > 0);
            assert_eq!(load.offset % PAGE as u64, load.vaddr % PAGE as u64);
            assert!(matches!(load.flags, 4 | 5 | 6)); // R, RX or RW; never RWX.
            let page = load.vaddr & !(PAGE as u64 - 1);
            let end = end_page(load.vaddr.checked_add(load.memory_size).unwrap());
            assert!(self.min_vaddr <= page && end <= self.max_vaddr);
            assert!(
                occupied
                    .iter()
                    .all(|prior| prior.end <= page || end <= prior.start)
            );
            occupied.push(page..end);
            let file_page = load.offset & !(PAGE as u64 - 1);
            let file_end = load.offset.checked_add(load.file_size).unwrap();
            assert!(file_end <= file_bytes.len() as u64);
            let length = usize::try_from(end - page).unwrap();
            assert!(file_page + length as u64 <= end_page(file_bytes.len() as u64));
            let address = self.bias.checked_add(page).unwrap();
            assert!(self.start <= address && address + length as u64 <= self.start + span as u64);
            let protection = libc::PROT_READ
                | if load.flags & 1 != 0 {
                    libc::PROT_EXEC
                } else {
                    0
                }
                | if load.flags & 2 != 0 {
                    libc::PROT_WRITE
                } else {
                    0
                };
            // SAFETY: exact checked file-page mapping replaces only an already
            // owned reservation interval. It cannot clobber another mapping.
            let mapped = unsafe {
                libc::mmap(
                    address as usize as *mut _,
                    length,
                    protection,
                    libc::MAP_PRIVATE | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    i64::try_from(file_page).unwrap(),
                )
            };
            assert_eq!(mapped as u64, address);
            for offset in (0..length).step_by(PAGE) {
                let at = usize::try_from(file_page).unwrap() + offset;
                let mut expected = vec![0; PAGE];
                let available = PAGE.min(file_bytes.len().saturating_sub(at));
                assert!(
                    available > 0,
                    "mapping would expose a whole page past file EOF"
                );
                expected[..available].copy_from_slice(&file_bytes[at..at + available]);
                let target = address + offset as u64;
                assert_eq!(
                    unsafe { std::slice::from_raw_parts(target as usize as *const u8, PAGE) },
                    expected
                );
                pages.push((target, expected));
            }
        }
        assert!(
            pages
                .iter()
                .any(|(page, _)| *page == self.oracle.code.address())
        );
        pages.sort_by_key(|(page, _)| *page);
        self.expected_pages = pages;
    }
}
