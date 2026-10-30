// Per-fixture address-space ownership for the short-neighbor oracle.
// Source and hand-emitted calibration pages never leave their reservation.
// The unchanged live planner requires vacant image windows, so those explicit
// windows are released before planning. A low-canonical namespace keeps them
// away from ordinary high, top-down mmap placement, including writable aliases
// created by publication. This is a placement assumption, not an atomic handoff:
// an unrelated exact or bottom-up mapping can still claim a released window.
// Such a collision remains a hard failure; there is no retry or replacement.
use super::{Mapping, NativeOracle, PAGE};
use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicU64, Ordering};

const ARENA_BYTES: u64 = 1_u64 << 32;
const SOURCE_OFFSET: u64 = 1_u64 << 31;
const FIRST_ARENA: u64 = 0x0100_0000_0000;
const ARENA_LIMIT: u64 = 0x1000_0000_0000;
const ARENA_SLOTS: u64 = (ARENA_LIMIT - FIRST_ARENA) / ARENA_BYTES;
static NEXT_ARENA: AtomicU64 = AtomicU64::new(0);

// Every Mapping in padding owns only its remaining disjoint interval. There is
// deliberately no owner or destructor covering the original complete envelope.
pub(crate) struct NeighborFixtureArena {
    start: u64,
    padding: Vec<Mapping>,
}

impl NeighborFixtureArena {
    fn new() -> Self {
        let ordinal = NEXT_ARENA
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next < ARENA_SLOTS {
                    next.checked_add(1)
                } else {
                    None
                }
            })
            .expect("neighbor fixture arena namespace exhausted");
        let start = ordinal
            .checked_mul(ARENA_BYTES)
            .and_then(|offset| FIRST_ARENA.checked_add(offset))
            .expect("neighbor fixture arena address overflow");
        // The ordinal is consumed even on failure. Never retry or reuse a slot.
        Self::reserve_at(start)
            .unwrap_or_else(|error| panic!("required neighbor fixture arena unavailable: {error}"))
    }

    fn reserve_at(start: u64) -> std::io::Result<Self> {
        let end = start
            .checked_add(ARENA_BYTES)
            .expect("neighbor fixture arena end overflow");
        assert!(start >= FIRST_ARENA && end <= ARENA_LIMIT);
        assert_eq!((start - FIRST_ARENA) % ARENA_BYTES, 0);
        let pointer = usize::try_from(start).expect("unrepresentable fixture arena address");
        let len = usize::try_from(ARENA_BYTES).expect("unrepresentable fixture arena length");
        // Collection storage exists before acquiring any mapping ownership.
        let mut padding = Vec::with_capacity(1);
        // SAFETY: one non-clobbering exact reservation of a checked page-aligned
        // low-canonical range. PROT_NONE padding is never read or initialized.
        let actual = unsafe {
            libc::mmap(
                pointer as *mut libc::c_void,
                len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if actual == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        // Own even an unexpected result before checking its address. An old
        // kernel ignoring NOREPLACE cannot turn a nonexact mapping into success.
        let mapping = Mapping {
            address: actual.cast(),
            len,
        };
        if mapping.address() != start {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "exact neighbor fixture arena was not honored",
            ));
        }
        padding.push(mapping);
        Ok(Self { start, padding })
    }

    fn source_address(&self) -> u64 {
        self.start
            .checked_add(SOURCE_OFFSET)
            .expect("neighbor fixture source address overflow")
    }

    // Transfer an interval without releasing or replacing any page. Validate
    // and reserve all collection capacity before changing a live owner.
    fn take(&mut self, address: u64, len: usize) -> Mapping {
        assert!(
            len != 0 && len & (PAGE - 1) == 0,
            "invalid neighbor fixture length"
        );
        assert_eq!(
            address % PAGE as u64,
            0,
            "unaligned neighbor fixture address"
        );
        let end = address
            .checked_add(u64::try_from(len).expect("unrepresentable fixture length"))
            .expect("neighbor fixture range overflow");
        let arena_end = self.start.checked_add(ARENA_BYTES).unwrap();
        assert!(
            address >= self.start && end <= arena_end,
            "neighbor fixture range outside arena"
        );
        let index = self
            .padding
            .iter()
            .position(|mapping| {
                let mapping_end = mapping.address().checked_add(mapping.len as u64).unwrap();
                mapping.address() <= address && end <= mapping_end
            })
            .expect("neighbor fixture range not wholly reserved");
        let original = &self.padding[index];
        let lower_len = usize::try_from(address - original.address()).unwrap();
        let remaining = original.len.checked_sub(lower_len).unwrap();
        let upper_len = remaining.checked_sub(len).unwrap();
        let upper_offset = lower_len.checked_add(len).unwrap();
        let lower_address = original.address;
        // SAFETY: both offsets are within this sole live reservation; the upper
        // address may be one-past only when no upper Mapping will be created.
        let middle_address = unsafe { original.address.add(lower_len) };
        let upper_address = unsafe { original.address.add(upper_offset) };
        self.padding.reserve(1);
        let _original = ManuallyDrop::new(self.padding.swap_remove(index));
        // The old destructor is now disabled. These disjoint owners partition
        // exactly its pages; subsequent pushes cannot allocate or unwind.
        let lower = if lower_len == 0 {
            None
        } else {
            Some(Mapping {
                address: lower_address,
                len: lower_len,
            })
        };
        let middle = Mapping {
            address: middle_address,
            len,
        };
        let upper = if upper_len == 0 {
            None
        } else {
            Some(Mapping {
                address: upper_address,
                len: upper_len,
            })
        };
        if let Some(lower) = lower {
            self.padding.push(lower);
        }
        if let Some(upper) = upper {
            self.padding.push(upper);
        }
        middle
    }

    pub(crate) fn take_writable(&mut self, address: u64, len: usize) -> Mapping {
        let mapping = self.take(address, len);
        mapping.protect(libc::PROT_READ | libc::PROT_WRITE);
        mapping
    }

    pub(crate) fn release(&mut self, address: u64, len: usize) {
        // Only these consumed pages are unmapped. No retained padding owner can
        // later unmap a production image or another mapping placed in this hole.
        drop(self.take(address, len));
    }

    pub(crate) fn assert_ownership_controls() {
        let mut first = Self::new();
        let second = Self::new();
        assert_ne!(first.start, second.start);
        assert_ne!(first.source_address(), second.source_address());
        assert!(
            first.start.checked_add(ARENA_BYTES).unwrap() <= second.start
                || second.start.checked_add(ARENA_BYTES).unwrap() <= first.start
        );
        let source_address = first.source_address();
        let source = first.take_writable(source_address, PAGE);
        let sentinel = [0x31, 0x62, 0x93, 0xc4];
        source.initialize(0, &sentinel);
        // This deliberate second acquisition must refuse the occupied range;
        // it is not a fallback attempt for either independently owned fixture.
        let error = match Self::reserve_at(first.start) {
            Err(error) => error,
            Ok(_) => panic!("occupied neighbor fixture arena was replaced"),
        };
        assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
        assert_eq!(&source.bytes()[..sentinel.len()], &sentinel);
        for len in [PAGE, 2 * PAGE] {
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                first.take_writable(source_address, len)
            }))
            .err()
            .expect("overlapping neighbor fixture transfer accepted");
            let message = failure
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| failure.downcast_ref::<&str>().copied())
                .expect("nontext neighbor fixture refusal");
            assert_eq!(message, "neighbor fixture range not wholly reserved");
        }
        // Refused transfers preserve both the original page and its untouched
        // neighbor, which can still be transferred by its sole owner.
        let adjacent = first.take_writable(source_address + PAGE as u64, PAGE);
        adjacent.initialize(0, &[0x5a]);
        assert_eq!(adjacent.bytes()[0], 0x5a);
        assert_eq!(&source.bytes()[..sentinel.len()], &sentinel);
        // The released hole acquires a new owner. Padding teardown must leave
        // it and both continuously owned transferred pages mapped and intact.
        let released_address = source_address + 2 * PAGE as u64;
        first.release(released_address, PAGE);
        let replacement = Mapping::exact_page(released_address);
        replacement.initialize(0, &[0xa5]);
        drop(first);
        assert_eq!(&source.bytes()[..sentinel.len()], &sentinel);
        assert_eq!(adjacent.bytes()[0], 0x5a);
        assert_eq!(replacement.bytes()[0], 0xa5);
    }
}

impl NativeOracle {
    pub(crate) fn with_neighbor_fixture(
        code: &[u8],
        lengths: &[usize],
    ) -> (Self, Vec<Mapping>, NeighborFixtureArena) {
        assert!(code.len() < PAGE / 2);
        let mut total = PAGE;
        for &len in lengths {
            assert!(len != 0 && len & (PAGE - 1) == 0);
            total = total
                .checked_add(len)
                .expect("fixture mapping length overflow");
        }
        assert!(
            total <= i32::MAX as usize,
            "fixture exceeds one rel32 envelope"
        );
        let mut adjacent = Vec::with_capacity(lengths.len());
        let mut arena = NeighborFixtureArena::new();
        let base = arena.source_address();
        let code_mapping = arena.take_writable(base, PAGE);
        let mut next = base.checked_add(PAGE as u64).unwrap();
        for &len in lengths {
            adjacent.push(arena.take_writable(next, len));
            next = next.checked_add(u64::try_from(len).unwrap()).unwrap();
        }
        (Self::from_code_mapping(code, code_mapping), adjacent, arena)
    }

    pub(crate) fn with_seeded_memory_and_flags_neighbor_fixture(
        code: &[u8],
        memory_seed: u64,
        lengths: &[usize],
    ) -> (Self, Vec<Mapping>, NeighborFixtureArena) {
        let (mut oracle, adjacent, arena) = Self::with_neighbor_fixture(code, lengths);
        oracle.initialize_seeded_memory_and_flags(memory_seed);
        (oracle, adjacent, arena)
    }
}
