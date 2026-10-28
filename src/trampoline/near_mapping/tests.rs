use super::*;
use std::sync::mpsc;
use std::thread::JoinHandle;

fn candidates(start: usize, end: usize, next_ip: usize, len: usize, page: usize) -> NearCandidates {
    let mut gaps = Vec::new();
    add_gap_candidate(&mut gaps, start, end, start, end - len, next_ip, len, page);
    gaps.sort_unstable_by_key(|gap| order_near_key(gap.next, next_ip));
    NearCandidates::new(gaps, page)
}

#[test]
fn reachable_mapping_gap_walk_is_complete_aligned_and_below_first() {
    let page = 0x1000;
    assert_eq!(
        candidates(0x1000, 0x7000, 0x3505, page, page).collect::<Vec<_>>(),
        [0x3000, 0x2000, 0x1000, 0x4000, 0x5000, 0x6000]
    );
    assert_eq!(
        candidates(0x1000, 0x7000, 0x3505, 2 * page, page).collect::<Vec<_>>(),
        [0x3000, 0x2000, 0x1000, 0x4000, 0x5000]
    );
    let mut gaps = Vec::new();
    add_gap_candidate(
        &mut gaps, 0x4000, 0x9000, 0x1000, 0xa000, 0x6505, page, page,
    );
    add_gap_candidate(
        &mut gaps, 0x1000, 0x3000, 0x1000, 0xa000, 0x6505, page, page,
    );
    gaps.sort_unstable_by_key(|gap| order_near_key(gap.next, 0x6505));
    assert_eq!(
        NearCandidates::new(gaps, page).collect::<Vec<_>>(),
        [0x6000, 0x5000, 0x4000, 0x2000, 0x1000, 0x7000, 0x8000]
    );
    assert_eq!(
        candidates(0x1001, 0x3fff, 0x2005, page, page).collect::<Vec<_>>(),
        [0x2000]
    );
}

#[test]
fn reachable_mapping_full_extent_and_address_boundaries_are_exact() {
    let page = 0x1000;
    let len = 3 * page;
    let next = 0x1_0000_0000;
    let (low, high) = near_start_bounds(next, len, page).unwrap();
    assert_eq!(low as i128 - next as i128, i32::MIN as i128);
    assert_eq!(
        high as i128 + len as i128 - 1 - next as i128,
        i32::MAX as i128
    );
    assert!(i32::try_from(low as i128 - 1 - next as i128).is_err());
    assert!(i32::try_from(high as i128 + len as i128 - next as i128).is_err());
    let mut gaps = Vec::new();
    add_gap_candidate(&mut gaps, 0, usize::MAX, low, high, next, len, page);
    let capacity = gaps
        .iter()
        .map(|g| g.next.abs_diff(g.last) / page + 1)
        .sum::<usize>();
    assert!(capacity <= (1_u64 << 32) as usize / page);
    for gap in gaps {
        for start in [gap.next, gap.last] {
            assert_eq!(start % page, 0);
            assert!(i32::try_from(start as i128 - next as i128).is_ok());
            assert!(i32::try_from(start as i128 + len as i128 - 1 - next as i128).is_ok());
        }
    }
    assert_eq!(
        near_start_bounds(usize::MAX, page, page).unwrap().1,
        usize::MAX - page
    );
    assert_eq!(near_start_bounds(0, page, page).unwrap().0, page);
    for (len, page) in [(0, 4096), (4097, 4096), (4096, 0), (4096, 3)] {
        assert!(matches!(
            near_start_bounds(next, len, page),
            Err(TrampolineError::InvalidPageSize)
        ));
    }
}

#[test]
fn reachable_mapping_occupied_exhaustion_and_errno_early_stop() {
    let mut visited = Vec::new();
    assert!(matches!(
        claim_near_candidate([0x3000, 0x2000, 0x1000], |at| {
            visited.push(at);
            Ok(false)
        }),
        Err(TrampolineError::NoReachableMapping)
    ));
    assert_eq!(visited, [0x3000, 0x2000, 0x1000]);
    for errno in [libc::ENOMEM, libc::EACCES, libc::EPERM, libc::EINVAL] {
        let mut visited = Vec::new();
        assert!(
            matches!(claim_near_candidate([0x3000, 0x2000, 0x1000], |at| {
            visited.push(at);
            Err(TrampolineError::BackingStore { operation: "injected mmap errno", errno })
        }), Err(TrampolineError::BackingStore { errno: actual, .. }) if actual == errno)
        );
        assert_eq!(visited, [0x3000]);
    }
}

struct Reservation {
    address: usize,
    len: usize,
}
impl Reservation {
    fn new(len: usize) -> Self {
        let at = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(at, libc::MAP_FAILED);
        let result = Self {
            address: at as usize,
            len,
        };
        // This fixture alone owns the complete reservation.
        unsafe { core::ptr::write_bytes(at, 0x5a, len) };
        result
    }
    fn hole(&self, start: usize, len: usize) {
        assert!(
            start >= self.address && start.checked_add(len).unwrap() <= self.address + self.len
        );
        assert_eq!(unsafe { libc::munmap(start as *mut libc::c_void, len) }, 0);
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if unsafe { libc::munmap(self.address as *mut libc::c_void, self.len) } != 0 {
            std::process::abort();
        }
    }
}
struct Competitor {
    request: Option<mpsc::SyncSender<usize>>,
    release: Option<mpsc::SyncSender<()>>,
    worker: Option<JoinHandle<()>>,
}
impl Drop for Competitor {
    fn drop(&mut self) {
        drop(self.request.take());
        drop(self.release.take());
        let failed = self.worker.take().unwrap().join().is_err();
        if failed && !std::thread::panicking() {
            panic!("competing mapper failed");
        }
    }
}

#[test]
fn reachable_mapping_native_stale_gap_retains_competitor() {
    run_staged_drop_test(
        "trampoline::near_mapping::tests::reachable_mapping_native_stale_gap_retains_competitor",
        stale_gap_body,
    );
}
fn stale_gap_body() {
    let page = page_size().unwrap();
    let guard = Reservation::new(6 * page);
    let start = guard.address + page;
    let end = start + 3 * page;
    let next_ip = end;
    let first = end - page;
    let second = first - page;
    // Every automatic RW alias and growable collection is prepared while the
    // complete guard reservation still occupies the future hole.
    let mut mapping = PendingMapping::new(page).unwrap();
    let mut last = PendingMapping::new(page).unwrap();
    let mut exhausted = PendingMapping::new(page).unwrap();
    let mut wrong = PendingMapping::new(page).unwrap();
    let mut reclaimed = PendingMapping::new(page).unwrap();
    let frozen = candidates(start, end, next_ip, page, page);
    let full = candidates(start, end, next_ip, page, page);
    let mut visits = Vec::with_capacity(3);
    let mut occupied = Vec::with_capacity(3);
    let (request, requested) = mpsc::sync_channel::<usize>(1);
    let (ready, observed) = mpsc::sync_channel::<()>(1);
    let (release, released) = mpsc::sync_channel::<()>(1);
    // Spawn before making the interior hole, so thread setup cannot consume it.
    let worker = std::thread::spawn(move || {
        let scratch = Vec::<u8>::with_capacity(page);
        core::hint::black_box(&scratch); // Establish this worker's allocator before the hole.
        ready.send(()).unwrap();
        let Ok(address) = requested.recv() else {
            return;
        };
        let at = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_ne!(at, libc::MAP_FAILED);
        let owned = Reservation {
            address: at as usize,
            len: page,
        };
        assert_eq!(owned.address, address);
        unsafe { core::ptr::write_bytes(at, 0xa5, page) };
        ready.send(()).unwrap();
        let _ = released.recv();
        assert!(
            unsafe { core::slice::from_raw_parts(at.cast::<u8>(), page) }
                .iter()
                .all(|&b| b == 0xa5)
        );
    });
    let mut competitor = Competitor {
        request: Some(request),
        release: Some(release),
        worker: Some(worker),
    };
    observed
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    guard.hole(start, 3 * page);
    competitor.request.take().unwrap().send(first).unwrap();
    observed
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let claimed = claim_near_candidate(frozen, |address| {
        let result = mapping.try_map_executable(address);
        visits.push((address, matches!(result, Ok(false))));
        result
    })
    .unwrap();
    assert_eq!(visits, [(first, true), (second, false)]);
    assert_eq!(claimed, second);
    assert_eq!(mapping.executable as usize, second);
    assert_eq!(mapping.len, page);
    assert!(i32::try_from(claimed as i128 - next_ip as i128).is_ok());
    assert!(i32::try_from(claimed as i128 + page as i128 - 1 - next_ip as i128).is_ok());
    // Occupy the last start: the same frozen geometric inventory must exhaust.
    assert!(last.try_map_executable(start).unwrap());
    // The old exact-address API still refuses an occupied address; its own RW
    // setup cannot steal a gap slot because all three slots are now occupied.
    assert!(
        matches!(PendingMapping::allocate_exact(first, page, first as u64),
        Err(TrampolineError::ExactAddressUnavailable { address }) if address == first as u64)
    );
    assert!(matches!(
        claim_near_candidate(full, |at| {
            let result = exhausted.try_map_executable(at);
            occupied.push((at, matches!(result, Ok(false))));
            result
        }),
        Err(TrampolineError::NoReachableMapping)
    ));
    assert_eq!(occupied, [(first, true), (second, true), (start, true)]);
    // Model a successful old-kernel mmap at the wrong address using a real
    // owned alias. The exact address guard must unmap it and never publish it.
    drop(last);
    let unexpected = unsafe {
        libc::mmap(
            start as *mut libc::c_void,
            page,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
            wrong.fd,
            0,
        )
    };
    assert_ne!(unexpected, libc::MAP_FAILED);
    let unexpected_owner = Reservation {
        address: unexpected as usize,
        len: page,
    };
    assert_eq!(unexpected_owner.address, start);
    core::mem::forget(unexpected_owner); // The helper takes ownership before any fallible cleanup.
    assert!(matches!(
        wrong.accept_executable_mapping(first, unexpected),
        Err(TrampolineError::BackingStore {
            errno: libc::EADDRNOTAVAIL,
            ..
        })
    ));
    assert!(wrong.executable.is_null());
    assert!(reclaimed.try_map_executable(start).unwrap());
    for address in [guard.address, end, end + page] {
        assert!(
            unsafe { core::slice::from_raw_parts(address as *const u8, page) }
                .iter()
                .all(|&b| b == 0x5a)
        );
    }
    drop(reclaimed);
    drop(wrong);
    drop(exhausted);
    drop(mapping);
    drop(competitor); // Joins and checks every competitor sentinel byte.
    drop(guard);
}
