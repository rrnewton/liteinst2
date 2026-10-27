use super::super::{Descriptor, DescriptorIdentity, Page, descriptor, projection};
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use std::{fs::File, io::Read, os::fd::IntoRawFd};

fn valid(storage: &mut [u8]) -> Query {
    storage.fill(0);
    storage[..9].copy_from_slice(b"/fixture\0");
    let mut q = Query::new(0x2000, storage);
    q.vma_start = 0x2000;
    q.vma_end = 0x3000;
    q.vma_page_size = PAGE;
    q.inode = 17;
    q.dev_major = 8;
    q.dev_minor = 3;
    q.vma_name_size = 9;
    q
}
fn refused_as(q: Query, address: u64, storage: &[u8], reason: &str) {
    assert!(matches!(q.identity(address, storage), Err(GateError::Refused(s)) if s == reason));
}
#[test]
fn query_rejects_malformed_kernel_rows() {
    let mut storage = [0; 32];
    let q = valid(&mut storage);
    assert_eq!(
        q.identity(0x2000, &storage).unwrap(),
        FileIdentity {
            major: 8,
            minor: 3,
            inode: 17
        }
    );
    let mutations: [fn(&mut Query); 10] = [
        |q| q.vma_flags = 1,
        |q| q.vma_offset = PAGE,
        |q| q.inode = 0,
        |q| q.vma_page_size = PAGE * 2,
        |q| q.vma_name_size = 0,
        |q| q.vma_name_size = 1,
        |q| q.vma_name_size = 33,
        |q| q.vma_name_size = u32::MAX,
        |q| q.vma_name_size = 8,
        |q| q.vma_name_size = 10,
    ];
    for mutate in mutations {
        let mut bad = q;
        mutate(&mut bad);
        refused_as(bad, 0x2000, &storage, "exec identity probe mapping differs");
    }
    for index in [0, 4] {
        storage[index] = 0;
        refused_as(q, 0x2000, &storage, "exec identity probe mapping differs");
        valid(&mut storage);
    }
    storage[8] = b'x';
    refused_as(q, 0x2000, &storage, "exec identity probe mapping differs");
}
#[test]
fn query_rejects_changed_requests_and_geometry() {
    let mut storage = [0; 32];
    let q = valid(&mut storage);
    let mutations: [fn(&mut Query); 6] = [
        |q| q.size -= 1,
        |q| q.query_flags = 1,
        |q| q.query_addr += PAGE,
        |q| q.vma_name_addr += 1,
        |q| q.build_id_addr = 1,
        |q| q.build_id_size = 1,
    ];
    for mutate in mutations {
        let mut bad = q;
        mutate(&mut bad);
        refused_as(bad, 0x2000, &storage, "exec identity query request changed");
    }
    for (start, end) in [(0x1000, 0x3000), (0x2000, 0x4000), (0x2000, 0x2000)] {
        let mut bad = q;
        bad.vma_start = start;
        bad.vma_end = end;
        refused_as(
            bad,
            0x2000,
            &storage,
            "exec identity probe mapping is absent or merged",
        );
    }
    for address in [0, 0x2001, !(PAGE - 1)] {
        refused_as(q, address, &storage, "exec identity probe geometry differs");
    }
}

// Only system calls touch this exclusively owned anonymous range; no Rust
// reference points into it. Moving its integer address transfers its ownership.
struct Region {
    address: usize,
    bytes: usize,
}
impl Region {
    fn new(pages: usize) -> Self {
        let bytes = pages.checked_mul(PAGE as usize).unwrap();
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(
            address,
            libc::MAP_FAILED,
            "anonymous pressure allocation failed"
        );
        Self {
            address: address as usize,
            bytes,
        }
    }
    fn protect(&self, page: usize, protection: i32) {
        let offset = page.checked_mul(PAGE as usize).unwrap();
        assert!(offset + PAGE as usize <= self.bytes);
        assert_eq!(
            unsafe {
                libc::mprotect(
                    (self.address + offset) as *mut libc::c_void,
                    PAGE as usize,
                    protection,
                )
            },
            0,
            "pressure mprotect failed"
        );
    }
}
impl Drop for Region {
    fn drop(&mut self) {
        if unsafe { libc::munmap(self.address as *mut libc::c_void, self.bytes) } != 0 {
            std::process::abort();
        }
    }
}
struct Churn {
    stop: Arc<AtomicBool>,
    cycles: Arc<AtomicUsize>,
    worker: Option<JoinHandle<()>>,
}
impl Churn {
    fn new() -> Self {
        let region = Region::new(3);
        let stop = Arc::new(AtomicBool::new(false));
        let cycles = Arc::new(AtomicUsize::new(0));
        let (s, c) = (stop.clone(), cycles.clone());
        let worker = thread::spawn(move || {
            while !s.load(Ordering::Acquire) {
                region.protect(1, libc::PROT_READ);
                region.protect(1, libc::PROT_NONE);
                c.fetch_add(1, Ordering::Release);
            }
        });
        Self {
            stop,
            cycles,
            worker: Some(worker),
        }
    }
    fn progressed(&self, previous: usize, until: Instant) -> usize {
        while self.cycles.load(Ordering::Acquire) <= previous {
            assert!(
                !self.worker.as_ref().unwrap().is_finished(),
                "churn worker exited early"
            );
            assert!(Instant::now() < until, "churn progress backstop expired");
            thread::yield_now();
        }
        self.cycles.load(Ordering::Acquire)
    }
}
impl Drop for Churn {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let failed = self.worker.take().unwrap().join().is_err();
        if failed && !thread::panicking() {
            panic!("churn worker panicked");
        }
    }
}
#[derive(Debug, Eq, PartialEq)]
struct Observation {
    fds: [i32; 2],
    opened: DescriptorIdentity,
    vma: FileIdentity,
    geometry: [u64; 5],
    name: Vec<u8>,
}
fn observed(
    maps: &Descriptor,
    exe: &Descriptor,
    page: &Page<'_>,
    storage: &mut [u8],
) -> Result<Observation, i32> {
    storage.fill(0);
    let mut q = Query::new(page.address(), storage);
    let result = unsafe { libc::ioctl(maps.raw(), REQUEST, &raw mut q) };
    assert!(result == 0 || result == -1, "unexpected ioctl result");
    if result == -1 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    let vma = q
        .identity(page.address(), storage)
        .expect("queried VMA must satisfy every guard");
    Ok(Observation {
        fds: [maps.raw(), exe.raw()],
        opened: descriptor(exe).unwrap(),
        vma,
        geometry: [
            q.vma_start,
            q.vma_end,
            q.vma_flags,
            q.vma_page_size,
            q.vma_offset,
        ],
        name: storage[..q.vma_name_size as usize].to_vec(),
    })
}
#[test]
fn native_query_or_legacy_profile_under_real_vma_pressure() {
    let exe = Descriptor::new(File::open("/proc/self/exe").unwrap().into_raw_fd());
    let opened = descriptor(&exe).unwrap();
    let page = Page::new(&exe).unwrap(); // Real executable fd; exactly one PROT_NONE page.
    let pressure = Region::new(516);
    for i in (0..516).step_by(2) {
        pressure.protect(i, libc::PROT_READ);
    }
    let mut raw = Vec::new();
    File::open("/proc/self/maps")
        .unwrap()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .unwrap();
    assert!(
        raw.len() <= 1024 * 1024 && raw.ends_with(b"\n"),
        "complete maps capture required"
    );
    let rows = raw.iter().filter(|&&b| b == b'\n').count();
    let owned = std::str::from_utf8(&raw)
        .unwrap()
        .lines()
        .filter(|line| {
            let (a, b) = line
                .split_whitespace()
                .next()
                .unwrap()
                .split_once('-')
                .unwrap();
            let (a, b) = (
                usize::from_str_radix(a, 16).unwrap(),
                usize::from_str_radix(b, 16).unwrap(),
            );
            a < pressure.address + pressure.bytes && b > pressure.address
        })
        .count();
    assert!(
        rows > MAP_ROWS && owned > MAP_ROWS,
        "measured own pressure must exceed 512 VMAs"
    );
    let reason = if raw.len() > MAP_BYTES {
        "exec source maps exceed fixed capture bound"
    } else {
        "exec source maps are malformed or excessive"
    };
    assert!(matches!(projection(&raw, page.address()), Err(GateError::Refused(s)) if s == reason));
    let maps = Descriptor::new(File::open("/proc/self/maps").unwrap().into_raw_fd());
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstatfs(maps.raw(), &mut fs) }, 0);
    assert_eq!(fs.f_type, libc::PROC_SUPER_MAGIC as libc::__fsword_t);
    let mut storage = [0; MAP_BYTES];
    let first = match observed(&maps, &exe, &page, &mut storage) {
        Ok(row) => row,
        Err(libc::ENOTTY) => {
            assert_eq!(descriptor(&exe).unwrap(), opened);
            println!(
                "native_query profile=UNSUPPORTED_ENOTTY_LEGACY queries=0 maps_rows={rows} owned_rows={owned} strict_text_refusal=true"
            );
            return; // Explicit legacy profile only; no atomic-query credit.
        }
        Err(errno) => panic!("PROCMAP_QUERY failed with errno {errno}"),
    };
    assert_eq!(first.opened, opened); // Never equate overlay fstat and VMA device projections.
    let churn = Churn::new();
    let until = Instant::now() + Duration::from_secs(10);
    let mut cycles = churn.progressed(0, until);
    for _ in 0..128 {
        assert_eq!(observed(&maps, &exe, &page, &mut storage).unwrap(), first);
        cycles = churn.progressed(cycles, until);
    }
    drop(churn); // Join before reporting, including worker error propagation.
    assert_eq!(descriptor(&exe).unwrap(), opened);
    page.unmap();
    maps.close().unwrap();
    exe.close().unwrap();
    drop(pressure);
    println!(
        "native_query profile=ATOMIC queries=128 baseline_queries=1 maps_rows={rows} owned_rows={owned} churn_cycles={cycles} strict_text_refusal=true"
    );
}
