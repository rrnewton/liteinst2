use super::machine::{Machine, PAGE, Snapshot};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;

pub const CASES: &[&str] = &[
    "cpuid",
    "rdtsc",
    "getpid",
    "gettid",
    "read",
    "write",
    "read_ebadf",
    "cross_instruction",
    "cross_redirect",
];
const DATA: &[u8; 32] = b"actual-kernel-read-write-fixture";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Cpuid,
    Rdtsc,
    Syscall,
    Ordinary,
}

/// Actual exclusive source owner, separately borrowed by the core/gate while
/// the fixture retains unrelated I/O/state storage.
pub struct Region {
    pub address: NonNull<u8>,
    pub len: usize,
}

pub struct Program {
    pub name: &'static str,
    pub kind: Kind,
    pub address: NonNull<u8>,
    pub original: Vec<u8>,
    pub heads: Vec<(usize, usize)>,
    pub offset: usize,
    pub pages: usize,
    pipe: [OwnedFd; 2],
    pub buffer: Box<[u8; 64]>,
    benchmark_fd: Option<OwnedFd>,
}

impl Program {
    pub fn new(name: &str) -> (Region, Self) {
        let name = *CASES
            .iter()
            .find(|&&value| value == name)
            .expect("unknown finite fixture case");
        let pages = if name.starts_with("cross_") { 2 } else { 1 };
        let offset = if pages == 2 { PAGE - 2 } else { 64 };
        let (kind, instruction): (Kind, &[u8]) = match name {
            "cpuid" => (Kind::Cpuid, &[0x0f, 0xa2]),
            "rdtsc" => (Kind::Rdtsc, &[0x0f, 0x31]),
            "cross_instruction" => (Kind::Ordinary, &[0x0f, 0x1f, 0x44, 0x00, 0x00]),
            _ => (Kind::Syscall, &[0x0f, 0x05]),
        };
        let mut original = vec![0xcc; pages * PAGE];
        original[offset..offset + instruction.len()].copy_from_slice(instruction);
        let mut heads = vec![(offset, instruction.len())];
        let mut next = offset + instruction.len();
        // Literal neutral tail gives the selected publisher a five-byte window.
        while next < offset + 5 {
            original[next] = 0x90;
            heads.push((next, 1));
            next += 1;
        }
        original[next] = 0xc3;
        heads.push((next, 1));
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                original.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(memory, libc::MAP_FAILED);
        let address = NonNull::new(memory.cast::<u8>()).unwrap();
        unsafe {
            std::ptr::copy_nonoverlapping(original.as_ptr(), address.as_ptr(), original.len());
        }
        assert_eq!(
            unsafe { libc::mprotect(memory, original.len(), libc::PROT_READ | libc::PROT_EXEC) },
            0
        );
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let pipe = unsafe { [OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])] };
        (
            Region {
                address,
                len: original.len(),
            },
            Self {
                name,
                kind,
                address,
                original,
                heads,
                offset,
                pages,
                pipe,
                buffer: Box::new([0xa5; 64]),
                benchmark_fd: None,
            },
        )
    }

    pub fn entry(&self) -> usize {
        self.address.as_ptr() as usize + self.offset
    }

    pub fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), self.original.len()) }
    }

    pub fn seed(&mut self, machine: &mut Machine, benchmark: bool) {
        machine.initial[0] = match self.name {
            "read" | "read_ebadf" => libc::SYS_read as u64,
            "write" => libc::SYS_write as u64,
            "gettid" => libc::SYS_gettid as u64,
            "cpuid" => 0,
            _ => libc::SYS_getpid as u64,
        };
        if self.kind == Kind::Cpuid {
            machine.initial[2] = 0;
        }
        if matches!(self.name, "read" | "write" | "read_ebadf") {
            self.buffer.fill(0xa5);
            if self.name == "write" {
                self.buffer[..32].copy_from_slice(DATA);
            }
            let fd = if self.name == "read_ebadf" {
                -1
            } else if benchmark {
                if self.benchmark_fd.is_none() {
                    let path = if self.name == "read" {
                        c"/dev/zero"
                    } else {
                        c"/dev/null"
                    };
                    let flags = if self.name == "read" {
                        libc::O_RDONLY
                    } else {
                        libc::O_WRONLY
                    };
                    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
                    assert!(fd >= 0);
                    self.benchmark_fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                }
                self.benchmark_fd.as_ref().unwrap().as_raw_fd()
            } else if self.name == "read" {
                assert_eq!(
                    unsafe { libc::write(self.pipe[1].as_raw_fd(), DATA.as_ptr().cast(), 32) },
                    32
                );
                self.pipe[0].as_raw_fd()
            } else {
                self.pipe[1].as_raw_fd()
            };
            machine.initial[5] = fd as i64 as u64;
            machine.initial[4] = self.buffer.as_mut_ptr() as u64;
            machine.initial[3] = 32;
        }
    }

    pub fn check_effect(&self, state: &Snapshot) {
        match self.name {
            "getpid" | "cross_redirect" => {
                assert_eq!(state.registers[0], unsafe { libc::getpid() } as u64)
            }
            "gettid" => assert_eq!(
                state.registers[0],
                unsafe { libc::syscall(libc::SYS_gettid) } as u64
            ),
            "read" => {
                assert_eq!(state.registers[0], 32);
                assert_eq!(&self.buffer[..32], DATA);
                assert_eq!(&self.buffer[32..], &[0xa5; 32]);
            }
            "write" => {
                assert_eq!(state.registers[0], 32);
                let mut actual = [0_u8; 33];
                assert_eq!(
                    unsafe {
                        libc::read(
                            self.pipe[0].as_raw_fd(),
                            actual.as_mut_ptr().cast(),
                            actual.len(),
                        )
                    },
                    32
                );
                assert_eq!(&actual[..32], DATA);
                assert_eq!(actual[32], 0);
                assert_eq!(&self.buffer[..32], DATA);
                assert_eq!(&self.buffer[32..], &[0xa5; 32]);
            }
            "read_ebadf" => {
                assert_eq!(state.registers[0] as i64, -i64::from(libc::EBADF));
                assert_eq!(&*self.buffer, &[0xa5; 64]);
            }
            _ => {}
        }
    }

    pub fn check_repeated_result(&self, result: u64) {
        match self.name {
            "getpid" | "cross_redirect" => assert_eq!(result, unsafe { libc::getpid() } as u64),
            "gettid" => assert_eq!(result, unsafe { libc::syscall(libc::SYS_gettid) } as u64),
            "read" | "write" => assert_eq!(result, 32),
            "read_ebadf" => assert_eq!(result as i64, -i64::from(libc::EBADF)),
            "cross_instruction" => assert_eq!(result, libc::SYS_getpid as u64),
            _ => {}
        }
    }

    pub fn compare(&self, original: &Snapshot, actual: &Snapshot, bracket: (u64, u64)) {
        if self.kind == Kind::Rdtsc {
            assert_eq!(actual.registers[0] >> 32, 0);
            assert_eq!(actual.registers[3] >> 32, 0);
            let observed = actual.registers[0] | (actual.registers[3] << 32);
            assert!(
                (bracket.0..=bracket.1).contains(&observed),
                "actual RDTSC outside its measured bracket"
            );
        }
        for (index, (expected, observed)) in
            original.registers.iter().zip(&actual.registers).enumerate()
        {
            if self.kind != Kind::Rdtsc || (index != 0 && index != 3) {
                assert_eq!(expected, observed, "native/gated register {index} differs");
            }
        }
        assert_eq!(
            original.xstate, actual.xstate,
            "native/gated architectural XSTATE differs"
        );
        assert_eq!(
            original.red_zone_and_return, actual.red_zone_and_return,
            "native/gated red zone/return differs"
        );
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::munmap(self.address.as_ptr().cast(), self.len) },
            0
        );
    }
}

// This separate boundary control observes live gate metrics from a real host
// callback. These globals are used only by the authenticated singleton thread,
// while the pointed-to ArmedGate remains immovable and alive on its stack.
static mut BOUNDARY_GATE: *const core::ffi::c_void = std::ptr::null();
static mut BOUNDARY_RETURN: usize = 0;
static mut BOUNDARY_FIRST: bool = false;
static mut BOUNDARY_OBSERVED: Option<liteinst_inprocess::GateMetrics> = None;
static mut BOUNDARY_CALLS: u64 = 0;

extern "C" fn boundary_observe(actual_return: usize) -> u64 {
    unsafe {
        let expected_return = BOUNDARY_RETURN;
        assert_eq!(actual_return, expected_return);
        BOUNDARY_CALLS = BOUNDARY_CALLS.checked_add(1).unwrap();
        if !BOUNDARY_GATE.is_null() {
            let gate = &*BOUNDARY_GATE.cast::<liteinst_inprocess::ArmedGate<'_>>();
            let metrics = gate.metrics();
            if BOUNDARY_FIRST {
                assert_eq!(metrics.faults, 1);
                assert_eq!(metrics.admitted_pages, 1);
                BOUNDARY_OBSERVED = Some(metrics);
                BOUNDARY_FIRST = false;
            } else {
                assert_eq!(metrics.faults, 2);
                assert_eq!(metrics.admitted_pages, 2);
            }
        }
    }
    7
}

pub fn boundary_call(iterations: usize) {
    use super::machine::{boundary_invoke, boundary_repeat};
    use super::{BATCHES, ns};
    use liteinst_inprocess::{InstructionExtent, PageBundle, PreparedGate};
    use std::time::Instant;
    let started = Instant::now();
    // Third page is the immutable direct CALL target, deliberately outside the
    // two-page gate. It forwards the actual stack word to the host callback.
    let mut bytes = vec![0xcc; 3 * PAGE];
    let offset = PAGE - 5;
    let helper = 2 * PAGE + 64;
    bytes[offset] = 0xe8;
    bytes[offset + 1..PAGE].copy_from_slice(&i32::try_from(helper - PAGE).unwrap().to_le_bytes());
    bytes[PAGE] = 0xc3;
    bytes[helper..helper + 4].copy_from_slice(&[0x48, 0x8b, 0x3c, 0x24]); // MOV RDI,[RSP]
    bytes[helper + 4..helper + 6].copy_from_slice(&[0x48, 0xb8]);
    bytes[helper + 6..helper + 14]
        .copy_from_slice(&(boundary_observe as *const () as u64).to_le_bytes());
    bytes[helper + 14..helper + 16].copy_from_slice(&[0xff, 0xe0]); // JMP RAX
    let raw = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes.len(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(raw, libc::MAP_FAILED);
    let address = NonNull::new(raw.cast::<u8>()).unwrap();
    let mut owner = Region {
        address,
        len: bytes.len(),
    };
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), address.as_ptr(), bytes.len());
    }
    assert_eq!(
        unsafe { libc::mprotect(raw, bytes.len(), libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    let entry = address.as_ptr() as usize + offset;
    unsafe {
        BOUNDARY_RETURN = address.as_ptr() as usize + PAGE;
    }
    let fixture_preparation_ns = ns(started);
    let started = Instant::now();
    assert_eq!(boundary_invoke(entry), 7);
    let native_capture_ns = ns(started);
    let mut native_ns = [0_u64; BATCHES];
    for elapsed in &mut native_ns {
        let started = Instant::now();
        let result = boundary_repeat(entry, iterations);
        *elapsed = ns(started);
        assert_eq!(result, 7);
    }
    let extents = [
        InstructionExtent {
            offset,
            len: 5,
            bundle: 0,
        },
        InstructionExtent {
            offset: PAGE,
            len: 1,
            bundle: 1,
        },
    ];
    let bundles = [
        PageBundle {
            first_page: 0,
            page_count: 1,
        },
        PageBundle {
            first_page: 1,
            page_count: 1,
        },
    ];
    let prepared =
        unsafe { PreparedGate::new(&mut owner, address, &bytes[..2 * PAGE], &extents, &bundles) }
            .unwrap();
    let armed = unsafe { prepared.arm() }.unwrap();
    assert_eq!(armed.metrics().faults, 0);
    unsafe {
        BOUNDARY_GATE = (&armed as *const liteinst_inprocess::ArmedGate<'_>).cast();
        BOUNDARY_FIRST = true;
    }
    let started = Instant::now();
    assert_eq!(boundary_invoke(entry), 7);
    let first_call_ns = ns(started);
    let intermediate = unsafe { BOUNDARY_OBSERVED }.expect("actual pre-RET callback absent");
    assert_eq!(intermediate.faults, 1);
    assert_eq!(intermediate.admitted_pages, 1);
    let first_metrics = armed.metrics();
    assert_eq!(first_metrics.faults, 2);
    assert_eq!(first_metrics.admitted_pages, 2);
    let mut gated_ns = [0_u64; BATCHES];
    for elapsed in &mut gated_ns {
        let started = Instant::now();
        let result = boundary_repeat(entry, iterations);
        *elapsed = ns(started);
        assert_eq!(result, 7);
    }
    assert_eq!(armed.metrics(), first_metrics);
    assert_eq!(boundary_invoke(entry), 7);
    assert_eq!(armed.metrics(), first_metrics);
    unsafe {
        let calls = BOUNDARY_CALLS;
        assert_eq!(calls, 3 + 2 * BATCHES as u64 * iterations as u64);
        BOUNDARY_GATE = std::ptr::null();
    }
    let metrics = armed.disarm().unwrap();
    assert_eq!(metrics, first_metrics);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(address.as_ptr(), bytes.len()) },
        bytes
    );
    println!(
        "{{\"schema_version\":1,\"case\":\"boundary_call\",\"status\":\"passed\",\"iterations\":{},\"batches\":{},\"register_words\":null,\"xstate_mask\":null,\"xstate_compared_bytes\":null,\"red_zone_bytes\":null,\"comparisons\":2,\"pushed_return_ok\":true,\"return_page_pending\":true,\"fixture_preparation_ns\":{},\"selected_preparation_ns\":0,\"publication_ns\":0,\"gate_preparation_ns\":{},\"arm_ns\":{},\"native_capture_ns\":{},\"first_call_ns\":{},\"handler_first_touch_ns\":{},\"handler_max_first_touch_ns\":{},\"faults\":{},\"admitted_pages\":{},\"native_steady_ns\":{:?},\"gated_steady_ns\":{:?}}}",
        iterations,
        BATCHES,
        fixture_preparation_ns,
        metrics.preparation_ns,
        metrics.arm_ns,
        native_capture_ns,
        first_call_ns,
        metrics.first_touch_ns,
        metrics.max_first_touch_ns,
        metrics.faults,
        metrics.admitted_pages,
        native_ns,
        gated_ns
    );
}
