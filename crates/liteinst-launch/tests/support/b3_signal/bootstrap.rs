//! Independent kernel-reset bootstrap. CLONE_VM resets the new task's rseq
//! registration before its first instruction. It does not share files, signal
//! dispositions or a thread group. Exec installs the original private mm.
use super::*;
#[cfg(test)]
use std::cell::UnsafeCell;
use std::ffi::CString;

// Parent ABI: (immutable config, separate stack top, kernel pidfd output).
// The parent-only saved R12 is popped only in the parent. A never returns on the
// caller stack and executes no Rust, TLS access, libc callback or allocator.
std::arch::global_asm!(
    ".text",
    ".global {entry}",
    ".type {entry},@function",
    "{entry}:",
    "push r12",
    "mov r12, rdi",
    "mov edi, 0x1100", // CLONE_VM | CLONE_PIDFD, exit_signal0.
    "xor r10d, r10d",
    "xor r8d, r8d",
    "mov eax, 56",
    "syscall",
    "test rax, rax",
    "jz .Lpristine_signal_child",
    "pop r12",
    "ret",
    ".Lpristine_signal_child:",
    "mov rdi, qword ptr [r12 + 32]",
    "test rdi, rdi",
    "js .Lpristine_signal_stdio",
    "mov eax, 3",
    "syscall",
    ".Lpristine_signal_stdio:",
    "mov r14, qword ptr [r12 + 40]",
    "mov rdi, r14",
    "xor esi, esi",
    "mov eax, 33",
    "syscall",
    "test rax, rax",
    "jnz .Lpristine_signal_fail",
    "mov rdi, r14",
    "mov esi, 1",
    "mov eax, 33",
    "syscall",
    "cmp rax, 1",
    "jne .Lpristine_signal_fail",
    "mov rdi, r14",
    "mov esi, 2",
    "mov eax, 33",
    "syscall",
    "cmp rax, 2",
    "jne .Lpristine_signal_fail",
    "mov rdi, r14",
    "mov eax, 3",
    "syscall",
    "mov rdi, qword ptr [r12 + 24]",
    "test rdi, rdi",
    "js .Lpristine_signal_altstack",
    "sub rsp, 16",
    "mov rsi, rsp",
    "mov edx, 1",
    "xor eax, eax",
    "syscall",
    "cmp rax, 1",
    "jne .Lpristine_signal_fail",
    "cmp byte ptr [rsp], 0x51",
    "jne .Lpristine_signal_fail",
    "mov eax, 3", // RDI still names A's private read descriptor.
    "syscall",
    "add rsp, 16",
    ".Lpristine_signal_altstack:",
    "mov r13, qword ptr [r12 + 56]",
    "test r13, r13",
    "jz .Lpristine_signal_exec",
    // Both buffers were allocated by H before clone. Only A writes output;
    // H reads it after the actual EXEC stop (or after physical cleanup).
    "mov rdi, qword ptr [r12 + 48]",
    "xor esi, esi",
    "mov eax, 131", // Native x86-64 sigaltstack.
    "syscall",
    "mov qword ptr [r13], rax",
    "or qword ptr [r13 + 16], 1",
    "xor edi, edi",
    "lea rsi, [r13 + 24]",
    "mov eax, 131",
    "syscall",
    "mov qword ptr [r13 + 8], rax",
    "or qword ptr [r13 + 16], 2",
    "cmp qword ptr [r13], 0",
    "jne .Lpristine_signal_fail",
    "test rax, rax",
    "jnz .Lpristine_signal_fail",
    ".Lpristine_signal_exec:",
    "mov rdi, qword ptr [r12]",
    "mov rsi, qword ptr [r12 + 8]",
    "mov rdx, qword ptr [r12 + 16]",
    "mov eax, 59",
    "syscall",
    ".Lpristine_signal_fail:",
    "mov edi, 127",
    "mov eax, 231",
    "syscall",
    "jmp .Lpristine_signal_fail",
    ".size {entry},.-{entry}",
    entry = sym liteinst_pristine_signal_clone_vm,
);
unsafe extern "C" {
    // Feature-library support and the existing integration target coexist in
    // one link. Unit/integration builds retain their original symbol spelling.
    #[cfg_attr(not(test), link_name = "liteinst_backing_cleanup_clone_vm")]
    fn liteinst_pristine_signal_clone_vm(
        config: *const Config,
        stack: *mut u8,
        pidfd: *mut i32,
    ) -> i64;
}
#[repr(C)]
struct Config {
    path: u64,
    argv: u64,
    env: u64,
    read: i64,
    write: i64,
    null: i64,
    altstack: u64,
    altstack_observation: u64,
}

/// Native x86-64 stack_t, including initialized ABI padding. A query's flags
/// describe whether SP is currently on the stack; they do not expose every
/// stored raw flag. Only a successful explicit setter establishes raw zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
struct Altstack {
    sp: u64,
    flags: u32,
    padding: u32,
    size: u64,
}
#[cfg(test)]
impl Altstack {
    const EMPTY: Self = Self {
        sp: 0,
        flags: 0,
        padding: 0,
        size: 0,
    };
    fn query(until: Instant) -> Self {
        assert!(Instant::now() < until, "pristine altstack query deadline");
        let mut actual = Self::EMPTY;
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_sigaltstack,
                    std::ptr::null::<Self>(),
                    &raw mut actual,
                )
            },
            0
        );
        assert!(Instant::now() < until, "pristine altstack query deadline");
        actual
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg(test)]
struct AltstackObservation {
    set_result: i64,
    query_result: i64,
    observed: u64,
    descriptor: Altstack,
}
#[cfg(test)]
struct AltstackBaseline {
    requested: Box<Altstack>,
    output: Box<UnsafeCell<AltstackObservation>>,
}
#[cfg(test)]
const _: () = {
    assert!(std::mem::size_of::<Altstack>() == 24);
    assert!(std::mem::offset_of!(Altstack, flags) == 8);
    assert!(std::mem::offset_of!(Altstack, size) == 16);
    assert!(std::mem::size_of::<AltstackObservation>() == 48);
    assert!(std::mem::offset_of!(AltstackObservation, query_result) == 8);
    assert!(std::mem::offset_of!(AltstackObservation, observed) == 16);
    assert!(std::mem::offset_of!(AltstackObservation, descriptor) == 24);
};
const _: () = {
    assert!(std::mem::offset_of!(Config, altstack) == 48);
    assert!(std::mem::offset_of!(Config, altstack_observation) == 56);
};
struct Stack {
    base: *mut libc::c_void,
    len: usize,
}
impl Stack {
    fn new() -> Self {
        let len = STACK_LEN + 2 * PAGE;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        let stack = Self { base, len };
        assert_eq!(
            unsafe {
                libc::mprotect(
                    base.cast::<u8>().add(PAGE).cast(),
                    STACK_LEN,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            0
        );
        stack
    }
    fn top(&self) -> *mut u8 {
        unsafe { self.base.cast::<u8>().add(PAGE + STACK_LEN) }
    }
}
impl Drop for Stack {
    fn drop(&mut self) {
        if unsafe { libc::munmap(self.base, self.len) } != 0 {
            std::process::abort();
        }
    }
}
/// Immutable input allocations and separate child stack outlive the actual
/// EXEC witness and every failure cleanup. Parent writes only its private
/// descriptor table and the release socket, never A's argument/config/stack bytes.
pub struct Resources {
    config: Box<Config>,
    stack: Stack,
    #[cfg(test)]
    altstack: Option<AltstackBaseline>,
    _arguments: Vec<CString>,
    _environment: Vec<CString>,
    _argv: Box<[*const libc::c_char]>,
    _env: Box<[*const libc::c_char]>,
    _read: Option<OwnedFd>,
    #[cfg(test)]
    write: Option<OwnedFd>,
    #[cfg(not(test))]
    _write: Option<OwnedFd>,
    _null: OwnedFd,
}
impl Resources {
    pub fn new(
        path: &std::path::Path,
        arguments: &[&str],
        environment: &[String],
        barrier: bool,
    ) -> Self {
        let stack = Stack::new();
        let mut strings = vec![CString::new(path.as_os_str().as_encoded_bytes()).unwrap()];
        strings.extend(arguments.iter().map(|word| CString::new(*word).unwrap()));
        let environment = environment
            .iter()
            .map(|word| CString::new(word.as_str()).unwrap())
            .collect::<Vec<_>>();
        let argv = strings
            .iter()
            .map(|word| word.as_ptr())
            .chain([std::ptr::null()])
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let env = environment
            .iter()
            .map(|word| word.as_ptr())
            .chain([std::ptr::null()])
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let (read, write) = if barrier {
            let mut sockets = [-1; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                        0,
                        sockets.as_mut_ptr(),
                    )
                },
                0
            );
            let read = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
            let write = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
            (Some(duplicate(&read)), Some(duplicate(&write)))
        } else {
            (None, None)
        };
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        let fd = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        assert!(fd >= 3);
        let null = unsafe { OwnedFd::from_raw_fd(fd) };
        let config = Box::new(Config {
            path: strings[0].as_ptr() as u64,
            argv: argv.as_ptr() as u64,
            env: env.as_ptr() as u64,
            read: read.as_ref().map_or(-1, |fd| i64::from(fd.as_raw_fd())),
            write: write.as_ref().map_or(-1, |fd| i64::from(fd.as_raw_fd())),
            null: i64::from(null.as_raw_fd()),
            altstack: 0,
            altstack_observation: 0,
        });
        Self {
            config,
            stack,
            #[cfg(test)]
            altstack: None,
            _arguments: strings,
            _environment: environment,
            _argv: argv,
            _env: env,
            _read: read,
            #[cfg(test)]
            write,
            #[cfg(not(test))]
            _write: write,
            _null: null,
        }
    }
    /// Establish the pristine worker's own finite pre-exec input. This never
    /// reads a production receipt. Reinstalling the same enabled descriptor
    /// with flags zero resolves query ambiguity without touching its storage.
    /// The assembly child repeats this setter after CLONE_VM's reset; exec
    /// then clears sp/size while preserving the explicitly stored raw zero.
    #[cfg(test)]
    pub fn prepare_altstack(&mut self, until: Instant) {
        assert!(self.write.is_some());
        assert!(self.altstack.is_none());
        assert_eq!(mask(), TRACER_MASK);
        let descriptor = Altstack::query(until);
        assert_eq!(descriptor.flags, 0, "enabled off-stack descriptor required");
        assert_eq!(descriptor.padding, 0);
        assert_ne!(descriptor.sp, 0);
        assert!((2048..=1024 * 1024).contains(&descriptor.size));
        let end = descriptor.sp.checked_add(descriptor.size).unwrap();
        let child_start = self.stack.base as u64;
        let child_end = child_start.checked_add(self.stack.len as u64).unwrap();
        assert!(end <= child_start || descriptor.sp >= child_end);
        assert!(Instant::now() < until, "pristine altstack setter deadline");
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_sigaltstack,
                    &raw const descriptor,
                    std::ptr::null_mut::<Altstack>(),
                )
            },
            0
        );
        assert!(Instant::now() < until, "pristine altstack setter deadline");
        assert_eq!(Altstack::query(until), descriptor);
        assert_eq!(mask(), TRACER_MASK);
        let baseline = AltstackBaseline {
            requested: Box::new(descriptor),
            output: Box::new(UnsafeCell::new(AltstackObservation {
                set_result: i64::MIN,
                query_result: i64::MIN,
                observed: 0,
                descriptor: Altstack {
                    sp: u64::MAX,
                    flags: u32::MAX,
                    padding: u32::MAX,
                    size: u64::MAX,
                },
            })),
        };
        self.config.altstack = (&raw const *baseline.requested) as u64;
        self.config.altstack_observation = baseline.output.get() as u64;
        self.altstack = Some(baseline);
        assert!(
            Instant::now() < until,
            "pristine altstack preparation deadline"
        );
    }
    /// Called only while the original pinned child is held at actual EXEC.
    /// It cannot run while A might still write these shared pre-exec outputs.
    #[cfg(test)]
    pub fn authenticate_altstack_at_exec(&self, until: Instant) {
        assert!(
            Instant::now() < until,
            "pristine altstack certificate deadline"
        );
        let baseline = self.altstack.as_ref().unwrap();
        let observed = unsafe { std::ptr::read_volatile(baseline.output.get()) };
        assert_eq!(observed.observed, 3);
        assert_eq!(observed.set_result, 0);
        assert_eq!(observed.query_result, 0);
        assert_eq!(observed.descriptor, *baseline.requested);
        assert_eq!(observed.descriptor.flags, 0);
        assert!(
            Instant::now() < until,
            "pristine altstack certificate deadline"
        );
    }
    pub fn spawn(&self) -> (i32, OwnedFd) {
        assert_eq!(mask(), TRACER_MASK);
        let mut fd = -1_i32;
        let result = unsafe {
            liteinst_pristine_signal_clone_vm(
                &raw const *self.config,
                self.stack.top(),
                &raw mut fd,
            )
        };
        assert!(result > 0, "independent raw VM clone errno {}", -result);
        // This is the first parent-side owner transfer, with no allocation or
        // fallible syscall between atomic clone success and stable ownership.
        (result as i32, unsafe { OwnedFd::from_raw_fd(fd) })
    }
    #[cfg(test)]
    pub fn release(&mut self) {
        let write = self.write.take().unwrap();
        let byte = 0x51_u8;
        assert_eq!(
            unsafe {
                libc::send(
                    write.as_raw_fd(),
                    (&raw const byte).cast(),
                    1,
                    libc::MSG_NOSIGNAL,
                )
            },
            1
        );
        drop(write);
    }
}
