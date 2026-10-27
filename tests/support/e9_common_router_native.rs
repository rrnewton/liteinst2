//! Controlled single-threaded test bootstrap. This is not the live publisher's
//! process-lifetime router, and grants no ordinary-loader/artifact conversion.
use super::*;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use router_contract::Route;

const STACK_LEN: usize = 32 * PAGE;
static TABLE: AtomicPtr<u64> = AtomicPtr::new(core::ptr::null_mut());
static COUNT: AtomicUsize = AtomicUsize::new(0);

core::arch::global_asm!(
    ".pushsection .text",
    ".global li2_common_router_entry", ".type li2_common_router_entry,@function",
    "li2_common_router_entry:", "endbr64", "int3",
    ".global li2_common_router_captured", "li2_common_router_captured:",
    "cmp edi,4", "jne 4f", "test rsi,rsi", "jz 4f", "test rdx,rdx", "jz 4f",
    "cmp dword ptr [rsi],4", "jne 4f", "cmp dword ptr [rsi+8],2", "jne 4f",
    "cmp qword ptr [rdx+{trap}],6", "jne 4f",
    "mov r8,qword ptr [rdx+{rip}]", "cmp qword ptr [rsi+16],r8", "jne 4f",
    "mov r9,qword ptr [rip+{table}]", "test r9,r9", "jz 4f",
    "mov rcx,qword ptr [rip+{count}]", "test rcx,rcx", "jz 4f", "cmp rcx,87", "ja 4f",
    "2:", "cmp qword ptr [r9],r8", "je 3f", "add r9,16", "dec rcx", "jnz 2b", "jmp 4f",
    "3:", "mov rax,qword ptr [r9+8]", "mov qword ptr [rdx+{rip}],rax", "ret",
    // Unowned/user-generated faults terminate the isolated child; they cannot
    // produce a success return. No syscall occurs on the success path.
    "4:", "mov edi,124", "mov eax,231", "syscall", "ud2",
    ".size li2_common_router_entry,.-li2_common_router_entry",
    ".global li2_common_router_restorer", ".type li2_common_router_restorer,@function",
    "li2_common_router_restorer:", "mov rax,15",
    ".global li2_common_router_syscall", "li2_common_router_syscall:",
    "syscall", "ud2", ".size li2_common_router_restorer,.-li2_common_router_restorer",
    ".global li2_common_router_end", "li2_common_router_end:", ".popsection",
    table = sym TABLE, count = sym COUNT,
    rip = const core::mem::offset_of!(libc::ucontext_t,uc_mcontext)
        + core::mem::offset_of!(libc::mcontext_t,gregs) + libc::REG_RIP as usize*8,
    trap = const core::mem::offset_of!(libc::ucontext_t,uc_mcontext)
        + core::mem::offset_of!(libc::mcontext_t,gregs) + libc::REG_TRAPNO as usize*8,
);
unsafe extern "C" {
    fn li2_common_router_entry();
    fn li2_common_router_captured();
    fn li2_common_router_restorer();
    fn li2_common_router_syscall();
    fn li2_common_router_end();
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Action {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}
fn action() -> Action {
    let mut a = Action {
        handler: 0,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                libc::SIGILL,
                core::ptr::null::<Action>(),
                &mut a,
                8_usize,
            )
        },
        0
    );
    a
}
fn mask() -> u64 {
    let mut m = 0_u64;
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                core::ptr::null::<u64>(),
                &mut m,
                8_usize,
            )
        },
        0
    );
    m
}
fn altstack() -> libc::stack_t {
    let mut s = unsafe { core::mem::zeroed() };
    assert_eq!(unsafe { libc::sigaltstack(core::ptr::null(), &mut s) }, 0);
    s
}
fn stack_identity(s: &libc::stack_t) -> (usize, i32, usize) {
    (s.ss_sp as usize, s.ss_flags, s.ss_size)
}

// The same 27 little-endian u64 fields as save_named_snapshot; no Rust
// struct padding is serialized as a register value.
fn registers_hex(r: &libc::user_regs_struct) -> String {
    let registers = [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ];
    let bytes: Vec<u8> = registers.iter().flat_map(|r| r.to_le_bytes()).collect();
    hex(&bytes)
}

pub(super) struct Router {
    stack: Mapping,
    table: Mapping,
    table_bytes: Vec<u8>,
    count: usize,
    installed: Action,
    prior: Action,
    prior_stack: libc::stack_t,
    prior_mask: u64,
    code: Vec<u8>,
}
impl Router {
    /// Isolated main thread only. Normal paths prove child ECHILD before Drop;
    /// failure paths retain the enclosing strict helper cleanup obligation.
    /// No source/generated page or application-stack byte is writable here.
    pub(super) fn new(routes: &[Route]) -> Self {
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            i64::from(std::process::id())
        );
        assert_eq!(
            (libc::SIGILL, libc::SYS_rt_sigreturn, libc::SYS_exit_group),
            (4, 15, 231)
        );
        assert_eq!(
            (
                core::mem::offset_of!(libc::siginfo_t, si_signo),
                core::mem::offset_of!(libc::siginfo_t, si_code)
            ),
            (0, 8)
        );
        router_contract::check_routes(routes);
        assert!(!routes.is_empty());
        assert!(TABLE.load(Ordering::Acquire).is_null());
        assert_eq!(COUNT.load(Ordering::Acquire), 0);
        let prior = action();
        assert_eq!(prior.handler, libc::SIG_DFL as u64);
        let prior_mask = mask();
        assert_eq!(prior_mask & (1 << (libc::SIGILL - 1)), 0);
        let prior_stack = altstack();
        assert_eq!(prior_stack.ss_flags, libc::SS_DISABLE);
        let stack = Mapping::new(STACK_LEN + 2 * PAGE);
        stack.protect(libc::PROT_NONE);
        protect(
            stack.address() + PAGE as u64,
            STACK_LEN,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        stack.initialize(PAGE, &vec![0xa6; STACK_LEN]);
        let table = Mapping::new(PAGE);
        let mut table_bytes = vec![0; PAGE];
        for (i, r) in routes.iter().enumerate() {
            table_bytes[i * 16..i * 16 + 8].copy_from_slice(&r.pc.to_le_bytes());
            table_bytes[i * 16 + 8..i * 16 + 16].copy_from_slice(&r.target.to_le_bytes());
        }
        table.initialize(0, &table_bytes);
        table.protect(libc::PROT_READ);
        let configured = libc::stack_t {
            ss_sp: (stack.address() + PAGE as u64) as usize as *mut _,
            ss_flags: 0,
            ss_size: STACK_LEN,
        };
        let installed = Action {
            handler: li2_common_router_entry as *const () as u64,
            flags: (libc::SA_SIGINFO | libc::SA_ONSTACK) as u64 | 0x0400_0000,
            restorer: li2_common_router_restorer as *const () as u64,
            mask: 0,
        };
        // Construct the rollback owner before the first signal state mutation.
        let code_start = li2_common_router_entry as *const () as usize;
        let code_len = (li2_common_router_end as *const () as usize)
            .checked_sub(code_start)
            .unwrap();
        assert!((1..=512).contains(&code_len));
        let code =
            unsafe { core::slice::from_raw_parts(code_start as *const u8, code_len) }.to_vec();
        let out = Self {
            stack,
            table,
            table_bytes,
            count: routes.len(),
            installed,
            prior,
            prior_stack,
            prior_mask,
            code,
        };
        assert_eq!(
            unsafe { libc::sigaltstack(&configured, core::ptr::null_mut()) },
            0
        );
        COUNT.store(routes.len(), Ordering::Release);
        TABLE.store(out.table.writable().cast(), Ordering::Release);
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigaction,
                    libc::SIGILL,
                    &installed,
                    core::ptr::null_mut::<Action>(),
                    8_usize,
                )
            },
            0
        );
        out.verify();
        out
    }
    pub(super) fn verify(&self) {
        assert_eq!(action(), self.installed);
        assert_eq!(mask(), self.prior_mask);
        assert_eq!(
            stack_identity(&altstack()),
            ((self.stack.address() + PAGE as u64) as usize, 0, STACK_LEN)
        );
        assert_eq!(TABLE.load(Ordering::Acquire), self.table.writable().cast());
        assert_eq!(COUNT.load(Ordering::Acquire), self.count);
        assert_eq!(self.table.bytes(), self.table_bytes);
    }
    pub(super) fn descriptor(&self) -> String {
        self.verify();
        format!(
            "router_bootstrap\t{}\nrouter_stack\t{}\t{}\t{}\nrouter_table\t{}\t{}\t{}\nrouter_action\t{}\t{}\t{}\t{}\nrouter_mask\t{}\nrouter_code\t{}\nrouter_prior\t{:?}\nrouter_scope\tcontrolled_single_thread_child_only\n",
            router_contract::PROFILE,
            self.stack.address(),
            self.stack.address() + PAGE as u64,
            STACK_LEN,
            self.table.address(),
            PAGE,
            hex(&self.table_bytes),
            self.installed.handler,
            self.installed.flags,
            self.installed.restorer,
            self.installed.mask,
            self.prior_mask,
            hex(&self.code),
            self.prior
        )
    }
    /// Read actual child owners while it is already stopped. Existing full
    /// before/after maps bind these ranges; no duplicate map dump or stop.
    pub(super) fn observed(&self, child: &Tracee, phase: &str, trace: &mut File) {
        assert!(matches!(phase, "before" | "after"));
        if phase == "before" {
            writeln!(
                trace,
                "router-layout\t{}\t{}\t{}\t{}\t{}\t{}",
                core::mem::size_of::<libc::siginfo_t>(),
                core::mem::size_of::<libc::ucontext_t>(),
                core::mem::offset_of!(libc::ucontext_t, uc_stack),
                core::mem::offset_of!(libc::ucontext_t, uc_mcontext)
                    + core::mem::offset_of!(libc::mcontext_t, gregs),
                core::mem::offset_of!(libc::ucontext_t, uc_mcontext)
                    + core::mem::offset_of!(libc::mcontext_t, fpregs),
                core::mem::offset_of!(libc::ucontext_t, uc_sigmask)
            )
            .unwrap();
        }
        let table = child.memory(self.table.address(), PAGE);
        let code = child.memory(self.installed.handler, self.code.len());
        let table_pointer = word(&child.memory(core::ptr::addr_of!(TABLE) as u64, 8), 0);
        let count = word(&child.memory(core::ptr::addr_of!(COUNT) as u64, 8), 0);
        writeln!(
            trace,
            "router-observed\t{}\t{}\t{}\t{}\t{}",
            phase,
            hex(&table),
            hex(&code),
            table_pointer,
            count
        )
        .unwrap();
        trace.flush().unwrap();
    }
    fn contains(&self, address: u64, len: usize) -> bool {
        self.stack.address() + PAGE as u64 <= address
            && address
                .checked_add(len as u64)
                .is_some_and(|end| end <= self.stack.address() + (PAGE + STACK_LEN) as u64)
    }
    fn maps(&self, child: &Tracee) {
        let mut maps = String::new();
        File::open(format!("/proc/{}/maps", child.pid))
            .unwrap()
            .take(1_048_577)
            .read_to_string(&mut maps)
            .unwrap();
        assert!(maps.len() <= 1_048_576 && maps.ends_with('\n'));
        for (start, len, permission) in [
            (self.stack.address(), PAGE, "---p"),
            (self.stack.address() + PAGE as u64, STACK_LEN, "rw-p"),
            (
                self.stack.address() + (PAGE + STACK_LEN) as u64,
                PAGE,
                "---p",
            ),
            (self.table.address(), PAGE, "r--p"),
        ] {
            for page in (start..start + len as u64).step_by(PAGE) {
                let rows: Vec<_> = maps
                    .lines()
                    .filter_map(|line| {
                        let f: Vec<_> = line.split_ascii_whitespace().collect();
                        let (a, b) = f[0].split_once('-').unwrap();
                        (u64::from_str_radix(a, 16).unwrap() <= page
                            && page + 4096 <= u64::from_str_radix(b, 16).unwrap())
                        .then_some(f)
                    })
                    .collect();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].len(), 5);
                assert_eq!(&rows[0][1..], &[permission, "00000000", "00:00", "0"]);
            }
        }
        assert_eq!(child.memory(self.table.address(), PAGE), self.table_bytes);
        assert_eq!(
            child.memory(self.installed.handler, self.code.len()),
            self.code
        );
        assert_eq!(
            word(&child.memory(core::ptr::addr_of!(TABLE) as u64, 8), 0),
            self.table.address()
        );
        assert_eq!(
            word(&child.memory(core::ptr::addr_of!(COUNT) as u64, 8), 0),
            self.count as u64
        );
        for address in ((self.installed.handler & !4095)
            ..page_end(self.installed.handler + self.code.len() as u64))
            .step_by(PAGE)
        {
            let executable = maps
                .lines()
                .filter(|line| {
                    let f: Vec<_> = line.split_ascii_whitespace().collect();
                    let (a, b) = f[0].split_once('-').unwrap();
                    u64::from_str_radix(a, 16).unwrap() <= address
                        && address + 4096 <= u64::from_str_radix(b, 16).unwrap()
                        && f[1] == "r-xp"
                })
                .count();
            assert_eq!(executable, 1);
        }
    }
    pub(super) fn deliver(
        &self,
        child: &Tracee,
        route: &Route,
        count: &mut usize,
        trace: &mut File,
    ) {
        self.verify();
        self.maps(child);
        route.check();
        let before = child.registers();
        let xstate = child.xstate();
        let data = child.memory(ARRAY, PAGE);
        let stack = child.memory(STACK_START, seed::STACK_BYTES);
        assert_eq!(before.rip, route.pc);
        assert_eq!(child.memory(route.pc, route.fetch.len()), route.fetch);
        charge(child, count);
        let observed_fault = child.synchronous_fault();
        writeln!(
            trace,
            "router-fault\t{}\t{}\t{}",
            observed_fault.0, observed_fault.1, observed_fault.2
        )
        .unwrap();
        assert_eq!(observed_fault, (libc::SIGILL, 2, route.pc));
        let fault = child.registers();
        assert_eq!(fault.rip, route.pc);
        // Actual kernel delivery reaches only this separately authenticated
        // instrumentation INT3. No target instruction or register is patched.
        charge(child, count);
        child.request(libc::PTRACE_CONT, 0, libc::SIGILL as usize);
        let stopped = child.wait();
        assert!(libc::WIFSTOPPED(stopped) && libc::WSTOPSIG(stopped) == libc::SIGTRAP);
        let entered = child.registers();
        assert_eq!(entered.rip, li2_common_router_captured as *const () as u64);
        let mut trap_info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        child.request(
            libc::PTRACE_GETSIGINFO,
            0,
            core::ptr::addr_of_mut!(trap_info) as usize,
        );
        assert_eq!(
            (trap_info.si_signo, trap_info.si_code),
            (libc::SIGTRAP, 128)
        );
        writeln!(
            trace,
            "router-entry\t{}\t{}\t{}\t{}\t{}",
            entered.rip, entered.rsp, entered.rsi, entered.rdx, trap_info.si_code
        )
        .unwrap();
        writeln!(
            trace,
            "router-entry-state\t{}\t{}",
            stopped,
            registers_hex(&entered)
        )
        .unwrap();
        assert!(self.contains(entered.rsp, 8));
        assert!(self.contains(entered.rsi, core::mem::size_of::<libc::siginfo_t>()));
        assert!(self.contains(entered.rdx, core::mem::size_of::<libc::ucontext_t>()));
        let info_bytes = child.memory(entered.rsi, core::mem::size_of::<libc::siginfo_t>());
        let info =
            unsafe { core::ptr::read_unaligned(info_bytes.as_ptr().cast::<libc::siginfo_t>()) };
        assert_eq!(
            (
                info.si_signo,
                info.si_code,
                unsafe { info.si_addr() } as usize as u64
            ),
            (libc::SIGILL, 2, route.pc)
        );
        let frame = child.memory(entered.rdx, core::mem::size_of::<libc::ucontext_t>());
        let context =
            unsafe { core::ptr::read_unaligned(frame.as_ptr().cast::<libc::ucontext_t>()) };
        assert_eq!(
            stack_identity(&context.uc_stack),
            ((self.stack.address() + PAGE as u64) as usize, 0, STACK_LEN)
        );
        assert_eq!(
            unsafe {
                core::ptr::read_unaligned(core::ptr::addr_of!(context.uc_sigmask).cast::<u64>())
            },
            self.prior_mask
        );
        assert_eq!(context.uc_mcontext.gregs[libc::REG_TRAPNO as usize], 6);
        assert_eq!(
            context.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            route.pc
        );
        assert_eq!(
            context.uc_mcontext.gregs[libc::REG_RSP as usize] as u64,
            before.rsp
        );
        let fp = context.uc_mcontext.fpregs as u64;
        assert!(self.contains(fp, 512));
        let legacy_fp = child.memory(fp, 512);
        // Linux x86-64 _fpx_sw_bytes: require the actual extended signal-frame
        // format, then save its complete declared extent and terminal magic.
        assert_eq!(u32_at(&legacy_fp, 464), 0x4650_5853);
        let extended = u32_at(&legacy_fp, 468) as usize;
        let xstate_size = u32_at(&legacy_fp, 480) as usize;
        assert!(
            (580..=65536).contains(&extended) && 576 <= xstate_size && xstate_size <= extended - 4
        );
        assert!(self.contains(fp, extended));
        let saved_fp = child.memory(fp, extended);
        assert_eq!(u32_at(&saved_fp, extended - 4), 0x4650_5845);
        // The handler may only change saved RIP. All other ucontext bytes and
        // the complete signal XSAVE area must survive its actual execution.
        while child.registers().rip != self.installed.restorer {
            let pc = child.registers().rip;
            assert!(
                li2_common_router_captured as *const () as u64 <= pc
                    && pc < self.installed.restorer
            );
            let offset = (pc - self.installed.handler) as usize;
            let mut decoder = iced_x86::Decoder::with_ip(
                64,
                &self.code[offset..],
                pc,
                iced_x86::DecoderOptions::NONE,
            );
            let instruction = decoder.decode();
            assert!(!instruction.is_invalid());
            assert_ne!(
                instruction.mnemonic(),
                iced_x86::Mnemonic::Syscall,
                "handler success has no syscall"
            );
            assert_ne!(instruction.mnemonic(), iced_x86::Mnemonic::Int3);
            let raw = &self.code[offset..offset + instruction.len()];
            assert_eq!(child.memory(pc, raw.len()), raw);
            step(child, count);
            writeln!(
                trace,
                "router-step\t{}\t{}\t{}",
                pc,
                child.registers().rip,
                hex(raw)
            )
            .unwrap();
        }
        let restorer_before = child.registers();
        let mov_len = (li2_common_router_syscall as *const () as u64)
            .checked_sub(self.installed.restorer)
            .unwrap() as usize;
        assert!((1..=self.code.len()).contains(&mov_len));
        let mov_bytes = child.memory(self.installed.restorer, mov_len);
        step(child, count);
        let restorer_after = child.registers();
        // step() already consumed the real wait status. Preserve its actual
        // stopped siginfo instead of inventing an unavailable wait value.
        let mut restorer_info = vec![0_u8; core::mem::size_of::<libc::siginfo_t>()];
        child.request(
            libc::PTRACE_GETSIGINFO,
            0,
            restorer_info.as_mut_ptr() as usize,
        );
        writeln!(
            trace,
            "router-restorer\t{}\t{}\t{}\t{}",
            registers_hex(&restorer_before),
            registers_hex(&restorer_after),
            hex(&mov_bytes),
            hex(&restorer_info)
        )
        .unwrap();
        assert_eq!(
            child.registers().rip,
            li2_common_router_syscall as *const () as u64
        );
        assert_eq!(child.registers().rax, libc::SYS_rt_sigreturn as u64);
        child.request(
            libc::PTRACE_SETOPTIONS,
            0,
            (libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESYSGOOD) as usize,
        );
        charge(child, count);
        child.request(libc::PTRACE_SYSCALL, 0, 0);
        let entry = child.wait();
        assert!(libc::WIFSTOPPED(entry) && libc::WSTOPSIG(entry) == (libc::SIGTRAP | 0x80));
        let syscall = child.registers();
        assert_eq!(syscall.orig_rax, libc::SYS_rt_sigreturn as u64);
        assert_eq!(
            syscall.rip,
            li2_common_router_syscall as *const () as u64 + 2
        );
        writeln!(
            trace,
            "router-syscall-entry\t{}\t{}",
            entry,
            registers_hex(&syscall)
        )
        .unwrap();
        let changed = child.memory(entered.rdx, frame.len());
        let rip_offset = core::mem::offset_of!(libc::ucontext_t, uc_mcontext)
            + core::mem::offset_of!(libc::mcontext_t, gregs)
            + libc::REG_RIP as usize * 8;
        let mut expected = frame.clone();
        expected[rip_offset..rip_offset + 8].copy_from_slice(&route.target.to_le_bytes());
        assert_eq!(changed, expected);
        assert_eq!(
            child.memory(context.uc_mcontext.fpregs as u64, saved_fp.len()),
            saved_fp
        );
        // A separate actual read records the paired extent at the same stopped
        // syscall entry. The original full comparison above remains literal.
        let fp_after = child.memory(fp, saved_fp.len());
        charge(child, count);
        child.request(libc::PTRACE_SYSCALL, 0, 0);
        let exit = child.wait();
        assert!(libc::WIFSTOPPED(exit) && libc::WSTOPSIG(exit) == (libc::SIGTRAP | 0x80));
        assert_eq!(child.registers().rip, route.target);
        let returned = child.registers();
        writeln!(
            trace,
            "router-syscall-exit\t{}\t{}",
            exit,
            registers_hex(&returned)
        )
        .unwrap();
        child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
        let actual = Snapshot {
            logical_pc: route.pc,
            registers: child.registers(),
            xstate: canonical_xstate(&child.xstate()),
            data: child.memory(ARRAY, PAGE),
            application_stack: child.memory(STACK_START, seed::STACK_BYTES),
        };
        let expected = Snapshot {
            logical_pc: route.pc,
            registers: before,
            xstate: canonical_xstate(&xstate),
            data,
            application_stack: stack,
        };
        assert_state(&expected, &actual); // The unchanged comparator excludes only physical RIP/debugger bits.
        self.maps(child);
        self.verify();
        writeln!(
            trace,
            "router\t{}\t{}\t{}",
            route.pc,
            route.target,
            hex(&route.fetch)
        )
        .unwrap();
        writeln!(
            trace,
            "router-frame\t{}\t{}\t{}\t{}\t{}",
            entered.rdx,
            hex(&info_bytes),
            hex(&frame),
            hex(&changed),
            hex(&saved_fp)
        )
        .unwrap();
        writeln!(trace, "router-fp-after\t{}\t{}", fp, hex(&fp_after)).unwrap();
        trace.flush().unwrap();
    }
}
fn charge(child: &Tracee, count: &mut usize) {
    assert!(*count < MAX_STEPS && Instant::now() < child.deadline);
    *count += 1;
}
impl Drop for Router {
    fn drop(&mut self) {
        // Declaration order runs Tracee's SIGKILL/wait attempt first. During
        // unwinding that wait may end after two seconds without a reap. Normal
        // callers prove ECHILD; failure absence remains the strict helper's duty.
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_rt_sigaction,
                    libc::SIGILL,
                    &self.prior,
                    core::ptr::null_mut::<Action>(),
                    8_usize,
                )
            },
            0
        );
        assert_eq!(
            unsafe { libc::sigaltstack(&self.prior_stack, core::ptr::null_mut()) },
            0
        );
        TABLE.store(core::ptr::null_mut(), Ordering::Release);
        COUNT.store(0, Ordering::Release);
        assert_eq!(action(), self.prior);
        assert_eq!(mask(), self.prior_mask);
        assert_eq!(
            stack_identity(&altstack()),
            stack_identity(&self.prior_stack)
        );
    }
}
