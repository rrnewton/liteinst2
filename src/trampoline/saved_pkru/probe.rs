//! Explicit, mandatory physical probe; never an ordinary unit test or authority.

use super::fixtures::{Mapping, PAGE, invoke_poisoned, ospke};
use super::*;
use crate::scanner::InstructionScanner;
use crate::trampoline::HookSite;
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, AtomicUsize};

static HOOK: AtomicPtr<InstalledHook> = AtomicPtr::new(core::ptr::null_mut());
static MODE: AtomicU8 = AtomicU8::new(0);
static EXPECTED: AtomicU32 = AtomicU32::new(0);
static NEXT: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static LAST_IMAGE: AtomicUsize = AtomicUsize::new(0);
static CONTROLS: AtomicUsize = AtomicUsize::new(0);
static FAULT_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static FAULT_KIND: AtomicU8 = AtomicU8::new(0);
static FAULTS: AtomicUsize = AtomicUsize::new(0);

global_asm!(
    ".text",
    ".global pkru_view_fault_read",
    ".global pkru_view_read_instruction",
    ".global pkru_view_read_resume",
    "pkru_view_fault_read:",
    "pkru_view_read_instruction:",
    "mov al, byte ptr [rdi]",
    "pkru_view_read_resume:",
    "ret",
    ".global pkru_view_fault_write",
    ".global pkru_view_write_instruction",
    ".global pkru_view_write_resume",
    "pkru_view_fault_write:",
    "pkru_view_write_instruction:",
    "mov byte ptr [rdi], 0x41",
    "pkru_view_write_resume:",
    "ret",
);

unsafe extern "C" {
    fn pkru_view_fault_read(page: *mut u8);
    fn pkru_view_fault_write(page: *mut u8);
    static pkru_view_read_instruction: u8;
    static pkru_view_read_resume: u8;
    static pkru_view_write_instruction: u8;
    static pkru_view_write_resume: u8;
}

unsafe fn read_pkru() -> u32 {
    let value: u32;
    unsafe {
        asm!("rdpkru", in("ecx") 0_u32, lateout("eax") value,
        lateout("edx") _, options(nostack, preserves_flags))
    };
    value
}

unsafe fn write_pkru(value: u32) {
    unsafe {
        asm!("wrpkru", in("eax") value, in("ecx") 0_u32,
        in("edx") 0_u32, options(nostack, preserves_flags))
    };
}

struct ScratchKey {
    key: i32,
    page: *mut u8,
    original: u32,
    opened: u32,
}

impl ScratchKey {
    fn required() -> Self {
        assert!(
            ospke(),
            "PKRU_UNSUPPORTED ospke=0; no protected positive is claimed"
        );
        let original = unsafe { read_pkru() };
        let key = unsafe { libc::syscall(libc::SYS_pkey_alloc, 0_i32, 0_i32) };
        assert!(
            key >= 0,
            "PKRU_UNSUPPORTED pkey_alloc failed: {}; no protected positive is claimed",
            std::io::Error::last_os_error()
        );
        assert!((1..16).contains(&key));
        let page = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pkey_mprotect,
                    page,
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    key,
                )
            },
            0
        );
        let opened = unsafe { read_pkru() };
        assert_eq!(opened & (3_u32 << (key as u32 * 2)), 0);
        unsafe { page.cast::<u8>().write_volatile(0x5a) };
        Self {
            key: key as i32,
            page: page.cast(),
            original,
            opened,
        }
    }
}

impl Drop for ScratchKey {
    fn drop(&mut self) {
        unsafe { write_pkru(self.original) };
        assert_eq!(unsafe { libc::munmap(self.page.cast(), PAGE) }, 0);
        assert_eq!(unsafe { libc::syscall(libc::SYS_pkey_free, self.key) }, 0);
    }
}

unsafe extern "C" fn fault(signal: i32, info: *mut libc::siginfo_t, raw: *mut libc::c_void) {
    let info = unsafe { &*info };
    // Linux's kernel ucontext prefix is smaller than libc::ucontext_t. A
    // whole mutable libc view would overlap the adjacent siginfo reference.
    // Access only the genuine greg words in the kernel prefix through raw
    // pointers; no reference covers the unused libc tail or siginfo bytes.
    let registers = unsafe {
        core::ptr::addr_of_mut!((*raw.cast::<libc::ucontext_t>()).uc_mcontext.gregs)
            .cast::<libc::greg_t>()
    };
    let rip = unsafe { registers.add(libc::REG_RIP as usize) };
    let error = unsafe { registers.add(libc::REG_ERR as usize).read() };
    let write = FAULT_KIND.load(Ordering::Relaxed) == 1;
    let (instruction, resume) = {
        if write {
            (
                core::ptr::addr_of!(pkru_view_write_instruction) as usize,
                core::ptr::addr_of!(pkru_view_write_resume) as usize,
            )
        } else {
            (
                core::ptr::addr_of!(pkru_view_read_instruction) as usize,
                core::ptr::addr_of!(pkru_view_read_resume) as usize,
            )
        }
    };
    // Linux x86 SEGV_PKUERR=4 and page-fault error PK bit=5. Require the exact
    // scratch byte and exact probe PC; any other fault terminates the child.
    if signal != libc::SIGSEGV
        || info.si_code != 4
        || unsafe { info.si_addr() } as usize != FAULT_ADDRESS.load(Ordering::Relaxed)
        || unsafe { rip.read() } as usize != instruction
        || error & (1 << 5) == 0
        || (error & 2 != 0) != write
    {
        unsafe { libc::_exit(90) };
    }
    FAULTS.fetch_add(1, Ordering::Relaxed);
    unsafe { rip.write(resume as libc::greg_t) };
}

fn faults_on_same_page(page: *mut u8) {
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = fault as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    let mut old: libc::sigaction = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGSEGV, &action, &mut old) },
        0
    );
    FAULT_ADDRESS.store(page as usize, Ordering::Relaxed);
    FAULTS.store(0, Ordering::Relaxed);
    FAULT_KIND.store(0, Ordering::Relaxed);
    unsafe { pkru_view_fault_read(page) };
    assert_eq!(FAULTS.load(Ordering::Relaxed), 1);
    FAULT_KIND.store(1, Ordering::Relaxed);
    unsafe { pkru_view_fault_write(page) };
    assert_eq!(FAULTS.load(Ordering::Relaxed), 2);
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGSEGV, &old, core::ptr::null_mut()) },
        0
    );
}

fn positive(hook: &InstalledHook, context: &mut HookContext) -> u32 {
    let descriptor = context.saved_extended_state();
    let value = unsafe { hook.saved_pkru_view(context) }
        .unwrap()
        .unwrap()
        .value();
    assert_eq!(context.saved_extended_state(), descriptor);
    value
}

fn malformed_inputs(hook: &InstalledHook, context: &mut HookContext) {
    let original = context.saved_extended_state();
    let layout = hook.trampoline().layout().saved_extended_state;
    let address = context as *mut HookContext as usize as u64;
    let geom = geometry(address, original, layout).unwrap().unwrap();
    let pkru_offset = geom.pkru_offset.unwrap();
    let expected = positive(hook, context);
    assert_ne!(unsafe { checked_header(geom) }.unwrap() & PKRU_XFEATURE, 0);

    // Genuine installed image positive, one malformed descriptor, exact restore
    // and revalidation per case. No wild address is dereferenced on refusal.
    for case in 0..8 {
        let mut bad = original;
        match case {
            0 => bad.address = 0,
            1 => bad.address += 64,
            2 => bad.address += 1,
            3 => bad.len = 0,
            4 => bad.len -= 1,
            5 => bad.mask ^= PKRU_XFEATURE,
            6 => bad.format = SavedExtendedStateFormat::UNAVAILABLE,
            7 => bad.format = SavedExtendedStateFormat(3),
            _ => unreachable!(),
        }
        context.saved_extended_state = bad;
        assert!(unsafe { hook.saved_pkru_view(context) }.is_err());
        assert_eq!(context.saved_extended_state(), bad);
        context.saved_extended_state = original;
        assert_eq!(positive(hook, context), expected);
        CONTROLS.fetch_add(1, Ordering::Relaxed);
    }

    // The retained layout is immutable. Mutate only a local copy and exercise
    // the SAME production geometry predicate against the actual frame address.
    // Rebind descriptor metadata so early descriptor inequality is not the
    // reason malformed component/image layouts are rejected.
    let pkru = layout
        .components()
        .iter()
        .position(|c| c.xfeature() == PKRU_XFEATURE)
        .unwrap();
    for case in 0..17 {
        let mut bad = layout;
        match case {
            0 => bad.component_count = (SAVED_EXTENDED_STATE_COMPONENT_CAPACITY + 1) as u64,
            1 => bad.components[pkru].size = 0,
            2 => bad.components[pkru].size = 4,
            3 => bad.components[pkru].offset = 568,
            4 => bad.components[pkru].offset += 4,
            5 => bad.components[pkru].offset = bad.image_len,
            6 => bad.components[pkru].offset = u64::MAX - 3,
            7 => bad.components[pkru].xfeature |= 1 << 2,
            8 => bad.mask &= !PKRU_XFEATURE,
            9 => bad.mask &= !1,
            10 => bad.image_len -= 1,
            11 => bad.allocation_len -= 64,
            12 => bad.components[bad.component_count as usize] = bad.components[pkru],
            13 => {
                bad.components[bad.component_count as usize] = bad.components[pkru];
                bad.component_count += 1;
            }
            14 => {
                bad.image_len = u64::MAX;
                bad.allocation_len = u64::MAX;
            }
            15 => bad.format = SavedExtendedStateFormat(3),
            16 => {
                // Two distinct selected xfeatures with individually in-bounds
                // extents but overlapping storage must still be rejected.
                let other = (0..bad.component_count as usize)
                    .find(|i| *i != pkru)
                    .unwrap_or(bad.component_count as usize);
                if other == bad.component_count as usize {
                    bad.component_count += 1;
                    bad.components[other].xfeature = 1 << 2;
                    bad.mask |= 1 << 2;
                }
                bad.components[other].offset = bad.components[pkru].offset;
                bad.components[other].size = 8;
            }
            _ => unreachable!(),
        }
        let rebound = SavedExtendedStateDescriptor {
            address: bad
                .format
                .required_alignment()
                .and_then(|a| (address & !(a - 1)).checked_sub(bad.len()))
                .unwrap_or(0),
            len: bad.len(),
            mask: bad.mask(),
            format: bad.format(),
        };
        assert!(geometry(address, rebound, bad).is_err());
        assert_eq!(positive(hook, context), expected);
        CONTROLS.fetch_add(1, Ordering::Relaxed);
    }
    for bad_address in [0, 8, u64::MAX - 7] {
        assert!(geometry(bad_address, original, layout).is_err());
        assert_eq!(positive(hook, context), expected);
        CONTROLS.fetch_add(1, Ordering::Relaxed);
    }

    let base = geom.address as usize as *mut u8;
    for (offset, value) in [
        (XSTATE_BV, 1_u64 << 63),
        (XCOMP_BV, 1),
        (XCOMP_BV, 1_u64 << 63),
    ]
    .into_iter()
    .chain((528..HEADER_END).step_by(8).map(|o| (o, 1)))
    {
        let word = unsafe { base.add(offset).cast::<u64>() };
        let saved = unsafe { word.read_volatile() };
        unsafe { word.write_volatile(value) };
        assert!(unsafe { hook.saved_pkru_view(context) }.is_err());
        assert_eq!(unsafe { word.read_volatile() }, value);
        unsafe { word.write_volatile(saved) };
        assert_eq!(positive(hook, context), expected);
        CONTROLS.fetch_add(1, Ordering::Relaxed);
    }
    let reserved = unsafe { base.add(pkru_offset + 4).cast::<u32>() };
    let saved_reserved = unsafe { reserved.read_volatile() };
    unsafe { reserved.write_volatile(1) };
    assert!(unsafe { hook.saved_pkru_view(context) }.is_err());
    unsafe { reserved.write_volatile(saved_reserved) };
    assert_eq!(positive(hook, context), expected);
    CONTROLS.fetch_add(1, Ordering::Relaxed);

    // A view is not permission to use stale metadata: commit independently
    // rejects a descriptor change and a header change, without image writes.
    let view = unsafe { hook.saved_pkru_view(context) }.unwrap().unwrap();
    view.context.saved_extended_state.address += 64;
    assert!(view.commit(!expected).is_err());
    context.saved_extended_state = original;
    assert_eq!(positive(hook, context), expected);
    CONTROLS.fetch_add(1, Ordering::Relaxed);
    let view = unsafe { hook.saved_pkru_view(context) }.unwrap().unwrap();
    let header = unsafe { base.add(XCOMP_BV).cast::<u64>() };
    unsafe { header.write_volatile(1) };
    assert!(view.commit(!expected).is_err());
    assert_eq!(unsafe { header.read_volatile() }, 1);
    unsafe { header.write_volatile(0) };
    assert_eq!(positive(hook, context), expected);
    assert_eq!(context.saved_extended_state(), original);
    CONTROLS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn installed_callback(raw: *mut HookContext) {
    let hook = unsafe { &*HOOK.load(Ordering::Relaxed) };
    let context = unsafe { &mut *raw };
    LAST_IMAGE.store(
        context.saved_extended_state().address() as usize,
        Ordering::Relaxed,
    );
    let descriptor = context.saved_extended_state();
    let layout = hook.trampoline().layout().saved_extended_state;
    assert!(descriptor.matches_layout(layout));
    assert_eq!(descriptor.len(), layout.len());
    assert!(layout.image_len() <= layout.len());
    let scratch = FAULT_ADDRESS.load(Ordering::Relaxed) as u64;
    let frame_end = (raw as usize as u64) + core::mem::size_of::<HookContext>() as u64;
    assert!(frame_end <= scratch || descriptor.address() >= scratch + PAGE as u64);
    assert_eq!(positive(hook, context), EXPECTED.load(Ordering::Relaxed));
    match MODE.load(Ordering::Relaxed) {
        0 => unsafe { write_pkru(NEXT.load(Ordering::Relaxed)) },
        1 => {
            // No view/image borrow exists during this intervening callback work.
            core::hint::black_box(context.instruction_pointer);
            unsafe { hook.saved_pkru_view(context) }
                .unwrap()
                .unwrap()
                .commit(NEXT.load(Ordering::Relaxed))
                .unwrap();
        }
        2 => malformed_inputs(hook, context),
        3 | 4 => {
            let geom = geometry(
                raw as usize as u64,
                descriptor,
                hook.trampoline().layout().saved_extended_state,
            )
            .unwrap()
            .unwrap();
            let pkru_offset = geom.pkru_offset.unwrap();
            let base = geom.address as usize as *mut u8;
            let header = unsafe { base.add(XSTATE_BV).cast::<u64>() };
            let present = unsafe { header.read_volatile() };
            assert_ne!(present & PKRU_XFEATURE, 0);
            // Deliberately absent component on a REAL image. Poison the already
            // initialized words; neither read view may consult this stale data.
            unsafe {
                base.add(pkru_offset).cast::<u32>().write_volatile(u32::MAX);
                base.add(pkru_offset + 4)
                    .cast::<u32>()
                    .write_volatile(u32::MAX);
                header.write_volatile(present & !PKRU_XFEATURE);
            }
            assert_eq!(positive(hook, context), 0);
            if MODE.load(Ordering::Relaxed) == 4 {
                unsafe { hook.saved_pkru_view(context) }
                    .unwrap()
                    .unwrap()
                    .commit(NEXT.load(Ordering::Relaxed))
                    .unwrap();
                assert_eq!(unsafe { header.read_volatile() }, present);
                assert_eq!(
                    unsafe { base.add(pkru_offset + 4).cast::<u32>().read_volatile() },
                    0
                );
            }
        }
        _ => panic!("unknown fixture mode"),
    }
    assert_eq!(context.saved_extended_state(), descriptor);
    unsafe { asm!("pxor xmm0, xmm0", out("xmm0") _, options(nostack)) };
    CALLS.fetch_add(1, Ordering::Relaxed);
}

fn physical() {
    let scratch = ScratchKey::required();
    // The atomic patch reads eight bytes; preserve the five-byte NOP and RET,
    // and provide two unreachable bytes after RET for that complete window.
    let code = [0x0f, 0x1f, 0x44, 0x00, 0x00, 0xc3, 0x90, 0x90];
    let mapping = Mapping::new(&code);
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&code, mapping.address()).unwrap();
    let site = HookSite::new(
        &scanner,
        &scan,
        &code,
        mapping.address(),
        mapping.address(),
        mapping.writable,
    );
    let hook = Box::new(
        unsafe { InstalledHook::install_replacing_first_quiescent(site, installed_callback) }
            .unwrap(),
    );
    HOOK.store(
        (&*hook) as *const InstalledHook as *mut InstalledHook,
        Ordering::Relaxed,
    );
    assert_eq!(
        hook.trampoline().layout().saved_extended_state.mask() & PKRU_XFEATURE,
        PKRU_XFEATURE
    );
    assert!(unsafe { hook.activate_quiescent() }.unwrap());
    let denied = scratch.opened | (3_u32 << (scratch.key as u32 * 2));
    FAULT_ADDRESS.store(scratch.page as usize, Ordering::Relaxed);
    EXPECTED.store(scratch.opened, Ordering::Relaxed);
    NEXT.store(denied, Ordering::Relaxed);

    MODE.store(0, Ordering::Relaxed);
    LAST_IMAGE.store(0, Ordering::Relaxed);
    let poisoned_image = invoke_poisoned(
        mapping.executable,
        hook.trampoline().layout().saved_extended_state,
    );
    assert_eq!(LAST_IMAGE.load(Ordering::Relaxed) as u64, poisoned_image);
    assert_eq!(
        unsafe { read_pkru() },
        scratch.opened,
        "transparent behavior changed"
    );
    assert_eq!(unsafe { scratch.page.read_volatile() }, 0x5a);
    MODE.store(1, Ordering::Relaxed);
    LAST_IMAGE.store(0, Ordering::Relaxed);
    let poisoned_image = invoke_poisoned(
        mapping.executable,
        hook.trampoline().layout().saved_extended_state,
    );
    assert_eq!(LAST_IMAGE.load(Ordering::Relaxed) as u64, poisoned_image);
    assert_eq!(
        unsafe { read_pkru() },
        denied,
        "saved commit did not reach XRSTOR/return"
    );
    faults_on_same_page(scratch.page);

    EXPECTED.store(denied, Ordering::Relaxed);
    NEXT.store(scratch.opened, Ordering::Relaxed);
    LAST_IMAGE.store(0, Ordering::Relaxed);
    let poisoned_image = invoke_poisoned(
        mapping.executable,
        hook.trampoline().layout().saved_extended_state,
    );
    assert_eq!(LAST_IMAGE.load(Ordering::Relaxed) as u64, poisoned_image);
    assert_eq!(unsafe { read_pkru() }, scratch.opened);
    unsafe { scratch.page.write_volatile(0x63) };
    assert_eq!(unsafe { scratch.page.read_volatile() }, 0x63);

    // A nonzero captured value gives genuine present component bytes for the
    // malformed/header controls and the controlled init-state cases.
    unsafe { write_pkru(denied) };
    EXPECTED.store(denied, Ordering::Relaxed);
    MODE.store(2, Ordering::Relaxed);
    LAST_IMAGE.store(0, Ordering::Relaxed);
    let poisoned_image = invoke_poisoned(
        mapping.executable,
        hook.trampoline().layout().saved_extended_state,
    );
    assert_eq!(LAST_IMAGE.load(Ordering::Relaxed) as u64, poisoned_image);
    assert_eq!(unsafe { read_pkru() }, denied);
    assert_eq!(CONTROLS.load(Ordering::Relaxed), 40);
    MODE.store(3, Ordering::Relaxed);
    LAST_IMAGE.store(0, Ordering::Relaxed);
    let poisoned_image = invoke_poisoned(
        mapping.executable,
        hook.trampoline().layout().saved_extended_state,
    );
    assert_eq!(LAST_IMAGE.load(Ordering::Relaxed) as u64, poisoned_image);
    assert_eq!(
        unsafe { read_pkru() },
        0,
        "absent bit9 did not restore architectural init PKRU"
    );
    unsafe { write_pkru(denied) };
    NEXT.store(scratch.opened, Ordering::Relaxed);
    MODE.store(4, Ordering::Relaxed);
    LAST_IMAGE.store(0, Ordering::Relaxed);
    let poisoned_image = invoke_poisoned(
        mapping.executable,
        hook.trampoline().layout().saved_extended_state,
    );
    assert_eq!(LAST_IMAGE.load(Ordering::Relaxed) as u64, poisoned_image);
    assert_eq!(unsafe { read_pkru() }, scratch.opened);
    unsafe { scratch.page.write_volatile(0x64) };
    assert_eq!(unsafe { scratch.page.read_volatile() }, 0x64);
    assert_eq!(CALLS.load(Ordering::Relaxed), 6);
    println!("PKRU_EMITTER_RESERVED_INIT poisoned-frames=6");
    assert!(unsafe { hook.deactivate_quiescent() }.unwrap());
    HOOK.store(core::ptr::null_mut(), Ordering::Relaxed);
    let layout = hook.trampoline().layout().saved_extended_state;
    println!(
        "PKRU_PHYSICAL_COMPLETE transparent=1 commit-return=1 pku-read=1 pku-write=1 reopen-same-page=1 init-absent=1 init-commit=1 input-negatives=40 calls=6 key={} allocation_len={} image_len={}",
        scratch.key,
        layout.len(),
        layout.image_len()
    );
}

/// Runs the required saved-PKRU tagged-page trial and all forty input negatives.
///
/// This probe has no receipt or isolation authority. Unavailable OSPKE/key setup
/// fails with `PKRU_UNSUPPORTED`; only full completion prints the physical
/// marker. Ordinary tests never invoke this function.
///
/// # Safety
///
/// Invoke exactly once in a dedicated, externally resource-bounded process with
/// no other application threads or outstanding SIGSEGV-handler users. The
/// process owns these globals, scratch mappings and quiescent patch sites.
/// Do not call from a production Tool callback, signal handler or guest.
pub unsafe fn run_saved_pkru_physical_probe() {
    physical();
}
