#![deny(warnings)]
extern crate liteinst2;
mod consumer;
mod elf;
#[allow(dead_code)]
mod isolation;
#[allow(dead_code)]
#[path = "../../tests/support/quiescent_oracle.rs"]
mod oracle;
use corelib::contracts::*;
use corelib::generated_unwind::{
    Backend, FramePreservingHook, Limits, PreparedUnwind, SourceCertificate,
};
use corelib::planner::HookSemantics;
use corelib::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install_detailed,
};
use corelib::scanner::InstructionScanner;
use corelib::trampoline::{HookContext, SavedExtendedStateDescriptor, TrampolinePlan};
use liteinst2 as corelib;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];
const LIVE_RBX: u64 = 0x5a637c91e2d4b608;
#[repr(C)]
struct OuterInput {
    callee: [u64; 6],
    subject: unsafe extern "C" fn() -> u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct OuterOutput {
    call_rsp: u64,
    return_pc: u64,
    result: u64,
    callee: [u64; 6],
}
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame {
    ip: u64,
    cfa: u64,
    callee: [u64; 6],
    before: i32,
    owned: u32,
}
impl Frame {
    const ZERO: Self = Self {
        ip: 0,
        cfa: 0,
        callee: [0; 6],
        before: 0,
        owned: 0,
    };
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Trace {
    frames: [Frame; 32],
    context: u64,
    context_rbx: u64,
    context_pc: u64,
    context_rsp: u64,
    xstate_address: u64,
    count: u32,
    reached: u32,
    overflow: u32,
    changed: u32,
    result: i32,
    reserved: u32,
}
impl Trace {
    const ZERO: Self = Self {
        frames: [Frame::ZERO; 32],
        context: 0,
        context_rbx: 0,
        context_pc: 0,
        context_rsp: 0,
        xstate_address: 0,
        count: 0,
        reached: 0,
        overflow: 0,
        changed: 0,
        result: 0,
        reserved: 0,
    };
}
#[repr(C)]
struct Config {
    outer_return: u64,
    outer_begin: u64,
    outer_end: u64,
    source_begin: u64,
    source_end: u64,
    generated_begin: u64,
    generated_end: u64,
    context_bytes: u64,
    context_rbx_offset: u64,
    context_descriptor_offset: u64,
    records: *mut Trace,
    capacity: u32,
    count: u32,
    failure: u32,
    reserved: u32,
}
struct AdmissionOwner {
    inner: Arc<dyn corelib::generated_unwind::SourceOwner>,
    refuse: AtomicBool,
}
unsafe impl corelib::generated_unwind::SourceOwner for AdmissionOwner {
    fn revalidate(&self) -> Result<(), corelib::generated_unwind::Refusal> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(corelib::generated_unwind::Refusal::SourceIdentity);
        }
        self.inner.revalidate()
    }
}
unsafe extern "C" {
    fn uw_outer(input: *const OuterInput, output: *mut OuterOutput);
    fn uw_frameless() -> u64;
    fn uw_frame_pointer() -> u64;
    fn uw_collect_original();
    fn uw_collect_hook(context: *mut HookContext);
    fn uw_capture_configure(config: *mut Config);
    fn uw_register(records: *const u8);
    fn uw_find_fde(pc: u64) -> *const u8;
    fn uw_registration_count() -> u64;
}
fn address(f: unsafe extern "C" fn() -> u64) -> u64 {
    f as *const () as usize as u64
}
fn canaries(seed: u64) -> [u64; 6] {
    std::array::from_fn(|i| seed ^ (i as u64 + 1) * 0x0110_0010_0020_0030)
}
fn permissions(page: u64, mode: i32) -> Result<(), Refusal> {
    if unsafe { libc::mprotect(page as usize as *mut libc::c_void, 4096, mode) } == 0 {
        Ok(())
    } else {
        Err(Refusal::Backend(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}
fn read_only_mapping(start: u64, len: usize) {
    let end = start.checked_add(len as u64).unwrap();
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    assert!(maps.len() < 2 * 1024 * 1024);
    let owners: Vec<_> = maps
        .lines()
        .filter(|line| {
            let field = line.split_whitespace().next().unwrap();
            let (left, right) = field.split_once('-').unwrap();
            u64::from_str_radix(left, 16).unwrap() <= start
                && end <= u64::from_str_radix(right, 16).unwrap()
        })
        .collect();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].split_whitespace().nth(1).unwrap(), "r--p");
}

struct Profile {
    start: u64,
    selected: u64,
    call: u64,
    after_call: u64,
    end: u64,
    subject: unsafe extern "C" fn() -> u64,
    heads: Vec<u64>,
    fp: bool,
}
fn profile(elf: &elf::Elf, fp: bool) -> Profile {
    let name = if fp {
        "uw_frame_pointer"
    } else {
        "uw_frameless"
    };
    let start = elf.address(name);
    let selected = elf.address(&format!("{name}_selected"));
    let call = elf.address(&format!("{name}_call"));
    let after_call = elf.address(&format!("{name}_after_call"));
    let end = elf.address(&format!("{name}_end"));
    let subject = if fp { uw_frame_pointer } else { uw_frameless };
    assert_eq!(start, address(subject));
    assert_eq!(start % 4096, 0);
    elf.authenticate_code(start, end);
    let mut bytes = if fp {
        vec![0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec, 0x18]
    } else {
        vec![0x53, 0x48, 0x83, 0xec, 0x20]
    };
    let mut offsets = if fp {
        vec![0, 1, 4, 5, 9]
    } else {
        vec![0, 1, 5]
    };
    bytes.extend_from_slice(&[0x48, 0xbb]);
    bytes.extend_from_slice(&LIVE_RBX.to_le_bytes());
    assert_eq!(selected, start + bytes.len() as u64);
    offsets.push(bytes.len());
    bytes.extend_from_slice(&[0x0f, 0x1f, 0x44, 0, 0]);
    assert_eq!(call, start + bytes.len() as u64);
    offsets.push(bytes.len());
    bytes.push(0xe8);
    let target = uw_collect_original as *const () as usize as u64;
    bytes.extend_from_slice(
        &i32::try_from(i128::from(target) - i128::from(call + 5))
            .unwrap()
            .to_le_bytes(),
    );
    assert_eq!(after_call, start + bytes.len() as u64);
    offsets.push(bytes.len());
    bytes.extend_from_slice(&[0x48, 0x89, 0xd8]);
    offsets.push(bytes.len());
    bytes.extend_from_slice(&[0x48, 0x83, 0xc4, if fp { 24 } else { 32 }]);
    offsets.push(bytes.len());
    bytes.push(0x5b);
    if fp {
        offsets.push(bytes.len());
        bytes.push(0x5d);
    }
    offsets.push(bytes.len());
    bytes.push(0xc3);
    assert_eq!(end, start + bytes.len() as u64);
    assert_eq!(elf.file_slice(start, bytes.len(), true), bytes);
    Profile {
        start,
        selected,
        call,
        after_call,
        end,
        subject,
        heads: offsets
            .into_iter()
            .map(|offset| start + offset as u64)
            .collect(),
        fp,
    }
}
fn capture(
    elf: &elf::Elf,
    p: &Profile,
    seed: u64,
    generated: Option<(u64, u64)>,
) -> (OuterOutput, Vec<Trace>) {
    let input = OuterInput {
        callee: canaries(seed),
        subject: p.subject,
    };
    assert_ne!(input.callee[0], LIVE_RBX);
    let mut output = OuterOutput::default();
    let mut traces = [Trace::ZERO; 2];
    let mut config = Config {
        outer_return: elf.address("uw_outer_return"),
        outer_begin: elf.address("uw_outer_begin"),
        outer_end: elf.address("uw_outer_end"),
        source_begin: p.start,
        source_end: p.end,
        generated_begin: generated.map_or(0, |x| x.0),
        generated_end: generated.map_or(0, |x| x.1),
        context_bytes: std::mem::size_of::<HookContext>() as u64,
        context_rbx_offset: std::mem::offset_of!(HookContext, rbx) as u64,
        context_descriptor_offset: (std::mem::size_of::<HookContext>()
            - std::mem::size_of::<SavedExtendedStateDescriptor>())
            as u64,
        records: traces.as_mut_ptr(),
        capacity: if generated.is_some() { 2 } else { 1 },
        count: 0,
        failure: 0,
        reserved: 0,
    };
    assert_eq!(config.context_descriptor_offset, 144);
    unsafe {
        uw_capture_configure(&mut config);
        uw_outer(&input, &mut output);
        uw_capture_configure(std::ptr::null_mut());
    }
    assert_eq!(config.failure, 0);
    assert_eq!(config.count, config.capacity);
    assert_eq!(output.return_pc, elf.address("uw_outer_return"));
    assert_eq!(output.result, LIVE_RBX);
    assert_eq!(output.callee, input.callee);
    (output, traces[..config.count as usize].to_vec())
}
fn compare(
    trace: &Trace,
    output: &OuterOutput,
    p: &Profile,
    seed: u64,
    generated_return: Option<u64>,
) {
    assert!((1..=32).contains(&trace.count));
    assert_eq!((trace.reached, trace.overflow, trace.changed), (1, 0, 0));
    // This frozen libgcc profile returns FATAL_PHASE1_ERROR after our explicit
    // NORMAL_STOP callback. Original controls must establish it before publish.
    assert_eq!(trace.result, 3);
    assert_eq!(trace.reserved, 0);
    let owned: Vec<_> = trace.frames[..trace.count as usize]
        .iter()
        .filter(|frame| frame.owned == 1)
        .collect();
    assert_eq!(
        owned.len(),
        2,
        "exact subject/generated frame then outer; no synthetic original frame"
    );
    assert_eq!(owned[0].before, 0);
    assert_eq!(owned[1].before, 0);
    assert_eq!(owned[1].ip, output.return_pc);
    assert_eq!(owned[1].cfa, output.call_rsp);
    assert_eq!(owned[1].callee, canaries(seed));
    if let Some(return_pc) = generated_return {
        assert_eq!(owned[0].ip, return_pc);
        assert_eq!(trace.context_pc, p.selected);
        assert_eq!(trace.context_rsp, output.call_rsp - 48);
        assert_eq!(trace.context, trace.context_rsp - 304);
        assert_eq!(trace.context_rbx, LIVE_RBX);
        assert_eq!(owned[0].callee[0], LIVE_RBX);
        assert_eq!(owned[0].cfa, trace.xstate_address);
    } else {
        assert_eq!(owned[0].ip, p.after_call);
        assert_eq!(owned[0].cfa, output.call_rsp - 48);
        assert_eq!(
            (
                trace.context,
                trace.context_pc,
                trace.context_rsp,
                trace.context_rbx,
                trace.xstate_address
            ),
            (0, 0, 0, 0, 0)
        );
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Positive,
    NoFde,
    KeepGated,
}
fn run(fp: bool, mode: Mode) {
    assert_eq!(std::mem::size_of::<OuterInput>(), 56);
    assert_eq!(std::mem::size_of::<OuterOutput>(), 72);
    assert_eq!(std::mem::size_of::<Frame>(), 72);
    assert_eq!(std::mem::size_of::<Trace>(), 2368);
    assert_eq!(std::mem::size_of::<Config>(), 104);
    assert_eq!(std::mem::offset_of!(Trace, context), 2304);
    assert_eq!(std::mem::offset_of!(Trace, count), 2344);
    assert_eq!(std::mem::offset_of!(Config, records), 80);
    assert_eq!(unsafe { libc::getpid() } as i64, unsafe {
        libc::syscall(libc::SYS_gettid)
    });
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let consumer = Arc::new(consumer::Consumer::qualify());
    let elf = Arc::new(elf::Elf::current(address(uw_frameless)));
    let p = profile(&elf, fp);
    let outer_begin = elf.address("uw_outer_begin");
    let outer_end = elf.address("uw_outer_end");
    let outer_call = elf.address("uw_outer_call");
    let outer_return = elf.address("uw_outer_return");
    elf.authenticate_code(outer_begin, outer_end);
    assert_eq!(outer_call + 2, outer_return);
    assert_eq!(elf.file_slice(outer_call, 2, true), [0xff, 0xd0]);
    assert_eq!(
        elf.file_slice(outer_begin, 14, true),
        [
            0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x18
        ]
    );
    // Exact assembly stores the real call-site RSP into OuterOutput after all
    // six saves and the 24-byte allocation, before loading canary registers.
    assert_eq!(
        elf.file_slice(outer_begin + 23, 3, true),
        [0x48, 0x89, 0x26]
    );
    let outer_fde = unsafe { uw_find_fde(outer_call) } as usize as u64;
    assert_ne!(outer_fde, 0);
    let outer_record = elf.cfi(outer_fde);
    for point in [outer_call, outer_return] {
        let row = elf::prove_point(&outer_record, point, outer_begin, outer_end);
        assert_eq!(row.cfa, (7, 80));
        assert_eq!(row.registers[16], Some(-8));
        for (reg, offset) in [
            (3, -16),
            (6, -24),
            (12, -32),
            (13, -40),
            (14, -48),
            (15, -56),
        ] {
            assert_eq!(row.registers[reg], Some(offset));
        }
    }
    let bytes = elf
        .file_slice(p.start, (p.end - p.start) as usize, true)
        .to_vec();
    let mut strict = unsafe { oracle::process_text::ProcessTextOracle::new(p.start) };
    let original_page =
        unsafe { std::slice::from_raw_parts(p.start as usize as *const u8, 4096) }.to_vec();
    let baselines: Vec<_> = SEEDS
        .into_iter()
        .map(|seed| strict.original(&[p.selected, p.call], seed))
        .collect();
    let mut calls = 0;
    let mut backtraces = 0;
    let mut generated_crossings = 0;
    for seed in SEEDS {
        let (output, traces) = capture(&elf, &p, seed, None);
        assert_eq!(traces.len(), 1);
        compare(&traces[0], &output, &p, seed, None);
        calls += 1;
        backtraces += 1;
        if seed == SEEDS[0] {
            let mut wrong = output;
            wrong.call_rsp += 8;
            assert!(
                std::panic::catch_unwind(|| compare(&traces[0], &wrong, &p, seed, None)).is_err()
            );
            let mut wrong = output;
            wrong.return_pc += 1;
            assert!(
                std::panic::catch_unwind(|| compare(&traces[0], &wrong, &p, seed, None)).is_err()
            );
            assert!(
                std::panic::catch_unwind(|| compare(&traces[0], &output, &p, seed ^ 1, None))
                    .is_err()
            );
        }
    }
    // Real original controls ran before source-row certification and publication.
    let fde = unsafe { uw_find_fde(p.selected) } as usize as u64;
    assert_ne!(fde, 0);
    assert_eq!(unsafe { uw_find_fde(p.call) } as usize as u64, fde);
    let record = elf.cfi(fde);
    for point in [p.selected, p.call] {
        let row = elf::prove_point(&record, point, p.start, p.end);
        assert_eq!(row.cfa, if p.fp { (6, 16) } else { (7, 48) });
        assert_eq!(row.registers[16], Some(-8));
        assert_eq!(row.registers[3], Some(if p.fp { -24 } else { -16 }));
        assert_eq!(row.registers[6], if p.fp { Some(-16) } else { None });
        for reg in [12, 13, 14, 15] {
            assert_eq!(row.registers[reg], None);
        }
    }
    let identity = CodeIdentity {
        source: SourceIdentity([if fp { 0xd2 } else { 0xd1 }; 32]),
        mapping: p.start,
        generation: 1,
    };
    let range = AddressRange::new(p.start, bytes.len()).unwrap();
    let entries = LegalEntrySet {
        identity,
        scope: range,
        provenance: EntryProvenance::Declared(
            "literal original frame assembly and authenticated ELF labels".into(),
        ),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: p
            .heads
            .iter()
            .map(|&address| LegalEntry {
                address,
                requires_endbr: false,
            })
            .collect(),
        resumes: ResumeObligation::NoneExist,
    };
    let mut allocation = AllocationPolicy::near(p.selected).unwrap();
    // Fixture placement is explicit; the default allocator search is not under
    // test here. Derive the module bias from the authenticated actual ELF symbol.
    let load_bias = elf
        .address("uw_frameless")
        .checked_sub(elf.symbol("uw_frameless"))
        .unwrap();
    let preferred = load_bias.checked_sub(64 * 1024 * 1024).unwrap();
    assert_eq!(preferred & 4095, 0);
    let displacement = i128::from(preferred) - i128::from(p.selected.checked_add(5).unwrap());
    assert!(i32::try_from(displacement).is_ok());
    assert_eq!(allocation.max_candidates, 256);
    assert_eq!(allocation.max_mappings, 1);
    assert_eq!(allocation.max_mapped_bytes, 8192);
    let envelope = AddressRange::new(preferred, allocation.max_mapped_bytes).unwrap();
    assert!(allocation.ranges.iter().any(|range| range.covers(envelope)));
    allocation.preferred_address = Some(preferred);
    let install = plan_install_detailed(&InstallRequest {
        identity,
        code: &bytes,
        base_address: p.start,
        function: range,
        block: AddressRange::new(p.selected, 5).unwrap(),
        logical_pc: p.selected,
        entries: &entries,
        hook: uw_collect_hook,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::RelocationOnly,
            max_upstream_bytes: 0,
            max_sites: 1,
            ..SearchPolicy::default()
        },
    })
    .unwrap_or_else(|failure| {
        use std::io::Read;
        const MAPS_LIMIT: usize = 128 * 1024;
        let mut maps = Vec::new();
        let maps_read = std::fs::File::open("/proc/self/maps").and_then(|file| {
            file.take((MAPS_LIMIT + 1) as u64).read_to_end(&mut maps)
        });
        let maps_truncated = maps.len() > MAPS_LIMIT;
        maps.truncate(MAPS_LIMIT);
        panic!(
            "required fixed-placement plan failed: selected={:#x}, load_bias={load_bias:#x}, preferred={preferred:#x}, displacement={displacement}, allocation={allocation:?}, failure={failure:#?}; post_failure_maps_read={maps_read:?}, post_failure_maps_truncated={maps_truncated}; post_failure_maps_snapshot (not atomic occupancy proof):\n{}",
            p.selected,
            String::from_utf8_lossy(&maps),
        );
    });
    assert_eq!(install.image().address(), preferred);
    assert_eq!(install.metrics().allocation_attempts, 1);
    assert_eq!(install.plan().parts().kind, PlanKind::Relocation);
    assert_eq!(install.plan().parts().writes.len(), 1);
    let scan = InstructionScanner::default().scan(&bytes, p.start).unwrap();
    let emission = TrampolinePlan::from_scan(&scan, p.selected, uw_collect_hook)
        .unwrap()
        .emit_with_frame_trace_at(install.image().address())
        .unwrap();
    assert_eq!(emission.image(), install.image());
    let trace = emission.trace().unwrap();
    assert_eq!(trace.calls().len(), 1);
    let generated_return = trace.calls()[0].return_pc();
    let owner = Arc::new(AdmissionOwner {
        inner: elf.owner(std::slice::from_ref(&record)),
        refuse: AtomicBool::new(false),
    });
    let source = Arc::new(
        unsafe {
            SourceCertificate::certify(
                identity,
                vec![record],
                vec![p.selected, p.call],
                owner.clone(),
                Limits::default(),
            )
        }
        .unwrap(),
    );
    let source_lifetime = Arc::downgrade(&source);
    // Six actual function pointers resolve into the same immutable, pinned
    // consumer image. Root also binds the exact frozen file and toolchain.
    consumer.revalidate();
    let backend =
        Arc::new(unsafe { Backend::qualified(uw_register, uw_find_fde, consumer.clone()) });
    let prepared = PreparedUnwind::prepare(
        &install,
        &emission,
        source,
        unsafe { FramePreservingHook::certify(uw_collect_hook) },
        backend,
        Limits::default(),
    )
    .unwrap();
    let image = install.image().bytes().to_vec();
    let generated = install.image().address();
    let edits: Vec<_> = install
        .plan()
        .parts()
        .writes
        .iter()
        .map(|edit| (edit.address, edit.bytes.clone()))
        .collect();
    let registration_before = unsafe { uw_registration_count() };
    assert_eq!(registration_before, 0);
    if mode == Mode::Positive {
        // Explicit admission failure is separate from stale source and mapping
        // collision. It cannot register, finalize or mutate the source.
        owner.refuse.store(true, Ordering::SeqCst);
        {
            let writable = strict.code.writable();
            let mut lease = unsafe { QuiescenceLease::new(&mut strict, identity, vec![range]) };
            let failure = unsafe {
                install.publish_with_unwind(&prepared, writable, &mut lease, || {
                    panic!("finalizer after source admission refusal")
                })
            }
            .err()
            .unwrap();
            assert!(matches!(
                failure,
                corelib::generated_unwind::PublicationError::Preparation(
                    corelib::generated_unwind::Refusal::SourceIdentity
                )
            ));
            assert!(!lease.is_poisoned());
        }
        assert_eq!(unsafe { uw_registration_count() }, registration_before);
        strict.assert_publication(&[]);
        owner.refuse.store(false, Ordering::SeqCst);
        // A stale original byte must fail before allocation or registration.
        let writable = strict.code.writable();
        permissions(p.start, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe {
            (p.selected as usize as *mut u8).write(0x90);
        }
        {
            let mut lease = unsafe { QuiescenceLease::new(&mut strict, identity, vec![range]) };
            let failure = unsafe {
                install.publish_with_unwind(&prepared, writable, &mut lease, || {
                    panic!("finalizer after stale byte")
                })
            }
            .err()
            .unwrap();
            assert!(matches!(
                failure,
                corelib::generated_unwind::PublicationError::Publication(PublicationFailure {
                    reason: Refusal::ExpectedBytesChanged,
                    stage: FailureStage::BeforeWrite
                })
            ));
            assert!(!lease.is_poisoned());
        }
        strict.assert_publication(&[(p.selected, vec![0x90])]);
        assert_eq!(unsafe { uw_registration_count() }, registration_before);
        unsafe {
            (p.selected as usize as *mut u8).write(0x0f);
        }
        permissions(p.start, libc::PROT_READ | libc::PROT_EXEC).unwrap();
        strict.assert_publication(&[]);
        // Exact occupied destination is a distinct required prewrite failure.
        let page = generated & !4095;
        let held = unsafe {
            libc::mmap(
                page as usize as *mut _,
                4096,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_eq!(held, page as usize as *mut _);
        {
            let mut lease = unsafe { QuiescenceLease::new(&mut strict, identity, vec![range]) };
            let failure = unsafe {
                install.publish_with_unwind(&prepared, writable, &mut lease, || {
                    panic!("finalizer after occupied target")
                })
            }
            .err()
            .unwrap();
            let corelib::generated_unwind::PublicationError::Publication(failure) = failure else {
                panic!("wrong collision class")
            };
            assert_eq!(failure.stage, FailureStage::BeforeWrite);
            assert_eq!(
                failure.reason,
                Refusal::Backend(
                    corelib::trampoline::TrampolineError::ExactAddressUnavailable {
                        address: generated
                    }
                    .to_string()
                )
            );
            assert!(!lease.is_poisoned());
        }
        assert_eq!(unsafe { libc::munmap(held, 4096) }, 0);
        assert_eq!(unsafe { uw_registration_count() }, registration_before);
        strict.assert_publication(&[]);
    }
    if mode == Mode::KeepGated {
        let writable = strict.code.writable();
        let mut lease = unsafe { QuiescenceLease::new(&mut strict, identity, vec![range]) };
        permissions(p.start, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        let failure = unsafe {
            install.publish_with_unwind(&prepared, writable, &mut lease, || {
                permissions(p.start, libc::PROT_READ | libc::PROT_EXEC)?;
                Err(Refusal::Backend(
                    "required unwind finalization refusal".into(),
                ))
            })
        }
        .err()
        .unwrap();
        let corelib::generated_unwind::PublicationError::Publication(failure) = failure else {
            panic!("wrong finalization class")
        };
        assert_eq!(failure.stage, FailureStage::KeepGated);
        assert!(lease.is_poisoned());
        assert_eq!(
            failure.reason,
            Refusal::Backend("required unwind finalization refusal".into())
        );
        assert_eq!(unsafe { uw_registration_count() }, 1);
        let registered_fde = unsafe { uw_find_fde(generated_return - 1) } as usize as u64;
        assert_ne!(registered_fde, 0);
        let fde_offset = prepared
            .fdes()
            .iter()
            .find(|(start, end, _)| *start <= generated_return - 1 && generated_return - 1 < *end)
            .unwrap()
            .2;
        let cfi = registered_fde.checked_sub(fde_offset as u64).unwrap();
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(cfi as usize as *const u8, prepared.bytes().len())
            },
            prepared.bytes()
        );
        read_only_mapping(cfi, (prepared.bytes().len() + 4095) & !4095);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(generated as usize as *const u8, image.len()) },
            image
        );
        let mut expected = original_page.clone();
        for edit in &edits {
            let offset = usize::try_from(edit.0 - p.start).unwrap();
            expected[offset..offset + edit.1.len()].copy_from_slice(&edit.1);
        }
        assert_eq!(
            unsafe { std::slice::from_raw_parts(p.start as usize as *const u8, 4096) },
            expected
        );
        drop(prepared);
        assert!(source_lifetime.upgrade().is_some());
        eprintln!(
            "required_keep_gated source_written=true lease_poisoned=true code_cfi_source_retained=true no_subject_reentry=true"
        );
        // Real exclusion persists until this fresh single-thread process dies.
        isolation::complete_and_exit();
    }
    let (mut installed, receipt, registration) = {
        let writable = strict.code.writable();
        let mut lease = unsafe { QuiescenceLease::new(&mut strict, identity, vec![range]) };
        permissions(p.start, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        if mode == Mode::NoFde {
            let (installed, receipt) = unsafe {
                install.publish_with(writable, &mut lease, || {
                    permissions(p.start, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap();
            (installed, receipt, None)
        } else {
            let (installed, receipt, registration) = unsafe {
                install.publish_with_unwind(&prepared, writable, &mut lease, || {
                    permissions(p.start, libc::PROT_READ | libc::PROT_EXEC)
                })
            }
            .unwrap();
            (installed, receipt, Some(registration))
        }
    };
    assert_eq!(receipt.plan(), install.plan());
    strict.assert_publication(&edits);
    let metadata = prepared.bytes().to_vec();
    let fdes = prepared.fdes().to_vec();
    if let Some(registration) = &registration {
        let stored = unsafe {
            std::slice::from_raw_parts(registration.address() as usize as *const u8, metadata.len())
        };
        assert_eq!(stored, metadata);
        read_only_mapping(registration.address(), registration.mapping_len());
    } else {
        assert_eq!(
            unsafe { uw_find_fde(generated_return - 1) },
            std::ptr::null()
        );
        assert_eq!(unsafe { uw_registration_count() }, 0);
    }
    drop(prepared);
    if mode == Mode::Positive {
        assert!(source_lifetime.upgrade().is_some());
    }
    drop(owner);
    for (&seed, baseline) in SEEDS.iter().zip(&baselines) {
        // Same callback and bytes, but no active collector: a bounded no-op
        // architectural prefix proof with the unchanged strict comparator.
        strict.assert_patched(
            baseline,
            p.selected,
            install.image().instruction_boundaries(),
            &[],
        );
        let (output, traces) = capture(
            &elf,
            &p,
            seed,
            Some((generated, generated + image.len() as u64)),
        );
        assert_eq!(traces.len(), 2);
        if mode == Mode::NoFde {
            assert_eq!(traces[0].reached, 0);
            assert_eq!((traces[0].overflow, traces[0].changed), (0, 0));
            assert_eq!(traces[0].result, 5);
            assert!(
                traces[0].frames[..traces[0].count as usize]
                    .iter()
                    .any(|f| f.ip == generated_return)
            );
            assert!(
                std::panic::catch_unwind(|| compare(
                    &traces[0],
                    &output,
                    &p,
                    seed,
                    Some(generated_return)
                ))
                .is_err()
            );
        } else {
            compare(&traces[0], &output, &p, seed, Some(generated_return));
            generated_crossings += 1;
        }
        compare(&traces[1], &output, &p, seed, None);
        calls += 1;
        backtraces += 2;
        assert_eq!(
            unsafe { std::slice::from_raw_parts(generated as usize as *const u8, image.len()) },
            image
        );
        strict.assert_publication(&edits);
    }
    {
        let mut ranges = vec![range];
        ranges.extend(install.plan().parts().allocations.iter().map(|a| a.range));
        let mut lease = unsafe { QuiescenceLease::new(&mut strict, identity, ranges) };
        permissions(p.start, libc::PROT_READ | libc::PROT_WRITE).unwrap();
        unsafe {
            installed.retire_with(&mut lease, || {
                permissions(p.start, libc::PROT_READ | libc::PROT_EXEC)
            })
        }
        .unwrap();
    }
    strict.assert_publication(&[]);
    for (&seed, baseline) in SEEDS.iter().zip(&baselines) {
        strict.assert_patched(baseline, p.selected, &[], &[]);
        let (output, traces) = capture(&elf, &p, seed, None);
        compare(&traces[0], &output, &p, seed, None);
        calls += 1;
        backtraces += 1;
    }
    assert_eq!(
        (calls, backtraces, generated_crossings),
        (6, 8, if mode == Mode::Positive { 2 } else { 0 })
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(generated as usize as *const u8, image.len()) },
        image
    );
    if let Some(registration) = &registration {
        read_only_mapping(registration.address(), registration.mapping_len());
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    registration.address() as usize as *const u8,
                    metadata.len(),
                )
            },
            metadata
        );
        let fde_offset = fdes
            .iter()
            .find(|(start, end, _)| *start <= generated_return - 1 && generated_return - 1 < *end)
            .unwrap()
            .2;
        assert_eq!(
            unsafe { uw_find_fde(generated_return - 1) } as usize as u64,
            registration.address() + fde_offset as u64
        );
    }
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    consumer.revalidate();
    eprintln!(
        "profile={} subjects=6 real_backtraces=8 generated_crossings={} strict_original=2 strict_installed=2 strict_retired=2 source_restored=true registered={}",
        if fp { "frame-pointer" } else { "frameless" },
        generated_crossings,
        mode == Mode::Positive
    );
}
pub fn run_cohort(cohort: &str) {
    match cohort {
        "frameless" => run(false, Mode::Positive),
        "frame-pointer" => run(true, Mode::Positive),
        "no-fde-frameless" => run(false, Mode::NoFde),
        "no-fde-frame-pointer" => run(true, Mode::NoFde),
        "keep-gated-frameless" => run(false, Mode::KeepGated),
        "keep-gated-frame-pointer" => run(true, Mode::KeepGated),
        _ => panic!("unknown fixed profile"),
    }
}
#[cfg(not(test))]
fn main() {
    isolation::main_thread_driver();
}
#[test]
fn required_frameless() {
    isolation::run_parent("frameless");
}
#[test]
fn required_frame_pointer() {
    isolation::run_parent("frame-pointer");
}
#[test]
fn rejects_no_fde_frameless() {
    isolation::run_parent("no-fde-frameless");
}
#[test]
fn rejects_no_fde_frame_pointer() {
    isolation::run_parent("no-fde-frame-pointer");
}
#[test]
fn retains_keep_gated_frameless() {
    isolation::run_parent("keep-gated-frameless");
}
#[test]
fn retains_keep_gated_frame_pointer() {
    isolation::run_parent("keep-gated-frame-pointer");
}
