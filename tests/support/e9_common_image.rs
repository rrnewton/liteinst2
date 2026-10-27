//! Controlled ORIGINAL-image references, not normal exec or paired equivalence.
//! The enclosing recipe must authenticate whole input hashes and their owners.
//! This adapter retains all input bytes and checks their exact closed-kernel,
//! LOAD, seed, target, mapping and stopped-state relationships itself.
use super::*;
use liteinst2::cache_line::CacheLineSize;
use liteinst2::scanner::InstructionScanner;

#[path = "e9_common_seed.rs"]
mod seed;

#[path = "e9_common_recording.rs"]
mod recording;
#[path = "e9_common_recording_native.rs"]
mod recording_native;

#[path = "e9_common_core.rs"]
pub mod core_pair;

#[path = "e9_common_e9.rs"]
pub mod e9_pair;

#[path = "e9_common_core_pages.rs"]
mod core_pages;
use core_pages::{IMAGE_END, IMAGE_START, LOADS};

const ARRAY: u64 = 0x6000_0000_0000;
const FRAME: u64 = 0x6000_0010_0008;
const STACK_START: u64 = FRAME - 32776;
const STACK_STOP: u64 = FRAME + 32760;

fn identity(m: &std::fs::Metadata) -> [i128; 8] {
    [
        i128::from(m.dev()),
        i128::from(m.ino()),
        i128::from(m.mode()),
        i128::from(m.len()),
        i128::from(m.mtime()),
        i128::from(m.mtime_nsec()),
        i128::from(m.ctime()),
        i128::from(m.ctime_nsec()),
    ]
}

struct Input {
    path: PathBuf,
    file: File,
    owner: [i128; 8],
    bytes: Vec<u8>,
}
impl Input {
    fn open(path: &Path, max: usize) -> Self {
        assert!(path.is_absolute());
        assert_eq!(path.canonicalize().unwrap().as_os_str(), path.as_os_str());
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .unwrap();
        let metadata = file.metadata().unwrap();
        assert!(metadata.is_file() && metadata.len() > 0 && metadata.len() <= max as u64);
        let mut bytes = Vec::new();
        (&file)
            .take((max + 1) as u64)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len() as u64, metadata.len());
        let result = Self {
            path: path.to_owned(),
            file,
            owner: identity(&metadata),
            bytes,
        };
        result.stable();
        result
    }
    fn stable(&self) {
        assert_eq!(identity(&self.file.metadata().unwrap()), self.owner);
        assert_eq!(
            identity(&std::fs::symlink_metadata(&self.path).unwrap()),
            self.owner
        );
        use std::os::unix::fs::FileExt;
        let mut bytes = vec![0; self.bytes.len()];
        self.file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, self.bytes, "whole input drift");
        assert_eq!(identity(&self.file.metadata().unwrap()), self.owner);
    }
}

/// Copies the actual PT_LOAD page views. No dynamic relocations, interpreter,
/// constructors or other process startup are emulated or executed.
fn original_pages(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() >= 64);
    assert_eq!(&bytes[..7], b"\x7fELF\x02\x01\x01");
    assert_eq!((u16_at(bytes, 16), u16_at(bytes, 18)), (2, 62));
    assert_eq!((u16_at(bytes, 52), u16_at(bytes, 54)), (64, 56));
    let phoff = usize::try_from(word(bytes, 32)).unwrap();
    let phnum = usize::from(u16_at(bytes, 56));
    assert!((1..=128).contains(&phnum));
    assert!(phoff.checked_add(phnum * 56).unwrap() <= bytes.len());
    let mut loads = Vec::new();
    for index in 0..phnum {
        let p = phoff + index * 56;
        if u32_at(bytes, p) == 1 {
            assert_eq!(word(bytes, p + 48), 4096);
            loads.push((
                word(bytes, p + 8),
                word(bytes, p + 16),
                word(bytes, p + 32),
                word(bytes, p + 40),
                u32_at(bytes, p + 4),
            ));
        }
    }
    assert_eq!(
        loads, LOADS,
        "only the inspected complete original LOAD geometry"
    );
    let mut pages = vec![0; (IMAGE_END - IMAGE_START) as usize];
    let mut owned = BTreeSet::new();
    for &(offset, address, file_len, memory_len, _) in &loads {
        assert!(file_len <= memory_len && offset + file_len <= bytes.len() as u64);
        assert_eq!(offset % 4096, address % 4096);
        let start = address & !4095;
        let end = page_end(address + memory_len);
        let file_start = offset & !4095;
        for page in (start..end).step_by(PAGE) {
            assert!(owned.insert(page), "ambiguous overlapping LOAD page");
            let file_offset = file_start + page - start;
            // File-page prefixes and suffixes are retained; BSS and its final
            // partial page are explicitly zeroed below, as declared by this view.
            if page < page_end(address + file_len) {
                let count = PAGE.min(bytes.len().saturating_sub(file_offset as usize));
                let at = (page - IMAGE_START) as usize;
                pages[at..at + count]
                    .copy_from_slice(&bytes[file_offset as usize..file_offset as usize + count]);
            }
        }
        if memory_len > file_len {
            pages[(address + file_len - IMAGE_START) as usize..(end - IMAGE_START) as usize]
                .fill(0);
        }
    }
    assert_eq!(
        owned,
        (IMAGE_START..IMAGE_END)
            .step_by(PAGE)
            .collect::<BTreeSet<_>>()
    );
    for range in seed::ORIGINAL_RANGES {
        let start = (range.pc - IMAGE_START) as usize;
        assert_eq!(&pages[start..start + range.bytes.len()], range.bytes);
    }
    // Relocations elsewhere in this dynamically linked file are not applied.
    // A relocation affecting any admitted instruction is an unsupported input.
    let shoff = usize::try_from(word(bytes, 40)).unwrap();
    let shnum = usize::from(u16_at(bytes, 60));
    assert_eq!(u16_at(bytes, 58), 64);
    assert!((1..=128).contains(&shnum));
    assert!(shoff.checked_add(shnum * 64).unwrap() <= bytes.len());
    for index in 0..shnum {
        let p = shoff + index * 64;
        let kind = u32_at(bytes, p + 4);
        if matches!(kind, 4 | 9) {
            let offset = usize::try_from(word(bytes, p + 24)).unwrap();
            let len = usize::try_from(word(bytes, p + 32)).unwrap();
            let stride = if kind == 4 { 24 } else { 16 };
            assert_eq!(word(bytes, p + 56), stride as u64);
            assert_eq!(len % stride, 0);
            assert!(offset.checked_add(len).unwrap() <= bytes.len());
            for row in bytes[offset..offset + len].chunks_exact(stride) {
                let destination = word(row, 0);
                assert!(
                    !seed::ORIGINAL_RANGES
                        .iter()
                        .any(|r| destination < r.pc + r.bytes.len() as u64
                            && r.pc < destination.checked_add(8).unwrap()),
                    "relocation can modify the closed kernel"
                );
            }
        }
    }
    pages
}

fn admit(original: &[u8], table: &[u8]) -> seed::Inventory {
    let ranges: Vec<_> = seed::ORIGINAL_RANGES
        .iter()
        .map(|r| seed::SourceRange {
            function: r.function,
            pc: r.pc,
            file_offset: r.file_offset,
            bytes: &original[r.file_offset as usize..r.file_offset as usize + r.bytes.len()],
        })
        .collect();
    let inventory = seed::authenticate(table, &ranges).unwrap();
    let scanner = InstructionScanner::new(CacheLineSize::new(64).unwrap());
    let mut count = 0;
    for range in ranges {
        let scan = scanner.scan(range.bytes, range.pc).unwrap();
        for instruction in scan.instructions() {
            let h = seed::HEADS[count];
            assert_eq!(
                (instruction.address(), instruction.len()),
                (h.pc, usize::from(h.length))
            );
            let i = instruction.instruction();
            assert!(
                !i.is_ip_rel_memory_operand(),
                "no external RIP-relative read"
            );
            let (flow, target) = match h.flow {
                seed::Flow::Next => ("Next", None),
                seed::Flow::Jb(to)
                | seed::Flow::Jae(to)
                | seed::Flow::Jbe(to)
                | seed::Flow::Jne(to) => ("ConditionalBranch", Some(to)),
                seed::Flow::Jump(to) => ("UnconditionalBranch", Some(to)),
                seed::Flow::Call(to) => ("Call", Some(to)),
                seed::Flow::Return => ("Return", None),
            };
            assert_eq!(format!("{:?}", i.flow_control()), flow);
            if let Some(to) = target {
                assert_eq!(i.near_branch_target(), to);
                assert!(seed::HEADS.iter().any(|head| head.pc == to));
            }
            count += 1;
        }
    }
    assert_eq!(count, seed::HEAD_COUNT);
    inventory
}

fn reserve(address: u64, len: usize) -> Mapping {
    // SAFETY: NOREPLACE atomically refuses every existing mapping; there is no
    // MAP_FIXED fallback. A mismatched result is never accepted as this owner.
    let pointer = unsafe {
        libc::mmap(
            address as usize as *mut _,
            len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    assert_ne!(
        pointer,
        libc::MAP_FAILED,
        "nonclobbering exact reservation failed"
    );
    let mapping = Mapping {
        address: pointer.cast(),
        len,
    };
    assert_eq!(mapping.address(), address, "kernel did not honor NOREPLACE");
    mapping
}
fn protect(address: u64, len: usize, protection: i32) {
    // SAFETY: each caller supplies a complete page interval of our held owner.
    assert_eq!(
        unsafe { libc::mprotect(address as usize as *mut _, len, protection) },
        0
    );
}
fn protection(flags: u32) -> i32 {
    match flags {
        4 => libc::PROT_READ,
        5 => libc::PROT_READ | libc::PROT_EXEC,
        6 => libc::PROT_READ | libc::PROT_WRITE,
        _ => panic!("unsupported permissions"),
    }
}
struct OwnedImage {
    image: Mapping,
    data: Mapping,
    stack: Mapping,
    pages: Vec<u8>,
    target: SavedExtendedStateLayout,
}
impl OwnedImage {
    fn new(pages: Vec<u8>) -> Self {
        seed::Anchors::new(ARRAY, FRAME).unwrap();
        let image = reserve(IMAGE_START, pages.len());
        let data = reserve(ARRAY - PAGE as u64, 3 * PAGE);
        let stack = reserve(STACK_START - PAGE as u64, seed::STACK_BYTES + 2 * PAGE);
        image.protect(libc::PROT_READ | libc::PROT_WRITE);
        image.initialize(0, &pages);
        for &(_, address, _, len, flags) in &LOADS {
            let start = address & !4095;
            protect(
                start,
                (page_end(address + len) - start) as usize,
                protection(flags),
            );
        }
        protect(
            STACK_START,
            seed::STACK_BYTES,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        Self {
            image,
            data,
            stack,
            pages,
            target: target(),
        }
    }
    fn initialize(&self, spec: &seed::SeedSpec) {
        assert_eq!(
            (
                spec.data.region.start,
                spec.stack.region.start,
                spec.stack.region.end
            ),
            (ARRAY, STACK_START, STACK_STOP)
        );
        assert_eq!(spec.compared_stack_start, FRAME - 128);
        protect(ARRAY, PAGE, libc::PROT_READ | libc::PROT_WRITE);
        self.data.initialize(PAGE, &spec.data.bytes);
        self.stack.initialize(PAGE, &spec.stack.bytes);
        if spec.data.region.permissions == seed::Permissions::Read {
            protect(ARRAY, PAGE, libc::PROT_READ);
        } else {
            assert_eq!(spec.data.region.permissions, seed::Permissions::ReadWrite);
        }
        assert_eq!(
            self.image.bytes(),
            self.pages,
            "parent original image drift"
        );
    }
}

fn map_record(child: &Tracee, spec: &seed::SeedSpec, dir: &Path, stem: &str) {
    let mut raw = String::new();
    File::open(format!("/proc/{}/maps", child.pid))
        .unwrap()
        .take(1024 * 1024 + 1)
        .read_to_string(&mut raw)
        .unwrap();
    write_new(&dir.join(format!("{stem}.maps")), raw.as_bytes());
    assert!(raw.len() <= 1024 * 1024 && raw.ends_with('\n'));
    let mut expected = Vec::new();
    for &(_, address, _, len, flags) in &LOADS {
        let permission = match flags {
            4 => "r--p",
            5 => "r-xp",
            6 => "rw-p",
            _ => unreachable!(),
        };
        expected.push((address & !4095, page_end(address + len), permission));
    }
    expected.push((
        ARRAY,
        ARRAY + 4096,
        if spec.data.region.permissions == seed::Permissions::Read {
            "r--p"
        } else {
            "rw-p"
        },
    ));
    expected.push((STACK_START, STACK_STOP, "rw-p"));
    for guard in spec.guards {
        expected.push((guard.start, guard.end, "---p"));
    }
    for (start, end, permission) in expected {
        for page in (start..end).step_by(PAGE) {
            let rows: Vec<_> = raw
                .lines()
                .filter_map(|line| {
                    let fields: Vec<_> = line.split_ascii_whitespace().collect();
                    assert!(fields.len() >= 5);
                    let (a, b) = fields[0].split_once('-').unwrap();
                    let a = u64::from_str_radix(a, 16).unwrap();
                    let b = u64::from_str_radix(b, 16).unwrap();
                    (a <= page && page + 4096 <= b).then_some(fields)
                })
                .collect();
            assert_eq!(rows.len(), 1, "one anonymous owned page view");
            let row = &rows[0];
            assert_eq!(row[1], permission);
            assert_eq!(u64::from_str_radix(row[2], 16).unwrap(), 0);
            assert_eq!(row[3], "00:00");
            assert_eq!(row[4], "0");
            assert_eq!(row.len(), 5, "no file or other named mapping owner");
        }
    }
    assert_eq!(
        std::fs::read_dir(format!("/proc/{}/task", child.pid))
            .unwrap()
            .count(),
        1
    );
}

fn apply(spec: &seed::SeedSpec, mut r: libc::user_regs_struct) -> libc::user_regs_struct {
    use seed::Reg::*;
    macro_rules! gpr { ($($field:ident:$reg:ident),*) => { $(r.$field = spec.registers.get($reg);)* }; }
    gpr!(rax:Rax,rbx:Rbx,rcx:Rcx,rdx:Rdx,rsi:Rsi,rdi:Rdi,rbp:Rbp,rsp:Rsp,
         r8:R8,r9:R9,r10:R10,r11:R11,r12:R12,r13:R13,r14:R14,r15:R15);
    r.rip = spec.registers.rip;
    r.orig_rax = spec.registers.orig_rax;
    r.eflags = spec.registers.rflags;
    r
}
fn inherited(r: &libc::user_regs_struct) -> [u64; 8] {
    [r.cs, r.ss, r.ds, r.es, r.fs, r.gs, r.fs_base, r.gs_base]
}
fn xstate_ready(raw: &[u8], state: &SavedExtendedStateLayout) {
    assert!(raw.len() >= state.image_len() as usize);
    for c in state.components() {
        assert!(c.xfeature().is_power_of_two());
        assert!(c.offset().checked_add(c.size()).unwrap() <= raw.len() as u64);
        let bit = c.xfeature().trailing_zeros();
        if bit >= 2 {
            assert!(components(raw).contains(&(bit, c.offset() as usize, c.size() as usize)));
        }
    }
    let _ = canonical_xstate(raw); // Existing standard-format and CPUID checks.
}
struct Captured {
    state: Snapshot,
    raw: Vec<u8>,
    stack: Vec<u8>,
}
fn capture(
    owned: &OwnedImage,
    child: &Tracee,
    spec: &seed::SeedSpec,
    dir: &Path,
    stem: &str,
) -> Captured {
    let registers = child.registers();
    let raw = child.xstate();
    assert_eq!(target(), owned.target);
    xstate_ready(&raw, &owned.target);
    let stack = child.memory(STACK_START, seed::STACK_BYTES);
    let state = Snapshot {
        logical_pc: registers.rip,
        registers,
        xstate: canonical_xstate(&raw),
        data: child.memory(ARRAY, PAGE),
        application_stack: stack[(spec.compared_stack_start - STACK_START) as usize..].to_vec(),
    };
    save_named_snapshot(dir, stem, &state);
    write_new(&dir.join(format!("{stem}.xstate-raw")), &raw);
    write_new(&dir.join(format!("{stem}.stack-owned")), &stack);
    let pages = child.memory(IMAGE_START, owned.pages.len());
    write_new(&dir.join(format!("{stem}.loads")), &pages);
    map_record(child, spec, dir, stem);
    assert_eq!(
        pages, owned.pages,
        "all original code/globals/journal/BSS stay exact"
    );
    Captured { state, raw, stack }
}

struct Context {
    registers: libc::user_regs_struct,
    xstate: Vec<u8>,
}
fn reference(
    owned: &OwnedImage,
    spec: &seed::SeedSpec,
    context: &mut Option<Context>,
    dir: &Path,
) -> (Captured, Captured) {
    owned.initialize(spec);
    let child = Tracee::fork();
    child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
    let initial = child.registers();
    let initial_xstate = child.xstate();
    assert_eq!(target(), owned.target);
    xstate_ready(&initial_xstate, &owned.target);
    if context.is_none() {
        *context = Some(Context {
            registers: initial,
            xstate: initial_xstate.clone(),
        });
    }
    let template = context.as_ref().unwrap();
    assert_eq!(inherited(&initial), inherited(&template.registers));
    assert_eq!(initial_xstate.len(), template.xstate.len());
    let wanted = apply(spec, template.registers);
    let seeded = seeded_xstate(template.xstate.clone(), spec.seed);
    child.set_registers(&wanted);
    child.set_xstate(&seeded);
    // This is the sole seed. From this point no SETREGS/SETREGSET or memory
    // writes occur in the child; the next state comes from hardware alone.
    let before = capture(owned, &child, spec, dir, "before");
    assert_eq!(before.state.registers.rip, spec.registers.rip);
    let expected = Snapshot {
        logical_pc: spec.registers.rip,
        registers: wanted,
        xstate: canonical_xstate(&seeded),
        data: spec.data.bytes.clone(),
        application_stack: spec.stack.bytes[(spec.compared_stack_start - STACK_START) as usize..]
            .to_vec(),
    };
    assert_state(&expected, &before.state);
    assert_eq!(before.stack, spec.stack.bytes);
    if let Some(effect) = spec.memory_effect {
        if effect.access == seed::Access::Read {
            assert_eq!(child.memory(effect.address, 8), effect.bytes);
        }
    }
    let mut steps = 0;
    let fault = match spec.completion {
        seed::Completion::OriginalPc { .. } => {
            step(&child, &mut steps);
            None
        }
        seed::Completion::Fault { .. } => {
            assert!(steps < MAX_STEPS && Instant::now() < child.deadline);
            steps += 1;
            Some(child.synchronous_fault())
        }
    };
    assert_eq!(
        steps, 1,
        "exactly one original hardware instruction attempt"
    );
    let after = capture(owned, &child, spec, dir, "after");
    assert_eq!(after.raw.len(), before.raw.len());
    let mut expected_data = spec.data.bytes.clone();
    let mut expected_stack = spec.stack.bytes.clone();
    match spec.completion {
        seed::Completion::OriginalPc { pc, rsp } => {
            assert_eq!(
                (after.state.registers.rip, after.state.registers.rsp),
                (pc, rsp)
            );
            if let Some(effect) = spec.memory_effect {
                if effect.access == seed::Access::Write {
                    let (bytes, base) = match effect.domain {
                        seed::Domain::Array => (&mut expected_data, ARRAY),
                        seed::Domain::Stack => (&mut expected_stack, STACK_START),
                    };
                    let offset = (effect.address - base) as usize;
                    bytes[offset..offset + 8].copy_from_slice(&effect.bytes);
                }
            }
        }
        seed::Completion::Fault {
            pc,
            rsp,
            signal,
            code,
            address,
        } => {
            assert_eq!(fault, Some((signal, code, address)));
            assert_eq!(
                (after.state.registers.rip, after.state.registers.rsp),
                (pc, rsp)
            );
            assert_state(&before.state, &after.state);
        }
    }
    assert_eq!(after.state.xstate, before.state.xstate);
    assert_eq!(
        inherited(&after.state.registers),
        inherited(&before.state.registers)
    );
    assert_eq!(after.state.data, expected_data);
    assert_eq!(
        after.stack, expected_stack,
        "whole owned original stack, including true CALL words"
    );
    let pid = child.pid;
    drop(child); // Existing exact-child SIGKILL and bounded reap, unchanged.
    let mut status = 0;
    // SAFETY: querying only the child just reaped by the existing owner.
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    write_new(&dir.join("complete.tsv"), format!(
        "LI2ORIGINALREFERENCE\t1\ncase\t{}\nsteps\t1\nnormal\t{}\nfault\t{:?}\nreaped_echild\ttrue\npaired_replay\tUNIMPLEMENTED_UNRUN\nqualification_complete\tfalse\n",
        spec.case_index, fault.is_none(), fault).as_bytes());
    (before, after)
}

pub fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        6,
        "replay-common-original ORIGINAL INSTRUCTIONS TARGET NEW_CAPTURES"
    );
    assert_eq!(args[1], "replay-common-original");
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    // SAFETY: scalar identity query; the driver must run on its process main thread.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        libc::c_long::from(std::process::id())
    );
    let original = Input::open(Path::new(&args[2]), 1024 * 1024);
    let instructions = Input::open(Path::new(&args[3]), 16384);
    let requested_target = Input::open(Path::new(&args[4]), 16384);
    assert_eq!(requested_target.bytes, target_tsv().as_bytes());
    let inventory = admit(&original.bytes, &instructions.bytes);
    let pages = original_pages(&original.bytes);
    let anchors = seed::Anchors::new(ARRAY, FRAME).unwrap();
    let specs: Vec<_> = (0..seed::CASE_COUNT)
        .map(|index| inventory.case(index, anchors).unwrap())
        .collect();
    let dir = Path::new(&args[5]);
    assert!(dir.is_absolute());
    assert_eq!(
        dir.parent().unwrap().canonicalize().unwrap().as_os_str(),
        dir.parent().unwrap().as_os_str()
    );
    std::fs::create_dir(dir).unwrap();
    write_new(&dir.join("original.elf"), &original.bytes);
    write_new(&dir.join("instructions.tsv"), &instructions.bytes);
    write_new(&dir.join("runtime-target.tsv"), &requested_target.bytes);
    write_new(&dir.join("original-pages.bin"), &pages);
    write_new(&dir.join("input-owners.tsv"), format!(
        "original\t{:?}\ninstructions\t{:?}\ntarget\t{:?}\nwhole_hash_admission\tCALLER_REQUIRED\n",
        original.owner, instructions.owner, requested_target.owner).as_bytes());
    let mut planned = String::from("case\thead\tstate\tpc\tseed\tcompletion\n");
    for spec in &specs {
        planned.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{:?}\n",
            spec.case_index,
            spec.head_index,
            spec.state_index,
            spec.registers.rip,
            spec.seed,
            spec.completion
        ));
    }
    write_new(&dir.join("planned-cases.tsv"), planned.as_bytes());
    let owned = OwnedImage::new(pages);
    let mut context = None;
    for spec in &specs {
        let case = dir.join(format!("case-{:03}", spec.case_index));
        std::fs::create_dir(&case).unwrap();
        write_new(&case.join("seed.tsv"), format!(
            "case\t{}\nhead\t{}\nstate\t{}\nseed\t{}\npc\t{}\nrsp\t{}\nrflags\t{}\narray\t{}\nframe\t{}\nstack_start\t{}\nstack_end\t{}\ncomparison_start\t{}\neffect\t{:?}\ncompletion\t{:?}\n",
            spec.case_index, spec.head_index, spec.state_index, spec.seed,
            spec.registers.rip, spec.registers.get(seed::Reg::Rsp), spec.registers.rflags,
            ARRAY, FRAME, STACK_START, STACK_STOP, spec.compared_stack_start,
            spec.memory_effect, spec.completion).as_bytes());
        reference(&owned, spec, &mut context, &case);
        original.stable();
        instructions.stable();
        requested_target.stable();
    }
    assert_eq!(specs.len(), 176);
    write_new(&dir.join("complete.tsv"), b"LI2COMMONORIGINAL\t1\nheads\t87\nnormal_references\t174\nfault_references\t2\nchildren\t176\nsteps_per_child\t1\npaired_replay\tUNIMPLEMENTED_UNRUN\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n");
    println!(
        "original references complete: heads=87 normal=174 faults=2 pairs=UNRUN qualification_complete=false"
    );
}
