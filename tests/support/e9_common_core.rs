//! Controlled core-null pairs. Structural witness/hash authority is external;
//! every consumed byte, route, state, memory owner and completion is checked here.
//! No normal-loader, E9, recording-hook or whole-A3 qualification is inferred.
use super::core_pages::{Page, materialize_load_pages};
use super::*;
#[path = "e9_common_planning_profile.rs"]
mod planning_profile;
use planning_profile::PlanningProfile;
#[path = "e9_common_router_contract.rs"]
mod router_contract;
#[path = "e9_common_router_native.rs"]
mod router_native;
use router_contract::{Route, RouterMode};
#[path = "e9_common_router_controls.rs"]
mod router_controls;
pub fn router_controls_main() {
    router_controls::main();
}

const MAX_INPUT: usize = 1_048_576;
const MAX_OUTPUT: usize = 16_777_216;
const HOOK: u64 = 0x401960;

fn text(input: &Input) -> &str {
    std::str::from_utf8(&input.bytes).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn bytes(s: &str) -> Vec<u8> {
    assert_eq!(s.len() & 1, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn digest(s: &str) {
    assert!(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}
fn read_empty(path: &Path) -> Input {
    assert!(path.is_absolute());
    assert_eq!(path.canonicalize().unwrap().as_os_str(), path.as_os_str());
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .unwrap();
    let m = file.metadata().unwrap();
    assert!(m.is_file() && m.len() <= MAX_OUTPUT as u64);
    let mut bytes = Vec::new();
    (&file)
        .take((MAX_OUTPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len() as u64, m.len());
    let input = Input {
        path: path.to_owned(),
        file,
        owner: identity(&m),
        bytes,
    };
    input.stable();
    input
}
#[derive(Clone)]
struct Walk {
    trap: bool,
    pc: u64,
    next: u64,
    bytes: Vec<u8>,
}
struct Head {
    pc: u64,
    body: u64,
    target: u64,
    bytes: Vec<u8>,
    walk: Vec<Walk>,
}
struct Candidate {
    inputs: Vec<Input>,
    heads: Vec<Head>,
    pages: Vec<Page>,
    base: Vec<u8>,
    routes: Vec<Route>,
}
impl Candidate {
    fn read(
        directory: &Path,
        witness: &Input,
        original: &Input,
        target: &Input,
        planning: PlanningProfile,
        router: RouterMode,
    ) -> Self {
        assert!(directory.is_absolute());
        assert_eq!(
            directory.canonicalize().unwrap().as_os_str(),
            directory.as_os_str()
        );
        assert!(witness.bytes.ends_with(b"\n"));
        let rows: Vec<Vec<_>> = text(witness)
            .lines()
            .map(|r| r.split('\t').collect())
            .collect();
        assert!(rows.len() <= 40000);
        assert_eq!(rows[0], vec!["LI2COMMONCORE", "1"]);
        assert_eq!(
            rows[1],
            vec!["scope", "STRUCTURAL_CORE_NULL_WITNESSES_ONLY"]
        );
        for (r, key) in rows[2..7].iter().zip([
            "original_sha256",
            "instructions_sha256",
            "target_sha256",
            "selection_sha256",
            "candidate_sha256",
        ]) {
            assert_eq!(r.len(), 2);
            assert_eq!(r[0], key);
            digest(r[1]);
        }
        assert_eq!(rows[7], vec!["qualification_complete", "false"]);
        let mut inputs = Vec::new();
        let mut names = BTreeSet::new();
        let mut cursor = 8;
        while rows[cursor][0] == "file" {
            let r = &rows[cursor];
            assert_eq!(r.len(), 4);
            assert!(
                r[1].bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    && !r[1].starts_with('.')
            );
            assert!(names.insert(r[1].to_owned()));
            digest(r[3]);
            let input = read_empty(&directory.join(r[1]));
            assert_eq!(input.bytes.len() as u64, number(r[2]));
            inputs.push(input);
            cursor += 1;
            assert!(inputs.len() <= 330);
        }
        assert_eq!(
            std::fs::read_dir(directory)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect::<BTreeSet<_>>(),
            names
        );
        let get = |name: &str| -> &Input {
            inputs
                .iter()
                .find(|i| i.path.file_name().unwrap() == name)
                .unwrap()
        };
        planning.marker(
            inputs
                .iter()
                .find(|i| i.path.file_name().unwrap() == planning_profile::MARKER)
                .map(|i| i.bytes.as_slice()),
        );
        if planning == PlanningProfile::OwnedForeignNeighbors {
            let indexed: Vec<Vec<_>> = text(get("bundle-index.tsv"))
                .lines()
                .map(|line| line.split('\t').collect::<Vec<_>>())
                .filter(|row| {
                    row.first() == Some(&"file") && row.get(1) == Some(&planning_profile::MARKER)
                })
                .collect();
            let witnessed: Vec<_> = rows[8..cursor]
                .iter()
                .filter(|row| row[1] == planning_profile::MARKER)
                .cloned()
                .collect();
            assert_eq!(indexed.len(), 1);
            assert_eq!(
                indexed, witnessed,
                "indexed marker has the exact witness size/hash binding"
            );
        }
        let elf = &get("candidate.elf").bytes;
        assert!(elf.len() > original.bytes.len());
        assert_eq!(&elf[..7], b"\x7fELF\x02\x01\x01");
        assert_eq!((u16_at(elf, 16), u16_at(elf, 18)), (2, 62));
        assert_eq!(get("target.tsv").bytes, target.bytes);
        assert!(
            get("ledger.tsv")
                .bytes
                .starts_with(&get("plan-ledger.tsv").bytes)
        );
        let phoff = usize::try_from(word(elf, 32)).unwrap();
        let count = usize::from(u16_at(elf, 56));
        assert_eq!(u16_at(elf, 54), 56);
        assert!((1..=512).contains(&count) && phoff.checked_add(count * 56).unwrap() <= elf.len());
        let mut loads = Vec::new();
        for i in 0..count {
            let p = phoff + i * 56;
            if u32_at(elf, p) == 1 {
                loads.push((
                    word(elf, p + 8),
                    word(elf, p + 16),
                    word(elf, p + 32),
                    word(elf, p + 40),
                    u32_at(elf, p + 4),
                ));
            }
        }
        let mut declared = Vec::new();
        while rows[cursor][0] == "load" {
            let r = &rows[cursor];
            assert_eq!(r.len(), 6);
            declared.push((
                number(r[1]),
                number(r[2]),
                number(r[3]),
                number(r[4]),
                u32::try_from(number(r[5])).unwrap(),
            ));
            cursor += 1;
        }
        assert_eq!(loads, declared);
        let (base, pages) = materialize_load_pages(elf, loads);
        let mut routes = Vec::new();
        if router.enabled() {
            assert_eq!(
                rows[cursor],
                vec!["router-profile", router_contract::PROFILE]
            );
            cursor += 1;
            while rows[cursor][0] == "router" {
                let r = &rows[cursor];
                assert_eq!(r.len(), 6);
                routes.push(Route {
                    pc: number(r[1]),
                    target: number(r[2]),
                    source_start: number(r[3]),
                    source_end: number(r[4]),
                    fetch: bytes(r[5]),
                });
                cursor += 1;
            }
        }
        router_contract::check_routes(&routes);
        let ledger: Vec<Vec<_>> = text(get("plan-ledger.tsv"))
            .lines()
            .map(|r| r.split('\t').collect())
            .collect();
        let declared: Vec<_> = ledger
            .iter()
            .filter(|r| r[0] == "entry-router-required")
            .map(|r| {
                assert_eq!(r.len(), 5);
                (number(r[3]), number(r[4]))
            })
            .collect();
        assert_eq!(declared.len(), routes.len());
        assert_eq!(
            declared.into_iter().collect::<BTreeSet<_>>(),
            routes.iter().map(|r| (r.pc, r.target)).collect()
        );
        for route in &routes {
            let source = seed::ORIGINAL_RANGES
                .iter()
                .find(|r| {
                    r.pc == route.source_start && r.pc + r.bytes.len() as u64 == route.source_end
                })
                .unwrap();
            assert!(source.pc <= route.pc && route.pc < source.pc + source.bytes.len() as u64);
            assert!(
                seed::HEADS
                    .iter()
                    .any(|h| h.pc == route.pc && !matches!(h.flow, seed::Flow::Call(_)))
            );
            assert_eq!(
                ledger
                    .iter()
                    .filter(|r| r[0] == "route"
                        && number(r[2]) == route.pc
                        && number(r[3]) == route.target)
                    .count(),
                1
            );
        }
        let mut used_routes = BTreeSet::new();
        let mut heads = Vec::new();
        for src in seed::HEADS {
            let r = &rows[cursor];
            assert_eq!(r.len(), 5);
            assert_eq!(r[0], "head");
            assert_eq!(number(r[1]), src.pc);
            let body = number(r[2]);
            let target = number(r[3]);
            let raw = bytes(r[4]);
            assert!(!raw.is_empty() && raw.len() <= 15);
            cursor += 1;
            let mut walk = Vec::new();
            let mut pc = src.pc;
            while rows[cursor][0] == "walk" || (router.enabled() && rows[cursor][0] == "trap") {
                let r = &rows[cursor];
                assert_eq!(r.len(), 5);
                assert_eq!(number(r[1]), src.pc);
                assert_eq!(number(r[2]), pc);
                let next = number(r[3]);
                let b = bytes(r[4]);
                assert!(!b.is_empty() && b.len() <= 15);
                let trap = r[0] == "trap";
                if trap {
                    assert_eq!(pc, src.pc);
                    assert!(walk.is_empty());
                    let route = routes.iter().find(|r| r.pc == pc).unwrap();
                    assert_eq!((next, b.as_slice()), (route.target, route.fetch.as_slice()));
                    assert!(used_routes.insert(pc));
                }
                walk.push(Walk {
                    trap,
                    pc,
                    next,
                    bytes: b,
                });
                pc = next;
                cursor += 1;
                assert!(walk.len() < MAX_STEPS);
            }
            assert_eq!(pc, body);
            if matches!(src.flow, seed::Flow::Call(_)) {
                assert_eq!(body, src.pc);
                assert!(walk.is_empty());
            }
            heads.push(Head {
                pc: src.pc,
                body,
                target,
                bytes: raw,
                walk,
            });
        }
        assert_eq!(
            rows[cursor],
            vec!["complete", "87", "174", "2", "E9_UNIMPLEMENTED_UNRUN"]
        );
        assert_eq!(cursor + 1, rows.len());
        assert_eq!(used_routes, routes.iter().map(|r| r.pc).collect());
        let out = Self {
            inputs,
            heads,
            pages,
            base,
            routes,
        };
        for route in &out.routes {
            assert!(out.pages.iter().any(|p| p.flags == 5
                && p.address <= route.target
                && route.target < p.address + 4096));
        }
        for h in &out.heads {
            assert_eq!(out.bytes_at(h.body, h.bytes.len()), h.bytes);
            for w in &h.walk {
                assert_eq!(out.bytes_at(w.pc, w.bytes.len()), w.bytes);
            }
        }
        out.stable();
        out
    }
    fn bytes_at(&self, pc: u64, len: usize) -> Vec<u8> {
        let stop = pc.checked_add(len as u64).unwrap();
        let mut out = Vec::new();
        let mut at = pc;
        while at < stop {
            if (IMAGE_START..IMAGE_END).contains(&at) {
                let n = (stop.min(IMAGE_END) - at) as usize;
                let offset = (at - IMAGE_START) as usize;
                out.extend_from_slice(&self.base[offset..offset + n]);
                at += n as u64;
            } else {
                let p = self
                    .pages
                    .iter()
                    .find(|p| p.address <= at && at < p.address + 4096)
                    .unwrap();
                assert_eq!(p.flags, 5);
                let n = (stop.min(p.address + 4096) - at) as usize;
                let offset = (at - p.address) as usize;
                out.extend_from_slice(&p.bytes[offset..offset + n]);
                at += n as u64;
            }
        }
        out
    }
    fn stable(&self) {
        for i in &self.inputs {
            i.stable();
        }
        let directory = self.inputs[0].path.parent().unwrap();
        assert_eq!(
            std::fs::read_dir(directory)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<BTreeSet<_>>(),
            self.inputs
                .iter()
                .map(|i| i.path.file_name().unwrap().to_os_string())
                .collect()
        );
    }
}
struct Versions<'a> {
    original: &'a OwnedImage,
    candidate: &'a Candidate,
    extra: Vec<Mapping>,
}
impl<'a> Versions<'a> {
    fn new(original: &'a OwnedImage, candidate: &'a Candidate) -> Self {
        let extra = candidate
            .pages
            .iter()
            .map(|p| reserve(p.address, PAGE))
            .collect();
        Self {
            original,
            candidate,
            extra,
        }
    }
    fn install(&self, candidate: bool) {
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        self.original
            .image
            .protect(libc::PROT_READ | libc::PROT_WRITE);
        self.original.image.initialize(
            0,
            if candidate {
                &self.candidate.base
            } else {
                &self.original.pages
            },
        );
        for &(_, address, _, len, flags) in &LOADS {
            let lo = address & !4095;
            protect(
                lo,
                (page_end(address + len) - lo) as usize,
                protection(flags),
            );
        }
        for (m, p) in self.extra.iter().zip(&self.candidate.pages) {
            if candidate {
                m.protect(libc::PROT_READ | libc::PROT_WRITE);
                m.initialize(0, &p.bytes);
                m.protect(protection(p.flags));
            } else {
                m.protect(libc::PROT_NONE);
            }
        }
    }
    fn capture(
        &self,
        child: &Tracee,
        spec: &seed::SeedSpec,
        dir: &Path,
        stem: &str,
        logical: u64,
        physical: u64,
    ) -> Captured {
        let registers = child.registers();
        let raw = child.xstate();
        let stack = child.memory(STACK_START, seed::STACK_BYTES);
        let state = Snapshot {
            logical_pc: logical,
            registers,
            xstate: canonical_xstate(&raw),
            data: child.memory(ARRAY, PAGE),
            application_stack: stack[(spec.compared_stack_start - STACK_START) as usize..].to_vec(),
        };
        save_named_snapshot(dir, stem, &state);
        write_new(&dir.join(format!("{stem}.xstate-raw")), &raw);
        write_new(&dir.join(format!("{stem}.stack-owned")), &stack);
        let base = child.memory(IMAGE_START, self.candidate.base.len());
        write_new(&dir.join(format!("{stem}.loads")), &base);
        let mut generated = Vec::new();
        for p in &self.candidate.pages {
            generated.extend(child.memory(p.address, PAGE));
        }
        write_new(&dir.join(format!("{stem}.generated")), &generated);
        map_record(child, spec, dir, stem);
        assert_eq!(
            registers.rip, physical,
            "exact admitted physical boundary before logical comparison"
        );
        assert_eq!(target(), self.original.target);
        xstate_ready(&raw, &self.original.target);
        assert_eq!(
            base, self.candidate.base,
            "all candidate original pages including globals/journal remain exact"
        );
        let maps = std::fs::read_to_string(dir.join(format!("{stem}.maps"))).unwrap();
        for (index, p) in self.candidate.pages.iter().enumerate() {
            assert_eq!(&generated[index * PAGE..(index + 1) * PAGE], p.bytes);
            let mut matches = 0;
            for line in maps.lines() {
                let f: Vec<_> = line.split_ascii_whitespace().collect();
                let (a, b) = f[0].split_once('-').unwrap();
                let a = u64::from_str_radix(a, 16).unwrap();
                let b = u64::from_str_radix(b, 16).unwrap();
                if a <= p.address && p.address + 4096 <= b {
                    matches += 1;
                    assert_eq!(f.len(), 5);
                    assert_eq!(f[1], if p.flags == 5 { "r-xp" } else { "r--p" });
                    assert_eq!(u64::from_str_radix(f[2], 16).unwrap(), 0);
                    assert_eq!((f[3], f[4]), ("00:00", "0"));
                }
            }
            assert_eq!(matches, 1);
        }
        Captured { state, raw, stack }
    }
}
fn endpoint(head: &Head, spec: &seed::SeedSpec) -> u64 {
    let source = seed::HEADS[spec.head_index];
    assert_eq!(head.pc, source.pc);
    match spec.completion {
        seed::Completion::Fault { .. } => head.body,
        seed::Completion::OriginalPc { pc, .. } => match source.flow {
            seed::Flow::Next => head.body + head.bytes.len() as u64,
            seed::Flow::Return => pc,
            seed::Flow::Call(t) | seed::Flow::Jump(t) => {
                assert_eq!(pc, t);
                head.target
            }
            seed::Flow::Jb(t) | seed::Flow::Jae(t) | seed::Flow::Jbe(t) | seed::Flow::Jne(t) => {
                if pc == t {
                    head.target
                } else {
                    assert_eq!(pc, source.pc + u64::from(source.length));
                    head.body + head.bytes.len() as u64
                }
            }
        },
    }
}
fn logical(spec: &seed::SeedSpec) -> u64 {
    match spec.completion {
        seed::Completion::OriginalPc { pc, .. } | seed::Completion::Fault { pc, .. } => pc,
    }
}
fn pair(
    versions: &Versions<'_>,
    spec: &seed::SeedSpec,
    context: &Context,
    before: &Captured,
    after: &Captured,
    dir: &Path,
) {
    let head = &versions.candidate.heads[spec.head_index];
    let finish = endpoint(head, spec);
    let has_hook = head.walk.iter().any(|w| w.next == HOOK);
    let s = spec.registers.get(seed::Reg::Rsp);
    let l = versions.original.target.len();
    let alignment = if versions.original.target.format() == SavedExtendedStateFormat::FXSAVE64 {
        16
    } else {
        64
    };
    let scratch_start = ((s.checked_sub(304).unwrap()) & !(alignment - 1))
        .checked_sub(l + 8)
        .unwrap();
    let scratch_end = s.checked_sub(128).unwrap();
    if has_hook {
        assert!(
            STACK_START <= scratch_start
                && scratch_start < scratch_end
                && scratch_end <= FRAME - 128
        );
    }
    let router = (!versions.candidate.routes.is_empty())
        .then(|| router_native::Router::new(&versions.candidate.routes));
    let child = Tracee::fork();
    child.request(libc::PTRACE_SETOPTIONS, 0, libc::PTRACE_O_EXITKILL as usize);
    assert_eq!(inherited(&child.registers()), inherited(&context.registers));
    let raw = child.xstate();
    assert_eq!(raw.len(), context.xstate.len());
    xstate_ready(&raw, &versions.original.target);
    let wanted = apply(spec, context.registers);
    let seeded = seeded_xstate(context.xstate.clone(), spec.seed);
    child.set_registers(&wanted);
    child.set_xstate(&seeded);
    let entry = versions.capture(&child, spec, dir, "before", head.pc, head.pc);
    assert_state(&before.state, &entry.state);
    assert_eq!(entry.stack, spec.stack.bytes);
    let mut trace = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dir.join("trace.tsv"))
        .unwrap();
    trace
        .write_all(b"phase\tbefore_pc\tafter_pc\tbytes\n")
        .unwrap();
    if let Some(router) = &router {
        trace.write_all(router.descriptor().as_bytes()).unwrap();
    }
    if let Some(router) = &router {
        router.observed(&child, "before", &mut trace);
    }
    let mut steps = 0;
    for w in &head.walk {
        assert_eq!(child.registers().rip, w.pc);
        assert_eq!(child.memory(w.pc, w.bytes.len()), w.bytes);
        if w.pc == HOOK {
            let r = child.registers();
            assert_eq!(
                word(&child.memory(r.rsp, 8), 0),
                w.next,
                "literal hook return word"
            );
        }
        if w.trap {
            let route = versions
                .candidate
                .routes
                .iter()
                .find(|r| r.pc == w.pc)
                .unwrap();
            router
                .as_ref()
                .unwrap()
                .deliver(&child, route, &mut steps, &mut trace);
        } else {
            step(&child, &mut steps);
        }
        let next = child.registers().rip;
        if w.trap {
            writeln!(
                &mut trace,
                "trap-prefix\t{}\t{}\t{}",
                w.pc,
                next,
                hex(&w.bytes)
            )
            .unwrap();
        } else {
            writeln!(&mut trace, "prefix\t{}\t{}\t{}", w.pc, next, hex(&w.bytes)).unwrap();
        }
        trace.flush().unwrap();
        assert_eq!(next, w.next);
    }
    let restored = versions.capture(&child, spec, dir, "restored", head.pc, head.body);
    assert_state(&before.state, &restored.state);
    assert_eq!(restored.raw.len(), before.raw.len());
    for (i, (actual, expected)) in restored.stack.iter().zip(&before.stack).enumerate() {
        let pc = STACK_START + i as u64;
        if !has_hook || pc < scratch_start || pc >= scratch_end {
            assert_eq!(
                actual, expected,
                "prefix write outside proven private scratch"
            );
        }
    }
    assert_eq!(child.memory(head.body, head.bytes.len()), head.bytes);
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
    let physical = child.registers().rip;
    writeln!(
        &mut trace,
        "original\t{}\t{}\t{}",
        head.body,
        physical,
        hex(&head.bytes)
    )
    .unwrap();
    trace.flush().unwrap();
    let final_state = versions.capture(&child, spec, dir, "after", logical(spec), finish);
    if let Some(router) = &router {
        router.observed(&child, "after", &mut trace);
    }
    assert_state(&after.state, &final_state.state);
    assert_eq!(final_state.raw.len(), after.raw.len());
    if let seed::Completion::Fault {
        signal,
        code,
        address,
        ..
    } = spec.completion
    {
        assert_eq!(fault, Some((signal, code, address)));
        assert_state(&restored.state, &final_state.state);
    } else {
        assert!(fault.is_none());
    }
    for (i, (actual, expected)) in final_state.stack.iter().zip(&after.stack).enumerate() {
        let pc = STACK_START + i as u64;
        if !has_hook || pc < scratch_start || pc >= scratch_end {
            assert_eq!(
                actual, expected,
                "completion write outside proven private scratch"
            );
        }
    }
    let pid = child.pid;
    drop(child);
    let mut status = 0;
    // SAFETY: query only the exact child reaped by the unchanged Tracee owner.
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    write_new(&dir.join("complete.tsv"),format!("LI2COREPAIRCHILD\t1\ncase\t{}\nsteps\t{}\nphysical_completion\t{}\nlogical_completion\t{}\nfault\t{:?}\ncomparisons\t3\nreaped_echild\ttrue\nqualification_complete\tfalse\n",spec.case_index,steps,finish,logical(spec),fault).as_bytes());
}

pub fn main() {
    let mut args: Vec<_> = std::env::args_os().collect();
    let router = RouterMode::arguments(&mut args);
    let planning = PlanningProfile::arguments(&mut args, 8);
    assert_eq!(
        args.len(),
        8,
        "replay-common-core ORIGINAL INSTRUCTIONS TARGET BUNDLE WITNESS NEW_CAPTURES"
    );
    assert_eq!(args[1], "replay-common-core");
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    // SAFETY: scalar identity query, no state change.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_gettid) },
        libc::c_long::from(std::process::id())
    );
    let original = Input::open(Path::new(&args[2]), MAX_INPUT);
    let instructions = Input::open(Path::new(&args[3]), 16384);
    let requested_target = Input::open(Path::new(&args[4]), 16384);
    assert_eq!(requested_target.bytes, target_tsv().as_bytes());
    let witness = Input::open(Path::new(&args[6]), MAX_OUTPUT);
    let candidate = Candidate::read(
        Path::new(&args[5]),
        &witness,
        &original,
        &requested_target,
        planning,
        router,
    );
    let inventory = admit(&original.bytes, &instructions.bytes);
    let original_view = original_pages(&original.bytes);
    let anchors = seed::Anchors::new(ARRAY, FRAME).unwrap();
    let specs: Vec<_> = (0..seed::CASE_COUNT)
        .map(|i| inventory.case(i, anchors).unwrap())
        .collect();
    let dir = Path::new(&args[7]);
    assert!(dir.is_absolute());
    assert_eq!(
        dir.parent().unwrap().canonicalize().unwrap().as_os_str(),
        dir.parent().unwrap().as_os_str()
    );
    std::fs::create_dir(dir).unwrap();
    for (name, b) in [
        ("original.elf", &original.bytes),
        ("instructions.tsv", &instructions.bytes),
        ("runtime-target.tsv", &requested_target.bytes),
        ("core-witness.tsv", &witness.bytes),
        ("original-pages.bin", &original_view),
    ] {
        write_new(&dir.join(name), b);
    }
    let mut owners = format!(
        "whole_hash_and_structural_witness_admission\tCALLER_REQUIRED\noriginal\t{:?}\ninstructions\t{:?}\ntarget\t{:?}\nwitness\t{:?}\n",
        original.owner, instructions.owner, requested_target.owner, witness.owner
    );
    for i in &candidate.inputs {
        owners.push_str(&format!(
            "{}\t{:?}\n",
            i.path.file_name().unwrap().to_str().unwrap(),
            i.owner
        ));
    }
    let records = text(&witness)
        .lines()
        .filter(|s| s.starts_with("file\t"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    write_new(&dir.join("bundle-inputs.tsv"), records.as_bytes());
    write_new(&dir.join("input-owners.tsv"), owners.as_bytes());
    let mut pages = candidate.base.clone();
    let mut page_plan = String::new();
    for p in &candidate.pages {
        page_plan.push_str(&format!("{}\t{}\t{}\n", p.address, p.flags, pages.len()));
        pages.extend_from_slice(&p.bytes);
    }
    write_new(&dir.join("candidate-pages.bin"), &pages);
    write_new(&dir.join("page-plan.tsv"), page_plan.as_bytes());
    let mut plan = String::from(
        "case\thead\tstate\toriginal_pc\tbody_pc\tcompletion_pc\tlogical_completion\n",
    );
    let mut names = Vec::new();
    for spec in &specs {
        let h = &candidate.heads[spec.head_index];
        plan.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            spec.case_index,
            spec.head_index,
            spec.state_index,
            h.pc,
            h.body,
            endpoint(h, spec),
            logical(spec)
        ));
    }
    write_new(&dir.join("planned-cases.tsv"), plan.as_bytes());
    for root in [
        "original.elf",
        "instructions.tsv",
        "runtime-target.tsv",
        "core-witness.tsv",
        "original-pages.bin",
        "bundle-inputs.tsv",
        "input-owners.tsv",
        "candidate-pages.bin",
        "page-plan.tsv",
        "planned-cases.tsv",
        "capture-inventory.tsv",
        "complete.tsv",
    ] {
        names.push(root.to_owned());
    }
    for spec in &specs {
        let case = format!("case-{:03}", spec.case_index);
        for name in ["pair.tsv", "witness.tsv"] {
            names.push(format!("{case}/{name}"));
        }
        for name in ["seed.tsv", "complete.tsv"] {
            names.push(format!("{case}/original/{name}"));
        }
        for stem in ["before", "after"] {
            for suffix in [
                "regs",
                "xstate",
                "xstate-raw",
                "data",
                "stack",
                "stack-owned",
                "loads",
                "maps",
            ] {
                names.push(format!("{case}/original/{stem}.{suffix}"));
            }
        }
        for name in ["trace.tsv", "complete.tsv"] {
            names.push(format!("{case}/candidate/{name}"));
        }
        for stem in ["before", "restored", "after"] {
            for suffix in [
                "regs",
                "xstate",
                "xstate-raw",
                "data",
                "stack",
                "stack-owned",
                "loads",
                "maps",
                "generated",
            ] {
                names.push(format!("{case}/candidate/{stem}.{suffix}"));
            }
        }
    }
    assert_eq!(names.len(), 8636);
    write_new(
        &dir.join("capture-inventory.tsv"),
        (names.join("\n") + "\n").as_bytes(),
    );
    let owned = OwnedImage::new(original_view);
    let versions = Versions::new(&owned, &candidate);
    let mut context = None;
    for spec in &specs {
        let case = dir.join(format!("case-{:03}", spec.case_index));
        std::fs::create_dir(&case).unwrap();
        let original_dir = case.join("original");
        let candidate_dir = case.join("candidate");
        std::fs::create_dir(&original_dir).unwrap();
        std::fs::create_dir(&candidate_dir).unwrap();
        write_new(&original_dir.join("seed.tsv"),format!("case\t{}\nhead\t{}\nstate\t{}\nseed\t{}\npc\t{}\nrsp\t{}\nrflags\t{}\narray\t{}\nframe\t{}\nstack_start\t{}\nstack_end\t{}\ncomparison_start\t{}\neffect\t{:?}\ncompletion\t{:?}\n",spec.case_index,spec.head_index,spec.state_index,spec.seed,spec.registers.rip,spec.registers.get(seed::Reg::Rsp),spec.registers.rflags,ARRAY,FRAME,STACK_START,STACK_STOP,spec.compared_stack_start,spec.memory_effect,spec.completion).as_bytes());
        let head = &candidate.heads[spec.head_index];
        write_new(
            &case.join("witness.tsv"),
            format!(
                "original\t{}\nbody\t{}\ncompletion\t{}\nlogical\t{}\nbytes\t{}\n",
                head.pc,
                head.body,
                endpoint(head, spec),
                logical(spec),
                hex(&head.bytes)
            )
            .as_bytes(),
        );
        let (before, after) = reference(&owned, spec, &mut context, &original_dir);
        owned.initialize(spec);
        versions.install(true);
        pair(
            &versions,
            spec,
            context.as_ref().unwrap(),
            &before,
            &after,
            &candidate_dir,
        );
        versions.install(false);
        original.stable();
        instructions.stable();
        requested_target.stable();
        witness.stable();
        candidate.stable();
        write_new(&case.join("pair.tsv"),format!("LI2COREPAIR\t1\ncase\t{}\ncomparisons\t3\nchildren\t2\nE9\tUNIMPLEMENTED_UNRUN\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n",spec.case_index).as_bytes());
    }
    write_new(&dir.join("complete.tsv"),b"LI2COMMONCOREPAIRS\t1\nheads\t87\nnormal_pairs\t174\nfault_pairs\t2\nchildren\t352\ncomparisons\t528\nfiles\t8636\nE9\tUNIMPLEMENTED_UNRUN\nrecording_hooks\tUNIMPLEMENTED_UNRUN\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n");
    println!(
        "core null pairs complete: heads=87 normal=174 faults=2 comparisons=528 E9=UNIMPLEMENTED_UNRUN qualification_complete=false"
    );
}
