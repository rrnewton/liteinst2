//! Private, bounded old/new static emission capture. This does not execute code.
//! Only the eight immediate bytes in an independently decoded MOV RAX,imm64
//! immediately preceding CALL RAX at each declared hook route are canonicalized.
use iced_x86::{Code, Decoder, DecoderOptions, Register};
use liteinst2::contracts::*;
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::scanner::InstructionScanner;
use liteinst2::trampoline::{HookCallback, HookContext, TrampolineImage, TrampolinePlan};
use std::fmt::Write as _;
use std::path::Path;

const BASE: u64 = 0x4_0000_0000;
const NEAR: u64 = BASE + 0x10_0000;
const FAR: u64 = BASE + 0x4_0000_0000;
const CANONICAL_CALLBACK: u64 = 0x1122_3344_5566_7788;

unsafe extern "C" fn hook_a(_: *mut HookContext) {
    std::hint::black_box(0_u64);
}
unsafe extern "C" fn hook_b(_: *mut HookContext) {
    std::hint::black_box(1_u64);
}

struct Capture<'a> {
    output: &'a Path,
    names: Vec<String>,
    hooks: usize,
}
impl Capture<'_> {
    fn image(
        &mut self,
        name: &str,
        source: &[u8],
        image: TrampolineImage,
        hooks: &[(u64, HookCallback)],
        plan_metadata: &str,
    ) {
        assert!(!self.names.iter().any(|old| old == name));
        assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
        let mut canonical = image.bytes().to_vec();
        let mut offsets = Vec::new();
        let mut metadata = format!(
            "fixture={name}\nsource_base={BASE}\nimage_address={}\nlayout={:?}\nprogram_counters={:?}\nentry_routes={:?}\ninstruction_boundaries={:?}\n{plan_metadata}\n",
            image.address(),
            image.layout(),
            image.program_counter_mappings(),
            image.entry_routes(),
            image.instruction_boundaries()
        );
        for &(logical, callback) in hooks {
            let route = image
                .entry_routes()
                .iter()
                .find(|&&(pc, _)| pc == logical)
                .unwrap()
                .1;
            let start = usize::try_from(route - image.address()).unwrap();
            let mut decoder =
                Decoder::with_ip(64, &image.bytes()[start..], route, DecoderOptions::NONE);
            let mut previous = None;
            let mut found = None;
            for _ in 0..256 {
                assert!(decoder.can_decode(), "missing callback at {logical:#x}");
                let instruction = decoder.decode();
                assert!(!instruction.is_invalid());
                if instruction.code() == Code::Call_rm64 {
                    assert_eq!(instruction.op0_register(), Register::RAX);
                    let mov: iced_x86::Instruction = previous.expect("call must follow MOV");
                    assert_eq!(mov.code(), Code::Mov_r64_imm64);
                    assert_eq!(mov.op0_register(), Register::RAX);
                    assert_eq!(mov.len(), 10);
                    assert_eq!(mov.immediate64(), callback as usize as u64);
                    assert_eq!(mov.next_ip(), instruction.ip());
                    let offset = usize::try_from(mov.ip() - image.address()).unwrap();
                    assert_eq!(&image.bytes()[offset..offset + 2], &[0x48, 0xb8]);
                    assert_eq!(&image.bytes()[offset + 10..offset + 12], &[0xff, 0xd0]);
                    assert_eq!(
                        &image.bytes()[offset + 2..offset + 10],
                        &(callback as usize as u64).to_le_bytes()
                    );
                    assert!(!offsets.contains(&offset));
                    canonical[offset + 2..offset + 10]
                        .copy_from_slice(&CANONICAL_CALLBACK.to_le_bytes());
                    found = Some(offset);
                    break;
                }
                previous = Some(instruction);
            }
            let offset =
                found.expect("bounded prologue must contain exactly the declared callback");
            offsets.push(offset);
            writeln!(&mut metadata, "callback_mov: logical={logical} route={route} instruction_offset={offset} immediate_offset={} immediate_len=8 next_call_offset={}", offset + 2, offset + 10).unwrap();
        }
        assert_eq!(offsets.len(), hooks.len());
        // The full original images remain available; every changed byte must
        // belong to one of the exact eight-byte operands proven above.
        for (i, (&raw, &normalized)) in image.bytes().iter().zip(&canonical).enumerate() {
            assert!(raw == normalized || offsets.iter().any(|&o| (o + 2..o + 10).contains(&i)));
        }
        writeln!(&mut metadata, "declared_callbacks={}", hooks.len()).unwrap();
        std::fs::write(self.output.join(format!("{name}.source.bin")), source).unwrap();
        std::fs::write(self.output.join(format!("{name}.raw.bin")), image.bytes()).unwrap();
        std::fs::write(self.output.join(format!("{name}.canonical.bin")), canonical).unwrap();
        std::fs::write(self.output.join(format!("{name}.metadata.txt")), metadata).unwrap();
        self.hooks += hooks.len();
        self.names.push(name.to_string());
    }
    fn plan(
        &mut self,
        name: &str,
        source: &[u8],
        plan: TrampolinePlan,
        generated: u64,
        hooks: &[(u64, HookCallback)],
    ) {
        let metadata = format!(
            "execute={}\nlogical={}\nreturn={}\ndisplaced_len={}\nreplaces_first={}",
            plan.execute_address(),
            plan.logical_address(),
            plan.return_address(),
            plan.displaced_len(),
            plan.replaces_first()
        );
        self.image(
            name,
            source,
            plan.emit_at(generated).unwrap(),
            hooks,
            &metadata,
        );
    }
    fn actions(
        &mut self,
        name: &str,
        source: &[u8],
        end: usize,
        actions: &[(u64, HookCallback, bool)],
        generated: u64,
    ) {
        let scan = InstructionScanner::default().scan(source, BASE).unwrap();
        let plan = TrampolinePlan::from_actions(&scan, BASE, BASE + end as u64, actions).unwrap();
        let hooks: Vec<_> = actions.iter().map(|&(pc, hook, _)| (pc, hook)).collect();
        self.plan(name, source, plan, generated, &hooks);
    }
}

fn main() {
    let output = std::env::args_os().nth(1).expect("output directory");
    let output = Path::new(&output);
    std::fs::create_dir_all(output).unwrap();
    assert_ne!(hook_a as *const () as usize, hook_b as *const () as usize);
    let mut capture = Capture {
        output,
        names: Vec::new(),
        hooks: 0,
    };
    let legacy = [0x48, 0xff, 0xc0, 0x48, 0xff, 0xc1, 0xc3];
    let scan = InstructionScanner::default().scan(&legacy, BASE).unwrap();
    capture.plan(
        "legacy_observe_near",
        &legacy,
        TrampolinePlan::from_scan(&scan, BASE, hook_a).unwrap(),
        NEAR,
        &[(BASE, hook_a)],
    );
    capture.plan(
        "legacy_observe_far",
        &legacy,
        TrampolinePlan::from_scan(&scan, BASE, hook_a).unwrap(),
        FAR,
        &[(BASE, hook_a)],
    );
    capture.plan(
        "legacy_replace",
        &legacy,
        TrampolinePlan::from_scan_replacing_first(&scan, BASE, hook_a).unwrap(),
        NEAR,
        &[(BASE, hook_a)],
    );
    capture.plan(
        "legacy_ptrace_replace",
        &legacy,
        TrampolinePlan::from_scan_replacing_first_with_ptrace_stops(&scan, BASE, hook_a).unwrap(),
        FAR,
        &[(BASE, hook_a)],
    );
    let syscall = [0x0f, 0x05, 0xc3];
    let scan = InstructionScanner::default().scan(&syscall, BASE).unwrap();
    capture.plan(
        "exact_syscall_replace",
        &syscall,
        TrampolinePlan::from_scan_replacing_exact_syscall(&scan, BASE, hook_a).unwrap(),
        FAR,
        &[(BASE, hook_a)],
    );

    let actions = [
        0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 2, 0x48, 0x83, 0xc0, 4, 0xc3,
    ];
    capture.actions(
        "actions_all_observe",
        &actions,
        12,
        &[
            (BASE, hook_a, false),
            (BASE + 4, hook_b, false),
            (BASE + 8, hook_a, false),
        ],
        NEAR,
    );
    capture.actions(
        "actions_all_replace",
        &actions,
        12,
        &[
            (BASE, hook_a, true),
            (BASE + 4, hook_b, true),
            (BASE + 8, hook_a, true),
        ],
        FAR,
    );
    capture.actions(
        "actions_mixed",
        &actions,
        13,
        &[
            (BASE, hook_a, true),
            (BASE + 4, hook_b, false),
            (BASE + 8, hook_a, true),
        ],
        NEAR,
    );
    capture.actions(
        "actions_upstream_prefix",
        &actions,
        12,
        &[(BASE + 4, hook_a, false), (BASE + 8, hook_b, true)],
        FAR,
    );
    capture.actions(
        "actions_single_observe",
        &legacy,
        6,
        &[(BASE, hook_a, false)],
        NEAR,
    );
    capture.actions(
        "actions_single_replace",
        &legacy,
        6,
        &[(BASE, hook_a, true)],
        NEAR,
    );
    let forward = [0xeb, 4, 0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xc0, 2, 0xc3];
    capture.actions(
        "actions_forward_branch",
        &forward,
        forward.len(),
        &[(BASE + 2, hook_a, false), (BASE + 6, hook_b, false)],
        NEAR,
    );
    let backedge = [0x48, 0xff, 0xc9, 0x75, 0xfb, 0x48, 0x89, 0xc8, 0xc3];
    capture.actions(
        "actions_backward_branch",
        &backedge,
        backedge.len(),
        &[(BASE, hook_a, false), (BASE + 3, hook_b, false)],
        NEAR,
    );
    let rip = [
        0x0f, 0xb6, 0x05, 0xf9, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc0, 1, 0xc3,
    ];
    capture.actions(
        "actions_rip_data_at_head",
        &rip,
        rip.len(),
        &[(BASE, hook_a, false), (BASE + 7, hook_b, false)],
        NEAR,
    );
    let external_branch = [0xe3, 6, 0xb8, 11, 0, 0, 0, 0xc3, 0xb8, 22, 0, 0, 0, 0xc3];
    capture.actions(
        "actions_far_literal_branch",
        &external_branch,
        7,
        &[(BASE, hook_a, false)],
        FAR,
    );

    for (name, code, generated) in [
        ("callback_free_nop", vec![0x90, 0xc3], FAR),
        (
            "callback_free_mov",
            vec![0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 0xc3],
            NEAR,
        ),
        ("callback_free_rip", rip.to_vec(), NEAR),
        ("callback_free_loop", vec![0xe2, 0xfe, 0xc3], FAR),
        (
            "callback_free_far_literal_branch",
            external_branch.to_vec(),
            FAR,
        ),
    ] {
        let scan = InstructionScanner::default().scan(&code, BASE).unwrap();
        capture.plan(
            name,
            &code,
            TrampolinePlan::from_instruction(&scan, BASE).unwrap(),
            generated,
            &[],
        );
    }

    // Public pure planning exercises the private exact-short emitter. All four
    // lengths and both semantics are required positives, with no fallback.
    for (len, code) in [
        (1, vec![0x90, 0x48, 0x8d, 0x4f, 0x08, 0xc3]),
        (2, vec![0xff, 0xc0, 0xb8, 0x34, 0x12, 0, 0, 0xc3]),
        (3, vec![0x48, 0xff, 0xc0, 0xb8, 0x34, 0x12, 0, 0, 0xc3]),
        (4, vec![0x48, 0x83, 0xc0, 1, 0xb8, 0x34, 0x12, 0, 0, 0xc3]),
    ] {
        let low_mask = (1_u32 << (8 * (len - 1))) - 1;
        let frozen = u32::from_le_bytes(code[1..5].try_into().unwrap()) & !low_mask;
        let displacement = (frozen | (0x0055_5555 & low_mask)) as i32;
        let target = u64::try_from(i128::from(BASE + 5) + i128::from(displacement)).unwrap();
        let identity = CodeIdentity {
            source: SourceIdentity([0x5a; 32]),
            mapping: BASE,
            generation: 1,
        };
        let scope = AddressRange::new(BASE, code.len()).unwrap();
        let entries = LegalEntrySet {
            identity,
            scope,
            provenance: EntryProvenance::Declared("static byte fingerprint".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: vec![],
            resumes: ResumeObligation::NoneExist,
        };
        let allocation = AllocationPolicy {
            ranges: vec![AddressRange::new(target & !4095, 8192).unwrap()],
            preferred_address: Some(target),
            max_candidates: 1,
            max_mappings: 1,
            max_mapped_bytes: 8192,
        };
        for (label, semantics) in [
            ("observe", HookSemantics::Observe),
            ("replace", HookSemantics::ReplaceFirst),
        ] {
            let request = InstallRequest {
                identity,
                code: &code,
                base_address: BASE,
                function: scope,
                block: AddressRange::new(BASE, len).unwrap(),
                logical_pc: BASE,
                entries: &entries,
                hook: hook_a,
                semantics,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: TacticPolicy::GeneralizedPunOnly,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 80,
                    max_sites: 1,
                },
            };
            let planned = plan_install(&request).unwrap();
            assert_eq!(planned.image().address(), target);
            assert!(matches!(
                planned.plan().parts().kind,
                PlanKind::GeneralizedPun(_)
            ));
            let parts = planned.plan().parts();
            assert_eq!(parts.generated.len(), 1);
            assert_eq!(parts.generated[0].address, planned.image().address());
            assert_eq!(parts.generated[0].bytes, planned.image().bytes());
            let metadata = format!(
                "short_len={len}\nsemantics={semantics:?}\nidentity={:?}\nprofile={:?}\nkind={:?}\nlogical={}\nphysical={}\ndisplaced={:?}\nreads={:?}\nwrites={:?}\ndependencies={:?}\nentries={:?}\nobligations={:?}\nallocations={:?}\ngenerated_address={}\ngenerated_bytes_recorded_in_image={}\nrequirements={:?}\nmetrics={:?}",
                parts.identity,
                parts.profile,
                parts.kind,
                parts.logical_pc,
                parts.physical_pc,
                parts.displaced,
                parts.reads,
                parts.writes,
                parts.dependencies,
                parts.entries,
                parts.obligations,
                parts.allocations,
                parts.generated[0].address,
                parts.generated[0].bytes.len(),
                parts.requirements,
                planned.metrics()
            );
            capture.image(
                &format!("short_l{len}_{label}"),
                &code,
                planned.image().clone(),
                &[(BASE, hook_a)],
                &metadata,
            );
        }
    }
    assert_eq!(capture.names.len(), 28);
    assert_eq!(capture.hooks, 33);
    std::fs::write(output.join("fixtures.txt"), capture.names.join("\n") + "\n").unwrap();
    std::fs::write(
        output.join("runtime-callbacks.txt"),
        format!(
            "hook_a={:#x}\nhook_b={:#x}\n",
            hook_a as *const () as usize, hook_b as *const () as usize
        ),
    )
    .unwrap();
    println!(
        "captured {} fixtures and {} exact callback operands",
        capture.names.len(),
        capture.hooks
    );
}
