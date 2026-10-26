//! Additional current live-chain and frame metadata parity; no native execution.
use super::*;
use crate::eviction_chain::{plan_successor_chain_detailed, plan_successor_chain_grouped_detailed};
use crate::frame_trace::{FrameEmission, FrameInstructionKind, FrameTraceLimits, FrameTraceRefusal};
use crate::grouping::{BackingKind, GroupingBudget};
use iced_x86::Encoder;

#[path = "chain_cases.rs"]
mod chain_cases;

const CHAIN_BASE: u64 = 0x3000_0000_0000;
const FRAME_BASE: u64 = 0x4000_0000;
const FRAME_NEAR: u64 = FRAME_BASE + 0x100_0000;
const FRAME_FAR: u64 = 0x80_0000_0000;

fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}

fn inventory(capture: &mut Capture, name: &str, images: usize, bindings: &[Binding<'_>]) {
    let controlled = bindings.iter().filter(|b| matches!(b, Binding::Controlled(..))).count();
    writeln!(&mut capture.inventory, "{name}\tsuccess\t{images}\t{}\t{controlled}\t{controlled}", bindings.len() - controlled).unwrap();
}

fn chains(capture: &mut Capture) {
    for (index, case) in chain_cases::CASES.iter().enumerate() {
        let fixture = chain_cases::Fixture::new(case, CHAIN_BASE);
        let request = fixture.request(HOOKS[0]);
        let ordinary = plan_successor_chain_detailed(&request, &fixture.policies[1..], fixture.search(), fixture.budget()).unwrap();
        fixture.assert_plan(&ordinary);
        let name = format!("chain_{index}");
        let inputs = format!("case={}\nbase={}\nentries={:?}\npolicies={:?}\nforced={:?}\nsearch={:?}\nbudget={:?}\nsemantics={:?}\n", case.name, fixture.base, fixture.entries, fixture.policies, fixture.forced, fixture.search(), fixture.budget(), request.semantics);
        capture.begin(&name, &fixture.code, &inputs, "success");
        capture.bundle(&name, ordinary.bundle(), &format!("nodes={:?}\nmetrics={:?}", ordinary.nodes(), ordinary.metrics()), fixture.base);
        if index != 0 { continue; }
        let budget = BundleBudget { max_steps: 4, max_mappings: 4, max_virtual_bytes: 16384, max_backing_bytes: 4096, max_virtual_span: 0x6d69_9000 };
        let grouping = GroupingBudget { max_mappings: 4, max_virtual_pages: 4, max_virtual_bytes: 16384, max_backing_bytes: 4096, max_virtual_span: 0x6d69_9000 };
        let grouped = plan_successor_chain_grouped_detailed(&request, &fixture.policies[1..], fixture.search(), budget, grouping).unwrap();
        assert_eq!(grouped.nodes(), ordinary.nodes());
        assert_eq!(grouped.metrics(), ordinary.metrics());
        let a = ordinary.bundle().plan();
        let b = grouped.bundle().plan();
        assert_eq!(b.identity(), a.identity());
        assert_eq!(b.originals(), a.originals());
        assert_eq!(b.final_bytes(), a.final_bytes());
        assert_eq!(b.steps(), a.steps());
        assert_eq!(b.locks(), a.locks());
        assert_eq!(grouped.bundle().images(), ordinary.bundle().images());
        assert_eq!(b.memory().mappings, 4);
        assert_eq!(b.memory().backing_pages, 1);
        assert_eq!(b.memory().backing_bytes, 4096);
        assert_eq!(b.memory().virtual_pages, 4);
        assert_eq!(b.memory().virtual_bytes, 16384);
        assert_eq!(b.memory().virtual_span, 0x6d69_9000);
        let g = grouped.bundle().grouping().unwrap();
        assert_eq!(g.images(), grouped.bundle().images());
        assert_eq!(g.groups().len(), 1);
        assert_eq!(g.groups()[0].kind(), BackingKind::SharedPage);
        assert_eq!(g.groups()[0].backing_len(), 4096);
        assert_eq!(g.groups()[0].image_indices(), &[0, 1, 2, 3]);
        let aliases: Vec<_> = fixture.targets.iter().rev().map(|&target| range(target & !4095, 4096)).collect();
        assert_eq!(g.groups()[0].aliases(), aliases);
        let name = "chain_grouped";
        capture.begin(name, &fixture.code, &format!("{inputs}grouped_budget={budget:?}\ngrouping_budget={grouping:?}\n"), "success");
        // GroupingPlan owns the same images: serialize them once through the
        // original operand authenticator, and compare every other field here.
        let mut metadata = format!("accepted\nnodes={:?}\nmetrics={:?}\nidentity={:?}\noriginals={:?}\nfinal_bytes={:?}\nlocks={:?}\nmemory={:?}\ngrouping_memory={:?}\ngroups={:?}\n", grouped.nodes(), grouped.metrics(), b.identity(), b.originals(), b.final_bytes(), b.locks(), b.memory(), g.memory(), g.groups());
        let mut selected = 0;
        for (i, (step, image)) in b.steps().iter().zip(grouped.bundle().images()).enumerate() {
            writeln!(&mut metadata, "step={i}\n{}", Capture::plan_metadata(step, image)).unwrap();
            let bindings = if step.parts().logical_pc == fixture.base { selected += 1; vec![Binding::Static(fixture.base, 0)] } else { vec![] };
            capture.image(name, i, image, &bindings);
        }
        assert_eq!(selected, 1);
        capture.write(&format!("{name}.result.txt"), metadata);
        inventory(capture, name, 4, &[Binding::Static(fixture.base, 0)]);
    }
}

// A frame helper's instruction may contain one of the exact operands already
// authenticated in its image. No other instruction or metadata field changes.
fn instruction(capture: &Capture, name: &str, start: u64, image: &TrampolineImage, original: &Instruction) -> String {
    let table = std::fs::read_to_string(capture.output.join(format!("{name}.image0.operands.tsv"))).unwrap();
    let mut value = *original;
    for line in table.lines().skip(1) {
        let cells: Vec<_> = line.split('\t').collect();
        assert_eq!(cells.len(), 8);
        let offset: u64 = cells[3].parse().unwrap();
        if image.address().checked_add(offset).unwrap() == start {
            assert_eq!(value.code(), Code::Mov_r64_imm64);
            assert_eq!(value.op0_register(), if cells[0] == "control" { Register::RSI } else { Register::RAX });
            assert_eq!(value.immediate64(), cells[5].parse::<u64>().unwrap());
            value.set_immediate64(cells[6].parse().unwrap());
        }
    }
    let mut encoder = Encoder::new(64);
    encoder.encode(&value, value.ip()).unwrap();
    format!("code={:?},code_size={:?},ip={},len={},encoded={},lock={},rep={},repe={},repne={},segment={:?},broadcast={},mask={:?},zero={},rounding={:?},sae={}", value.code(), value.code_size(), value.ip(), value.len(), hex(&encoder.take_buffer()), value.has_lock_prefix(), value.has_rep_prefix(), value.has_repe_prefix(), value.has_repne_prefix(), value.segment_prefix(), value.is_broadcast(), value.op_mask(), value.zeroing_masking(), value.rounding_control(), value.suppress_all_exceptions())
}

fn frames(capture: &mut Capture, name: &str, code: &[u8], plan: &TrampolinePlan, address: u64, bindings: &[Binding<'_>], expected: Option<FrameTraceRefusal>, limits: Option<FrameTraceLimits>) {
    let plain = plan.emit_at(address).unwrap();
    let emitted: FrameEmission = match limits { Some(limits) => plan.emit_with_frame_trace_limits_at(address, limits).unwrap(), None => plan.emit_with_frame_trace_at(address).unwrap() };
    assert_eq!(emitted.image(), &plain);
    assert_eq!(emitted.trace().err(), expected);
    capture.begin(name, code, &format!("source_base={FRAME_BASE}\nimage_address={address}\nlimits={limits:?}\nexpected_trace_refusal={expected:?}\n"), "success");
    capture.image(name, 0, &plain, bindings);
    capture.write(&format!("{name}.result.txt"), format!("accepted\nexecute={}\nlogical={}\nreturn={}\ndisplaced_len={}\nreplaces_first={}\n", plan.execute_address(), plan.logical_address(), plan.return_address(), plan.displaced_len(), plan.replaces_first()));
    let mut metadata = format!("origin={:?}\n", emitted.origin());
    match emitted.trace() {
        Err(reason) => { writeln!(&mut metadata, "refused={reason:?}").unwrap(); }
        Ok(trace) => {
            assert!(trace.matches_image(&plain));
            assert_eq!(trace.origin(), emitted.origin());
            writeln!(&mut metadata, "trace_origin={:?}\ndata={:?}\ncalls={:?}\nrequirements={:?}", trace.origin(), trace.data_ranges(), trace.calls(), trace.requirements()).unwrap();
            for row in trace.instructions() {
                write!(&mut metadata, "start={} end={} original={} ", row.start(), row.end(), row.original_pc()).unwrap();
                match row.kind() {
                    FrameInstructionKind::Helper(helper) => {
                        writeln!(&mut metadata, "helper stage={:?} before={:?} after={:?} instruction={}", helper.stage(), helper.before(), helper.after(), instruction(capture, name, row.start(), &plain, helper.instruction())).unwrap();
                    }
                    FrameInstructionKind::Relocated(original) => {
                        // Original operands never receive pointer normalization.
                        let mut encoder = Encoder::new(64);
                        encoder.encode(original, original.ip()).unwrap();
                        writeln!(&mut metadata, "relocated code={:?} ip={} len={} bytes={}", original.code(), original.ip(), original.len(), hex(&encoder.take_buffer())).unwrap();
                    }
                    FrameInstructionKind::ReturnTransfer(target) => { writeln!(&mut metadata, "return={target}").unwrap(); }
                }
            }
        }
    }
    capture.write(&format!("{name}.trace.txt"), metadata);
    inventory(capture, name, 1, bindings);
}

#[test]
fn capture_current_features() {
    let output = PathBuf::from(std::env::var_os("LITEINST_CURRENT_PARITY_OUTPUT").expect("explicit new output directory"));
    assert!(!output.exists() && output.parent().is_some_and(Path::is_dir));
    std::fs::create_dir(&output).unwrap();
    let mut capture = Capture { output, names: vec![], inventory: "fixture\toutcome\timages\tcallback_operands\tdispatch_operands\tcontrol_operands\n".into(), images: 0, static_operands: 0, dispatch_operands: 0, control_operands: 0, refusals: 0 };
    for i in 0..HOOKS.len() {
        for j in i + 1..HOOKS.len() { assert_ne!(HOOKS[i] as usize, HOOKS[j] as usize); }
    }
    chains(&mut capture);
    let scan = |code: &[u8]| InstructionScanner::default().scan(code, FRAME_BASE).unwrap();
    let code = [0x0f, 0x1f, 0x44, 0, 0];
    let normal = TrampolinePlan::from_scan(&scan(&code), FRAME_BASE, HOOKS[0]).unwrap();
    for (name, address) in [("frame_normal_near", FRAME_NEAR), ("frame_normal_far", FRAME_FAR)] {
        frames(&mut capture, name, &code, &normal, address, &[Binding::Static(FRAME_BASE, 0)], None, None);
    }
    for (n, bytes) in [&[0x89, 0xc0][..], &[0x48, 0x89, 0xc0][..], &[0x48, 0x8d, 0x40, 0][..]].iter().enumerate() {
        let plan = TrampolinePlan::from_short_instruction(&scan(bytes), FRAME_BASE, HOOKS[0], false).unwrap();
        frames(&mut capture, &format!("frame_short_{}", n + 2), bytes, &plan, FRAME_NEAR, &[Binding::Static(FRAME_BASE, 0)], None, None);
    }
    let upstream = [0x48, 0x8d, 0x41, 1, 0x90, 0x90];
    let plan = TrampolinePlan::from_window(&scan(&upstream), FRAME_BASE, FRAME_BASE + 4, FRAME_BASE + 6, HOOKS[0], false).unwrap();
    frames(&mut capture, "frame_upstream", &upstream, &plan, FRAME_NEAR, &[Binding::Static(FRAME_BASE + 4, 0)], None, None);
    let coalesced = [0xb8, 1, 2, 3, 4, 0xb9, 5, 6, 7, 8, 0xba, 9, 10, 11, 12];
    let actions: Vec<_> = [FRAME_BASE, FRAME_BASE + 5, FRAME_BASE + 10].into_iter().map(|pc| (pc, HOOKS[0], false)).collect();
    let plan = TrampolinePlan::from_actions(&scan(&coalesced), FRAME_BASE, FRAME_BASE + 15, &actions).unwrap();
    let b: Vec<_> = actions.iter().map(|a| Binding::Static(a.0, 0)).collect();
    frames(&mut capture, "frame_coalesced_static", &coalesced, &plan, FRAME_NEAR, &b, None, None);
    let actions: Vec<_> = [FRAME_BASE, FRAME_BASE + 5, FRAME_BASE + 10].into_iter().enumerate().map(|(i, pc)| ControlledAction { logical_pc: pc, control: ProbeControl::new(HOOKS[i], i != 1) }).collect();
    let plan = TrampolinePlan::from_controlled_actions(&scan(&coalesced), FRAME_BASE, FRAME_BASE + 15, &actions).unwrap();
    let b = bindings(&actions);
    frames(&mut capture, "frame_coalesced_controlled", &coalesced, &plan, FRAME_NEAR, &b, None, None);
    for (name, bytes) in [("nop", &[0x90][..]), ("mov", &[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8][..]), ("jcc", &[0x75, 0][..]), ("ret", &[0xc3][..])] {
        let plan = TrampolinePlan::from_instruction(&scan(bytes), FRAME_BASE).unwrap();
        frames(&mut capture, &format!("frame_free_{name}"), bytes, &plan, FRAME_NEAR, &[], None, None);
    }
    let replaced = TrampolinePlan::from_scan_replacing_first(&scan(&code), FRAME_BASE, HOOKS[0]).unwrap();
    frames(&mut capture, "frame_refuse_replace", &code, &replaced, FRAME_NEAR, &[Binding::Static(FRAME_BASE, 0)], Some(FrameTraceRefusal::ReplacementRequiresFrameContract), None);
    let ptrace = TrampolinePlan::from_scan_replacing_first_with_ptrace_stops(&scan(&code), FRAME_BASE, HOOKS[0]).unwrap();
    // The old prologue authenticator refuses the intentional entry INT3. This
    // fixture retains ordinary bytes through the unchanged 28-case capture;
    // here compare the exact independent refusal without reinterpreting INT3.
    let ptrace_emitted = ptrace.emit_with_frame_trace_at(FRAME_NEAR).unwrap();
    assert_eq!(ptrace_emitted.image(), &ptrace.emit_at(FRAME_NEAR).unwrap());
    assert_eq!(ptrace_emitted.trace(), Err(FrameTraceRefusal::UnsupportedEntryOrigin));
    assert_eq!(ptrace_emitted.origin(), crate::frame_trace::FrameEntryOrigin::ControllerOwnedStack);
    let syscall_code = [0x0f, 0x05];
    let syscall = TrampolinePlan::from_scan_replacing_exact_syscall(&scan(&syscall_code), FRAME_BASE, HOOKS[0]).unwrap();
    frames(&mut capture, "frame_refuse_syscall", &syscall_code, &syscall, FRAME_NEAR, &[Binding::Static(FRAME_BASE, 0)], Some(FrameTraceRefusal::ExactSyscallRequiresFrameContract), None);
    let branch = [0x75, 0x7e];
    let expanded = TrampolinePlan::from_instruction(&scan(&branch), FRAME_BASE).unwrap();
    frames(&mut capture, "frame_refuse_expanded", &branch, &expanded, FRAME_FAR, &[], Some(FrameTraceRefusal::ExpandedRelocation), None);
    for (name, limits) in [("instructions", FrameTraceLimits { instructions: 0, calls: 64 }), ("calls", FrameTraceLimits { instructions: 4096, calls: 0 })] {
        frames(&mut capture, &format!("frame_limit_{name}"), &code, &normal, FRAME_NEAR, &[Binding::Static(FRAME_BASE, 0)], Some(FrameTraceRefusal::ResourceLimit), Some(limits));
    }
    let before = normal.emit_at(u64::MAX - 4).unwrap_err().to_string();
    let after = normal.emit_with_frame_trace_at(u64::MAX - 4).unwrap_err().to_string();
    assert_eq!(before, after);
    capture.write("independent-refusals.txt", format!("ptrace={:?}\nptrace_origin={:?}\noverflow={before}\n", ptrace_emitted.trace().unwrap_err(), ptrace_emitted.origin()));
    assert_eq!(capture.names.len(), 21);
    assert_eq!(capture.images, 34);
    assert_eq!(capture.static_operands, 17);
    assert_eq!(capture.dispatch_operands, 3);
    assert_eq!(capture.control_operands, 3);
    capture.write("fixtures.tsv", &capture.inventory);
    capture.write("complete.txt", "cases=21\nimages=34\ncallback_operands=17\ndispatch_operands=3\ncontrol_operands=3\nframe_metadata_successes=12\nframe_metadata_refusals=5\nindependent_refusals=2\n");
    println!("current-feature static capture complete: 4 chain/grouped cases, 17 frame images, 2 independent refusals; no generated execution");
}
