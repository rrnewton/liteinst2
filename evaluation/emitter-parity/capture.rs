//! Private STATIC parity capture, installed identically as a crate-private test
//! module in two isolated source copies. No image is mapped or executed.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use crate::bundle::{BundleBudget, PlannedBundle};
use crate::contracts::*;
use crate::controls::{ControlledAction, ProbeControl};
use crate::engine::{self, EnginePolicy, Tactic};
use crate::eviction;
use crate::neighbor::{self, NeighborSearch};
use crate::planner::HookSemantics;
use crate::quiescent::{self, AllocationPolicy, InstallRequest, SearchPolicy, TacticPolicy};
use crate::scanner::InstructionScanner;
use crate::trampoline::{HookCallback, HookContext, TrampolineImage, TrampolinePlan};
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, Register};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const BASE: u64 = 0x4200_0000_0000;
const SELECTED: u64 = BASE + 128;
const NEAR: u64 = SELECTED + 0x0400_0000;
const FAR: u64 = SELECTED + 0x4_0000_0000;
const BODY: [u8; 16] = [0xb8, 1, 0, 0, 0, 0x05, 2, 0, 0, 0, 0x05, 4, 0, 0, 0, 0xc3];

unsafe extern "C" fn hook_a(_: *mut HookContext) {
    std::hint::black_box(11_u64);
}
unsafe extern "C" fn hook_b(_: *mut HookContext) {
    std::hint::black_box(22_u64);
}
unsafe extern "C" fn hook_c(_: *mut HookContext) {
    std::hint::black_box(33_u64);
}
const HOOKS: [HookCallback; 3] = [hook_a, hook_b, hook_c];

fn range(start: u64, len: usize) -> AddressRange {
    AddressRange::new(start, len).unwrap()
}
fn allocation(target: u64) -> AllocationPolicy {
    AllocationPolicy {
        ranges: vec![range(target & !4095, 8192)],
        preferred_address: Some(target),
        max_candidates: 1,
        max_mappings: 1,
        max_mapped_bytes: 8192,
    }
}
fn identity() -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([0x59; 32]),
        mapping: 17,
        generation: 3,
    }
}

#[derive(Clone, Copy, Debug)]
enum Shape {
    B1,
    B2,
    T1,
    T2,
    T3,
    Upstream,
}
impl Shape {
    fn name(self) -> &'static str {
        match self {
            Self::B1 => "b1",
            Self::B2 => "b2",
            Self::T1 => "t1",
            Self::T2 => "t2",
            Self::T3 => "t3",
            Self::Upstream => "upstream",
        }
    }
    fn tactic(self) -> Tactic {
        match self {
            Self::B1 | Self::Upstream => Tactic::Relocation,
            Self::B2 => Tactic::GeneralizedPun,
            Self::T1 => Tactic::PrefixedPun,
            Self::T2 => Tactic::SuccessorEviction,
            Self::T3 => Tactic::NeighborEviction,
        }
    }
}

struct Fixture {
    code: Vec<u8>,
    base: u64,
    logical: u64,
    function: AddressRange,
    block: AddressRange,
    entries: LegalEntrySet,
    selected: AllocationPolicy,
    victim: AllocationPolicy,
    search: SearchPolicy,
    shape: Shape,
}
impl Fixture {
    fn new(shape: Shape) -> Self {
        let (mut body, block_len) = match shape {
            Shape::B1 => (vec![0xb8, 42, 0, 0, 0, 0xc3], 6),
            Shape::B2 => (vec![0x0f, 0x1f, 0, 0xb8, 42, 0, 0, 0, 0xc3], 9),
            Shape::T1 => (vec![0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3], 8),
            Shape::T2 => (
                vec![
                    0x0f, 0x1f, 0, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3,
                ],
                17,
            ),
            Shape::T3 => (vec![0x75, 1, 0x90, 0xc3], 2),
            Shape::Upstream => (vec![0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x89, 0xc0, 0xc3], 10),
        };
        if matches!(shape, Shape::T2 | Shape::T3) {
            body.resize(64, 0x90);
            body.extend_from_slice(&[0x48, 0xb8, 42, 0, 0, 0, 0, 0, 0, 0, 0xc3]);
        }
        let function = range(SELECTED, body.len());
        let mut code = vec![0x90; 16];
        code.extend_from_slice(&body);
        let logical = SELECTED
            + if matches!(shape, Shape::Upstream) {
                7
            } else {
                0
            };
        let selected_target = match shape {
            Shape::B1 | Shape::T3 | Shape::Upstream => NEAR,
            Shape::B2 => SELECTED + 5 + 0x2ab8_0000 + 0x8000,
            Shape::T1 => SELECTED + 6 + 0x2ab8,
            Shape::T2 => SELECTED + 5 + 0x56e9_0000 + 0x8000,
        };
        let victim_target = match shape {
            Shape::T2 => SELECTED + 3 + 5 + 0x0012_3456,
            _ => SELECTED + 0x0600_0000,
        };
        let tactics = match shape {
            Shape::B2 | Shape::T2 => TacticPolicy::GeneralizedPunOnly,
            Shape::T1 => TacticPolicy::PrefixPunOnly,
            _ => TacticPolicy::RelocationOnly,
        };
        Self {
            code,
            base: SELECTED - 16,
            logical,
            function,
            block: range(SELECTED, block_len),
            entries: LegalEntrySet {
                identity: identity(),
                scope: function,
                provenance: EntryProvenance::Declared(
                    "fixed static parity instruction heads".into(),
                ),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: vec![],
                resumes: ResumeObligation::NoneExist,
            },
            selected: allocation(selected_target),
            victim: allocation(victim_target),
            search: SearchPolicy {
                tactics,
                max_upstream_bytes: if matches!(shape, Shape::Upstream) {
                    7
                } else {
                    0
                },
                max_displaced_bytes: 80,
                max_sites: if matches!(shape, Shape::Upstream) {
                    2
                } else {
                    1
                },
            },
            shape,
        }
    }
    fn request(&self, semantics: HookSemantics) -> InstallRequest<'_> {
        InstallRequest {
            identity: identity(),
            code: &self.code,
            base_address: self.base,
            function: self.function,
            block: self.block,
            logical_pc: self.logical,
            entries: &self.entries,
            hook: hook_a,
            semantics,
            allocation: &self.selected,
            search: self.search,
        }
    }
    fn policy(&self) -> EnginePolicy {
        EnginePolicy {
            forced: Some(self.shape.tactic()),
            successor_puns: TacticPolicy::GeneralizedPunOnly,
            neighbor: NeighborSearch {
                forced_victim: Some(SELECTED + 64),
                max_victims: 1,
                max_pairs: 1,
            },
            bundle: BundleBudget::default(),
        }
    }
    fn inputs(&self, semantics: HookSemantics) -> String {
        format!(
            "identity={:?}\nbase={}\nlogical={}\nfunction={:?}\nblock={:?}\nentries={:?}\nhook=hook0\nsemantics={semantics:?}\nselected_allocation={:?}\nvictim_allocation={:?}\nsearch={:?}\nengine_policy={:?}\n",
            identity(),
            self.base,
            self.logical,
            self.function,
            self.block,
            self.entries,
            self.selected,
            self.victim,
            self.search,
            self.policy()
        )
    }
}

enum Binding<'a> {
    Static(u64, usize),
    Controlled(u64, usize, &'a ProbeControl),
}
impl Binding<'_> {
    fn logical(&self) -> u64 {
        match self {
            Self::Static(pc, _) | Self::Controlled(pc, _, _) => *pc,
        }
    }
}

struct Capture {
    output: PathBuf,
    names: Vec<String>,
    inventory: String,
    images: usize,
    static_operands: usize,
    dispatch_operands: usize,
    control_operands: usize,
    refusals: usize,
}
impl Capture {
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.output.join(name))
            .unwrap();
        file.write_all(bytes.as_ref()).unwrap();
    }
    fn begin(&mut self, name: &str, source: &[u8], inputs: &str, expected: &str) {
        assert!(!self.names.iter().any(|n| n == name));
        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        self.names.push(name.to_owned());
        self.write(&format!("{name}.source.bin"), source);
        self.write(
            &format!("{name}.inputs.txt"),
            format!("expected={expected}\n{inputs}"),
        );
    }
    fn refusal(&mut self, name: &str, actual: &Refusal, expected: Refusal, diagnostics: String) {
        assert_eq!(*actual, expected, "fixed required refusal {name}");
        self.write(
            &format!("{name}.result.txt"),
            format!("refused={actual:?}\n{diagnostics}"),
        );
        writeln!(&mut self.inventory, "{name}\trefusal\t0\t0\t0\t0").unwrap();
        self.refusals += 1;
    }
    fn image(
        &mut self,
        name: &str,
        index: usize,
        image: &TrampolineImage,
        bindings: &[Binding<'_>],
    ) {
        assert_eq!(image.layout().total_len(), Some(image.bytes().len()));
        let mut canonical = image.bytes().to_vec();
        let mut meta = format!(
            "address={}\nlayout={:?}\nprogram_counters={:?}\nentry_routes={:?}\ninstruction_boundaries={:?}\n",
            image.address(),
            image.layout(),
            image.program_counter_mappings(),
            image.entry_routes(),
            image.instruction_boundaries()
        );
        let controlled: Vec<_> = bindings
            .iter()
            .filter_map(|b| match b {
                Binding::Controlled(_, _, c) => Some(*c),
                _ => None,
            })
            .collect();
        assert_eq!(image.controls().len(), controlled.len());
        for (retained, declared) in image.controls().iter().zip(&controlled) {
            assert_eq!(retained, *declared);
        }
        let mut auth = String::from(
            "kind\tlogical\troute\tinstruction\timmediate\tactual\tcanonical\tlabel\n",
        );
        let mut normalized_ranges = Vec::new();
        for binding in bindings {
            let logical = binding.logical();
            let routes: Vec<_> = image
                .entry_routes()
                .iter()
                .filter(|&&(pc, _)| pc == logical)
                .collect();
            assert_eq!(routes.len(), 1);
            let route = routes[0].1;
            let start = usize::try_from(route.checked_sub(image.address()).unwrap()).unwrap();
            let mut decoder =
                Decoder::with_ip(64, &image.bytes()[start..], route, DecoderOptions::NONE);
            let mut preceding = Vec::<Instruction>::new();
            let call = (0..256)
                .find_map(|_| {
                    assert!(
                        decoder.can_decode(),
                        "declared prologue must contain its call"
                    );
                    let instruction = decoder.decode();
                    assert!(!instruction.is_invalid());
                    if instruction.code() == Code::Call_rm64 {
                        assert_eq!(instruction.op0_register(), Register::RAX);
                        Some(instruction)
                    } else {
                        assert_eq!(
                            instruction.flow_control(),
                            FlowControl::Next,
                            "no control flow may precede the declared first call"
                        );
                        preceding.push(instruction);
                        None
                    }
                })
                .expect("bounded declared hook prologue");
            let mov = *preceding.last().unwrap();
            assert_eq!(mov.next_ip(), call.ip());
            let call_offset = usize::try_from(call.ip() - image.address()).unwrap();
            assert_eq!(&image.bytes()[call_offset..call_offset + 2], &[0xff, 0xd0]);
            let mut operand = |instruction: Instruction,
                               register: Register,
                               actual: u64,
                               value: u64,
                               kind: &str,
                               label: &str| {
                assert_eq!(instruction.code(), Code::Mov_r64_imm64);
                assert_eq!(instruction.op0_register(), register);
                assert_eq!(instruction.len(), 10);
                assert_eq!(
                    instruction.immediate64(),
                    actual,
                    "producer-supplied pointer identity"
                );
                let offset = usize::try_from(instruction.ip() - image.address()).unwrap();
                let opcode = match register {
                    Register::RAX => [0x48, 0xb8],
                    Register::RSI => [0x48, 0xbe],
                    _ => unreachable!(),
                };
                assert_eq!(&image.bytes()[offset..offset + 2], &opcode);
                assert_eq!(
                    &image.bytes()[offset + 2..offset + 10],
                    &actual.to_le_bytes()
                );
                assert!(
                    normalized_ranges
                        .iter()
                        .all(|&(a, b)| offset + 2 >= b || offset + 10 <= a)
                );
                normalized_ranges.push((offset + 2, offset + 10));
                canonical[offset + 2..offset + 10].copy_from_slice(&value.to_le_bytes());
                writeln!(
                    &mut auth,
                    "{kind}\t{logical}\t{route}\t{offset}\t{}\t{actual}\t{value}\t{label}",
                    offset + 2
                )
                .unwrap();
            };
            match binding {
                Binding::Static(_, hook) => {
                    operand(
                        mov,
                        Register::RAX,
                        HOOKS[*hook] as usize as u64,
                        0x6100_0000_0000_0000 + *hook as u64,
                        "callback",
                        &format!("hook{hook}"),
                    );
                    self.static_operands += 1;
                }
                Binding::Controlled(_, id, control) => {
                    assert_eq!(control.callback() as usize, HOOKS[*id] as usize);
                    let block_mov = preceding[preceding.len() - 2];
                    assert_eq!(block_mov.next_ip(), mov.ip());
                    operand(
                        block_mov,
                        Register::RSI,
                        control.block_address(),
                        0x7100_0000_0000_0000 + *id as u64,
                        "control",
                        &format!("control{id}"),
                    );
                    operand(
                        mov,
                        Register::RAX,
                        crate::controls::dispatch as *const () as usize as u64,
                        0x6100_0000_0000_0010,
                        "dispatch",
                        "dispatch",
                    );
                    writeln!(
                        &mut meta,
                        "control={id} callback=hook{id} enabled={} payload_bytes={}",
                        control.is_enabled(),
                        ProbeControl::payload_bytes()
                    )
                    .unwrap();
                    self.dispatch_operands += 1;
                    self.control_operands += 1;
                }
            }
        }
        for (i, (&a, &b)) in image.bytes().iter().zip(&canonical).enumerate() {
            assert!(a == b || normalized_ranges.iter().any(|&(lo, hi)| lo <= i && i < hi));
        }
        let stem = format!("{name}.image{index}");
        self.write(&format!("{stem}.raw.bin"), image.bytes());
        self.write(&format!("{stem}.canonical.bin"), canonical);
        self.write(&format!("{stem}.metadata.txt"), meta);
        self.write(&format!("{stem}.operands.tsv"), auth);
        self.images += 1;
    }
    fn plan_metadata(plan: &PatchPlan, image: &TrampolineImage) -> String {
        // Destructure exhaustively: a newly added contract field must be captured.
        let PlanParts {
            identity,
            profile,
            kind,
            logical_pc,
            physical_pc,
            displaced,
            reads,
            writes,
            dependencies,
            entries,
            obligations,
            allocations,
            generated,
            requirements,
        } = plan.parts();
        assert_eq!(generated.len(), 1);
        assert_eq!(generated[0].address, image.address());
        assert_eq!(generated[0].bytes, image.bytes());
        assert_eq!(
            generated[0].program_counters,
            image.program_counter_mappings()
        );
        format!(
            "identity={identity:?}\nprofile={profile:?}\nkind={kind:?}\nlogical={logical_pc}\nphysical={physical_pc}\ndisplaced={displaced:?}\nreads={reads:?}\nwrites={writes:?}\ndependencies={dependencies:?}\nentries={entries:?}\nobligations={obligations:?}\nallocations={allocations:?}\ngenerated_address={}\ngenerated_length={}\ngenerated_program_counters={:?}\nrequirements={requirements:?}\n",
            generated[0].address,
            generated[0].bytes.len(),
            generated[0].program_counters
        )
    }
    fn single(&mut self, name: &str, member: &quiescent::PlannedInstall, bindings: &[Binding<'_>]) {
        self.write(
            &format!("{name}.result.txt"),
            format!(
                "accepted\nmetrics={:?}\n{}",
                member.metrics(),
                Self::plan_metadata(member.plan(), member.image())
            ),
        );
        self.image(name, 0, member.image(), bindings);
        let c = bindings
            .iter()
            .filter(|b| matches!(b, Binding::Controlled(..)))
            .count();
        writeln!(
            &mut self.inventory,
            "{name}\tsuccess\t1\t{}\t{c}\t{c}",
            bindings.len() - c
        )
        .unwrap();
    }
    fn bundle(&mut self, name: &str, bundle: &PlannedBundle, diagnostics: &str, logical: u64) {
        let plan = bundle.plan();
        assert_eq!(plan.steps().len(), bundle.images().len());
        let mut meta = format!(
            "accepted\n{diagnostics}\nidentity={:?}\noriginals={:?}\nfinal_bytes={:?}\nlocks={:?}\nmemory={:?}\ngrouping={:?}\n",
            plan.identity(),
            plan.originals(),
            plan.final_bytes(),
            plan.locks(),
            plan.memory(),
            bundle.grouping()
        );
        let mut hooks = 0;
        for (index, (step, image)) in plan.steps().iter().zip(bundle.images()).enumerate() {
            writeln!(
                &mut meta,
                "step={index}\n{}",
                Self::plan_metadata(step, image)
            )
            .unwrap();
            let bindings = if step.parts().logical_pc == logical {
                hooks += 1;
                vec![Binding::Static(logical, 0)]
            } else {
                vec![]
            };
            self.image(name, index, image, &bindings);
        }
        assert_eq!(hooks, 1, "only selected image has callback");
        self.write(&format!("{name}.result.txt"), meta);
        writeln!(
            &mut self.inventory,
            "{name}\tsuccess\t{}\t1\t0\t0",
            bundle.images().len()
        )
        .unwrap();
    }
    fn direct(
        &mut self,
        name: &str,
        source: &[u8],
        plan: &TrampolinePlan,
        target: u64,
        bindings: &[Binding<'_>],
        inputs: &str,
    ) {
        self.begin(name, source, inputs, "success");
        self.write(&format!("{name}.result.txt"), format!("accepted\nexecute={}\nlogical={}\nreturn={}\ndisplaced_len={}\nreplaces_first={}\n", plan.execute_address(), plan.logical_address(), plan.return_address(), plan.displaced_len(), plan.replaces_first()));
        self.image(name, 0, &plan.emit_at(target).unwrap(), bindings);
        writeln!(&mut self.inventory, "{name}\tsuccess\t1\t0\t3\t3").unwrap();
    }
}

fn capture_tactic(capture: &mut Capture, shape: Shape, semantics: HookSemantics, outer: bool) {
    let fixture = Fixture::new(shape);
    let label = if semantics == HookSemantics::Observe {
        "observe"
    } else {
        "replace"
    };
    let name = format!(
        "{}_{}_{}",
        shape.name(),
        label,
        if outer { "engine" } else { "leaf" }
    );
    capture.begin(&name, &fixture.code, &fixture.inputs(semantics), "success");
    let request = fixture.request(semantics);
    let expected_images = if matches!(shape, Shape::T2 | Shape::T3) {
        2
    } else {
        1
    };
    if outer {
        let planned = engine::plan(&request, &fixture.victim, fixture.policy())
            .expect("fixed forced engine positive");
        assert_eq!(planned.tactic(), shape.tactic());
        assert_eq!(planned.attempts().len(), 1);
        assert_eq!(planned.bundle().images().len(), expected_images);
        assert_eq!(planned.attempts()[0].refusal, None);
        capture.bundle(
            &name,
            planned.bundle(),
            &format!(
                "tactic={:?}\nmetrics={:?}\nordered_attempts={:?}",
                planned.tactic(),
                planned.metrics(),
                planned.attempts()
            ),
            fixture.logical,
        );
    } else {
        match shape {
            Shape::T2 => {
                let planned = eviction::plan_successor_detailed(
                    &request,
                    &fixture.victim,
                    fixture.policy().bundle,
                )
                .expect("fixed T2 positive");
                assert_eq!(
                    planned.kind(),
                    eviction::EvictionKind::Successor {
                        victim: SELECTED + 3
                    }
                );
                assert_eq!(planned.bundle().images().len(), expected_images);
                capture.bundle(
                    &name,
                    planned.bundle(),
                    &format!("kind={:?}\nmetrics={:?}", planned.kind(), planned.metrics()),
                    fixture.logical,
                );
            }
            Shape::T3 => {
                let planned = neighbor::plan_neighbor_detailed(
                    &request,
                    &fixture.victim,
                    fixture.policy().neighbor,
                    fixture.policy().bundle,
                )
                .expect("fixed T3 positive");
                assert_eq!(planned.geometry().victim, SELECTED + 64);
                assert_eq!(planned.geometry().rel8, 67);
                assert_eq!(planned.bundle().images().len(), expected_images);
                capture.bundle(
                    &name,
                    planned.bundle(),
                    &format!(
                        "geometry={:?}\nmetrics={:?}",
                        planned.geometry(),
                        planned.metrics()
                    ),
                    fixture.logical,
                );
            }
            _ => {
                let planned =
                    quiescent::plan_install_detailed(&request).expect("fixed leaf positive");
                assert_eq!(
                    planned.image().address(),
                    fixture.selected.preferred_address.unwrap()
                );
                match shape {
                    Shape::B1 | Shape::Upstream => {
                        assert_eq!(planned.plan().parts().kind, PlanKind::Relocation)
                    }
                    Shape::B2 => assert!(matches!(
                        planned.plan().parts().kind,
                        PlanKind::GeneralizedPun(_)
                    )),
                    Shape::T1 => assert!(
                        matches!(&planned.plan().parts().kind, PlanKind::PrefixedPun(p) if p.prefix_count == 1)
                    ),
                    _ => unreachable!(),
                }
                if matches!(shape, Shape::Upstream) {
                    assert_eq!(planned.plan().parts().physical_pc, SELECTED);
                    assert_eq!(planned.plan().parts().logical_pc, SELECTED + 7);
                    assert_eq!(planned.metrics().upstream_bytes, 7);
                    assert_eq!(planned.metrics().attempts.len(), 2);
                    assert_eq!(
                        planned.metrics().attempts[0].refusal,
                        Some(Refusal::NoPatchWindow)
                    );
                }
                capture.single(&name, &planned, &[Binding::Static(fixture.logical, 0)]);
            }
        }
    }
}

fn prefix_geometries(capture: &mut Capture) {
    for (len, body) in [
        (2_usize, vec![0x89, 0xc0, 0x48, 0x8d, 0x4f, 8, 0xc3]),
        (3, vec![0x48, 0x8d, 7, 0x48, 0x89, 7, 0xc3]),
        (4, vec![0x48, 0x8d, 0x4f, 8, 0x48, 0x89, 0x0f, 0xc3]),
    ] {
        for prefixes in 1..len {
            let mut fixture = Fixture::new(Shape::T1);
            fixture.code = vec![0x90; 16];
            fixture.code.extend_from_slice(&body);
            fixture.function = range(SELECTED, body.len());
            fixture.block = range(SELECTED, len);
            fixture.entries.scope = fixture.function;
            let free = len - prefixes - 1;
            let mut bytes = [0_u8; 4];
            bytes[free..].copy_from_slice(&body[len..5 + prefixes]);
            let window_start = u64::try_from(
                i128::from(SELECTED + 5 + prefixes as u64) + i128::from(i32::from_le_bytes(bytes)),
            )
            .unwrap();
            let width = 1_usize << (8 * free);
            let target = window_start + width as u64 / 2;
            fixture.selected = allocation(target);
            let name = format!("t1_l{len}_p{prefixes}");
            capture.begin(
                &name,
                &fixture.code,
                &fixture.inputs(HookSemantics::Observe),
                "success",
            );
            let member = quiescent::plan_install_detailed(&fixture.request(HookSemantics::Observe))
                .expect("all six fixed T1 geometries");
            assert_eq!(member.image().address(), target);
            let PlanKind::PrefixedPun(pun) = &member.plan().parts().kind else {
                panic!("forced T1 replaced by another tactic")
            };
            assert_eq!(usize::from(pun.instruction_len), len);
            assert_eq!(usize::from(pun.prefix_count), prefixes);
            assert_eq!(pun.target_window, range(window_start, width));
            assert_eq!(pun.consumed, range(SELECTED, 5 + prefixes));
            capture.single(&name, &member, &[Binding::Static(SELECTED, 0)]);
        }
    }
}

fn actions(pcs: &[u64; 3], mask: usize) -> Vec<ControlledAction> {
    pcs.iter()
        .enumerate()
        .map(|(index, &logical_pc)| ControlledAction {
            logical_pc,
            control: ProbeControl::new(HOOKS[index], mask & (1 << index) != 0),
        })
        .collect()
}
fn bindings(actions: &[ControlledAction]) -> Vec<Binding<'_>> {
    actions
        .iter()
        .enumerate()
        .map(|(index, action)| Binding::Controlled(action.logical_pc, index, &action.control))
        .collect()
}
fn controlled_fixture() -> Fixture {
    let mut fixture = Fixture::new(Shape::B1);
    fixture.code = BODY.to_vec();
    fixture.base = SELECTED;
    fixture.function = range(SELECTED, BODY.len());
    fixture.block = fixture.function;
    fixture.entries.scope = fixture.function;
    fixture.search.max_displaced_bytes = 15;
    fixture
}
fn controls(capture: &mut Capture) {
    let fixture = controlled_fixture();
    let scan = InstructionScanner::default().scan(&BODY, SELECTED).unwrap();
    for mask in 0..8 {
        let action = actions(&[SELECTED, SELECTED + 5, SELECTED + 10], mask);
        let plan = TrampolinePlan::from_controlled_actions(&scan, SELECTED, SELECTED + 15, &action)
            .unwrap();
        capture.direct(
            &format!("controls_direct_mask{mask}"),
            &BODY,
            &plan,
            NEAR,
            &bindings(&action),
            &format!(
                "mask={mask}\ntarget={NEAR}\naction_pcs={:?}\ncallback_ids=[0,1,2]\n",
                [SELECTED, SELECTED + 5, SELECTED + 10]
            ),
        );
        let name = format!("controls_coalesced_mask{mask}");
        capture.begin(
            &name,
            &BODY,
            &format!(
                "{}mask={mask}\naction_pcs={:?}\ncallback_ids=[0,1,2]\n",
                fixture.inputs(HookSemantics::Observe),
                [SELECTED, SELECTED + 5, SELECTED + 10]
            ),
            "success",
        );
        let member =
            quiescent::plan_coalesced_detailed(&fixture.request(HookSemantics::Observe), &action)
                .expect("fixed coalesced positive");
        assert_eq!(member.plan().parts().displaced, range(SELECTED, 15));
        assert_eq!(member.image().address(), NEAR);
        capture.single(&name, &member, &bindings(&action));
    }
    // Internal CFG belongs to the lower-level emitter, not BasicBlockBounds.
    let code = [
        0xeb, 3, 0x48, 0x8d, 7, 0x80, 7, 1, 0x80, 0x3f, 14, 0x75, 0xf5, 0xc3,
    ];
    let scan = InstructionScanner::default().scan(&code, SELECTED).unwrap();
    for (label, target) in [("near", NEAR), ("far", FAR)] {
        let action = actions(&[SELECTED + 2, SELECTED + 5, SELECTED + 8], 5);
        let plan = TrampolinePlan::from_controlled_actions(&scan, SELECTED, SELECTED + 13, &action)
            .unwrap();
        capture.direct(
            &format!("controls_cfg_{label}"),
            &code,
            &plan,
            target,
            &bindings(&action),
            &format!(
                "mask=5\ntarget={target}\naction_pcs={:?}\ncallback_ids=[0,1,2]\n",
                [SELECTED + 2, SELECTED + 5, SELECTED + 8]
            ),
        );
    }
}

fn refusals(capture: &mut Capture) {
    for shape in [Shape::B1, Shape::B2, Shape::T1, Shape::T2, Shape::T3] {
        let mut fixture = Fixture::new(shape);
        let mut policy = fixture.policy();
        let reason = match shape {
            Shape::B1 => {
                fixture.search.max_sites = 0;
                Refusal::NoPatchWindow
            }
            Shape::B2 | Shape::T1 => {
                fixture.selected.max_candidates = 0;
                Refusal::AllocationUnavailable
            }
            Shape::T2 => {
                fixture.victim.max_candidates = 0;
                Refusal::AllocationUnavailable
            }
            Shape::T3 => {
                policy.neighbor.max_pairs = 0;
                Refusal::AllocationUnavailable
            }
            Shape::Upstream => unreachable!(),
        };
        let name = format!("refuse_{}_budget", shape.name());
        capture.begin(
            &name,
            &fixture.code,
            &format!(
                "{}actual_engine_policy={policy:?}\n",
                fixture.inputs(HookSemantics::Observe)
            ),
            &format!("{reason:?}"),
        );
        let failure = engine::plan(
            &fixture.request(HookSemantics::Observe),
            &fixture.victim,
            policy,
        )
        .expect_err("fixed forced bounded refusal");
        assert_eq!(failure.attempts.len(), 1);
        assert_eq!(failure.attempts[0].tactic, shape.tactic());
        capture.refusal(
            &name,
            &failure.reason,
            reason,
            format!("failure={failure:?}\n"),
        );
    }
    let mut fixture = Fixture::new(Shape::B1);
    let mut policy = fixture.policy();
    policy.bundle.max_steps = 0;
    let name = "refuse_b1_aggregate";
    capture.begin(
        name,
        &fixture.code,
        &format!(
            "{}actual_engine_policy={policy:?}\n",
            fixture.inputs(HookSemantics::Observe)
        ),
        "AllocationUnavailable",
    );
    let failure = engine::plan(
        &fixture.request(HookSemantics::Observe),
        &fixture.victim,
        policy,
    )
    .unwrap_err();
    assert_eq!(failure.attempts.len(), 1);
    assert!(
        failure.attempts[0].search.accepted,
        "leaf success remains visible under outer refusal"
    );
    assert!(failure.attempts[0].outer_refusal.is_some());
    capture.refusal(
        name,
        &failure.reason,
        Refusal::AllocationUnavailable,
        format!("failure={failure:?}\n"),
    );
    fixture.entries.completeness = EntryCompleteness::Incomplete;
    let name = "refuse_incomplete_entries";
    capture.begin(
        name,
        &fixture.code,
        &fixture.inputs(HookSemantics::Observe),
        "UnresolvedEntry",
    );
    let failure =
        quiescent::plan_install_detailed(&fixture.request(HookSemantics::Observe)).unwrap_err();
    capture.refusal(
        name,
        &failure.reason,
        Refusal::UnresolvedEntry,
        format!("failure={failure:?}\n"),
    );
    let fixture = controlled_fixture();
    for mode in 0..3 {
        let mut action = actions(&[SELECTED, SELECTED + 5, SELECTED + 10], 0);
        let (name, semantics, expected) = match mode {
            0 => (
                "refuse_coalesced_replace",
                HookSemantics::ReplaceFirst,
                Refusal::UnsupportedSemantics(
                    "runtime coalesced controls currently require observing hooks".into(),
                ),
            ),
            1 => {
                action[1].control = action[0].control.clone();
                (
                    "refuse_coalesced_duplicate_control",
                    HookSemantics::Observe,
                    Refusal::InvalidPlan,
                )
            }
            2 => {
                action[1].logical_pc = SELECTED + 1;
                (
                    "refuse_coalesced_mid_instruction",
                    HookSemantics::Observe,
                    Refusal::NotInstructionHead,
                )
            }
            _ => unreachable!(),
        };
        let pcs: Vec<_> = action.iter().map(|a| a.logical_pc).collect();
        capture.begin(
            name,
            &fixture.code,
            &format!(
                "{}mask=0\naction_pcs={pcs:?}\nduplicate_control={}\n",
                fixture.inputs(semantics),
                mode == 1
            ),
            &format!("{expected:?}"),
        );
        let failure =
            quiescent::plan_coalesced_detailed(&fixture.request(semantics), &action).unwrap_err();
        capture.refusal(
            name,
            &failure.reason,
            expected,
            format!("failure={failure:?}\n"),
        );
    }
}

#[test]
fn capture_extended_live_parity() {
    let output = PathBuf::from(
        std::env::var_os("LITEINST_EXTENDED_PARITY_OUTPUT")
            .expect("explicit new private output directory required"),
    );
    assert!(
        !output.exists(),
        "never overwrite any earlier capture or failure"
    );
    assert!(output.parent().is_some_and(Path::is_dir));
    std::fs::create_dir(&output).unwrap();
    for i in 0..HOOKS.len() {
        for j in i + 1..HOOKS.len() {
            assert_ne!(HOOKS[i] as usize, HOOKS[j] as usize);
        }
    }
    let mut capture = Capture {
        output,
        names: vec![],
        inventory:
            "fixture\toutcome\timages\tcallback_operands\tdispatch_operands\tcontrol_operands\n"
                .into(),
        images: 0,
        static_operands: 0,
        dispatch_operands: 0,
        control_operands: 0,
        refusals: 0,
    };
    for shape in [
        Shape::B1,
        Shape::B2,
        Shape::T1,
        Shape::T2,
        Shape::T3,
        Shape::Upstream,
    ] {
        for semantics in [HookSemantics::Observe, HookSemantics::ReplaceFirst] {
            for outer in [false, true] {
                capture_tactic(&mut capture, shape, semantics, outer);
            }
        }
    }
    prefix_geometries(&mut capture);
    controls(&mut capture);
    refusals(&mut capture);
    assert_eq!(capture.names.len(), 58);
    assert_eq!(capture.refusals, 10);
    assert_eq!(capture.images, 56);
    assert_eq!(capture.static_operands, 30);
    assert_eq!(capture.dispatch_operands, 54);
    assert_eq!(capture.control_operands, 54);
    capture.write("fixtures.tsv", &capture.inventory);
    capture.write("complete.txt", "fixtures=58\nsuccesses=48\nrefusals=10\nimages=56\ncallback_operands=30\ndispatch_operands=54\ncontrol_operands=54\n");
    println!(
        "static capture complete: 58 fixtures, 48 successes, 10 refusals, 56 images, 138 authenticated pointer operands; no generated execution"
    );
}
