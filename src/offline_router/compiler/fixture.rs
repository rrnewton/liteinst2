//! Test-only ELF assembly. It uses real opaque production plans, not fabricated
//! steps. The code is synthetic; RW layout/stack match the authored corpus.
use super::super::*;
use crate::contracts::*;
use crate::emission::{
    ArtifactEmission, ArtifactRequest, PlanningSite, SymbolicHook, TargetProfile,
};
use crate::planner::HookSemantics;
use crate::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
use liteinst_artifact::startup::{Dependency, Policy, State};
use liteinst_artifact::{Compatibility, Metadata, Outcome, Site, Tactic};

pub const RW_START: u64 = 0x404000;
pub const RW_BYTES: usize = 335872;
pub const STACK_START: u64 = 0x446000;
pub const STACK_BYTES: usize = 65536;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    B1,
    B2,
    T1,
    T2,
    Neighbor,
    ShortNeighbor,
    ShortOverlay,
}
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
fn p16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn p32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn p64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
#[derive(Clone, Copy)]
struct Ph {
    kind: u32,
    flags: u32,
    off: u64,
    va: u64,
    files: u64,
    mem: u64,
    align: u64,
}
fn record(b: &mut [u8], at: usize, p: Ph) {
    p32(b, at, p.kind);
    p32(b, at + 4, p.flags);
    p64(b, at + 8, p.off);
    p64(b, at + 16, p.va);
    p64(b, at + 24, p.va);
    p64(b, at + 32, p.files);
    p64(b, at + 40, p.mem);
    p64(b, at + 48, p.align);
}
struct Code {
    base: u64,
    selected: u64,
    victim: u64,
    bytes: Vec<u8>,
    heads: Vec<u64>,
    len: usize,
    selected_target: u64,
    victim_target: u64,
    family: Family,
}
fn code(index: usize, family: Family) -> Code {
    let base = 0x401100 + index as u64 * 64;
    let (bytes, offsets, len, selected_target, victim_target) = match family {
        Family::B1 => (
            vec![0xb8, 7, 0, 0, 0, 0xc3],
            vec![0, 5],
            5,
            0x20000000 + index as u64 * 8192,
            0,
        ),
        Family::B2 => (
            vec![0xff, 0xc0, 0xb8, 0x10, 0, 0, 0, 0xc3],
            vec![0, 2, 7],
            2,
            base + 5 + 0x0010b800,
            0,
        ),
        Family::T1 => (
            vec![0x48, 0xff, 0xc0, 0xb8, 0x10, 1, 0, 0, 0xc3],
            vec![0, 3, 8],
            3,
            base + 6 + 0x0110b800,
            0,
        ),
        Family::T2 => (
            vec![0xff, 0xc0, 0xb8, 0x10, 0, 0, 0, 0xc3],
            vec![0, 2, 7],
            2,
            base + 5 + 0x0010e900,
            base + 7 + 0x06000010,
        ),
        Family::ShortOverlay => (
            vec![0x2e, 0xb8, 1, 2, 3, 4, 0xff, 0xc0, 0x10, 0, 0xc3],
            vec![0, 6, 8, 10],
            2,
            base + 10 + 0x0010fdeb,
            0x21000000,
        ),
        Family::Neighbor | Family::ShortNeighbor => {
            let mut bytes = vec![0x90; 16];
            bytes[..2].copy_from_slice(&[0xff, 0xc0]);
            let mut offsets = vec![0];
            offsets.extend(2..=16);
            let target = if family == Family::Neighbor {
                bytes.extend_from_slice(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 0xc3]);
                offsets.push(26);
                0x20000000
            } else {
                bytes.extend_from_slice(&[
                    0x2e, 0x2e, 0x2e, 0x2e, 0xb8, 1, 2, 3, 4, 0x01, 0x00, 0xc3,
                ]);
                offsets.extend([25, 27]);
                base + 26 + 0x01000000
            };
            (bytes, offsets, 2, target, 0x21000000)
        }
    };
    Code {
        base,
        selected: base + if family == Family::ShortOverlay { 6 } else { 0 },
        victim: base
            + if family == Family::ShortOverlay {
                0
            } else {
                16
            },
        bytes,
        heads: offsets.into_iter().map(|v| base + v).collect(),
        len,
        selected_target,
        victim_target,
        family,
    }
}

pub fn accepted(program: u64, family: Family) -> (Input, Vec<(u64, ArtifactPlan)>) {
    let (nh, ns) = match program {
        1 => (80, 16),
        2 => (107, 26),
        _ => panic!("fixed program"),
    };
    let codes = (0..ns)
        .map(|i| code(i, if i == 0 { family } else { Family::B1 }))
        .collect::<Vec<_>>();
    let ro = Ph {
        kind: 1,
        flags: 4,
        off: 0,
        va: 0x400000,
        files: 4096,
        mem: 4096,
        align: 4096,
    };
    let rx = Ph {
        kind: 1,
        flags: 5,
        off: 4096,
        va: 0x401000,
        files: 12288,
        mem: 12288,
        align: 4096,
    };
    let rw = Ph {
        kind: 1,
        flags: 6,
        off: 16384,
        va: RW_START,
        files: RW_BYTES as u64,
        mem: RW_BYTES as u64,
        align: 4096,
    };
    let stack = Ph {
        kind: 0x6474e551,
        flags: 6,
        off: 0,
        va: 0,
        files: 0,
        mem: 0,
        align: 0,
    };
    let note = Ph {
        kind: 4,
        flags: 4,
        off: 400,
        va: 0x400190,
        files: 20,
        mem: 20,
        align: 4,
    };
    let original_headers = [
        Ph {
            kind: 6,
            flags: 4,
            off: 64,
            va: 0x400040,
            files: 336,
            mem: 336,
            align: 8,
        },
        ro,
        rx,
        rw,
        note,
        stack,
    ];
    let mut original = vec![0; 16384 + RW_BYTES];
    original[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    p16(&mut original, 16, 2);
    p16(&mut original, 18, 62);
    p32(&mut original, 20, 1);
    p64(&mut original, 24, codes[0].base);
    p64(&mut original, 32, 64);
    p16(&mut original, 52, 64);
    p16(&mut original, 54, 56);
    p16(&mut original, 56, 6);
    for (i, p) in original_headers.into_iter().enumerate() {
        record(&mut original, 64 + i * 56, p);
    }
    original[400..420].copy_from_slice(&[
        4, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, b'L', b'I', b'2', 0, 1, 0, 0, 0,
    ]);
    // Exact data geometry: input 69632 + output 200704 + stack 65536.
    assert_eq!(RW_START + 69632 + 200704, STACK_START);
    assert_eq!(RW_BYTES, 69632 + 200704 + STACK_BYTES);
    let stack_offset = (STACK_START - 0x400000) as usize;
    original[stack_offset..stack_offset + STACK_BYTES].fill(0x5a);
    let mut heads = Vec::new();
    for c in &codes {
        let at = (c.base - 0x400000) as usize;
        original[at..at + c.bytes.len()].copy_from_slice(&c.bytes);
        heads.extend_from_slice(&c.heads);
    }
    original[0x3000] = 0xc3;
    heads.push(0x403000);
    for i in 0..nh - heads.len() {
        original[0x2800 + i] = 0x90;
        heads.push(0x402800 + i as u64);
    }
    heads.sort_unstable();
    assert_eq!(heads.len(), nh);
    assert!(heads.windows(2).all(|w| w[0] < w[1]));
    let identity = CodeIdentity {
        source: SourceIdentity(ContentId::of(&original).0),
        mapping: 1,
        generation: 1,
    };
    let emission = ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            crate::trampoline::SavedExtendedStateLayout::describe_target_fxsave64(),
            1,
        )
        .unwrap(),
        SymbolicHook {
            identity: 1,
            address: Some(0x403000),
        },
        vec![range(0x400000, 0x56000)],
    );
    let mut plans = Vec::new();
    for (i, c) in codes.iter().enumerate() {
        let source = range(c.base, c.bytes.len());
        let entries = LegalEntrySet {
            identity,
            scope: source,
            provenance: EntryProvenance::Declared(
                "literal compiler control; no corpus execution".into(),
            ),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: c
                .heads
                .iter()
                .map(|&address| LegalEntry {
                    address,
                    requires_endbr: false,
                })
                .collect(),
            resumes: ResumeObligation::NoneExist,
        };
        let policy = allocation(c.selected_target);
        let victim = allocation(c.victim_target.max(4096));
        let tactics = match c.family {
            Family::B2 | Family::T2 => TacticPolicy::GeneralizedPunOnly,
            Family::T1 => TacticPolicy::PrefixPunOnly,
            _ => TacticPolicy::RelocationOnly,
        };
        let request = ArtifactRequest {
            site: PlanningSite {
                identity,
                code: &c.bytes,
                base_address: c.base,
                function: source,
                block: range(c.selected, c.len),
                logical_pc: c.selected,
                entries: &entries,
                semantics: HookSemantics::Observe,
                allocation: &policy,
                search: SearchPolicy {
                    tactics,
                    max_upstream_bytes: 0,
                    max_displaced_bytes: 15,
                    max_sites: 1,
                },
            },
            emission: &emission,
        };
        let budget = crate::bundle::BundleBudget {
            max_steps: 2,
            max_mappings: 2,
            max_virtual_bytes: 16384,
            max_backing_bytes: 16384,
            max_virtual_span: 1 << 31,
        };
        let search = crate::neighbor::NeighborSearch {
            forced_victim: Some(c.victim),
            max_victims: 1,
            max_pairs: 1,
        };
        let plan = match c.family {
            Family::T2 => {
                crate::eviction::plan_successor_with_emission(&request, &victim, budget).unwrap()
            }
            Family::Neighbor => {
                crate::neighbor::plan_neighbor_with_emission(&request, &victim, search, budget)
                    .unwrap()
            }
            Family::ShortNeighbor | Family::ShortOverlay => {
                crate::neighbor::plan_neighbor_short_with_emission(
                    &request, &victim, search, budget,
                )
                .unwrap()
            }
            _ => crate::quiescent::plan_install_with_emission(&request).unwrap(),
        };
        assert!(!plan.qualification_complete());
        plans.push((i as u64 + 1, plan));
    }
    let policy = Policy {
        interpreter: b"/pkg/ld.so".to_vec(),
        bootstrap_dso: format!("/pkg/program-{program}.so").into_bytes(),
        dependencies: vec![Dependency {
            path: b"/pkg/ld.so".to_vec(),
            identity: ContentId::of(b"pinned loader fixture"),
        }],
        app_stack: Span {
            start: STACK_START,
            len: STACK_BYTES as u64,
        },
        hook_pc: 0x403000,
        hook_id: 1,
        state: State {
            domain: 1,
            format: 1,
            allocation: 512,
            image: 512,
            mask: 3,
            components: vec![],
        },
        qualification_contract: ContentId::of(b"pure compiler control; no runtime authority"),
    };
    let selection = format!("fixed compiler control program {program} {family:?}").into_bytes();
    let target = c::target_bytes(&policy.state).unwrap();
    let sites = codes
        .iter()
        .enumerate()
        .map(|(i, c)| Site {
            id: i as u64 + 1,
            original_pc: c.selected,
            file_offset: c.selected - 0x400000,
            length: c.len as u8,
            outcome: Outcome::Rewritten(match c.family {
                Family::B2 => Tactic::GeneralizedPun,
                Family::T1 => Tactic::PrefixedPun,
                Family::T2 => Tactic::SuccessorEviction,
                Family::Neighbor | Family::ShortNeighbor | Family::ShortOverlay => {
                    Tactic::NeighborEviction
                }
                _ => Tactic::Relocation,
            }),
        })
        .collect();
    let metadata = Metadata::new(
        &original,
        ContentId::of(&selection),
        Compatibility {
            planner: 3,
            encoder: 1,
            hook_abi: 1,
            arena: 1,
            target: ContentId::of(&target),
            binding: ContentId::of(&selection),
        },
        sites,
    )
    .unwrap()
    .encode(liteinst_artifact::Limits::default())
    .unwrap();
    let main = main_bytes(&original, &plans, &policy, &[ro, rx, rw, note, stack]);
    (
        Input {
            program,
            policy,
            original,
            main,
            selection,
            metadata,
            target,
            ledger: b"test compiler plan inventory; W01 remains required".to_vec(),
            heads,
            steps: vec![],
            images: vec![],
        },
        plans,
    )
}
fn main_bytes(
    original: &[u8],
    plans: &[(u64, ArtifactPlan)],
    policy: &Policy,
    old: &[Ph],
) -> Vec<u8> {
    let mut main = original.to_vec();
    for (_, plan) in plans {
        for step in plan.source_steps() {
            let p = step.parts();
            for w in &p.writes {
                let at = (w.address - 0x400000) as usize;
                main[at..at + w.bytes.len()].copy_from_slice(&w.bytes);
            }
            match &p.kind {
                PlanKind::GeneralizedPun(p) => {
                    let at = (p.store.address - 0x400000) as usize;
                    main[at..at + p.store.bytes.len()].copy_from_slice(&p.store.bytes)
                }
                PlanKind::PrefixedPun(p) => {
                    let at = (p.store.address - 0x400000) as usize;
                    main[at..at + p.store.bytes.len()].copy_from_slice(&p.store.bytes)
                }
                PlanKind::Relocation => {}
            }
        }
    }
    let mut loads = Vec::new();
    for (_, plan) in plans {
        for image in plan.images() {
            let off = (main.len() + 4095) & !4095;
            let va = image.address() & !4095;
            let prefix = (image.address() - va) as usize;
            let size = prefix + image.bytes().len();
            main.resize(off + size, 0);
            main[off + prefix..off + size].copy_from_slice(image.bytes());
            loads.push(Ph {
                kind: 1,
                flags: 5,
                off: off as u64,
                va,
                files: size as u64,
                mem: size as u64,
                align: 4096,
            });
        }
    }
    let count = old.len() + loads.len() + 4;
    let carrier = (main.len() + 4095) & !4095;
    let va = 0x30000000u64;
    let delta = va - carrier as u64;
    let interpreter = carrier + count * 56 + 64;
    let str_start = interpreter + policy.interpreter.len() + 1;
    let strings = [&[0][..], policy.bootstrap_dso.as_slice(), &[0]].concat();
    let str_end = str_start + strings.len();
    let sym = (str_end + 7) & !7;
    let hash = (sym + 24 + 3) & !3;
    let dynamic = (hash + 16 + 7) & !7;
    main.resize(dynamic + 112, 0);
    main[interpreter..interpreter + policy.interpreter.len()].copy_from_slice(&policy.interpreter);
    main[str_start..str_end].copy_from_slice(&strings);
    for (i, n) in [1u32, 1, 0, 0].into_iter().enumerate() {
        p32(&mut main, hash + 4 * i, n);
    }
    for (i, (tag, v)) in [
        (1, 1),
        (5, delta + str_start as u64),
        (10, strings.len() as u64),
        (6, delta + sym as u64),
        (11, 24),
        (4, delta + hash as u64),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        p64(&mut main, dynamic + 16 * i, tag);
        p64(&mut main, dynamic + 16 * i + 8, v);
    }
    let mut headers = vec![
        Ph {
            kind: 6,
            flags: 4,
            off: carrier as u64,
            va,
            files: (count * 56) as u64,
            mem: (count * 56) as u64,
            align: 8,
        },
        Ph {
            kind: 3,
            flags: 4,
            off: interpreter as u64,
            va: delta + interpreter as u64,
            files: policy.interpreter.len() as u64 + 1,
            mem: policy.interpreter.len() as u64 + 1,
            align: 1,
        },
    ];
    loads.extend(old.iter().copied().filter(|p| p.kind == 1));
    loads.push(Ph {
        kind: 1,
        flags: 4,
        off: carrier as u64,
        va,
        files: (main.len() - carrier) as u64,
        mem: (main.len() - carrier) as u64,
        align: 4096,
    });
    loads.sort_by_key(|p| p.va);
    headers.extend(loads);
    headers.extend(old.iter().copied().filter(|p| p.kind != 1));
    headers.push(Ph {
        kind: 2,
        flags: 4,
        off: dynamic as u64,
        va: delta + dynamic as u64,
        files: 112,
        mem: 112,
        align: 8,
    });
    assert_eq!(headers.len(), count);
    p64(&mut main, 32, carrier as u64);
    p16(&mut main, 56, count as u16);
    for (i, p) in headers.into_iter().enumerate() {
        record(&mut main, carrier + 56 * i, p);
    }
    main
}
