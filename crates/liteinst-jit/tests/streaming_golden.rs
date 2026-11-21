//! Golden-emission proof for S3-A streaming-decoder reuse.
//!
//! The constants below were captured from the pre-streaming
//! implementation at the S3-A branch base. This integration target
//! deliberately runs after the O1 oracle target so the required
//! mutation chains keep seeing their semantic assertions first;
//! the golden hashes are an additional byte-identity guard, not a
//! replacement kill attribution for those mutants.
//!
//! P1b.1 adds five cases, each captured from the base tree (before
//! P1b.1) and proven equal to base emission in-run: the three
//! indirect fixtures, `indirect_jmp` under the remote trap style,
//! and `sum_loop` with budget stubs. Closure retranslation must not
//! change emission for a translation's one-root set.

use liteinst_jit::fixtures;
use liteinst_jit::translate::{
    ExitStyle, TranslateOptions, Translation, translate, translate_with_exit_style,
    translate_with_options,
};
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};

/// How a golden case is emitted.
#[derive(Clone, Copy)]
enum Emit {
    /// `translate`: the in-process return style.
    Default,
    /// The remote `TrapToDispatcher` style.
    Trap,
    /// Budget stubs on (`TranslateOptions::rcb_budget`).
    Budget,
}

fn fnv_mix(h: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *h ^= u64::from(b);
        *h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

fn mix_u64(h: &mut u64, v: u64) {
    fnv_mix(h, &v.to_le_bytes());
}

fn mix_debug<T: core::fmt::Debug>(h: &mut u64, v: &T) {
    fnv_mix(h, format!("{v:?}").as_bytes());
    fnv_mix(h, b"\n");
}

fn translation_golden_hash(t: &Translation) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    mix_u64(&mut h, t.entry_src);
    mix_u64(&mut h, t.gen_base);
    mix_u64(&mut h, t.code.len() as u64);
    fnv_mix(&mut h, &t.code);
    for (&src, &generated) in &t.block_gen {
        mix_u64(&mut h, src);
        mix_u64(&mut h, generated);
    }
    for e in t.pcmap.entries() {
        mix_u64(&mut h, e.gen_start);
        mix_u64(&mut h, e.gen_end);
        mix_u64(&mut h, e.src_pc);
        mix_debug(&mut h, &e.phase);
        mix_debug(&mut h, &e.recovery);
    }
    for (&start, b) in &t.blocks {
        mix_u64(&mut h, start);
        mix_u64(&mut h, b.start);
        mix_debug(&mut h, &b.terminator);
        for insn in b.insns.iter().chain(b.term.iter()) {
            mix_u64(&mut h, insn.pc);
            mix_u64(&mut h, insn.len as u64);
            mix_debug(&mut h, &insn.class);
            mix_debug(&mut h, &insn.instruction);
        }
    }
    h
}

#[test]
fn streaming_translation_matches_golden_emission() {
    // S3-A is a decoder-reuse change only: emitted bytes, PC
    // maps, block layout, and decoded terminators for these
    // representative fixtures must remain byte-identical to
    // the pre-streaming implementation captured by these
    // golden hashes.
    // (case, emission, golden); the fixture is the case name before
    // any '/'. The last five are P1b.1's base-captured cases (see
    // the module doc).
    let cases: &[(&str, Emit, u64)] = &[
        ("sum_loop", Emit::Default, 0x7e5c_5b3d_7321_6795),
        ("branchy_even_sum", Emit::Default, 0x0a5a_f7e7_f3fa_453f),
        ("flags_adc", Emit::Default, 0x2d92_ca28_0452_24e1),
        ("call_helper", Emit::Default, 0x3cf4_4083_d71e_d9d1),
        ("rip_data", Emit::Default, 0x281b_f55a_e9f4_65d0),
        ("loop_insn", Emit::Default, 0xb60a_7a68_7b6a_4073),
        ("syscall_write", Emit::Default, 0x484e_5ea6_d0f8_ffa7),
        ("cpuid_leaf", Emit::Default, 0x6e72_991d_2632_07d6),
        // The five values below are the base tree's GOLDEN lines,
        // captured before P1b.1 (run A, 2026-11-20).
        ("indirect_jmp", Emit::Default, 0x3bee_e988_bb4c_4ec2),
        ("indirect_call", Emit::Default, 0x330b_4086_1a65_1ec6),
        ("jump_table", Emit::Default, 0xf6a3_91c5_6b08_917c),
        ("indirect_jmp/trap", Emit::Trap, 0x4b37_fad7_a580_479d),
        ("sum_loop/budget", Emit::Budget, 0x209b_f0c1_2f62_49e5),
    ];
    let (base, gen_base, data) = (0x10_0000u64, 0x80_0000u64, 0x81_0000u64);
    let profile = CountProfile::BranchesAndInstructions;
    let actual: Vec<(&str, u64)> = cases
        .iter()
        .map(|&(case, emit, _)| {
            let name = case.split('/').next().unwrap_or(case);
            let fix = fixtures::by_name(name);
            let region = RegionFacts {
                base,
                bytes: fix.bytes,
                generation: Generation(1),
                immutable_private: true,
            };
            let t = match emit {
                Emit::Default => translate(&region, base, profile, gen_base, data),
                Emit::Trap => translate_with_exit_style(
                    &region,
                    base,
                    profile,
                    gen_base,
                    data,
                    ExitStyle::TrapToDispatcher,
                ),
                Emit::Budget => translate_with_options(
                    &region,
                    base,
                    profile,
                    gen_base,
                    data,
                    TranslateOptions {
                        exit_style: ExitStyle::ReturnToDispatcher,
                        rcb_budget: true,
                    },
                ),
            }
            .unwrap_or_else(|e| panic!("{case} must translate for golden hash: {e:?}"));
            (case, translation_golden_hash(&t))
        })
        .collect();
    // Every case's value first (the base capture reads these), then
    // one assertion per case, naming it.
    for (case, got) in &actual {
        println!("GOLDEN\t{case}\t{got:#018x}");
    }
    for (&(case, _, want), &(_, got)) in cases.iter().zip(&actual) {
        assert_eq!(
            got, want,
            "golden mismatch: case={case}, got {got:#018x}, want {want:#018x}"
        );
    }
}
