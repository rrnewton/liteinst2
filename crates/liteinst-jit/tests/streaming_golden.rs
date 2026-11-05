//! Golden-emission proof for S3-A streaming-decoder reuse.
//!
//! The constants below were captured from the pre-streaming
//! implementation at the S3-A branch base. This integration target
//! deliberately runs after the O1 oracle target so the required
//! mutation chains keep seeing their semantic assertions first;
//! the golden hashes are an additional byte-identity guard, not a
//! replacement kill attribution for those mutants.

use liteinst_jit::fixtures;
use liteinst_jit::translate::{Translation, translate};
use liteinst_jit::types::{CountProfile, Generation, RegionFacts};

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
    let cases: &[(&str, u64)] = &[
        ("sum_loop", 0x7e5c_5b3d_7321_6795),
        ("branchy_even_sum", 0x0a5a_f7e7_f3fa_453f),
        ("flags_adc", 0x2d92_ca28_0452_24e1),
        ("call_helper", 0x3cf4_4083_d71e_d9d1),
        ("rip_data", 0x281b_f55a_e9f4_65d0),
        ("loop_insn", 0xb60a_7a68_7b6a_4073),
        ("syscall_write", 0x484e_5ea6_d0f8_ffa7),
        ("cpuid_leaf", 0x6e72_991d_2632_07d6),
    ];
    let actual: Vec<(&str, u64)> = cases
        .iter()
        .map(|&(name, _)| {
            let fix = fixtures::by_name(name);
            let region = RegionFacts {
                base: 0x10_0000,
                bytes: fix.bytes,
                generation: Generation(1),
                immutable_private: true,
            };
            let t = translate(
                &region,
                0x10_0000,
                CountProfile::BranchesAndInstructions,
                0x80_0000,
                0x81_0000,
            )
            .unwrap_or_else(|e| panic!("{name} must translate for golden hash: {e:?}"));
            (name, translation_golden_hash(&t))
        })
        .collect();
    assert_eq!(actual, cases);
}
