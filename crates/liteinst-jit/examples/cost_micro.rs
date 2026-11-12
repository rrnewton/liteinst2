//! Fixture cost micro-benchmark (10-sample benchmark format inputs).
//!
//! Prints CSV: fixture,mode,median_us_per_run,iqr_us,samples,reps
//! Modes: `prepare` (translate+install once), `translate`
//! (translate only, repeated per sample), `jit` (steady-state
//! translated execution, both counters on), `native` (same bytes
//! called directly). Exactly 10 timed samples per cell after one
//! warmup sample; medians and IQRs are over the 10 samples.
//! Fixture-scale only — not a whole-program measurement.

use std::time::Instant;

use liteinst_jit::exec::{Executable, ProcessMemory};
use liteinst_jit::fixtures;
use liteinst_jit::handler::CaptureHandler;
use liteinst_jit::harness::{MappedGuest, RETURN_SENTINEL};
use liteinst_jit::types::{CountProfile, Generation};

const SAMPLES: usize = 10;
/// Bench working-set size (distinct from test parameters, labelled).
const N: u64 = 4096;
const REPS: u64 = 2000;
const TRANSLATE_REPS: u64 = 1000;

fn median_iqr(mut v: Vec<f64>) -> (f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let med = if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    };
    let q = |p: f64| v[((n as f64 - 1.0) * p).round() as usize];
    (med, q(0.75) - q(0.25))
}

fn main() {
    println!("fixture,mode,median_us_per_run,iqr_us,samples,reps_per_sample");
    let data: Vec<u64> = (0..N).collect();
    for name in [
        "sum_loop",
        "branchy_even_sum",
        "call_helper",
        "rip_data",
        "loop_insn",
        "rep_movsb",
    ] {
        let fixture = fixtures::by_name(name);
        let guest = MappedGuest::map(&fixture.bytes).expect("map");
        let region = guest.region(&fixture.bytes, Generation(1));
        let mut dst = vec![0u8; 8192];
        let src: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
        let set_args = |st: &mut liteinst_jit::GuestState, dstp: u64| match name {
            "sum_loop" | "branchy_even_sum" | "call_helper" => {
                st.rdi = data.as_ptr() as u64;
                st.rsi = N;
            }
            "rip_data" => st.rdi = 1,
            "loop_insn" => st.rsi = N,
            "rep_movsb" => {
                st.rdi = dstp;
                st.rsi = src.as_ptr() as u64;
                st.rdx = 8192;
            }
            _ => unreachable!(),
        };

        // prepare: translate + install, fresh Executable per sample.
        let mut times = Vec::new();
        for _ in 0..=SAMPLES {
            let t = Instant::now();
            let e = Executable::prepare(&region, guest.base, CountProfile::BranchesAndInstructions)
                .expect("prepare");
            let dt = t.elapsed().as_secs_f64() * 1e6;
            drop(e);
            times.push(dt);
        }
        let (med, iqr) = median_iqr(times.split_off(1));
        println!("{name},prepare,{med:.3},{iqr:.3},{SAMPLES},1");

        // translate only: block discovery plus emission, without
        // cache install or execution. Generated/data bases sit
        // near the mapped guest so RIP-relative re-encodes stay
        // within rel32 reach.
        let translate_gen_base = guest.base.wrapping_add(0x0010_0000);
        let translate_data_addr = translate_gen_base.wrapping_add(0x0001_0000);
        let mut times = Vec::new();
        for _ in 0..=SAMPLES {
            let t = Instant::now();
            let mut acc: u64 = 0;
            for _ in 0..TRANSLATE_REPS {
                let tr = liteinst_jit::translate::translate(
                    &region,
                    guest.base,
                    CountProfile::BranchesAndInstructions,
                    translate_gen_base,
                    translate_data_addr,
                )
                .expect("translate");
                acc = acc
                    .wrapping_add(tr.code.len() as u64)
                    .wrapping_add(tr.pcmap.len() as u64)
                    .wrapping_add(tr.blocks.len() as u64);
            }
            std::hint::black_box(acc);
            times.push(t.elapsed().as_secs_f64() * 1e6 / TRANSLATE_REPS as f64);
        }
        let (med, iqr) = median_iqr(times.split_off(1));
        println!("{name},translate,{med:.3},{iqr:.3},{SAMPLES},{TRANSLATE_REPS}");

        // jit steady state.
        let mut exec =
            Executable::prepare(&region, guest.base, CountProfile::BranchesAndInstructions)
                .expect("prepare");
        let mut handler = CaptureHandler::default();
        let mut times = Vec::new();
        for _ in 0..=SAMPLES {
            let t = Instant::now();
            let mut acc: u64 = 0;
            for _ in 0..REPS {
                let mut st = guest.initial_state();
                set_args(&mut st, dst.as_mut_ptr() as u64);
                let out = exec
                    .run(st, &mut handler, &ProcessMemory, RETURN_SENTINEL)
                    .expect("jit run");
                acc = acc.wrapping_add(out.state.rax.wrapping_add(out.branches));
            }
            std::hint::black_box(acc);
            times.push(t.elapsed().as_secs_f64() * 1e6 / REPS as f64);
        }
        let (med, iqr) = median_iqr(times.split_off(1));
        println!("{name},jit,{med:.4},{iqr:.4},{SAMPLES},{REPS}");

        // native: call the mapped bytes directly (SysV-compatible
        // fixtures only; rsi carries N where the fixture wants it).
        type F3 = unsafe extern "C" fn(u64, u64, u64) -> u64;
        let f: F3 = unsafe { core::mem::transmute(guest.base as usize) };
        let mut times = Vec::new();
        for _ in 0..=SAMPLES {
            let t = Instant::now();
            let mut acc: u64 = 0;
            for _ in 0..REPS {
                let r = match name {
                    "sum_loop" | "branchy_even_sum" | "call_helper" => unsafe {
                        f(data.as_ptr() as u64, N, 0)
                    },
                    "rip_data" => unsafe { f(1, 0, 0) },
                    "loop_insn" => unsafe { f(0, N, 0) },
                    "rep_movsb" => unsafe { f(dst.as_mut_ptr() as u64, src.as_ptr() as u64, 8192) },
                    _ => unreachable!(),
                };
                acc = acc.wrapping_add(r);
            }
            std::hint::black_box(acc);
            times.push(t.elapsed().as_secs_f64() * 1e6 / REPS as f64);
        }
        let (med, iqr) = median_iqr(times.split_off(1));
        println!("{name},native,{med:.4},{iqr:.4},{SAMPLES},{REPS}");
    }
}
