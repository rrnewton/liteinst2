//! Standalone P1a driver: runs the corpus-v1 fixtures through the
//! translator and prints software counts. This is a bounded-fixture
//! driver, not a whole-program runner.

use liteinst_jit::exec::{Executable, ProcessMemory, RunError};
use liteinst_jit::fixtures;
use liteinst_jit::handler::CaptureHandler;
use liteinst_jit::harness::{MappedGuest, RETURN_SENTINEL};
use liteinst_jit::types::{CountProfile, Generation};

fn main() -> std::process::ExitCode {
    let data: Vec<u64> = (0..16).collect();
    let mut failures = 0;
    for fixture in fixtures::all() {
        let guest = match MappedGuest::map(&fixture.bytes) {
            Ok(g) => g,
            Err(e) => {
                println!("{}: MAP-FAIL {e}", fixture.name);
                failures += 1;
                continue;
            }
        };
        let region = guest.region(&fixture.bytes, Generation(1));
        guest.plant_below_rsp(liteinst_jit::harness::REDZONE_MARKER);
        let expected = match fixture.name {
            "indirect_jmp" | "rdtsc_exit" => "REFUSED",
            "fault_ret" => "FAULT",
            _ => "OK",
        };
        let mut exec =
            match Executable::prepare(&region, guest.base, CountProfile::BranchesAndInstructions) {
                Ok(e) => e,
                Err(e) => {
                    println!("{}: REFUSED {e}", fixture.name);
                    if expected != "REFUSED" {
                        failures += 1;
                    }
                    continue;
                }
            };
        let mut dst = vec![0u8; 32];
        let src: Vec<u8> = (0..32u8).collect();
        let mut state = guest.initial_state();
        let (rdi, rsi, rdx, rax, rcx) = MappedGuest::fixture_args(
            fixture.name,
            guest.base,
            data.as_ptr() as u64,
            dst.as_mut_ptr() as u64,
            src.as_ptr() as u64,
        );
        state.rdi = rdi;
        state.rsi = rsi;
        state.rdx = rdx;
        state.rax = rax;
        state.rcx = rcx;
        let mut handler = CaptureHandler::default();
        let actual = match exec.run(state, &mut handler, &ProcessMemory, RETURN_SENTINEL) {
            Ok(out) => {
                println!(
                    "{}: OK rax={} branches={} instructions={} exits={}",
                    fixture.name, out.state.rax as i64, out.branches, out.instructions, out.exits
                );
                "OK"
            }
            Err(RunError::Refuse(r)) => {
                println!("{}: REFUSED {r}", fixture.name);
                "REFUSED"
            }
            Err(RunError::Fault(f)) => {
                println!(
                    "{}: FAULT src={:#x} addr={:#x} sig={} branches={} instructions={}",
                    fixture.name, f.src_pc, f.addr, f.signum, f.branches, f.instructions
                );
                "FAULT"
            }
        };
        if actual != expected {
            println!(
                "{}: MISMATCH expected {expected} got {actual}",
                fixture.name
            );
            failures += 1;
        }
        if fixture.name == "rep_movsb" && dst != src {
            println!("rep_movsb: BUFFER MISMATCH");
            failures += 1;
        }
        if fixture.name == "syscall_write" && handler.written != src[..5] {
            println!("syscall_write: CAPTURE MISMATCH {:?}", handler.written);
            failures += 1;
        }
    }
    if failures == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
