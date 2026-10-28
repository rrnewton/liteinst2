#![cfg(all(target_os="linux",target_arch="x86_64"))]
//! Additive dynamic-ELF reference generator; no existing test is replaced.
use liteinst_admission::scan::{Policy,SiteClass};
use liteinst_launch::gate::{ImageFacts,SelectedCompletion,SelectedEvent,SelectedExecution,SelectedMetrics,SelectedPageGate};
use liteinst_launch::selected::{InstructionProvider,ProviderDecision,SelectedInput,SelectedResult,SemanticsError,SyscallAliases,SyscallResult};
use liteinst_launch::{ExecCheckpoint,LaunchCommand,RegisterSnapshot};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;
const TIMEOUT:Duration=Duration::from_secs(3);
const STEP_BUDGET:usize=128;
static FILE_FORK:Mutex<()>=Mutex::new(());
#[path="support/b2_dynamic_reference/image.rs"] mod image;
// These four source files are consumed directly, byte-for-byte. In particular
// raw::run keeps full RegisterSnapshot, NT_X86_XSTATE, mask and memory equality.
#[path="support/b2_reference/model.rs"] mod model;
#[path="support/b2_reference/raw.rs"] mod raw;
#[path="support/b2_reference/cases.rs"] mod cases;
#[path="support/b2_reference/checks.rs"] mod checks;
#[path="support/b2_dynamic_reference/record.rs"] mod record;
use image::{BASE,Builder,DATA,DATA_LEN,FLAGS,Fixture,MASK,PAGE,STACK};
use model::{Reply,Row,State,Trace};
use checks::{Replay,check_completion,check_metrics,rethrow};

// This additive corpus starts in the C native-page profile's exact application
// signal domain. The original SIGUSR1-only static tests/MaskGuard remain exact.
struct ApplicationMask(u64);
impl ApplicationMask {
    fn new()->Self {
        let mut old=0_u64;let chosen=MASK;
        assert_eq!(unsafe {libc::syscall(libc::SYS_rt_sigprocmask,libc::SIG_SETMASK,
            &raw const chosen,&raw mut old,8_usize)},0);
        let guard=Self(old);let mut actual=0_u64;
        assert_eq!(unsafe {libc::syscall(libc::SYS_rt_sigprocmask,libc::SIG_SETMASK,
            std::ptr::null::<u64>(),&raw mut actual,8_usize)},0);
        assert_eq!(actual,MASK);guard
    }
}
impl Drop for ApplicationMask {
    fn drop(&mut self) {
        let mut actual=0_u64;
        let restored=unsafe {libc::syscall(libc::SYS_rt_sigprocmask,libc::SIG_SETMASK,
            &raw const self.0,std::ptr::null_mut::<u64>(),8_usize)};
        let read=unsafe {libc::syscall(libc::SYS_rt_sigprocmask,libc::SIG_SETMASK,
            std::ptr::null::<u64>(),&raw mut actual,8_usize)};
        if restored!=0 || read!=0 || actual!=self.0 {std::process::abort();}
    }
}

fn reference(case:&cases::Case) {
    let fixture=&case.fixture;
    let mut strict=raw::Raw::launch(fixture);
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let expected=model::interpret(fixture,strict.state(),&case.replies,STEP_BUDGET).unwrap();
        let observed=strict.run(fixture,&case.replies,STEP_BUDGET).unwrap();
        assert_eq!(observed,expected,"complete raw strict-block trajectory");
        case.check_trace(&observed); observed
    }));
    strict.finish(); let expected=rethrow(result);
    let checkpoint={ let _fork=FILE_FORK.lock().unwrap();let _mask=ApplicationMask::new();
        ExecCheckpoint::launch(&LaunchCommand::new(&fixture.path),TIMEOUT).unwrap() };
    let facts=vec![fixture.facts(),fixture.interpreter_facts(&checkpoint)];
    // SAFETY: generated immutable private RX images, complete literal heads
    // including alternate entries, singleton, fixed RW/NX data/stack, no signal
    // sender, aliases or source-as-data. No code may enter the private island.
    let mut gate=unsafe {
        if case.covered { SelectedPageGate::new_with_coverage(checkpoint,facts,Policy::default(),
            SyscallAliases::new(),Replay::new(&expected.rows),TIMEOUT,Default::default()) }
        else { SelectedPageGate::new(checkpoint,facts,Policy::default(),SyscallAliases::new(),
            Replay::new(&expected.rows),TIMEOUT) }
    }.unwrap();
    let pin=raw::pin(gate.pid());
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(gate.read_memory(BASE,fixture.bytes.len()).unwrap(),fixture.bytes);
        raw::nx(gate.pid(),&pin,BASE+PAGE as u64);
        for row in &expected.rows {
            let SelectedEvent::Completed(done)=gate.next_event().unwrap() else { panic!("incomplete explicit-trap reference") };
            check_completion(&done,row);
            let actual=State {registers:gate.read_registers().unwrap(),xstate:gate.read_xstate().unwrap(),
                mask:raw::held_mask(gate.pid(),&pin),data:gate.read_memory(DATA,DATA_LEN).unwrap()};
            assert_eq!(actual,row.after,"full explicit-trap frame, XSTATE, mask and memory");
        }
        assert_eq!(gate.provider().calls,case.replies.len()); check_metrics(gate.metrics(),&expected.rows);
        assert_eq!(gate.gate_metrics().collateral_completions,case.collateral);
    }));
    drop(gate);raw::reaped(&pin);rethrow(result);
    record::write(case,&expected);
}

#[test]
fn dynamic_five_trajectory_reference_boundary() {
    // All five original case constructors and their literal assertions execute.
    let cases=[cases::masked(),cases::timestamps(),cases::prefixed(),cases::embedded(),cases::cross_page()];
    assert_eq!(cases.iter().map(|c|c.replies.len()).sum::<usize>(),17);
    for case in &cases { reference(case); }
    println!("LI2_B2_DYNAMIC_REFERENCE programs=5 selected_per_lane=17 raw_processes=5 trap_processes=5 model_passes=5");
}
