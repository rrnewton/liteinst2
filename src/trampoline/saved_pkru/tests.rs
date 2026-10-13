//! Ordinary exact/non-PKU component-absence controls; never a protected trial.

use super::fixtures::{Mapping, invoke, ospke};
use super::*;
use crate::scanner::InstructionScanner;
use crate::trampoline::TrampolinePlan;
use core::sync::atomic::{AtomicPtr, AtomicUsize};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ABSENCE_ID: &str = "trampoline::saved_pkru::tests::emitted_saved_pkru_component_absence";
const CHILD: &str = "LITEINST2_SAVED_PKRU_CHILD";
static EXACT: AtomicPtr<ExecutableTrampoline> = AtomicPtr::new(core::ptr::null_mut());
static CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn absence_callback(raw: *mut HookContext) {
    let trampoline = unsafe { &*EXACT.load(Ordering::Relaxed) };
    let context = unsafe { &mut *raw };
    let original = context.saved_extended_state();
    assert_eq!(original.mask() & PKRU_XFEATURE, 0);
    assert!(
        unsafe { trampoline.saved_pkru_view(context) }
            .unwrap()
            .is_none()
    );
    assert_eq!(context.saved_extended_state(), original);
    CALLS.fetch_add(1, Ordering::Relaxed);
}

fn absence() {
    let code = [0x0f, 0x05, 0x90, 0x90, 0x90, 0xc3];
    let mapping = Mapping::new(&code);
    let scan = InstructionScanner::default()
        .scan(&code, mapping.address())
        .unwrap();
    let plan = TrampolinePlan::from_scan_replacing_exact_syscall(
        &scan,
        mapping.address(),
        absence_callback,
    )
    .unwrap();
    let trampoline = ExecutableTrampoline::allocate(&plan).unwrap();
    EXACT.store(
        (&trampoline) as *const ExecutableTrampoline as *mut ExecutableTrampoline,
        Ordering::Relaxed,
    );
    invoke(trampoline.address() as usize as *const u8);
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    if !ospke() {
        let ordinary_code = [0x0f, 0x1f, 0x44, 0x00, 0x00, 0xc3];
        let ordinary_mapping = Mapping::new(&ordinary_code);
        let ordinary_scan = InstructionScanner::default()
            .scan(&ordinary_code, ordinary_mapping.address())
            .unwrap();
        let plan = TrampolinePlan::from_scan_replacing_first(
            &ordinary_scan,
            ordinary_mapping.address(),
            absence_callback,
        )
        .unwrap();
        let ordinary = ExecutableTrampoline::allocate(&plan).unwrap();
        EXACT.store(
            (&ordinary) as *const ExecutableTrampoline as *mut ExecutableTrampoline,
            Ordering::Relaxed,
        );
        invoke(ordinary.address() as usize as *const u8);
        assert_eq!(CALLS.load(Ordering::Relaxed), 2);
        println!(
            "PKRU_HARDWARE_ABSENCE ospke=0 ordinary-format={}; no protected positive",
            ordinary.layout().saved_extended_state.format().raw()
        );
    }
    EXACT.store(core::ptr::null_mut(), Ordering::Relaxed);
    println!("PKRU_ABSENCE_COMPLETE exact-component-none=1 protected-positive=0");
}

fn isolated(name: &str, marker: &str, child: fn()) {
    if std::env::var(CHILD).as_deref() == Ok(name) {
        child();
        return;
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut process = command.spawn().unwrap();
    let total = Arc::new(AtomicUsize::new(0));
    let collect = |mut input: Box<dyn Read + Send>| {
        let total = total.clone();
        std::thread::spawn(move || {
            let mut output = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let count = input.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                let before = total.fetch_add(count, Ordering::Relaxed);
                output.extend_from_slice(
                    &buffer[..count.min((64 * 1024_usize).saturating_sub(before))],
                );
            }
            output
        })
    };
    let stdout = collect(Box::new(process.stdout.take().unwrap()));
    let stderr = collect(Box::new(process.stderr.take().unwrap()));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut breach = false;
    let status = loop {
        if let Some(status) = process.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline || total.load(Ordering::Relaxed) > 64 * 1024 {
            unsafe { libc::kill(-(process.id() as i32), libc::SIGKILL) };
            breach = true;
            break process.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    print!("{}", String::from_utf8_lossy(&stdout));
    eprint!("{}", String::from_utf8_lossy(&stderr));
    assert!(
        !breach && total.load(Ordering::Relaxed) <= 64 * 1024,
        "child wall/output breach"
    );
    assert!(status.success(), "{name}: child failed {status}");
    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.lines().any(|line| line.contains(marker)),
        "missing absence completion marker"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "wrong child test selection/count"
    );
}

#[test]
fn emitted_saved_pkru_component_absence() {
    isolated(ABSENCE_ID, "PKRU_ABSENCE_COMPLETE", absence);
}
