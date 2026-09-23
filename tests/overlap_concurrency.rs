#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use liteinst2::patcher::{JumpPatchPlan, LiveJumpPatch, PatchError, StalenessBudget};
use liteinst2::scanner::InstructionScanner;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

const TEST: &str = "three_overlapping_envelopes_allow_only_complete_executions";
const CHILD: &str = "LITEINST_OVERLAP_CONCURRENCY_CHILD";
const ITERATIONS: u64 = 2_000;
const OFFSETS: [usize; 3] = [23, 28, 33];
const TARGETS: [usize; 3] = [128, 144, 160];

fn retry<T>(mut operation: impl FnMut() -> Result<T, PatchError>) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match operation() {
            Ok(value) => return value,
            Err(PatchError::Contended) if Instant::now() < deadline => thread::yield_now(),
            Err(error) => panic!("publication failed: {error}"),
        }
    }
}

fn body() {
    let name = c"liteinst2-overlap-chain";
    // SAFETY: all mappings cover the single page and intentionally remain live.
    let (writable, executable) = unsafe {
        let fd = libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC);
        assert!(fd >= 0);
        assert_eq!(libc::ftruncate(fd, 4096), 0);
        let writable = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        let executable = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED,
            fd,
            0,
        );
        assert_ne!(writable, libc::MAP_FAILED);
        assert_ne!(executable, libc::MAP_FAILED);
        assert_eq!(libc::close(fd), 0);
        (writable as usize, executable as usize)
    };
    let mut code = [0x90_u8; 192];
    code[19..23].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]); // ENDBR64
    code[23..28].copy_from_slice(&[0xb8, 1, 0, 0, 0]); // MOV eax,1
    code[28..33].copy_from_slice(&[0x05, 2, 0, 0, 0]); // ADD eax,2
    code[33..38].copy_from_slice(&[0x05, 4, 0, 0, 0]); // ADD eax,4
    code[38] = 0xc3;
    for index in 0..3 {
        let target = TARGETS[index];
        code[target..target + 5].copy_from_slice(&[
            if index == 0 { 0xb8 } else { 0x05 },
            8 << index,
            0,
            0,
            0,
        ]);
        code[target + 5] = 0xe9;
        let displacement = (OFFSETS[index] + 5) as i32 - (target + 10) as i32;
        code[target + 6..target + 10].copy_from_slice(&displacement.to_le_bytes());
    }
    // SAFETY: no reader or writer exists until the fixture has been initialized.
    unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), writable as *mut u8, code.len()) };
    let scanner = InstructionScanner::default();
    let scan = scanner.scan(&code, executable as u64).unwrap();
    let plans: Vec<_> = (0..3)
        .map(|index| {
            JumpPatchPlan::from_scan(
                &scanner,
                &scan,
                &code,
                executable as u64,
                (executable + OFFSETS[index]) as u64,
                (executable + TARGETS[index]) as u64,
            )
            .unwrap()
        })
        .collect();
    // SAFETY: the fixture is an ENDBR64-prefixed leaf with the System V ABI.
    let function: extern "C" fn() -> u32 = unsafe { std::mem::transmute(executable + 19) };
    assert_eq!(function(), 7);
    let barrier = Arc::new(Barrier::new(8)); // three writers, four readers, parent
    let stop = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicU64::new(0));
    let writes = Arc::new(AtomicU64::new(0));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let barrier = Arc::clone(&barrier);
        let stop = Arc::clone(&stop);
        let calls = Arc::clone(&calls);
        readers.push(thread::spawn(move || {
            barrier.wait();
            let mut local = 0;
            loop {
                let observed = function();
                assert!(
                    [7, 14, 21, 28, 35, 42, 49, 56].contains(&observed),
                    "torn execution: {observed}"
                );
                local += 1;
                if stop.load(Ordering::Acquire) {
                    break;
                }
            }
            calls.fetch_add(local, Ordering::Relaxed);
            local
        }));
    }
    let mut writers = Vec::new();
    for (index, plan) in plans.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        let writes = Arc::clone(&writes);
        writers.push(thread::spawn(move || {
            // SAFETY: aliases remain live; registration coordinates all writers.
            let patch = retry(|| unsafe {
                LiveJumpPatch::bind(
                    plan.clone(),
                    (writable + OFFSETS[index]) as *mut u8,
                    StalenessBudget::new(1).unwrap(),
                )
            });
            barrier.wait();
            for _ in 0..ITERATIONS {
                // SAFETY: only registered writers modify these envelopes.
                retry(|| unsafe { patch.apply() });
                retry(|| unsafe { patch.revert() });
                writes.fetch_add(2, Ordering::Relaxed);
            }
        }));
    }
    barrier.wait();
    for writer in writers {
        writer.join().unwrap();
    }
    stop.store(true, Ordering::Release);
    for reader in readers {
        assert!(reader.join().unwrap() > 0);
    }
    assert_eq!(writes.load(Ordering::Relaxed), 3 * 2 * ITERATIONS);
    assert!(calls.load(Ordering::Relaxed) >= 4);
    assert_eq!(function(), 7);
    // SAFETY: every worker has joined; inspect complete restoration and canaries.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(writable as *const u8, code.len()) },
        code
    );
    println!(
        "overlap-chain-receipt writers=3 writes=12000 readers=4 calls={}",
        calls.load(Ordering::Relaxed)
    );
}

#[test]
fn three_overlapping_envelopes_allow_only_complete_executions() {
    if std::env::var(CHILD).as_deref() == Ok(TEST) {
        body();
        return;
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--nocapture"])
        .env(CHILD, TEST)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the post-fork closure only installs a bounded resource limit.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "overlap child timed out: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "status={}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout
            .matches("overlap-chain-receipt writers=3 writes=12000 readers=4 calls=")
            .count(),
        1,
        "missing body receipt: {stdout}"
    );
    assert!(
        stdout.contains("1 passed; 0 failed"),
        "missing exact test receipt: {stdout}"
    );
    print!("{stdout}");
}
