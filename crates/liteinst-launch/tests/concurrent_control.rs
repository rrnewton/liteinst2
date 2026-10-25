#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use liteinst_launch::publication::PublicationStop;
use liteinst_launch::{
    ExecCheckpoint, FIXED_CLONE_FLAGS, LaunchCommand, LaunchError, ProcessEvent, SharedMmProcess,
    SignalStop,
};
use liteinst2::contracts::{AddressRange, CodeIdentity, SourceIdentity};

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const WORKER: u64 = BASE + 2 * PAGE as u64;
const TIMEOUT: Duration = Duration::from_secs(2);
static NEXT: AtomicUsize = AtomicUsize::new(0);
// A concurrent fork must not inherit another fixture's writable executable FD.
// This serializes only file creation and fork/exec, never worker execution.
static EXEC_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    path: PathBuf,
    freeze: u64,
}

impl Fixture {
    fn new() -> Self {
        let mut image = vec![0; 5 * PAGE];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut image, 16, 2);
        put16(&mut image, 18, 62);
        put32(&mut image, 20, 1);
        put64(&mut image, 24, BASE + PAGE as u64);
        put64(&mut image, 32, 64);
        put16(&mut image, 52, 64);
        put16(&mut image, 54, 56);
        put16(&mut image, 56, 2);
        load(&mut image, 64, 0, BASE, 3 * PAGE, 5);
        load(
            &mut image,
            120,
            3 * PAGE,
            BASE + 3 * PAGE as u64,
            2 * PAGE,
            6,
        );
        let mut code = Vec::new();
        for worker in 0..2 {
            code.push(0xb8);
            code.extend_from_slice(&(libc::SYS_clone as u32).to_le_bytes());
            code.push(0xbf);
            code.extend_from_slice(&(FIXED_CLONE_FLAGS as u32).to_le_bytes());
            code.push(0xbe);
            code.extend_from_slice(&((BASE + (4 + worker) * PAGE as u64) as u32).to_le_bytes());
            code.extend_from_slice(&[
                0x31, 0xd2, 0x45, 0x31, 0xd2, 0x45, 0x31, 0xc0, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x0f,
                0x84,
            ]);
            let next_pc = BASE + PAGE as u64 + code.len() as u64 + 4;
            code.extend_from_slice(&((WORKER as i64 - next_pc as i64) as i32).to_le_bytes());
        }
        let freeze = BASE + PAGE as u64 + code.len() as u64;
        code.push(0xcc);
        image[PAGE..PAGE + code.len()].copy_from_slice(&code);
        image[2 * PAGE..2 * PAGE + 2].copy_from_slice(&[0x0f, 0x0b]);
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-tmp");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!(
            "group-control-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _exec = EXEC_LOCK.lock().unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
            .unwrap();
        file.write_all(&image).unwrap();
        Self { path, freeze }
    }

    fn register(&self) -> SharedMmProcess {
        let exec = EXEC_LOCK.lock().unwrap();
        let checkpoint = ExecCheckpoint::launch(&LaunchCommand::new(&self.path), TIMEOUT).unwrap();
        drop(exec);
        let mut process = checkpoint.into_stopped_process(TIMEOUT).unwrap();
        process.gate_initial_images(TIMEOUT).unwrap();
        process
            .hold()
            .unwrap()
            .mprotect(
                BASE + PAGE as u64,
                PAGE,
                libc::PROT_READ | libc::PROT_EXEC,
                TIMEOUT,
            )
            .unwrap();
        // SAFETY: this immutable handcrafted image has the exact checked clone
        // factory and distinct RW/NX stacks; all worker and other code is NX.
        unsafe { SharedMmProcess::register(process, 2, self.freeze, TIMEOUT).unwrap() }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_file(&self.path).unwrap();
    }
}
fn put16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(image: &mut [u8], offset: usize, value: u64) {
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn load(image: &mut [u8], header: usize, offset: usize, address: u64, size: usize, flags: u32) {
    put32(image, header, 1);
    put32(image, header + 4, flags);
    put64(image, header + 8, offset as u64);
    put64(image, header + 16, address);
    put64(image, header + 32, size as u64);
    put64(image, header + 40, size as u64);
    put64(image, header + 48, PAGE as u64);
}

fn first_faults(group: &mut SharedMmProcess) -> Vec<(libc::pid_t, SignalStop)> {
    // A newly cloned task can report its authenticated clone syscall exit
    // before executing its branch; no application syscall is advanced here.
    for _ in 0..3 {
        let events = group.resume_workers_until_all_stopped(TIMEOUT).unwrap();
        let mut faults = Vec::new();
        for event in events {
            match event.event {
                ProcessEvent::Signal(signal) => {
                    assert_eq!(
                        (signal.signal, signal.code, signal.instruction_pointer),
                        (libc::SIGSEGV, 2, WORKER)
                    );
                    faults.push((event.tid, signal));
                }
                ProcessEvent::SyscallExit {
                    result: 0,
                    is_error: false,
                } => {}
                other => panic!("unexpected initial worker event: {other:?}"),
            }
        }
        if !faults.is_empty() {
            assert_eq!(faults.len(), 2);
            return faults;
        }
    }
    panic!("workers did not reach their first NX fetch");
}

fn assert_reaped(tids: &[libc::pid_t]) {
    for &tid in tids {
        let mut status = 0;
        // SAFETY: only formerly owned, terminated TIDs are queried.
        let result = unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
        assert_eq!(result, -1, "owned task remains waitable");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(!PathBuf::from(format!("/proc/{tid}")).exists());
    }
}

fn identity() -> CodeIdentity {
    CodeIdentity {
        source: SourceIdentity([19; 32]),
        mapping: 1,
        generation: 1,
    }
}

#[test]
fn group_publication_holds_every_real_task_and_preserves_complete_state() {
    let fixture = Fixture::new();
    let mut group = fixture.register();
    let tgid = group.pid();
    let tids = group.task_ids();
    assert_eq!(tids.len(), 3);
    let faults = first_faults(&mut group);
    let mut states = Vec::new();
    for &tid in &tids {
        let stop = group.hold_for(tid).unwrap();
        states.push((
            tid,
            stop.read_registers().unwrap(),
            stop.read_xstate().unwrap(),
        ));
    }
    let selected = faults[0].0;
    {
        let mut stop = group.hold_for(selected).unwrap();
        assert_eq!(stop.pid(), tgid);
        assert_eq!(stop.task_id(), selected);
        assert!(stop.acknowledge_owned_signal(&faults[1].1).is_err());
        stop.acknowledge_owned_signal(&faults[0].1).unwrap();
        // SAFETY: this complete fixture mm has no aliases or external users;
        // all entry/resume facts are fixed and every actual thread is held.
        unsafe {
            stop.with_publication_lease(
                identity(),
                vec![
                    AddressRange::new(WORKER, PAGE).unwrap(),
                    AddressRange::new(0x60000000, PAGE).unwrap(),
                ],
                |ops, lease| {
                    assert_eq!(lease.identity(), identity());
                    assert_eq!(ops.pid(), tgid);
                    for &(tid, registers, _) in &states {
                        let mut raw = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
                        // SAFETY: this reads one registered traced task's GPRs. A
                        // running task cannot satisfy GETREGS, independently checking
                        // actual held exclusion through the narrow lease callback.
                        assert_eq!(
                            libc::ptrace(
                                libc::PTRACE_GETREGS,
                                tid,
                                std::ptr::null_mut::<libc::c_void>(),
                                raw.as_mut_ptr()
                            ),
                            0
                        );
                        assert_eq!(
                            liteinst_launch::RegisterSnapshot::from(raw.assume_init()),
                            registers
                        );
                    }
                    ops.mprotect(WORKER, PAGE, libc::PROT_READ | libc::PROT_WRITE, TIMEOUT)?;
                    ops.exact_store_checked(WORKER, &[0x0f], &[0x90], TIMEOUT)?;
                    assert!(
                        ops.exact_store_checked(WORKER, &[0x0f], &[0xcc], TIMEOUT)
                            .is_err()
                    );
                    assert_eq!(ops.read_memory(WORKER, 2)?, [0x90, 0x0b]);
                    let image = vec![0xcc; PAGE];
                    assert_eq!(
                        ops.map_private_code(0x60000000, &image, TIMEOUT)?,
                        0x60000000..0x60001000
                    );
                    ops.mprotect(WORKER, PAGE, libc::PROT_READ | libc::PROT_EXEC, TIMEOUT)?;
                    ops.sync_core(TIMEOUT)
                },
            )
        }
        .unwrap();
    }
    for (tid, registers, extended) in states {
        let stop = group.hold_for(tid).unwrap();
        assert_eq!(
            stop.read_registers().unwrap(),
            registers,
            "GPR change in task {tid}"
        );
        assert_eq!(
            stop.read_xstate().unwrap(),
            extended,
            "XSTATE change in task {tid}"
        );
    }
    group.terminate().unwrap();
    assert_reaped(&tids);
}

#[test]
fn group_lease_errors_poison_and_unwinds_reap_every_task() {
    struct ResultWithDrop {
        panic_on_drop: bool,
    }
    impl Drop for ResultWithDrop {
        fn drop(&mut self) {
            if self.panic_on_drop {
                panic!("injected group result destructor unwind");
            }
        }
    }
    let fixture = Fixture::new();
    for failure in 0..4 {
        let mut group = fixture.register();
        let tids = group.task_ids();
        let faults = first_faults(&mut group);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut stop = group.hold_for(faults[0].0).unwrap();
            stop.acknowledge_owned_signal(&faults[0].1).unwrap();
            // SAFETY: this exclusively owned complete fixture has no outside
            // accesses. The actual group remains held across each failure.
            unsafe {
                stop.with_publication_lease(
                    identity(),
                    vec![
                        AddressRange::new(WORKER, PAGE).unwrap(),
                        AddressRange::new(0x60000000, PAGE).unwrap(),
                    ],
                    |ops, lease| {
                        ops.map_private_code(0x60000000, &vec![0; PAGE], TIMEOUT)?;
                        match failure {
                            0 => {
                                lease.poison();
                                Err(LaunchError::Invalid("injected group publication error"))
                            }
                            1 => {
                                lease.poison();
                                Ok(ResultWithDrop {
                                    panic_on_drop: false,
                                })
                            }
                            2 => panic!("injected group publication unwind"),
                            _ => {
                                lease.poison();
                                Ok(ResultWithDrop {
                                    panic_on_drop: true,
                                })
                            }
                        }
                    },
                )
            }
        }));
        match outcome {
            Ok(result) => match failure {
                0 => assert!(matches!(
                    result,
                    Err(LaunchError::Invalid("injected group publication error"))
                )),
                1 => assert!(matches!(
                    result,
                    Err(LaunchError::Invalid(
                        "core group publication lease remained poisoned"
                    ))
                )),
                _ => panic!("group lease swallowed unwind"),
            },
            Err(_) => assert!(failure >= 2),
        }
        assert!(group.hold_for(faults[0].0).is_err());
        assert_reaped(&tids);
    }
}

#[test]
fn unacknowledged_worker_fault_refuses_trusted_execution_and_group_resume() {
    let fixture = Fixture::new();
    let mut group = fixture.register();
    let tids = group.task_ids();
    let faults = first_faults(&mut group);
    assert!(
        group
            .hold_for(faults[0].0)
            .unwrap()
            .sync_core(TIMEOUT)
            .is_err()
    );
    assert!(matches!(
        group.resume_workers_until_all_stopped(TIMEOUT),
        Err(LaunchError::Invalid("worker signal is not acknowledged"))
    ));
    assert_reaped(&tids);
}
