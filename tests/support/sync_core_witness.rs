//! Required Linux x86-64 capability witness; an unsupported host is a failure.
use liteinst2::sync_core::{SyncCore, SyncCoreError};

pub fn run() {
    const { assert!(cfg!(all(target_os = "linux", target_arch = "x86_64"))) };
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    let capability = SyncCore::prepare().expect("required native sync-core preparation");
    capability
        .synchronize()
        .expect("required native sync-core completion");
    // SAFETY: getpid has no caller preconditions.
    let parent = unsafe { libc::getpid() };
    // SAFETY: this fresh dedicated driver has exactly one thread; the child
    // performs only the capability calls below and exits without unwinding.
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "required fork witness failed");
    if child == 0 {
        // SAFETY: getpid has no caller preconditions.
        let current = unsafe { libc::getpid() };
        let inherited = capability.synchronize();
        if inherited
            != Err(SyncCoreError::DifferentProcess {
                prepared: parent,
                current,
            })
        {
            // SAFETY: terminate only this test child, without parent cleanup.
            unsafe { libc::_exit(21) };
        }
        let fresh = match SyncCore::prepare() {
            Ok(fresh) => fresh,
            Err(_) => unsafe { libc::_exit(22) },
        };
        if fresh.synchronize().is_err() {
            // SAFETY: terminate only this test child.
            unsafe { libc::_exit(23) };
        }
        // SAFETY: child has completed all required checks.
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    loop {
        // SAFETY: child is owned by this driver and status is writable.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        assert_eq!(waited, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINTR)
        );
    }
    assert!(libc::WIFEXITED(status), "child did not exit normally");
    assert_eq!(libc::WEXITSTATUS(status), 0);
    capability
        .synchronize()
        .expect("parent capability remains valid after fork");
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    println!(
        "sync-core capability native: preparation=2 completions=3 inherited_child_refusal=1 child_exit=0 instruction_coherence_qualified=false"
    );
}
