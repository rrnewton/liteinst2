//! Byte and ownership controls for the opt-in compiled-DSO witness. These
//! compile the producer helpers but never compile C, load a DSO, call a hook or
//! claim native unwind qualification. Native build/caller/consumer admission
//! remains a separately invoked campaign.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

// Runtime-only helper entrypoints are intentionally not invoked by this suite.
// Keeping their bodies compiled here catches API drift before native admission.
#[allow(dead_code)]
#[path = "../examples/indexed_dso_support/caller.rs"]
mod caller;
#[allow(dead_code)]
#[path = "../examples/indexed_dso_support/elf.rs"]
mod elf;
#[allow(dead_code)]
#[path = "../../unwind-oracle/consumer.rs"]
mod indexed_consumer;
#[allow(dead_code)]
#[path = "../examples/indexed_dso_support/leaf.rs"]
mod leaf;
#[allow(dead_code)]
#[path = "../examples/indexed_dso_support/observations.rs"]
mod observations;
#[allow(dead_code)]
#[path = "../examples/indexed_dso_support/prepare.rs"]
mod prepare;

#[test]
fn snapshot_refuses_a_fifo_without_waiting_for_a_writer() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SERIAL: AtomicU64 = AtomicU64::new(0);
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = (0..32)
        .find_map(|_| {
            let path = std::env::temp_dir().join(format!(
                "li2-indexed-fifo-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => Some(Scratch(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => panic!("create owned FIFO fixture: {error}"),
            }
        })
        .expect("bounded exclusive FIFO fixture directory");
    let fifo = directory.0.join("no-writer");
    let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: the NUL-terminated path is retained through the syscall and names
    // a new member of this test's exclusively created private directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    // There is deliberately no writer or timing tolerance. O_NONBLOCK must
    // allow the descriptor's exact nonregular-file refusal to be reached. A
    // blocking-open regression is caught by the existing outer test deadline.
    assert!(matches!(
        elf::Snapshot::read(&fifo),
        Err(elf::Error::Format("regular input file"))
    ));
}
