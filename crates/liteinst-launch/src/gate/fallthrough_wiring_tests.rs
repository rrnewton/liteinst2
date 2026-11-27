//! Wiring witness for the reference gate's native single-step check: the
//! trace stop after a selected instruction must be exactly its fallthrough.

use crate::gate::{GateError, GateEvent, ImageFacts, SingleThreadPageGate};
use crate::{ExecCheckpoint, LaunchCommand};
use liteinst_admission::scan::{Policy, SiteClass};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const PAGE: usize = 4096;
const BASE: u64 = 0x400000;
const DATA: u64 = 0x600000;
const TIMEOUT: Duration = Duration::from_secs(3);
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A private static ELF whose entry is RDTSC (`0f 31`) followed by UD2
/// (`0f 0b`), so the only selected site's fallthrough raises SIGILL.
struct Fixture {
    directory: PathBuf,
    path: PathBuf,
    image: Vec<u8>,
    heads: BTreeSet<u64>,
    site: u64,
}

impl Fixture {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-tmp");
        fs::create_dir_all(&root).unwrap();
        let directory = root.join(format!(
            "fallthrough-wiring-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("fixture");
        let mut image = vec![0xcc; 3 * PAGE];
        image[..PAGE].fill(0);
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut image, 16, 2);
        put16(&mut image, 18, 62);
        put32(&mut image, 20, 1);
        let site = BASE + PAGE as u64;
        put64(&mut image, 24, site);
        put64(&mut image, 32, 64);
        put16(&mut image, 52, 64);
        put16(&mut image, 54, 56);
        put16(&mut image, 56, 3);
        put32(&mut image, 64, 1);
        put32(&mut image, 68, 5);
        put64(&mut image, 80, BASE);
        put64(&mut image, 96, (3 * PAGE) as u64);
        put64(&mut image, 104, (3 * PAGE) as u64);
        put64(&mut image, 112, PAGE as u64);
        put32(&mut image, 120, 1);
        put32(&mut image, 124, 6);
        put64(&mut image, 128, (3 * PAGE) as u64);
        put64(&mut image, 136, DATA);
        put64(&mut image, 152, PAGE as u64);
        put64(&mut image, 160, PAGE as u64);
        put64(&mut image, 168, PAGE as u64);
        put32(&mut image, 176, 0x6474_e551);
        put32(&mut image, 180, 6);
        put64(&mut image, 224, 16);
        let offset = (site - BASE) as usize;
        image[offset..offset + 4].copy_from_slice(&[0x0f, 0x31, 0x0f, 0x0b]);
        let heads = BTreeSet::from([site, site + 2]);
        let mut file_image = image.clone();
        file_image.resize(4 * PAGE, 0);
        let _guard = crate::TEST_FILE_FORK.lock().unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .unwrap();
        file.write_all(&file_image).unwrap();
        drop(file);
        Self {
            directory,
            path,
            image,
            heads,
            site,
        }
    }

    fn launch(&self) -> SingleThreadPageGate {
        let checkpoint = {
            let _guard = crate::TEST_FILE_FORK.lock().unwrap();
            ExecCheckpoint::launch(&LaunchCommand::new(&self.path), TIMEOUT).unwrap()
        };
        // SAFETY: this fixed private ELF has one task, immutable code, an exact
        // reachable-head census (the RDTSC and the UD2 after it) and no aliases,
        // code reads, signal handlers or mapping changes. We exclusively own
        // tracing and reaping.
        unsafe {
            SingleThreadPageGate::new(
                checkpoint,
                vec![ImageFacts {
                    start: BASE,
                    bytes: self.image.clone(),
                    heads: self.heads.clone(),
                }],
                Policy {
                    version: 1,
                    selected: [SiteClass::Rdtsc].into_iter().collect(),
                },
                TIMEOUT,
            )
        }
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn observe_site(gate: &mut SingleThreadPageGate, site: u64) {
    match gate.next_event().unwrap() {
        GateEvent::Observe(observation) => {
            assert_eq!(observation.site.address, site);
            assert_eq!(observation.site.class, SiteClass::Rdtsc);
            assert_eq!(observation.registers.rip, site);
        }
        other => panic!("expected the RDTSC observation, got {other:?}"),
    }
}

#[test]
fn rdtsc_site_control_raises_sigill_after_its_fallthrough() {
    let fixture = Fixture::new();
    let mut gate = fixture.launch();
    observe_site(&mut gate, fixture.site);
    match gate.next_event().unwrap() {
        GateEvent::ApplicationSignal {
            signal, registers, ..
        } => {
            assert_eq!(signal, libc::SIGILL);
            assert_eq!(registers.rip, fixture.site + 2);
        }
        other => panic!("expected SIGILL at the fallthrough, got {other:?}"),
    }
}

#[test]
fn perturbed_step_rip_is_refused_off_the_fallthrough() {
    let fixture = Fixture::new();
    let mut gate = fixture.launch();
    observe_site(&mut gate, fixture.site);
    gate.inject_cpu_step_rip_fault(1);
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Refused(
            "single-step stopped off the selected instruction's fallthrough"
        ))
    ));
    assert!(matches!(
        gate.next_event(),
        Err(GateError::Refused("execution loop is closed"))
    ));
}
