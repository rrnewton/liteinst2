//! Finite Linux loader execution, separately from carrier/parser acceptance.
//! The raw static ET_DYN fixtures have no interpreter or external tool inputs.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use formats::ContentId;
use iced_x86::{Decoder, DecoderOptions, Mnemonic, Register};
use liteinst_rewrite::carrier::elf64::{
    Elf64, ElfVaddr, FileOffset, FileRange, ParseLimits, SegmentType,
};
use liteinst_rewrite::carrier::{
    CarrierOutput, CarrierPolicy, DeclaredEdit, ImagePolicy, ImageRequest, RxImage,
    append_carrier_with_images, append_carrier_with_linux_rx_runs, dynamic,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[path = "../../../tests/support/isolated_native_test.rs"]
mod isolated_native_test;

const PAGE: usize = 4096;
const ENTRY: usize = 0x1000;
const ORIGINAL_BODY: usize = 0x1100;
const ORIGINAL_BYTES: usize = 0x8000;
const CARRIER: u64 = 0x10000;
const FIRST_IMAGE: u64 = 0x40000;
const LARGE: usize = 1172;
const IMAGE_BYTES: usize = 96;
const FILE_CAP: usize = 6 * 1024 * 1024;
const STREAM_CAP: usize = 64 * 1024;
const SUBJECT_AS: u64 = 1024 * 1024 * 1024;
const SUBJECT_CPU: u64 = 5;
const SUBJECT_WALL: Duration = Duration::from_secs(10);
const PAYLOAD: &[u8] = b"RX-RUN-LOADER-ORACLE-V1";
const _: () = assert!(PAGE.is_power_of_two());

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn cookie(index: usize) -> u64 {
    0xd6e8_feb8_6659_fd93 ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
}
fn store(index: usize) -> Vec<u8> {
    // MOVABS RAX,cookie; MOV [R13],RAX; ADD R13,8. The cursor records
    // actual execution order, rather than writing into per-image indexed slots.
    let mut bytes = vec![0x48, 0xb8];
    bytes.extend_from_slice(&cookie(index).to_le_bytes());
    bytes.extend_from_slice(&[0x49, 0x89, 0x45, 0, 0x49, 0x83, 0xc5, 8]);
    assert_eq!(bytes.len(), 18);
    bytes
}
fn jump(from: u64, target: u64) -> Vec<u8> {
    let displacement = i32::try_from(i128::from(target) - i128::from(from) - 5).unwrap();
    let mut bytes = vec![0xe9];
    bytes.extend_from_slice(&displacement.to_le_bytes());
    let instruction = Decoder::with_ip(64, &bytes, from, DecoderOptions::NONE).decode();
    assert_eq!(
        (
            instruction.mnemonic(),
            instruction.len(),
            instruction.near_branch64()
        ),
        (Mnemonic::Jmp, 5, target)
    );
    bytes
}
fn image_address(index: usize) -> u64 {
    FIRST_IMAGE + (index * PAGE + 3 + (index % 3) * 16) as u64
}
fn parse(bytes: &[u8]) -> Elf64<'_> {
    Elf64::parse(
        bytes,
        ParseLimits {
            max_program_headers: LARGE + 4,
        },
    )
    .unwrap()
}
fn policy() -> ImagePolicy {
    ImagePolicy {
        layout: CarrierPolicy {
            page_size: PAGE as u64,
            user_address_limit: 1 << 47,
            max_added_file_bytes: FILE_CAP as u64,
            max_output_file_bytes: FILE_CAP as u64,
            max_program_headers: LARGE + 4,
            max_virtual_span: 8 * 1024 * 1024,
        },
        dynamic: dynamic::Limits::default(),
        max_images: LARGE,
        max_new_load_pages: (LARGE + 17) as u64,
    }
}
struct Fixture {
    original: Vec<u8>,
    images: Vec<RxImage>,
    edits: Vec<DeclaredEdit>,
    dependencies: Vec<FileRange>,
    expected: Vec<u8>,
    finish: u64,
}
impl Fixture {
    fn new(count: usize) -> Self {
        assert!(matches!(count, 4 | LARGE));
        let expected: Vec<u8> = (0..count)
            .flat_map(|index| cookie(index).to_le_bytes())
            .collect();
        assert!(expected.len() <= STREAM_CAP && expected.len() & 15 == 0);
        let finish = ORIGINAL_BODY + count * 18;
        // Check the number of executed stores before the one write. Then
        // require its exact return length. Neither count nor I/O failure retries.
        let mut tail = vec![0x4c, 0x89, 0xe8, 0x4c, 0x29, 0xe0, 0x48, 0x3d]; // RAX=R13-R12
        tail.extend_from_slice(&(expected.len() as u32).to_le_bytes());
        let count_branch = tail.len();
        tail.extend_from_slice(&[0x75, 0]);
        tail.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x4c, 0x89, 0xe6, 0xba]);
        tail.extend_from_slice(&(expected.len() as u32).to_le_bytes());
        tail.extend_from_slice(&[0x0f, 0x05, 0x48, 0x3d]);
        tail.extend_from_slice(&(expected.len() as u32).to_le_bytes());
        let write_branch = tail.len();
        tail.extend_from_slice(&[
            0x75, 0, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b,
        ]);
        let failure = tail.len();
        tail.extend_from_slice(&[0xb8, 60, 0, 0, 0, 0xbf, 97, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b]);
        for at in [count_branch, write_branch] {
            tail[at + 1] = i8::try_from(failure - (at + 2)).unwrap() as u8;
            let branch =
                Decoder::with_ip(64, &tail[at..], (finish + at) as u64, DecoderOptions::NONE)
                    .decode();
            assert_eq!(
                (branch.mnemonic(), branch.near_branch64()),
                (Mnemonic::Jne, (finish + failure) as u64)
            );
        }
        assert!(finish + tail.len() < ORIGINAL_BYTES);
        let mut original = vec![0; ORIGINAL_BYTES];
        original[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        put16(&mut original, 16, 3); // static ET_DYN, no PT_INTERP
        put16(&mut original, 18, 62);
        put32(&mut original, 20, 1);
        put64(&mut original, 24, ENTRY as u64);
        put64(&mut original, 32, 64);
        put16(&mut original, 52, 64);
        put16(&mut original, 54, 56);
        put16(&mut original, 56, 2);
        put32(&mut original, 64, 1); // unchanged readable/executable source LOAD
        put32(&mut original, 68, 5);
        put64(&mut original, 96, ORIGINAL_BYTES as u64);
        put64(&mut original, 104, ORIGINAL_BYTES as u64);
        put64(&mut original, 112, PAGE as u64);
        put32(&mut original, 120, 0x6474_e551); // nonexecutable GNU stack
        put32(&mut original, 124, 6);
        put64(&mut original, 168, 16);
        original[ENTRY..ENTRY + 3].copy_from_slice(&[0x48, 0x81, 0xec]);
        put32(&mut original, ENTRY + 3, expected.len() as u32); // SUB RSP,trace_len
        original[ENTRY + 7..ENTRY + 10].copy_from_slice(&[0x49, 0x89, 0xe4]); // MOV R12,RSP
        original[ENTRY + 10..ENTRY + 13].copy_from_slice(&[0x49, 0x89, 0xe5]); // MOV R13,RSP
        let slot = ENTRY + 13;
        original[slot..slot + 5].copy_from_slice(&jump(slot as u64, ORIGINAL_BODY as u64));
        for index in 0..count {
            original[ORIGINAL_BODY + index * 18..ORIGINAL_BODY + (index + 1) * 18]
                .copy_from_slice(&store(index));
        }
        original[finish..finish + tail.len()].copy_from_slice(&tail);
        // Reverse caller order deliberately differs from execution and VA order.
        let images: Vec<_> = (0..count)
            .rev()
            .map(|index| {
                let address = image_address(index);
                let target = if index + 1 == count {
                    finish as u64
                } else {
                    image_address(index + 1)
                };
                let mut bytes = store(index);
                bytes.extend_from_slice(&jump(address + 18, target));
                bytes.resize(IMAGE_BYTES, 0xcc);
                let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
                let first = decoder.decode();
                let second = decoder.decode();
                let third = decoder.decode();
                let fourth = decoder.decode();
                assert_eq!(
                    (first.mnemonic(), first.op0_register(), first.immediate64()),
                    (Mnemonic::Mov, Register::RAX, cookie(index))
                );
                assert_eq!(
                    (
                        second.mnemonic(),
                        second.memory_base(),
                        second.memory_displacement64(),
                        second.op1_register()
                    ),
                    (Mnemonic::Mov, Register::R13, 0, Register::RAX)
                );
                assert_eq!(
                    (third.mnemonic(), third.op0_register(), third.immediate8()),
                    (Mnemonic::Add, Register::R13, 8)
                );
                assert_eq!(
                    (
                        fourth.mnemonic(),
                        fourth.near_branch64(),
                        decoder.position()
                    ),
                    (Mnemonic::Jmp, target, 23)
                );
                RxImage {
                    entry: ElfVaddr(address),
                    bytes,
                }
            })
            .collect();
        let edits = vec![DeclaredEdit {
            offset: FileOffset(slot as u64),
            expected: original[slot..slot + 5].to_vec(),
            replacement: jump(slot as u64, image_address(0)),
        }];
        let dependencies = std::iter::once(
            FileRange::checked(
                FileOffset(ENTRY as u64),
                (finish + tail.len() - ENTRY) as u64,
            )
            .unwrap(),
        )
        .collect();
        assert_eq!(parse(&original).header().program_count, 2);
        assert_eq!(
            parse(&original).segments(SegmentType::Interpreter).count(),
            0
        );
        Self {
            original,
            images,
            edits,
            dependencies,
            expected,
            finish: finish as u64,
        }
    }
    fn request(&self) -> ImageRequest<'_> {
        ImageRequest {
            carrier_vaddr: ElfVaddr(CARRIER),
            payload: PAYLOAD,
            images: &self.images,
            source_dependencies: &self.dependencies,
        }
    }
    fn inspect(&self, output: &CarrierOutput, packed: bool) {
        let elf = parse(output.bytes());
        let count = self.images.len();
        assert_eq!(
            usize::from(elf.header().program_count),
            if packed { 5 } else { count + 4 }
        );
        assert_eq!(elf.header().entry, ElfVaddr(ENTRY as u64));
        assert_eq!(
            elf.header().object_type,
            parse(&self.original).header().object_type
        );
        assert_eq!(elf.segments(SegmentType::Interpreter).count(), 0);
        assert_eq!(output.images.len(), count);
        assert_eq!(output.changes().len(), 3);
        let mut expected = self.original.clone();
        for change in output.changes() {
            let at = change.edit.offset.0 as usize;
            assert_eq!(
                &self.original[at..at + change.edit.expected.len()],
                change.edit.expected
            );
            expected[at..at + change.edit.replacement.len()]
                .copy_from_slice(&change.edit.replacement);
        }
        assert_eq!(&output.bytes()[..self.original.len()], expected);
        for (index, original_header) in self.original[64..176].chunks_exact(56).enumerate() {
            let at = output.program_table.start().0 as usize
                + output.original_to_output_header[index] * 56;
            assert_eq!(&output.bytes()[at..at + 56], original_header);
        }
        let mut headers = std::collections::BTreeSet::new();
        for (image, placement) in self.images.iter().zip(&output.images) {
            assert_eq!(placement.entry, image.entry);
            assert_eq!(placement.file.len(), IMAGE_BYTES as u64);
            assert_eq!(
                elf.executable_bytes(image.entry, IMAGE_BYTES as u64)
                    .unwrap(),
                image.bytes
            );
            let mapping = elf
                .file_to_virtual(placement.file.start(), placement.file.len())
                .unwrap();
            assert_eq!(
                (
                    mapping.virtual_range.start(),
                    mapping.program_header,
                    mapping.flags.0
                ),
                (image.entry, placement.program_header, 5)
            );
            let header = &elf.program_headers()[placement.program_header];
            assert_eq!(
                image.entry.0 - header.vaddr.0,
                placement.file.start().0 - header.offset.0
            );
            assert_eq!((header.flags.0, header.file_size), (5, header.memory_size));
            headers.insert(placement.program_header);
        }
        assert_eq!(headers.len(), if packed { 1 } else { count });
        assert!(!headers.contains(&output.carrier_index));
        assert_eq!(elf.program_headers()[output.carrier_index].flags.0, 4);
        let carrier_bytes = output.payload.end().0 - output.program_table.start().0;
        assert_eq!(
            output.new_load_pages,
            count as u64 + carrier_bytes.div_ceil(PAGE as u64)
        );
        let highest = elf
            .segments(SegmentType::Load)
            .map(|load| (load.vaddr.0 + load.memory_size).div_ceil(PAGE as u64) * PAGE as u64)
            .max()
            .unwrap();
        assert_eq!(highest, FIRST_IMAGE + (count * PAGE) as u64);
        assert!(highest < 8 * 1024 * 1024 && highest < SUBJECT_AS);
        assert!(output.bytes().len() <= FILE_CAP);
        assert_eq!(
            elf.executable_bytes(ElfVaddr(self.finish), 6).unwrap(),
            &[0x4c, 0x89, 0xe8, 0x4c, 0x29, 0xe0]
        );
        // The caller ordering is stable even though packed file order reverses.
        assert_eq!(
            output.images[0].file.start() > output.images[count - 1].file.start(),
            packed
        );
    }
}

fn digest(bytes: &[u8]) -> String {
    ContentId::of(bytes)
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn write_new(path: &Path, bytes: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    assert_eq!(file.metadata().unwrap().len(), bytes.len() as u64);
    assert_eq!(file.metadata().unwrap().mode() & 0o777, mode);
}
fn bounded_read(path: &Path) -> Vec<u8> {
    assert!(path.metadata().unwrap().len() <= STREAM_CAP as u64);
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take((STREAM_CAP + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= STREAM_CAP);
    bytes
}
#[derive(Debug)]
struct Outcome {
    status: Option<ExitStatus>,
    exec_errno: Option<i32>,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
struct OwnedChild {
    child: Child,
    reaped: bool,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn arm(root: &Path, name: &str, bytes: &[u8]) -> Outcome {
    assert!(!bytes.is_empty() && bytes.len() <= FILE_CAP);
    let directory = root.join(name);
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("fixture.elf");
    write_new(&path, bytes, 0o500);
    let executable = File::open(&path).unwrap();
    let identity = executable.metadata().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let stdout_path = directory.join("stdout.bin");
    let stderr_path = directory.join("stderr.bin");
    let output = |path: &Path| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
    };
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .current_dir(&directory)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(output(&stdout_path)))
        .stderr(Stdio::from(output(&stderr_path)));
    // Use the standard spawn error pipe/owned reap, but never execvp (which can
    // hide ENOEXEC behind a shell fallback). This pre_exec either directly
    // execveat's the already-authenticated FD or returns its exact errno.
    // SAFETY: only async-signal-safe limit/query/alarm/exec syscalls and stack
    // scalar operations run in this fork child. No allocator, locks or Rust I/O.
    unsafe {
        command.pre_exec(move || {
            for (resource, value) in [
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_CPU, SUBJECT_CPU),
                (libc::RLIMIT_AS, SUBJECT_AS),
                (libc::RLIMIT_FSIZE, STREAM_CAP as u64),
            ] {
                let limits = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(resource, &limits) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut actual = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(resource, &mut actual) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if actual.rlim_cur != value || actual.rlim_max != value {
                    return Err(std::io::Error::from_raw_os_error(libc::EPROTO));
                }
            }
            libc::alarm(10);
            let argv = [c"rx-run-fixture".as_ptr(), std::ptr::null()];
            let envp = [c"LC_ALL=C".as_ptr(), std::ptr::null()];
            // libc declares char** here; Linux only reads these arrays and strings.
            libc::execveat(
                executable.as_raw_fd(),
                c"".as_ptr(),
                argv.as_ptr().cast(),
                envp.as_ptr().cast(),
                libc::AT_EMPTY_PATH,
            );
            Err(std::io::Error::last_os_error())
        });
    }
    let start = Instant::now();
    let mut timed_out = false;
    let (status, exec_errno) = match command.spawn() {
        Err(error) => (
            None,
            Some(error.raw_os_error().expect("raw exec/setup errno")),
        ),
        Ok(child) => {
            let mut owned = OwnedChild {
                child,
                reaped: false,
            };
            let status = loop {
                if let Some(status) = owned.child.try_wait().unwrap() {
                    break status;
                }
                if start.elapsed() >= SUBJECT_WALL {
                    timed_out = true;
                    owned.child.kill().unwrap();
                    break owned.child.wait().unwrap();
                }
                std::thread::sleep(Duration::from_millis(2));
            };
            owned.reaped = true;
            (Some(status), None)
        }
    };
    let closure_elapsed = start.elapsed();
    timed_out |= closure_elapsed > SUBJECT_WALL;
    // Only after the exact child was reaped (including std's spawn-error path).
    let stdout = bounded_read(&stdout_path);
    let stderr = bounded_read(&stderr_path);
    let after = path.metadata().unwrap();
    assert_eq!(
        (
            identity.dev(),
            identity.ino(),
            identity.mode(),
            identity.len(),
            identity.mtime(),
            identity.mtime_nsec(),
            identity.ctime(),
            identity.ctime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec()
        )
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let receipt = format!(
        "RXRUNARM\t1\nname\t{name}\nattempts\t1\ninput_bytes\t{}\ninput_sha256\t{}\nargv0\trx-run-fixture\nenvironment\tLC_ALL=C\nAS\t{SUBJECT_AS}\nCPU\t{SUBJECT_CPU}\nwall_seconds\t10\nstream_file_cap\t{STREAM_CAP}\nstatus_code\t{:?}\nsignal\t{:?}\nexec_errno\t{exec_errno:?}\ntimed_out\t{timed_out}\nelapsed_ns\t{}\nstdout_bytes\t{}\nstdout_sha256\t{}\nstderr_bytes\t{}\nstderr_sha256\t{}\nclosure\texact_child_reaped_or_std_spawn_error_reaped\n",
        bytes.len(),
        digest(bytes),
        status.and_then(|s| s.code()),
        status.and_then(|s| s.signal()),
        closure_elapsed.as_nanos(),
        stdout.len(),
        digest(&stdout),
        stderr.len(),
        digest(&stderr)
    );
    write_new(&directory.join("receipt.tsv"), receipt.as_bytes(), 0o600);
    Outcome {
        status,
        exec_errno,
        timed_out,
        stdout,
        stderr,
    }
}
fn campaign(count: usize, name: &str) {
    let fixture = Fixture::new(count);
    let input = parse(&fixture.original);
    let legacy =
        append_carrier_with_images(&input, fixture.request(), &fixture.edits, policy()).unwrap();
    let packed =
        append_carrier_with_linux_rx_runs(&input, fixture.request(), &fixture.edits, policy())
            .unwrap();
    fixture.inspect(&legacy, false);
    fixture.inspect(&packed, true);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/evaluation/rx-run-loader-native");
    std::fs::create_dir_all(&root).unwrap();
    let root = root
        .canonicalize()
        .unwrap()
        .join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap(); // fresh campaign; no overwrite or retry
    write_new(&root.join("expected.bin"), &fixture.expected, 0o600);
    // Exactly one call per arm; preserve all three receipts before judging parity.
    let original = arm(&root, "original", &fixture.original);
    let legacy = arm(&root, "legacy", legacy.bytes());
    let packed = arm(&root, "packed", packed.bytes());
    for outcome in [&original, &legacy, &packed] {
        assert!(!outcome.timed_out, "{outcome:?}");
        assert!(outcome.stderr.is_empty(), "{outcome:?}");
    }
    for outcome in [&original, &packed] {
        assert_eq!(outcome.exec_errno, None, "{outcome:?}");
        assert_eq!(
            outcome.status.and_then(|s| s.code()),
            Some(0),
            "{outcome:?}"
        );
        assert_eq!(outcome.stdout, fixture.expected);
    }
    if count == LARGE {
        assert_eq!(legacy.exec_errno, Some(libc::ENOEXEC));
        assert_eq!(legacy.status, None);
        assert!(legacy.stdout.is_empty());
    } else {
        assert_eq!(legacy.exec_errno, None);
        assert_eq!(legacy.status.and_then(|s| s.code()), Some(0));
        assert_eq!(legacy.stdout, fixture.expected);
    }
    // Each decoded u64 is checked, not merely a commutative checksum. Removing,
    // duplicating or reordering an image cannot satisfy this complete sequence.
    assert_eq!(packed.stdout.len(), count * 8);
    for (index, word) in packed.stdout.chunks_exact(8).enumerate() {
        assert_eq!(u64::from_le_bytes(word.try_into().unwrap()), cookie(index));
    }
    write_new(&root.join("COMPLETE"), format!("RXRUNNATIVE\t1\nimages\t{count}\narms\t3\nattempts_per_arm\t1\nmatched_trace_words\t{count}\nlegacy_expected_enoexec\t{}\nfull_program_qualification\tfalse\n", count == LARGE).as_bytes(), 0o600);
}

#[test]
fn linux_rx_runs_execute_original_legacy_and_packed_compact_fixture() {
    fn body() {
        campaign(4, "compact");
    }
    isolated_native_test::run(
        "linux_rx_runs_execute_original_legacy_and_packed_compact_fixture",
        "LI2_RX_RUN_LOADER_COMPACT_CHILD",
        body,
    );
}

#[test]
fn linux_rx_runs_execute_1172_images_under_one_gib_and_preserve_legacy_enoexec() {
    fn body() {
        campaign(LARGE, "header-boundary");
    }
    isolated_native_test::run(
        "linux_rx_runs_execute_1172_images_under_one_gib_and_preserve_legacy_enoexec",
        "LI2_RX_RUN_LOADER_BOUNDARY_CHILD",
        body,
    );
}
