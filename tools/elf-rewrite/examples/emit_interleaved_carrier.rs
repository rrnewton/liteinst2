//! Emit four tiny static ELF fixtures. This example never executes them.
use liteinst_rewrite::carrier::elf64::{
    Elf64, ElfVaddr, FileOffset, FileRange, ParseLimits, SegmentType,
};
use liteinst_rewrite::carrier::{
    self, CarrierPolicy, DeclaredEdit, ImagePolicy, ImageRequest, RxImage,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn body() -> Vec<u8> {
    // write(1, RIP-relative "42\n", 3), then exit(0). No stack or libc use.
    let mut b = vec![
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x48, 0x8d, 0x35, 16, 0, 0, 0, 0xba, 3, 0, 0, 0, 0x0f,
        0x05, 0x31, 0xff, 0xb8, 60, 0, 0, 0, 0x0f, 0x05,
    ];
    assert_eq!(b.len(), 33);
    b.extend_from_slice(b"42\n");
    b
}

fn jump(from: u64, to: u64) -> Vec<u8> {
    let delta = i32::try_from(i128::from(to) - i128::from(from) - 5).unwrap();
    let mut b = vec![0xe9];
    b.extend_from_slice(&delta.to_le_bytes());
    b
}

fn original(body: &[u8]) -> Vec<u8> {
    let mut b = vec![0_u8; 0x3000];
    b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut b, 16, 2);
    put16(&mut b, 18, 62);
    put32(&mut b, 20, 1);
    put64(&mut b, 24, 0x401100);
    put64(&mut b, 32, 64);
    put16(&mut b, 52, 64);
    put16(&mut b, 54, 56);
    put16(&mut b, 56, 4);
    for (i, (offset, address, flags, size, memory)) in [
        (0, 0x400000, 4, 0x1000, 0x1000),
        (0x1000, 0x401000, 5, 0x1000, 0x1000),
        (0x2000, 0x406000, 6, 0x1000, 0x2000),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + i * 56;
        put32(&mut b, at, 1);
        put32(&mut b, at + 4, flags);
        for (field, value) in [
            (8, offset),
            (16, address),
            (24, address),
            (32, size),
            (40, memory),
            (48, 4096),
        ] {
            put64(&mut b, at + field, value);
        }
    }
    put32(&mut b, 64 + 3 * 56, 0x6474e551);
    put32(&mut b, 64 + 3 * 56 + 4, 6);
    put64(&mut b, 64 + 3 * 56 + 48, 16);
    b[0x1100..0x1105].copy_from_slice(&jump(0x401100, 0x401200));
    b[0x1200..0x1200 + body.len()].copy_from_slice(body);
    b
}

fn publish(directory: &Path, name: &str, b: &[u8]) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(directory.join(name))
        .unwrap();
    f.write_all(b).unwrap();
    f.sync_all().unwrap();
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(args.len(), 2);
    let directory = Path::new(&args[1]);
    assert!(directory.is_absolute() && !directory.exists());
    fs::create_dir(directory).unwrap();
    let code = body();
    let original = original(&code);
    let parsed = Elf64::parse(&original, ParseLimits::default()).unwrap();
    assert_eq!(parsed.header().entry, ElfVaddr(0x401100));
    assert_eq!(
        parsed
            .executable_bytes(ElfVaddr(0x401200), code.len() as u64)
            .unwrap(),
        code
    );
    publish(directory, "original.elf", &original);
    let policy = ImagePolicy {
        layout: CarrierPolicy {
            page_size: 4096,
            user_address_limit: 1 << 47,
            max_added_file_bytes: 0x4000,
            max_output_file_bytes: 0x7000,
            max_program_headers: 8,
            max_virtual_span: 0x800000,
        },
        dynamic: carrier::dynamic::Limits::default(),
        max_images: 1,
        max_new_load_pages: 2,
    };
    for (name, entry) in [
        ("below.elf", 0x10005),
        ("gap.elf", 0x403007),
        ("above.elf", 0x40c003),
    ] {
        let images = [RxImage {
            entry: ElfVaddr(entry),
            bytes: code.clone(),
        }];
        let edits = [DeclaredEdit {
            offset: FileOffset(0x1100),
            expected: original[0x1100..0x1105].to_vec(),
            replacement: jump(0x401100, entry),
        }];
        let deps = [FileRange::checked(FileOffset(0x1100), 5).unwrap()];
        let output = carrier::append_exec_carrier_with_interleaved_images(
            &parsed,
            ImageRequest {
                carrier_vaddr: ElfVaddr(0x40a000),
                payload: b"interleaved-fixture-v1",
                images: &images,
                source_dependencies: &deps,
            },
            &edits,
            policy,
        )
        .unwrap();
        let elf = Elf64::parse(output.bytes(), ParseLimits::default()).unwrap();
        assert_eq!(elf.header().entry, parsed.header().entry);
        assert_eq!(
            elf.executable_bytes(ElfVaddr(entry), code.len() as u64)
                .unwrap(),
            code
        );
        assert_eq!(
            elf.executable_bytes(ElfVaddr(0x401100), 5).unwrap(),
            edits[0].replacement
        );
        assert_eq!(output.new_load_pages, 2);
        assert_eq!(output.changes().len(), 3);
        assert_eq!(elf.segments(SegmentType::ProgramHeaders).count(), 1);
        let mut expected = original.clone();
        for change in output.changes() {
            let at = change.edit.offset.0 as usize;
            assert_eq!(
                &original[at..at + change.edit.expected.len()],
                change.edit.expected
            );
            expected[at..at + change.edit.replacement.len()]
                .copy_from_slice(&change.edit.replacement);
        }
        assert_eq!(&output.bytes()[..original.len()], expected);
        publish(directory, name, output.bytes());
    }
    println!(
        "emitted four static ET_EXEC fixtures; execution remains separate; expected stdout=42\\n exit=0"
    );
}
