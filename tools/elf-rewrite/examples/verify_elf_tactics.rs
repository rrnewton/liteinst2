//! Read-only metadata/sparse/image join for the four authored ELF tactic fixtures.
//! This example does not plan, emit, map, or execute generated code.
#![forbid(unsafe_code)]

use formats::sparse::{FileEdit, SparsePages};
use formats::{Compatibility, ContentId, Metadata, Outcome, Site, Tactic};
use li2core::contracts::{CONTRACT_VERSION, EntryCompleteness, ResumeObligation};
use li2core::engine;
use li2core::trampoline::SavedExtendedStateFormat;
use liteinst_rewrite::carrier::elf64::{Elf64, ElfVaddr, ObjectType, ParseLimits, Storage};
use liteinst_rewrite::model::Selection;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const LIMIT: usize = 1024 * 1024;
const SUBJECT: u64 = 0x421100;

fn read(path: &Path, limit: usize) -> Vec<u8> {
    let file = File::open(path).expect("open artifact input");
    assert!(file.metadata().unwrap().is_file(), "regular file required");
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= limit, "file byte bound");
    bytes
}

// Same canonical target serialization as the frontend's ledger::target; it is
// derived from the supplied selection, not trusted from the output directory.
fn expected_target(s: &Selection) -> Vec<u8> {
    let state = s.target;
    let kind = if state.format() == SavedExtendedStateFormat::FXSAVE64 {
        "fxsave64"
    } else {
        "xsave64-standard"
    };
    let mut out = format!(
        "LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t{}\nformat\t{}\nallocation_bytes\t{}\nimage_bytes\t{}\nxcr0_mask\t{}\nqualification_complete\tfalse\n",
        s.bias_domain,
        kind,
        state.len(),
        state.image_len(),
        state.mask()
    );
    for c in state.components() {
        writeln!(
            &mut out,
            "component\t{}\t{}\t{}",
            c.xfeature(),
            c.offset(),
            c.size()
        )
        .unwrap();
    }
    out.into_bytes()
}

// These original bytes, heads and displacements are authored expectations.
// Neither generated code nor a producer ledger supplies expected semantics.
struct Fixture {
    core: engine::Tactic,
    wire: Tactic,
    body: Vec<u8>,
    heads: Vec<u64>,
    length: u8,
    block: usize,
    selected: u64,
    victim: u64,
    images: Vec<u64>,
    patches: Vec<(u64, Vec<u8>)>,
}
fn near(source: u64, target: u64) -> Vec<u8> {
    let displacement = i32::try_from(i128::from(target) - i128::from(source) - 5).unwrap();
    let mut bytes = vec![0xe9];
    bytes.extend_from_slice(&displacement.to_le_bytes());
    bytes
}
fn fixture(name: &str) -> Fixture {
    let (core, wire, mut body, heads, length, block, selected, victim) = match name {
        "B2" => (
            engine::Tactic::GeneralizedPun,
            Tactic::GeneralizedPun,
            vec![0x0f, 0x1f, 0, 0xb8, 42, 0, 0, 0, 0xc3],
            vec![0, 3, 8],
            3,
            9,
            SUBJECT + 5 + 0x2ab80000 + 0x8000,
            SUBJECT + 0x6000000,
        ),
        "T1" => (
            engine::Tactic::PrefixedPun,
            Tactic::PrefixedPun,
            vec![0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3],
            vec![0, 2, 7],
            2,
            8,
            SUBJECT + 6 + 0x2ab8,
            SUBJECT + 0x6000000,
        ),
        "T2" => (
            engine::Tactic::SuccessorEviction,
            Tactic::SuccessorEviction,
            vec![
                0x0f, 0x1f, 0, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3,
            ],
            vec![0, 3, 11, 16, 64, 74],
            3,
            17,
            SUBJECT + 5 + 0x56e90000 + 0x8000,
            SUBJECT + 8 + 0x00123456,
        ),
        "T3" => (
            engine::Tactic::NeighborEviction,
            Tactic::NeighborEviction,
            vec![0x75, 1, 0x90, 0xc3],
            vec![0, 2, 3, 64, 74],
            2,
            2,
            SUBJECT + 0x4000000,
            SUBJECT + 0x6000000,
        ),
        _ => panic!("required finite tactic name"),
    };
    if matches!(name, "T2" | "T3") {
        body.resize(64, 0x90);
        body.extend_from_slice(&[0x48, 0xb8]);
        body.extend_from_slice(&42_u64.to_le_bytes());
        body.push(0xc3);
    }
    let (images, patches) = match name {
        "B2" => {
            let jump = near(SUBJECT, selected);
            assert_eq!(&jump[3..], &body[3..5]);
            (vec![selected], vec![(SUBJECT, jump[..3].to_vec())])
        }
        "T1" => {
            let jump = near(SUBJECT + 1, selected);
            assert_eq!(&jump[1..], &body[2..6]);
            (vec![selected], vec![(SUBJECT, vec![0x2e, 0xe9])])
        }
        "T2" => {
            let successor = near(SUBJECT + 3, victim);
            let jump = near(SUBJECT, selected);
            assert_eq!(&jump[3..], &successor[..2]);
            (
                vec![victim, selected],
                vec![(SUBJECT, jump[..3].to_vec()), (SUBJECT + 3, successor)],
            )
        }
        "T3" => {
            let relay = SUBJECT + 69;
            let displacement = i8::try_from(i128::from(relay) - i128::from(SUBJECT) - 2).unwrap();
            let mut stolen = near(SUBJECT + 64, victim);
            stolen.extend_from_slice(&near(relay, selected));
            (
                vec![victim, selected],
                vec![
                    (SUBJECT, vec![0xeb, displacement as u8]),
                    (SUBJECT + 64, stolen),
                ],
            )
        }
        _ => unreachable!(),
    };
    Fixture {
        core,
        wire,
        body,
        heads,
        length,
        block,
        selected,
        victim,
        images,
        patches,
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn number(value: &str) -> u64 {
    value.parse().expect("decimal producer field")
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        5,
        "verify_elf_tactics ORIGINAL SELECTION TACTIC OUTPUT_DIRECTORY"
    );
    let name = args[3].to_str().unwrap();
    let f = fixture(name);
    let original = read(Path::new(&args[1]), LIMIT);
    let selection = read(Path::new(&args[2]), LIMIT);
    let directory = Path::new(&args[4]);
    let s = liteinst_rewrite::selection::parse(&selection).unwrap();
    assert_eq!(s.original, ContentId::of(&original));
    assert_eq!(s.manifest, selection);
    assert_eq!(s.bias_domain, 1);
    assert_eq!(s.carrier_pc, 0x422000);
    assert_eq!(
        s.target.format(),
        SavedExtendedStateFormat::XSAVE64_STANDARD
    );
    assert_eq!((s.sites.len(), s.hooks.len()), (1, 1));
    let site = &s.sites[0];
    assert_eq!((site.id, site.pc, site.length), (1, SUBJECT, f.length));
    assert_eq!(site.forced, Some(f.core));
    assert_eq!(site.completeness, EntryCompleteness::Complete);
    assert_eq!(site.resumes, ResumeObligation::NoneExist);
    assert_eq!(
        site.heads
            .iter()
            .map(|h| (h.address, h.requires_endbr))
            .collect::<Vec<_>>(),
        f.heads
            .iter()
            .map(|&h| (SUBJECT + h, false))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        (site.snapshot.start(), site.snapshot.len()),
        (SUBJECT - 16, u64::try_from(f.body.len() + 16).unwrap())
    );
    assert_eq!(
        (site.function.start(), site.function.len()),
        (SUBJECT, u64::try_from(f.body.len()).unwrap())
    );
    assert_eq!(
        (site.block.start(), site.block.len()),
        (SUBJECT, u64::try_from(f.block).unwrap())
    );
    for (policy, address) in [
        (&site.selected_allocation, f.selected),
        (&site.victim_allocation, f.victim),
    ] {
        assert_eq!(policy.preferred_address, Some(address));
        assert_eq!(policy.max_candidates, 256);
        assert_eq!(policy.max_mapped_bytes, 8192);
        assert_eq!(policy.ranges.len(), 1);
        assert_eq!(
            (policy.ranges[0].start(), policy.ranges[0].len()),
            (address & !4095, 8192)
        );
    }
    let elf_limits = ParseLimits {
        max_program_headers: 64,
    };
    let original_elf = Elf64::parse(&original, elf_limits).unwrap();
    assert_eq!(original_elf.header().object_type, ObjectType::Executable);
    assert_eq!(original_elf.header().entry, ElfVaddr(0x401000));
    assert_eq!(
        original_elf
            .executable_bytes(ElfVaddr(SUBJECT), f.body.len() as u64)
            .unwrap(),
        f.body
    );
    assert_eq!(
        original_elf
            .executable_bytes(ElfVaddr(SUBJECT - 16), 16)
            .unwrap(),
        [0x90; 16]
    );
    let owner = original_elf
        .virtual_to_storage(ElfVaddr(SUBJECT), f.body.len() as u64)
        .unwrap();
    assert_eq!(owner.flags.0, 5);
    let Storage::FileBacked(range) = owner.storage else {
        panic!("file-backed source required")
    };
    assert_eq!(site.file_offset, range.start().0);
    let hook = &s.hooks[0];
    assert_eq!(site.hook, hook.id);
    assert!(matches!(
        (hook.id, hook.pc, hook.length),
        (2, 0x401200, 1) | (3, 0x401220, 19)
    ));
    let hook_bytes = original_elf
        .executable_bytes(ElfVaddr(hook.pc), hook.length as u64)
        .unwrap();
    assert_eq!(hook.expected, ContentId::of(hook_bytes));
    assert_eq!(read(&directory.join("selection.txt"), LIMIT), selection);
    let target = expected_target(&s);
    assert_eq!(read(&directory.join("target.tsv"), LIMIT), target);
    let policy = Compatibility {
        planner: CONTRACT_VERSION,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&target),
        binding: ContentId::of(&selection),
    };
    let metadata = Metadata::decode(
        &read(&directory.join("metadata.li2meta"), LIMIT),
        &policy,
        formats::Limits {
            bytes: LIMIT,
            chunks: LIMIT.div_ceil(formats::CHUNK_BYTES),
            sites: 1,
        },
    )
    .unwrap();
    metadata.verify_original(&original).unwrap();
    metadata
        .verify_selection(ContentId::of(&selection), &[1])
        .unwrap();
    assert_eq!(metadata.compatibility(), &policy);
    assert_eq!(
        metadata.sites(),
        &[Site {
            id: 1,
            original_pc: SUBJECT,
            file_offset: site.file_offset,
            length: f.length,
            outcome: Outcome::Rewritten(f.wire)
        }]
    );
    assert!(metadata.declares_complete_trampoline_coverage());

    let candidate = read(&directory.join("candidate.elf"), LIMIT);
    assert!(candidate.len() > original.len());
    let elf = Elf64::parse(&candidate, elf_limits).unwrap();
    assert_eq!(elf.header().object_type, ObjectType::Executable);
    assert_eq!(elf.header().entry, original_elf.header().entry);
    let mut expected_body = f.body.clone();
    for (pc, bytes) in &f.patches {
        let offset = usize::try_from(pc - SUBJECT).unwrap();
        expected_body[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    assert_eq!(
        elf.executable_bytes(ElfVaddr(SUBJECT), expected_body.len() as u64)
            .unwrap(),
        expected_body
    );
    // Derive the canonical changed runs from independent expected instruction
    // patches, never from candidate bytes or a producer's declared edit list.
    let mut edits = Vec::new();
    let mut at = 0;
    while at < f.body.len() {
        if f.body[at] == expected_body[at] {
            at += 1;
            continue;
        }
        let start = at;
        while at < f.body.len() && f.body[at] != expected_body[at] {
            at += 1;
        }
        edits.push(FileEdit {
            offset: site.file_offset + start as u64,
            expected: f.body[start..at].to_vec(),
            replacement: expected_body[start..at].to_vec(),
        });
    }
    let sparse_limits = formats::sparse::Limits {
        edits: edits.len(),
        edited_bytes: edits.iter().map(|e| e.expected.len()).sum(),
        pages: 1,
    };
    let sparse = formats::sparse_wire::decode(
        &read(&directory.join("source.li2sparse"), LIMIT),
        &original,
        formats::sparse_wire::Limits {
            bytes: LIMIT,
            content: sparse_limits,
        },
    )
    .unwrap();
    assert_eq!(
        sparse,
        SparsePages::build(&original, edits, sparse_limits).unwrap()
    );
    assert_eq!(sparse.pages().len(), 1);
    for edit in sparse.edits() {
        let offset = usize::try_from(edit.offset).unwrap();
        assert_eq!(
            &original[offset..offset + edit.expected.len()],
            edit.expected
        );
        assert_eq!(
            &candidate[offset..offset + edit.replacement.len()],
            edit.replacement
        );
    }
    for page in sparse.pages() {
        let offset = usize::try_from(page.offset).unwrap();
        assert_eq!(&candidate[offset..offset + page.bytes.len()], page.bytes);
    }
    let mut overlay = original.clone();
    let offset = usize::try_from(site.file_offset).unwrap();
    overlay[offset..offset + expected_body.len()].copy_from_slice(&expected_body);
    overlay[32..40].copy_from_slice(&candidate[32..40]);
    overlay[56..58].copy_from_slice(&candidate[56..58]);
    assert_eq!(&candidate[..original.len()], overlay);

    let plan = read(&directory.join("plan-ledger.tsv"), LIMIT);
    let lines: Vec<Vec<&str>> = std::str::from_utf8(&plan)
        .unwrap()
        .lines()
        .map(|l| l.split('\t').collect())
        .collect();
    assert!(!lines.iter().any(|r| r[0] == "entry-router-required"));
    let images: Vec<_> = lines.iter().filter(|r| r[0] == "image").collect();
    assert_eq!(images.len(), f.images.len());
    let ledger = read(&directory.join("ledger.tsv"), LIMIT);
    let image_rows: Vec<_> = std::str::from_utf8(&ledger)
        .unwrap()
        .lines()
        .filter(|r| r.starts_with("elf-image\t"))
        .collect();
    let mut expected_rows = Vec::new();
    let mut page_ranges = Vec::new();
    for (id, (&address, row)) in f.images.iter().zip(images).enumerate() {
        assert_eq!(row.len(), 7);
        assert_eq!(
            (number(row[1]), number(row[2]), number(row[3])),
            (id as u64, 1, address)
        );
        let filename = format!("image-{id:04}.bin");
        assert_eq!(row[6], filename);
        let image = read(&directory.join(&filename), 8192);
        assert_eq!(number(row[4]), image.len() as u64);
        assert_eq!(row[5], hex(&ContentId::of(&image).0));
        let owner = elf
            .virtual_to_storage(ElfVaddr(address), image.len() as u64)
            .unwrap();
        assert_eq!(owner.flags.0, 5);
        let Storage::FileBacked(range) = owner.storage else {
            panic!("file-backed image required")
        };
        assert_eq!(
            elf.executable_bytes(ElfVaddr(address), image.len() as u64)
                .unwrap(),
            image
        );
        let start = address & !4095;
        let end = address
            .checked_add(image.len() as u64)
            .unwrap()
            .checked_add(4095)
            .unwrap()
            & !4095;
        assert!(start >= 0x423000 && end - start <= 8192);
        assert!(page_ranges.iter().all(|&(a, b)| end <= a || b <= start));
        page_ranges.push((start, end));
        expected_rows.push(format!(
            "elf-image\t{id}\t{address}\t{}\t{}\t{}",
            range.start().0,
            image.len(),
            owner.program_header
        ));
    }
    assert_eq!(image_rows, expected_rows);
    // Select the hooked image by its original route, then join its address.
    // T2/T3 currently put the unhooked victim first; image 0 is not hook authority.
    let selected_routes: Vec<_> = lines
        .iter()
        .filter(|r| r[0] == "route" && number(r[2]) == SUBJECT)
        .collect();
    assert_eq!(selected_routes.len(), 1);
    let selected = selected_routes[0];
    assert_eq!(selected.len(), 4);
    let selected_id = usize::try_from(number(selected[1])).unwrap();
    assert_eq!(f.images[selected_id], f.selected);
    assert_eq!(number(selected[3]), f.selected);
    println!(
        "elf tactics artifact verified: tactic={name} metadata=1 sparse_pages=1 images={} qualification_complete=false",
        f.images.len()
    );
}
