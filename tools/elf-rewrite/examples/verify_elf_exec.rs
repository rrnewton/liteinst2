//! Read-only metadata/sparse/image join for the authored ELF-exec fixture.
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
const SUBJECT: u64 = 0x401100;
const IMAGE: u64 = 0x420000;
const SOURCE: [u8; 6] = [0xb8, 5, 0, 0, 0, 0xc3];

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

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        4,
        "verify_elf_exec ORIGINAL SELECTION OUTPUT_DIRECTORY"
    );
    let original = read(Path::new(&args[1]), LIMIT);
    let selection = read(Path::new(&args[2]), LIMIT);
    let directory = Path::new(&args[3]);
    let s = liteinst_rewrite::selection::parse(&selection).unwrap();
    assert_eq!(s.original, ContentId::of(&original));
    assert_eq!(s.manifest, selection);
    assert_eq!(s.bias_domain, 1);
    assert_eq!(s.carrier_pc, 0x418000);
    assert_eq!(
        s.target.format(),
        SavedExtendedStateFormat::XSAVE64_STANDARD
    );
    assert_eq!((s.sites.len(), s.hooks.len()), (1, 1));
    let site = &s.sites[0];
    assert_eq!((site.id, site.pc, site.length), (1, SUBJECT, 5));
    assert_eq!(site.forced, Some(engine::Tactic::Relocation));
    assert_eq!(site.completeness, EntryCompleteness::Complete);
    assert_eq!(site.resumes, ResumeObligation::NoneExist);
    assert_eq!(
        site.heads
            .iter()
            .map(|h| (h.address, h.requires_endbr))
            .collect::<Vec<_>>(),
        [(SUBJECT, false), (SUBJECT + 5, false)]
    );
    assert_eq!(site.selected_allocation.preferred_address, Some(IMAGE));
    assert_eq!(site.selected_allocation.ranges.len(), 1);
    assert_eq!(site.selected_allocation.ranges[0].start(), IMAGE);
    assert_eq!(site.selected_allocation.ranges[0].len(), 4096);
    let elf_limits = ParseLimits {
        max_program_headers: 64,
    };
    let original_elf = Elf64::parse(&original, elf_limits).unwrap();
    assert_eq!(original_elf.header().object_type, ObjectType::Executable);
    assert_eq!(original_elf.header().entry, ElfVaddr(0x401000));
    assert_eq!(
        original_elf.executable_bytes(ElfVaddr(SUBJECT), 6).unwrap(),
        SOURCE
    );
    let original_owner = original_elf
        .virtual_to_storage(ElfVaddr(SUBJECT), 6)
        .unwrap();
    assert_eq!(original_owner.flags.0, 5);
    let Storage::FileBacked(original_range) = original_owner.storage else {
        panic!("source must be file-backed")
    };
    assert_eq!(site.file_offset, original_range.start().0);
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
            length: 5,
            outcome: Outcome::Rewritten(Tactic::Relocation),
        }]
    );
    assert!(metadata.declares_complete_trampoline_coverage());

    let candidate = read(&directory.join("candidate.elf"), LIMIT);
    assert!(candidate.len() > original.len());
    let candidate_elf = Elf64::parse(&candidate, elf_limits).unwrap();
    assert_eq!(candidate_elf.header().object_type, ObjectType::Executable);
    assert_eq!(candidate_elf.header().entry, original_elf.header().entry);
    let mut patch = vec![0xe9];
    patch.extend_from_slice(&i32::try_from(IMAGE - (SUBJECT + 5)).unwrap().to_le_bytes());
    // At these fixed addresses only the first four bytes change; byte five is
    // zero in both instructions. The RET at the second legal head stays exact.
    assert_eq!(patch, [0xe9, 0xfb, 0xee, 1, 0]);
    assert_eq!(
        candidate_elf
            .executable_bytes(ElfVaddr(SUBJECT), 5)
            .unwrap(),
        patch
    );
    assert_eq!(
        candidate_elf
            .executable_bytes(ElfVaddr(SUBJECT + 5), 1)
            .unwrap(),
        [0xc3]
    );
    let sparse_limits = formats::sparse::Limits {
        edits: 1,
        edited_bytes: 4,
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
    let expected = SparsePages::build(
        &original,
        vec![FileEdit {
            offset: site.file_offset,
            expected: SOURCE[..4].to_vec(),
            replacement: patch[..4].to_vec(),
        }],
        sparse_limits,
    )
    .unwrap();
    assert_eq!(sparse, expected);
    assert_eq!(sparse.pages().len(), 1);
    for edit in sparse.edits() {
        let at = usize::try_from(edit.offset).unwrap();
        assert_eq!(&original[at..at + edit.expected.len()], edit.expected);
        assert_eq!(
            &candidate[at..at + edit.replacement.len()],
            edit.replacement
        );
    }
    for page in sparse.pages() {
        let at = usize::try_from(page.offset).unwrap();
        assert_eq!(&candidate[at..at + page.bytes.len()], page.bytes);
    }
    // Sparse records cover source edits, not the carrier's two ELF-header edits.
    // Reject any other original-byte change, including hook/data/stack changes.
    let mut original_overlay = original.clone();
    let at = usize::try_from(site.file_offset).unwrap();
    original_overlay[at..at + 5].copy_from_slice(&patch);
    original_overlay[32..40].copy_from_slice(&candidate[32..40]);
    original_overlay[56..58].copy_from_slice(&candidate[56..58]);
    assert_eq!(&candidate[..original.len()], original_overlay);

    let image = read(&directory.join("image-0000.bin"), 4096);
    let image_owner = candidate_elf
        .virtual_to_storage(ElfVaddr(IMAGE), image.len() as u64)
        .unwrap();
    assert_eq!(image_owner.flags.0, 5);
    let Storage::FileBacked(image_range) = image_owner.storage else {
        panic!("generated image must be file-backed")
    };
    assert_eq!(
        candidate_elf
            .executable_bytes(ElfVaddr(IMAGE), image.len() as u64)
            .unwrap(),
        image
    );
    let ledger = read(&directory.join("ledger.tsv"), LIMIT);
    let image_rows: Vec<_> = std::str::from_utf8(&ledger)
        .unwrap()
        .lines()
        .filter(|r| r.starts_with("elf-image\t"))
        .collect();
    let expected_row = format!(
        "elf-image\t0\t{}\t{}\t{}\t{}",
        IMAGE,
        image_range.start().0,
        image.len(),
        image_owner.program_header
    );
    assert_eq!(image_rows, [expected_row.as_str()]);
    println!(
        "elf exec artifact verified: metadata=1 sparse_pages=1 images=1 qualification_complete=false"
    );
}
