//! Pure adjacent refusals for one authored ELF tactic input; no generated code runs.
//! Mutants are independent memory copies. This example writes only stdout.
#![forbid(unsafe_code)]

use formats::{Compatibility, ContentId, Metadata, Outcome};
use li2core::contracts::{CONTRACT_VERSION, EntryCompleteness, ResumeObligation};
use li2core::engine::Tactic;
use li2core::planner::HookSemantics;
use li2core::trampoline::SavedExtendedStateFormat;
use liteinst_rewrite::carrier::elf64::{Elf64, ElfVaddr, ObjectType, ParseLimits, Storage};
use liteinst_rewrite::model::Selection;
use liteinst_rewrite::{Product, prepare, selection};
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const LIMIT: usize = 1024 * 1024;
const SUBJECT: u64 = 0x421100;
const LIMITS_ROW: &str = "limits 1048576 16 16 65536 64 1048576 262144 64 4294967296\n";

fn read(path: &Path) -> Vec<u8> {
    let file = File::open(path).unwrap();
    assert!(file.metadata().unwrap().is_file());
    let mut bytes = Vec::new();
    file.take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= LIMIT);
    bytes
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn replace_once(text: &str, old: &str, new: &str) -> String {
    assert_eq!(text.matches(old).count(), 1, "one exact mutation owner");
    text.replacen(old, new, 1)
}

// Fixed input geometry, independent of the planner's outcomes.
fn checked_input(original: &[u8], manifest: &[u8], name: &str) -> (Selection, usize) {
    let (core, mut body, heads, length, block, selected) = match name {
        "B2" => (
            Tactic::GeneralizedPun,
            vec![0x0f, 0x1f, 0, 0xb8, 42, 0, 0, 0, 0xc3],
            vec![0, 3, 8],
            3,
            9,
            SUBJECT + 5 + 0x2ab80000 + 0x8000,
        ),
        "T1" => (
            Tactic::PrefixedPun,
            vec![0x89, 0xc0, 0xb8, 42, 0, 0, 0, 0xc3],
            vec![0, 2, 7],
            2,
            8,
            SUBJECT + 6 + 0x2ab8,
        ),
        "T2" => (
            Tactic::SuccessorEviction,
            vec![
                0x0f, 0x1f, 0, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3,
            ],
            vec![0, 3, 11, 16, 64, 74],
            3,
            17,
            SUBJECT + 5 + 0x56e90000 + 0x8000,
        ),
        "T3" => (
            Tactic::NeighborEviction,
            vec![0x75, 1, 0x90, 0xc3],
            vec![0, 2, 3, 64, 74],
            2,
            2,
            SUBJECT + 0x4000000,
        ),
        _ => panic!("finite tactic required"),
    };
    if matches!(name, "T2" | "T3") {
        body.resize(64, 0x90);
        body.extend_from_slice(&[0x48, 0xb8]);
        body.extend_from_slice(&42_u64.to_le_bytes());
        body.push(0xc3);
    }
    let victim = if name == "T2" {
        SUBJECT + 8 + 0x00123456
    } else {
        SUBJECT + 0x6000000
    };
    let s = selection::parse(manifest).unwrap();
    assert_eq!(s.original, ContentId::of(original));
    assert_eq!(s.manifest, manifest);
    assert_eq!(s.bias_domain, 1);
    assert_eq!(s.carrier_pc, 0x422000);
    assert_eq!(
        s.target.format(),
        SavedExtendedStateFormat::XSAVE64_STANDARD
    );
    assert_eq!((s.sites.len(), s.hooks.len()), (1, 1));
    let text = std::str::from_utf8(manifest).unwrap();
    assert_eq!(text.matches(LIMITS_ROW).count(), 1);
    let search_row = format!("search 1 {name} 0 80 1 {} 64 256\n", SUBJECT + 64);
    assert_eq!(text.matches(search_row.as_str()).count(), 1);
    let site = &s.sites[0];
    assert_eq!((site.id, site.pc, site.length), (1, SUBJECT, length));
    assert_eq!(site.forced, Some(core));
    assert_eq!(site.semantics, HookSemantics::Observe);
    assert_eq!(site.completeness, EntryCompleteness::Complete);
    assert_eq!(site.resumes, ResumeObligation::NoneExist);
    assert_eq!(
        site.heads
            .iter()
            .map(|h| (h.address, h.requires_endbr))
            .collect::<Vec<_>>(),
        heads
            .iter()
            .map(|&h| (SUBJECT + h, false))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        (site.snapshot.start(), site.snapshot.len()),
        (SUBJECT - 16, u64::try_from(body.len() + 16).unwrap())
    );
    assert_eq!(
        (site.function.start(), site.function.len()),
        (SUBJECT, u64::try_from(body.len()).unwrap())
    );
    assert_eq!((site.block.start(), site.block.len()), (SUBJECT, block));
    for (policy, address) in [
        (&site.selected_allocation, selected),
        (&site.victim_allocation, victim),
    ] {
        assert_eq!(policy.preferred_address, Some(address));
        assert_eq!(
            (
                policy.max_candidates,
                policy.max_mappings,
                policy.max_mapped_bytes
            ),
            (256, 1, 8192)
        );
        assert_eq!(policy.ranges.len(), 1);
        assert_eq!(
            (policy.ranges[0].start(), policy.ranges[0].len()),
            (address & !4095, 8192)
        );
    }
    let elf = Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: 64,
        },
    )
    .unwrap();
    assert_eq!(elf.header().object_type, ObjectType::Executable);
    assert_eq!(elf.header().entry, ElfVaddr(0x401000));
    elf.check_load_page_congruence(4096).unwrap();
    assert_eq!(
        elf.executable_bytes(ElfVaddr(SUBJECT), body.len() as u64)
            .unwrap(),
        body
    );
    assert_eq!(
        elf.executable_bytes(ElfVaddr(SUBJECT - 16), 16).unwrap(),
        [0x90; 16]
    );
    let owner = elf
        .virtual_to_storage(ElfVaddr(SUBJECT), body.len() as u64)
        .unwrap();
    assert_eq!(owner.flags.0, 5);
    let Storage::FileBacked(range) = owner.storage else {
        panic!("file-backed subject required")
    };
    assert_eq!(site.file_offset, range.start().0);
    let hook = &s.hooks[0];
    assert_eq!(site.hook, hook.id);
    assert!(matches!(
        (hook.id, hook.pc, hook.length),
        (2, 0x401200, 1) | (3, 0x401220, 19)
    ));
    let owner = elf
        .virtual_to_storage(ElfVaddr(hook.pc), hook.length as u64)
        .unwrap();
    assert_eq!(owner.flags.0, 5);
    let Storage::FileBacked(range) = owner.storage else {
        panic!("file-backed hook required")
    };
    let hook_bytes = elf
        .executable_bytes(ElfVaddr(hook.pc), hook.length as u64)
        .unwrap();
    let expected_hook = if hook.id == 2 {
        vec![0xc3]
    } else {
        vec![
            0x48, 0x8b, 0x07, 0x48, 0x89, 0x05, 0xde, 0x2d, 0, 0, 0x48, 0x83, 0x05, 0xce, 0x2d, 0,
            0, 1, 0xc3,
        ]
    };
    assert_eq!(hook_bytes, expected_hook);
    assert_eq!(hook.expected, ContentId::of(hook_bytes));
    let hook_offset = usize::try_from(range.start().0).unwrap();
    (s, hook_offset)
}
fn target_record(s: &Selection) -> Vec<u8> {
    let state = s.target;
    let mut out = format!(
        "LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t{}\nformat\txsave64-standard\nallocation_bytes\t{}\nimage_bytes\t{}\nxcr0_mask\t{}\nqualification_complete\tfalse\n",
        s.bias_domain,
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
fn refused(original: &[u8], manifest: &[u8], code: u32) {
    let original_before = original.to_vec();
    let manifest_before = manifest.to_vec();
    let s = selection::parse(manifest).unwrap();
    let product: Product =
        prepare(original, manifest).expect("typed site refusal, not parser/identity error");
    assert_eq!(original, original_before);
    assert_eq!(manifest, manifest_before);
    assert!(!product.candidate_complete() && !product.qualification_complete());
    assert_eq!(product.reports().len(), 1);
    let report = &product.reports()[0];
    let site = &s.sites[0];
    assert_eq!(
        (report.id, report.pc, report.length, report.file_offset),
        (1, SUBJECT, site.length, site.file_offset)
    );
    assert_eq!(report.refusal_code, Some(code));
    assert_eq!(report.refusal.as_ref().unwrap().stage, "core");
    assert!(!report.candidate_emitted && report.core_tactic.is_none());
    assert!(!product.files().contains_key("candidate.elf"));
    assert!(!product.files().contains_key("source.li2sparse"));
    assert!(!product.files().keys().any(|n| n.starts_with("image-")));
    assert_eq!(product.files()["selection.txt"], manifest);
    let target = target_record(&s);
    assert_eq!(product.files()["target.tsv"], target);
    let policy = Compatibility {
        planner: CONTRACT_VERSION,
        encoder: 1,
        hook_abi: 1,
        arena: 1,
        target: ContentId::of(&target),
        binding: ContentId::of(manifest),
    };
    let metadata = Metadata::decode(
        &product.files()["metadata.li2meta"],
        &policy,
        formats::Limits {
            bytes: LIMIT,
            chunks: LIMIT.div_ceil(formats::CHUNK_BYTES),
            sites: 1,
        },
    )
    .unwrap();
    metadata.verify_original(original).unwrap();
    metadata
        .verify_selection(ContentId::of(manifest), &[1])
        .unwrap();
    assert_eq!(metadata.compatibility(), &policy);
    assert_eq!(metadata.sites().len(), 1);
    assert_eq!(metadata.sites()[0].outcome, Outcome::Refused(code));
    assert!(!metadata.declares_complete_trampoline_coverage());
}
fn identity_error(original: &[u8], manifest: &[u8], stage: &str, detail: &str) {
    let before = original.to_vec();
    let selection_before = manifest.to_vec();
    selection::parse(manifest).unwrap();
    let error = prepare(original, manifest).unwrap_err();
    assert_eq!(error.stage, stage);
    assert_eq!(error.detail, detail);
    assert_eq!(original, before);
    assert_eq!(manifest, selection_before);
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        4,
        "check_elf_tactic_refusals ORIGINAL SELECTION TACTIC"
    );
    let name = args[3].to_str().unwrap();
    let original = read(Path::new(&args[1]));
    let manifest = read(Path::new(&args[2]));
    let (s, hook_offset) = checked_input(&original, &manifest, name);
    let text = std::str::from_utf8(&manifest).unwrap();
    let mut results = Vec::new();

    let unknown = replace_once(text, "entries 1 complete ", "entries 1 unknown ");
    refused(&original, unknown.as_bytes(), 7);
    results.push("unknown-entries Refused(7) no-artifact");

    let mut source_tamper = original.clone();
    source_tamper[usize::try_from(s.sites[0].file_offset).unwrap()] ^= 1;
    identity_error(
        &source_tamper,
        &manifest,
        "original-identity",
        "\"SHA-256 mismatch\"",
    );
    results.push("source-byte-tamper original-identity");

    let mut hook_tamper = original.clone();
    hook_tamper[hook_offset] ^= 1;
    let rebound = replace_once(
        text,
        &format!("original {}\n", hex(&s.original.0)),
        &format!("original {}\n", hex(&ContentId::of(&hook_tamper).0)),
    );
    assert_eq!(
        selection::parse(rebound.as_bytes()).unwrap().hooks[0].expected,
        s.hooks[0].expected
    );
    identity_error(
        &hook_tamper,
        rebound.as_bytes(),
        "hook-identity",
        &s.hooks[0].id.to_string(),
    );
    results.push("hook-byte-tamper-rebound-original hook-identity");

    let policy = &s.sites[0].selected_allocation;
    let selected = policy.preferred_address.unwrap();
    let old = format!(
        "allocation 1 selected {selected} 256 8192 {}:8192\n",
        selected & !4095
    );
    // A real occupied original RX page is the only allowed selected placement.
    // Candidate/search quotas stay fixed; no fresh page may overwrite it.
    let new = format!(
        "allocation 1 selected {selected} 256 8192 {}:4096\n",
        SUBJECT & !4095
    );
    let unavailable = replace_once(text, &old, &new);
    refused(&original, unavailable.as_bytes(), 11);
    results.push("selected-placement-unavailable Refused(11) no-artifact");

    if matches!(name, "T2" | "T3") {
        let one = replace_once(
            text,
            LIMITS_ROW,
            "limits 1048576 16 1 65536 64 1048576 262144 64 4294967296\n",
        );
        refused(&original, one.as_bytes(), 11);
        results.push("one-image-budget Refused(11) no-artifact");
    }
    assert_eq!(
        results.len(),
        if matches!(name, "T2" | "T3") { 5 } else { 4 }
    );
    assert_eq!(read(Path::new(&args[1])), original, "original file changed");
    assert_eq!(
        read(Path::new(&args[2])),
        manifest,
        "selection file changed"
    );
    for result in &results {
        println!("{name} {result}");
    }
    println!(
        "PASS adjacent tactic refusals: tactic={name} cases={} qualification_complete=false",
        results.len()
    );
}
