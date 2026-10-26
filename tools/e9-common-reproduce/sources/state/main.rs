//! Separate E9 passthrough oracle over actual corrected-backend ELF file bytes.
//! Manual fixture loading only; no loader admission or full A3 qualification.
#![deny(warnings)]

#[allow(dead_code)]
#[path = "quiescent_oracle.rs"]
mod oracle;

use liteinst2_artifact_draft::trampoline::SavedExtendedStateLayout;
mod sparse_module;
use sparse_module::BodyModule as FileModule;
use oracle::{FileLoad, FileTraceEvidence, TraceMap};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::Path;

const SEEDS: [u64; 2] = [0x1234_5678_8765_4320, 0xfedc_ba98_0123_4567];

struct Fixture {
    name: &'static str,
    body_kind: &'static str,
    original_path: &'static str,
    output_path: &'static str,
    original_sha256: &'static str,
    output_sha256: &'static str,
    original: &'static [u8],
    rewritten: &'static [u8],
    original_loads: &'static [FileLoad],
    output_loads: &'static [FileLoad],
    source_pc: u64,
    source_file_offset: usize,
    patched_source_file_offset: usize,
    source_page: u64,
    image_pc: u64,
    image_file_offset: usize,
    image_bytes: usize,
    restored_boundary: u64,
    min_vaddr: u64,
    max_vaddr: u64,
    target_profile: &'static str,
}
include!("fixtures.rs");

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn check_inputs(fixture: &Fixture) {
    assert_eq!(digest(fixture.original), fixture.original_sha256);
    assert_eq!(digest(fixture.rewritten), fixture.output_sha256);
    assert_eq!(
        std::fs::read(fixture.original_path).unwrap(),
        fixture.original
    );
    assert_eq!(
        std::fs::read(fixture.output_path).unwrap(),
        fixture.rewritten
    );
    // Agreement with the recorded fixture host description is required, but
    // does not establish early-loader, IFUNC or CPU-migration readiness.
    let actual = SavedExtendedStateLayout::detect().unwrap();
    assert_eq!(format!("{actual:#?}\n"), fixture.target_profile);
    let body = &fixture.original[fixture.source_file_offset..fixture.source_file_offset + 6];
    assert_eq!(body[0], 0xb8);
    assert_eq!(body[5], 0xc3);
    let image = &fixture.rewritten
        [fixture.image_file_offset..fixture.image_file_offset + fixture.image_bytes];
    // The copied ABI bootstrap remains part of the authenticated whole file,
    // but is not mapped or executed by this separate body-state oracle.
    assert_eq!(fixture.image_bytes, 10);
    assert_eq!(fixture.restored_boundary, fixture.image_pc);
    assert_eq!(&image[..5], &body[..5]);
    assert_eq!(image[5], 0xe9);
    let return_delta = i32::from_le_bytes(image[6..10].try_into().unwrap());
    assert_eq!(
        i128::from(fixture.image_pc) + 10 + i128::from(return_delta),
        i128::from(fixture.source_pc) + 5
    );
    let at = fixture.patched_source_file_offset;
    let patch = &fixture.rewritten[at..at + 5];
    assert_eq!(patch[0], 0xe9);
    let redirect_delta = i32::from_le_bytes(patch[1..5].try_into().unwrap());
    assert_eq!(
        i128::from(fixture.source_pc) + 5 + i128::from(redirect_delta),
        i128::from(fixture.image_pc)
    );
    assert_eq!(fixture.rewritten[at + 5], 0xc3);
    let in_page = usize::try_from(fixture.source_pc - fixture.source_page).unwrap();
    assert!(in_page + 6 < 2048);
    let original_page = fixture.source_file_offset.checked_sub(in_page).unwrap();
    let rewritten_page = at.checked_sub(in_page).unwrap();
    let mut expected_page = fixture.original[original_page..original_page + 4096].to_vec();
    expected_page[in_page..in_page + 5].copy_from_slice(patch);
    assert_eq!(
        &fixture.rewritten[rewritten_page..rewritten_page + 4096],
        expected_page.as_slice()
    );
    assert_eq!(fixture.original_loads.len(), 4);
    assert_eq!(fixture.output_loads.len(), 5);
}

fn backing_evidence(directory: &Path, file: &File, expected: &[u8]) {
    // Capture the same open fd supplied to mmap, never a replacement pathname.
    let before = file.metadata().unwrap();
    assert!(before.is_file());
    assert_eq!(before.len(), expected.len() as u64);
    let mut actual = vec![0; expected.len()];
    file.read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(actual, expected);
    let fd = file.as_raw_fd();
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap();
    let mount_ids: Vec<_> = fdinfo
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:\t"))
        .collect();
    assert_eq!(mount_ids.len(), 1);
    let mount_id: u64 = mount_ids[0].parse().unwrap();
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let owners: Vec<_> = mountinfo
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                == Some(mount_id)
        })
        .collect();
    assert_eq!(owners.len(), 1);
    let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
    let after = file.metadata().unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.len()),
        (after.dev(), after.ino(), after.len())
    );
    std::fs::write(
        directory.join("backing.tsv"),
        format!(
            "fd\t{fd}\nstat_dev\t{}\nstat_ino\t{}\nstat_size\t{}\nsha256\t{}\n",
            before.dev(),
            before.ino(),
            before.len(),
            digest(&actual)
        ),
    )
    .unwrap();
    std::fs::write(directory.join("fdinfo.txt"), fdinfo).unwrap();
    std::fs::write(directory.join("mountinfo.txt"), format!("{}\n", owners[0])).unwrap();
    std::fs::write(directory.join("backing-path.txt"), path.to_str().unwrap()).unwrap();
}

fn phase_evidence(directory: &Path, module: &FileModule, file: &File, expected: &[u8]) {
    std::fs::create_dir(directory).unwrap();
    backing_evidence(directory, file, expected);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    std::fs::write(directory.join("maps.txt"), &maps).unwrap();
    std::fs::write(directory.join("ownership.tsv"), module.ownership_tsv(&maps)).unwrap();
    let mut pages = String::from("address\tbytes\tsha256\n");
    for (address, bytes) in &module.expected_pages {
        writeln!(&mut pages, "{address}\t{}\t{}", bytes.len(), digest(bytes)).unwrap();
    }
    std::fs::write(directory.join("pages.tsv"), pages).unwrap();
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 2, "NEW_CAPTURE_DIRECTORY or --ownership-controls");
    if args[1] == "--ownership-controls" {
        assert_eq!(FIXTURES.len(), 6);
        for fixture in FIXTURES { check_inputs(fixture); }
        sparse_module::controls(FIXTURES);
        return;
    }
    let output = Path::new(&args[1]);
    assert!(!output.exists());
    std::fs::create_dir(output).unwrap();
    assert_eq!(FIXTURES.len(), 6);
    for fixture in FIXTURES {
        check_inputs(fixture);
    }
    let mut retained = Vec::new();
    let mut counts = [0_usize; 3]; // original, rewritten, restored original; exact no-hook evidence below.
    let mut all_biases = std::collections::BTreeSet::new();
    let mut case_inventory =
        String::from("fixture\tbias_index\tbias\tsource\timage\trestored_head\tterminal\n");
    for fixture in FIXTURES {
        let directory = output.join(fixture.name);
        std::fs::create_dir(&directory).unwrap();
        let original_file = File::open(fixture.original_path).unwrap();
        let rewritten_file = File::open(fixture.output_path).unwrap();
        let mut modules = [
            FileModule::new(
                fixture.min_vaddr,
                fixture.max_vaddr,
                fixture.source_page,
                &original_file,
                fixture.original,
                fixture.original_loads,
            ),
            FileModule::new(
                fixture.min_vaddr,
                fixture.max_vaddr,
                fixture.source_page,
                &original_file,
                fixture.original,
                fixture.original_loads,
            ),
        ];
        assert_ne!(
            modules[0].bias, modules[1].bias,
            "required common-bias variety was not observed"
        );
        for (bias_index, module) in modules.iter_mut().enumerate() {
            assert_eq!(module.kind(), fixture.body_kind);
            all_biases.insert(module.bias);
            let directory = directory.join(format!("bias-{bias_index}"));
            std::fs::create_dir(&directory).unwrap();
            let address = |pc: u64| module.bias.checked_add(pc).unwrap();
            let selected = address(fixture.source_pc);
            let image = address(fixture.image_pc);
            let restored = address(fixture.restored_boundary);
            let terminal = module.oracle.return_pc();
            let heads = [selected, selected + 5];
            let redirect = &fixture.rewritten[fixture.patched_source_file_offset..fixture.patched_source_file_offset + 5];
            let redirect_delta = i32::from_le_bytes(redirect[1..5].try_into().unwrap());
            let returned = &fixture.rewritten[fixture.image_file_offset + 6..fixture.image_file_offset + 10];
            let return_delta = i32::from_le_bytes(returned.try_into().unwrap());
            assert_eq!(i128::from(selected) + 5 + i128::from(redirect_delta), i128::from(image));
            assert_eq!(i128::from(image) + 10 + i128::from(return_delta), i128::from(selected) + 5);
            writeln!(
                &mut case_inventory,
                "{}\t{bias_index}\t{}\t{selected}\t{image}\t{restored}\t{terminal}",
                fixture.name, module.bias
            )
            .unwrap();
            let original_phase = directory.join("original");
            phase_evidence(&original_phase, module, &original_file, fixture.original);
            let mut originals = Vec::new();
            for (seed_index, seed) in SEEDS.into_iter().enumerate() {
                for (entry_index, &entry) in heads.iter().enumerate() {
                    let trace_dir =
                        original_phase.join(format!("entry-{entry_index}-seed-{seed_index}"));
                    std::fs::create_dir(&trace_dir).unwrap();
                    let evidence = FileTraceEvidence {
                        pages: &module.expected_pages,
                        directory: &trace_dir,
                        hook: None::<oracle::FileHookWitness>,
                    };
                    let trace = module.oracle.trace_original_file(
                        entry,
                        &heads,
                        &[terminal],
                        seed,
                        &evidence,
                    );
                    assert_eq!(
                        trace.visits(),
                        heads[entry_index..]
                            .iter()
                            .copied()
                            .chain([terminal])
                            .collect::<Vec<_>>()
                    );
                    originals.push((entry_index, seed_index, entry, trace));
                    counts[0] += 1;
                }
            }
            module.load(&rewritten_file, fixture.rewritten, fixture.output_loads);
            let replacement = fixture.rewritten
                [fixture.patched_source_file_offset..fixture.patched_source_file_offset + 5]
                .to_vec();
            module.oracle.assert_publication(&[(selected, replacement)]);
            let rewritten_phase = directory.join("rewritten");
            phase_evidence(&rewritten_phase, module, &rewritten_file, fixture.rewritten);
            let map = TraceMap {
                boundaries: vec![
                    (selected, restored),
                    (selected + 5, selected + 5),
                    (terminal, terminal),
                ],
                gateways: vec![selected],
                generated_ranges: std::iter::once(image..image + fixture.image_bytes as u64)
                    .collect(),
            };
            for (entry_index, seed_index, entry, trace) in &originals {
                let trace_dir =
                    rewritten_phase.join(format!("entry-{entry_index}-seed-{seed_index}"));
                std::fs::create_dir(&trace_dir).unwrap();
                let evidence = FileTraceEvidence {
                    pages: &module.expected_pages,
                    directory: &trace_dir,
                    // Exact frontend passthru RPC has no call. The unchanged
                    // file-trace helper requires zero witnessed hook calls.
                    hook: None,
                };
                module
                    .oracle
                    .assert_file_trace(trace, *entry, &map, &evidence);
                counts[1] += 1;
            }
            module.load(&original_file, fixture.original, fixture.original_loads);
            module.oracle.assert_publication(&[]);
            let restored_phase = directory.join("restored-original");
            phase_evidence(&restored_phase, module, &original_file, fixture.original);
            let original_map = TraceMap {
                boundaries: heads
                    .iter()
                    .copied()
                    .chain([terminal])
                    .map(|pc| (pc, pc))
                    .collect(),
                ..TraceMap::default()
            };
            for (entry_index, seed_index, entry, trace) in &originals {
                let trace_dir =
                    restored_phase.join(format!("entry-{entry_index}-seed-{seed_index}"));
                std::fs::create_dir(&trace_dir).unwrap();
                let evidence = FileTraceEvidence {
                    pages: &module.expected_pages,
                    directory: &trace_dir,
                    hook: None,
                };
                module
                    .oracle
                    .assert_file_trace(trace, *entry, &original_map, &evidence);
                counts[2] += 1;
            }
            check_inputs(fixture);
        }
        retained.extend(modules);
    }
    assert_eq!(retained.len(), 12);
    assert_eq!(retained.iter().map(FileModule::root_count).sum::<usize>(), 16);
    assert_eq!(retained.iter().map(FileModule::owned_bytes).sum::<u64>(), 416 * 1024);
    assert!(all_biases.len() >= 2);
    assert_eq!(counts, [48, 48, 48]);
    std::fs::write(output.join("cases.tsv"), case_inventory).unwrap();
    std::fs::write(output.join("complete.tsv"), format!("actual_output_files\t6\nretained_module_instances\t12\nreservation_roots\t16\nbody_owned_bytes\t425984\ndata_stack_owned_bytes\t884736\noriginal_traces\t48\nrewritten_comparisons\t48\nrestored_original_comparisons\t48\npassthru_hook_events\t0\nobserved_distinct_biases\t{}\nmanual_fixture_load\ttrue\nloader_admission\tfalse\nqualification_complete\tfalse\n", all_biases.len())).unwrap();
    println!(
        "actual E9 passthru file state oracle: 6 outputs, two distinct common biases each, 48 original/48 rewritten/48 restored-original, zero hook events; manual fixture load; artifact qualification incomplete"
    );
}
