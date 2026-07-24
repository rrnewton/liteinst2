#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use goblin::elf::Elf;
use goblin::elf::program_header::PF_X;
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use liteinst2::patcher::{JumpPatchPlan, PatchError};
use liteinst2::scanner::InstructionScanner;

const REQUESTED_BINARIES: [&str; 4] = [
    "/bin/ls",
    "/bin/cat",
    "/usr/bin/python3",
    "/usr/bin/sqlite3",
];
const STALE_WINDOWS_PER_IMAGE: usize = 16;

#[derive(Clone, Copy)]
struct DecodedInstruction {
    offset: usize,
    address: u64,
    len: usize,
}

#[derive(Default)]
struct SiteCounts {
    found: usize,
    patched: usize,
    missed: usize,
}

#[derive(Default)]
struct BinaryMetrics {
    images: usize,
    instructions: usize,
    syscall: SiteCounts,
    cpuid: SiteCounts,
    rdtsc: SiteCounts,
    stale_windows: usize,
    stale_rejected: usize,
    stale_accepted: usize,
}

#[test]
#[ignore = "requires the requested distro binaries and their dynamic dependency closure"]
fn requested_real_binary_patch_matrix_rejects_stale_plans() {
    for binary in REQUESTED_BINARIES {
        let images = loaded_images(Path::new(binary));
        let mut metrics = BinaryMetrics::default();
        for image in &images {
            scan_image(image, &mut metrics);
        }

        let target_sites = metrics.syscall.found + metrics.cpuid.found + metrics.rdtsc.found;
        assert!(
            target_sites > 0,
            "{binary} dependency closure exposed no nondeterministic instruction sites"
        );
        assert_eq!(
            metrics.syscall.patched + metrics.syscall.missed,
            metrics.syscall.found
        );
        assert_eq!(
            metrics.cpuid.patched + metrics.cpuid.missed,
            metrics.cpuid.found
        );
        assert_eq!(
            metrics.rdtsc.patched + metrics.rdtsc.missed,
            metrics.rdtsc.found
        );
        assert!(
            metrics.stale_windows >= images.len(),
            "{binary} produced too few same-layout mutation witnesses: {} across {} images",
            metrics.stale_windows,
            images.len()
        );
        assert_eq!(
            metrics.stale_accepted, 0,
            "{binary} accepted {} stale plans out of {} real instruction windows",
            metrics.stale_accepted, metrics.stale_windows
        );
        assert_eq!(metrics.stale_rejected, metrics.stale_windows);

        eprintln!(
            "real-binary path={binary} images={} instructions={} syscall(patched={},missed={}) cpuid(patched={},missed={}) rdtsc(patched={},missed={}) stale(rejected={},accepted={})",
            metrics.images,
            metrics.instructions,
            metrics.syscall.patched,
            metrics.syscall.missed,
            metrics.cpuid.patched,
            metrics.cpuid.missed,
            metrics.rdtsc.patched,
            metrics.rdtsc.missed,
            metrics.stale_rejected,
            metrics.stale_accepted,
        );
    }
}

fn loaded_images(binary: &Path) -> BTreeSet<PathBuf> {
    assert!(
        binary.is_file() || binary.is_symlink(),
        "required binary {} is missing",
        binary.display()
    );
    let mut images = BTreeSet::from([fs::canonicalize(binary)
        .unwrap_or_else(|error| panic!("failed to canonicalize {}: {error}", binary.display()))]);
    let output = Command::new("ldd")
        .arg(binary)
        .output()
        .unwrap_or_else(|error| panic!("failed to run ldd on {}: {error}", binary.display()));
    assert!(
        output.status.success(),
        "ldd failed for {}: {}",
        binary.display(),
        String::from_utf8_lossy(&output.stderr)
    );

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let candidate = match line.split_once("=>") {
            Some((_, remainder)) => remainder.split_whitespace().next(),
            None => line.split_whitespace().next(),
        };
        let Some(candidate) = candidate.filter(|candidate| candidate.starts_with('/')) else {
            continue;
        };
        let candidate = Path::new(candidate);
        if candidate.is_file() {
            images.insert(fs::canonicalize(candidate).unwrap_or_else(|error| {
                panic!("failed to canonicalize {}: {error}", candidate.display())
            }));
        }
    }
    images
}

fn scan_image(path: &Path, metrics: &mut BinaryMetrics) {
    let bytes =
        fs::read(path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let elf = Elf::parse(&bytes)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
    metrics.images += 1;

    for header in elf
        .program_headers
        .iter()
        .filter(|header| header.p_flags & PF_X != 0 && header.p_filesz != 0)
    {
        let start = usize::try_from(header.p_offset).expect("ELF offset fits usize");
        let file_len = usize::try_from(header.p_filesz).expect("ELF length fits usize");
        let end = start.checked_add(file_len).expect("ELF segment range");
        let code = bytes
            .get(start..end)
            .unwrap_or_else(|| panic!("invalid executable segment in {}", path.display()));
        scan_segment(code, header.p_vaddr, metrics);
    }
}

fn scan_segment(code: &[u8], base: u64, metrics: &mut BinaryMetrics) {
    let mut decoder = Decoder::with_ip(64, code, base, DecoderOptions::NONE);
    let mut decoded = Vec::new();

    while decoder.can_decode() {
        let offset = decoder.position();
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        metrics.instructions += 1;
        let record = DecodedInstruction {
            offset,
            address: instruction.ip(),
            len: instruction.len(),
        };
        match instruction.mnemonic() {
            Mnemonic::Syscall => measure_target(code, record, &mut metrics.syscall),
            Mnemonic::Cpuid => measure_target(code, record, &mut metrics.cpuid),
            Mnemonic::Rdtsc => measure_target(code, record, &mut metrics.rdtsc),
            _ => {}
        }
        decoded.push(record);
    }

    let mut witnesses = 0;
    for (index, instruction) in decoded.iter().enumerate() {
        if witnesses >= STALE_WINDOWS_PER_IMAGE || instruction.len < 5 {
            continue;
        }
        let Some((original, mutated)) = same_layout_mutation(code, &decoded, index) else {
            continue;
        };
        witnesses += 1;
        metrics.stale_windows += 1;

        let scanner = InstructionScanner::default();
        let scan = scanner
            .scan(&original, instruction.address)
            .expect("selected original window must decode");
        let target = instruction
            .address
            .checked_add(0x1000)
            .expect("near target");
        match JumpPatchPlan::from_scan(
            &scanner,
            &scan,
            &mutated,
            instruction.address,
            instruction.address,
            target,
        ) {
            Err(PatchError::RegionMismatch { .. }) => metrics.stale_rejected += 1,
            Ok(_) => metrics.stale_accepted += 1,
            Err(error) => panic!(
                "unexpected stale-plan result for {:#x}: {error}",
                instruction.address
            ),
        }
    }
}

fn measure_target(code: &[u8], instruction: DecodedInstruction, counts: &mut SiteCounts) {
    counts.found += 1;
    let end = instruction
        .offset
        .checked_add(instruction.len)
        .expect("instruction range");
    let bytes = &code[instruction.offset..end];
    let scanner = InstructionScanner::default();
    let scan = scanner
        .scan(bytes, instruction.address)
        .expect("decoded target instruction must rescan");
    let target = instruction
        .address
        .checked_add(0x1000)
        .expect("near target");
    match JumpPatchPlan::from_scan(
        &scanner,
        &scan,
        bytes,
        instruction.address,
        instruction.address,
        target,
    ) {
        Ok(_) => counts.patched += 1,
        Err(PatchError::InstructionTooShort { .. }) => counts.missed += 1,
        Err(error) => panic!(
            "unexpected direct-plan result for {:#x}: {error}",
            instruction.address
        ),
    }
}

fn same_layout_mutation(
    code: &[u8],
    decoded: &[DecodedInstruction],
    index: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let first = decoded[index];
    let start = first.offset;
    let mut end = start.checked_add(first.len)?;
    let mut next = index + 1;
    while end - start < 8 {
        let instruction = *decoded.get(next)?;
        if instruction.offset != end {
            return None;
        }
        end = end.checked_add(instruction.len)?;
        next += 1;
    }
    let original = code.get(start..end)?.to_vec();
    let scanner = InstructionScanner::default();
    let original_scan = scanner.scan(&original, first.address).ok()?;

    for byte in 1..first.len {
        for bit in [1_u8, 2, 4, 8, 0x10, 0x20, 0x40, 0x80] {
            let mut mutated = original.clone();
            mutated[byte] ^= bit;
            let Ok(mutated_scan) = scanner.scan(&mutated, first.address) else {
                continue;
            };
            if original_scan.sites() == mutated_scan.sites()
                && original_scan.instructions()[0].instruction()
                    != mutated_scan.instructions()[0].instruction()
            {
                return Some((original, mutated));
            }
        }
    }
    None
}
