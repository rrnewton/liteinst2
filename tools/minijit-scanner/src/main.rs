//! Scanner oracle + speed driver.
//!
//! For each ELF input, extract the `.text` section (falling back
//! to the largest executable PT_LOAD), walk instruction
//! boundaries with iced-x86, and at every boundary compare the
//! table scanner against iced plus liteinst-jit admission. Then
//! measure scanner-only, iced streaming decode-only, scanner
//! fast-path end-to-end (memcpy movable runs + full decode for
//! the rest), and full-decode-everything throughput. Component
//! costs only; no whole-program claim.

use std::process::ExitCode;
use std::time::Instant;

use iced_x86::{Decoder, DecoderOptions, Instruction};
use liteinst_jit::decode::{InsnClass, SupportedDecoder, decode_one, decode_supported};
use minijit_scanner::{Scan, scan_one};

const SAMPLES: usize = 10;

fn median_iqr(mut v: Vec<f64>) -> (f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let med = if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    };
    let q = |p: f64| v[((n as f64 - 1.0) * p).round() as usize];
    (med, q(0.75) - q(0.25))
}

fn bench(reps: u64, mut f: impl FnMut() -> u64) -> (f64, f64) {
    let mut times = Vec::new();
    for _ in 0..=SAMPLES {
        let t = Instant::now();
        let mut acc = 0u64;
        for _ in 0..reps {
            acc = acc.wrapping_add(f());
        }
        std::hint::black_box(acc);
        times.push(t.elapsed().as_secs_f64() / reps as f64);
    }
    median_iqr(times.split_off(1))
}

struct TextSegment {
    bytes: Vec<u8>,
    vaddr: u64,
    kind: &'static str,
}

fn elf_text(f: &[u8]) -> Result<TextSegment, &'static str> {
    // All header/section slicing is bounds-checked: malformed or
    // truncated input returns Err so the driver can report
    // BLOCKED (still with zero speed cells) instead of panicking.
    let u16le = |o: usize| -> Option<usize> {
        f.get(o..o + 2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()) as usize)
    };
    let u32le = |o: usize| -> Option<u32> {
        f.get(o..o + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let u64le = |o: usize| -> Option<u64> {
        f.get(o..o + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    };
    let slice = |off: u64, size: u64| -> Option<&[u8]> {
        let off = usize::try_from(off).ok()?;
        let end = off.checked_add(usize::try_from(size).ok()?)?;
        f.get(off..end)
    };
    if f.len() < 64 || &f[0..4] != b"\x7fELF" || f[4] != 2 || f[5] != 1 {
        return Err("not a little-endian ELF64 file");
    }
    let shoff = u64le(40).ok_or("truncated ELF header")? as usize;
    let shentsize = u16le(58).ok_or("truncated ELF header")?;
    let shnum = u16le(60).ok_or("truncated ELF header")?;
    let shstrndx = u16le(62).ok_or("truncated ELF header")?;
    if shoff != 0 && shnum > 0 && shstrndx < shnum {
        if shentsize < 64 {
            return Err("section header entry too small");
        }
        let str_hdr = shoff
            .checked_add(
                shstrndx
                    .checked_mul(shentsize)
                    .ok_or("section header overflow")?,
            )
            .ok_or("section header overflow")?;
        if f.get(str_hdr..str_hdr + 64).is_none() {
            return Err("truncated section headers");
        }
        let names = slice(
            u64le(str_hdr + 24).ok_or("truncated section headers")?,
            u64le(str_hdr + 32).ok_or("truncated section headers")?,
        )
        .ok_or("section string table out of bounds")?;
        for i in 0..shnum {
            let h = shoff
                .checked_add(i.checked_mul(shentsize).ok_or("section header overflow")?)
                .ok_or("section header overflow")?;
            if f.get(h..h + 64).is_none() {
                return Err("truncated section headers");
            }
            let name_off = u32le(h).ok_or("truncated section headers")? as usize;
            let Some(name) = names.get(name_off..) else {
                continue;
            };
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            if &name[..end] == b".text" {
                let addr = u64le(h + 16).ok_or("truncated section headers")?;
                let off = u64le(h + 24).ok_or("truncated section headers")?;
                let size = u64le(h + 32).ok_or("truncated section headers")?;
                return Ok(TextSegment {
                    bytes: slice(off, size)
                        .ok_or(".text section out of bounds")?
                        .to_vec(),
                    vaddr: addr,
                    kind: ".text section",
                });
            }
        }
    }
    let phoff = u64le(32).ok_or("truncated ELF header")? as usize;
    let phentsize = u16le(54).ok_or("truncated ELF header")?;
    let phnum = u16le(56).ok_or("truncated ELF header")?;
    if phnum > 0 && phentsize < 56 {
        return Err("program header entry too small");
    }
    let mut best = None;
    for i in 0..phnum {
        let p = phoff
            .checked_add(i.checked_mul(phentsize).ok_or("program header overflow")?)
            .ok_or("program header overflow")?;
        if f.get(p..p + 56).is_none() {
            return Err("truncated program headers");
        }
        if u32le(p) == Some(1) && u32le(p + 4).is_some_and(|flags| flags & 1 != 0) {
            let off = u64le(p + 8).ok_or("truncated program headers")?;
            let vaddr = u64le(p + 16).ok_or("truncated program headers")?;
            let filesz = u64le(p + 32).ok_or("truncated program headers")?;
            if best.is_none_or(|(_, _, l)| filesz > l) {
                best = Some((off, vaddr, filesz));
            }
        }
    }
    let (off, vaddr, len) = best.ok_or("no executable PT_LOAD or .text section")?;
    Ok(TextSegment {
        bytes: slice(off, len)
            .ok_or("executable PT_LOAD out of bounds")?
            .to_vec(),
        vaddr,
        kind: "executable PT_LOAD",
    })
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[derive(Default)]
struct OracleStats {
    boundaries: u64,
    skipped_bytes: u64,
    length_disagreements: u64,
    false_movable: u64,
    missed_movable: u64,
    relative_mismatches: u64,
    rip_mismatches: u64,
    intercept_mismatches: u64,
    scanner_movable_insns: u64,
    scanner_movable_bytes: u64,
    oracle_movable_insns: u64,
    relative_sites: u64,
    rip_sites: u64,
    intercept_sites: u64,
    examples: Vec<String>,
}

fn oracle_relative(ins: &Instruction, class: InsnClass) -> bool {
    let _ = ins;
    matches!(
        class,
        InsnClass::CondBranch { .. } | InsnClass::DirectJump { .. } | InsnClass::DirectCall { .. }
    )
}

fn validate(seg: &TextSegment) -> OracleStats {
    let bytes = &seg.bytes;
    let mut st = OracleStats::default();
    let mut off = 0usize;
    let mut dec = Decoder::with_ip(64, bytes, seg.vaddr, DecoderOptions::NONE);
    while off < bytes.len() {
        dec.set_position(off).expect("oracle position");
        dec.set_ip(seg.vaddr + off as u64);
        if !dec.can_decode() {
            // Fail closed: an invalid/truncated boundary is not
            // resynchronized by guessing the next byte.
            st.skipped_bytes += 1;
            st.examples.push(format!(
                "invalid-boundary pc={:#x} bytes={:02x?}",
                seg.vaddr + off as u64,
                &bytes[off..(off + 15).min(bytes.len())]
            ));
            break;
        }
        let ins = dec.decode();
        if ins.is_invalid() || ins.len() == 0 || off + ins.len() > bytes.len() {
            st.skipped_bytes += 1;
            st.examples.push(format!(
                "invalid-boundary pc={:#x} bytes={:02x?}",
                seg.vaddr + off as u64,
                &bytes[off..(off + 15).min(bytes.len())]
            ));
            break;
        }
        let pc = seg.vaddr + off as u64;
        let scan: Scan = scan_one(&bytes[off..], pc);
        let reference = decode_one(&bytes[off..], pc).expect("iced boundary decodes");
        let admitted = decode_supported(&bytes[off..], pc);
        let o_relative = oracle_relative(&ins, reference.class);
        let o_rip = ins.is_ip_rel_memory_operand();
        let o_intercept = matches!(reference.class, InsnClass::Syscall | InsnClass::Nondet(_));
        let o_movable = matches!(admitted, Ok(ref d) if d.class == InsnClass::Ordinary)
            && !o_relative
            && !o_rip
            && !o_intercept;
        st.boundaries += 1;
        st.relative_sites += u64::from(o_relative);
        st.rip_sites += u64::from(o_rip);
        st.intercept_sites += u64::from(o_intercept);
        st.oracle_movable_insns += u64::from(o_movable);
        st.scanner_movable_insns += u64::from(scan.allowlisted_movable);
        if scan.allowlisted_movable {
            st.scanner_movable_bytes += scan.len as u64;
        }
        if scan.len != ins.len() {
            st.length_disagreements += 1;
            if st.examples.len() < 12 {
                st.examples.push(format!(
                    "len pc={pc:#x} iced={} scan={} bytes={:02x?}",
                    ins.len(),
                    scan.len,
                    &bytes[off..(off + 15).min(bytes.len())]
                ));
            }
        }
        if scan.relative_branch_or_call != o_relative {
            st.relative_mismatches += 1;
            if st.examples.len() < 12 {
                st.examples.push(format!(
                    "relative pc={pc:#x} oracle={o_relative} scan={} bytes={:02x?}",
                    scan.relative_branch_or_call,
                    &bytes[off..(off + ins.len()).min(bytes.len())]
                ));
            }
        }
        if scan.rip_relative != o_rip {
            st.rip_mismatches += 1;
            if st.examples.len() < 12 {
                st.examples.push(format!(
                    "rip pc={pc:#x} oracle={o_rip} scan={} bytes={:02x?}",
                    scan.rip_relative,
                    &bytes[off..(off + ins.len()).min(bytes.len())]
                ));
            }
        }
        if scan.interception_target != o_intercept {
            st.intercept_mismatches += 1;
            if st.examples.len() < 12 {
                st.examples.push(format!(
                    "intercept pc={pc:#x} oracle={o_intercept} scan={} class={:?} bytes={:02x?}",
                    scan.interception_target,
                    reference.class,
                    &bytes[off..(off + ins.len()).min(bytes.len())]
                ));
            }
        }
        if scan.allowlisted_movable && !o_movable {
            st.false_movable += 1;
            if st.examples.len() < 12 {
                st.examples.push(format!(
                    "false-movable pc={pc:#x} bytes={:02x?} class={:?} rip={o_rip}",
                    &bytes[off..(off + ins.len()).min(bytes.len())],
                    reference.class
                ));
            }
        } else if o_movable && !scan.allowlisted_movable {
            st.missed_movable += 1;
        }
        off += ins.len();
    }
    st
}

fn scanner_seq(bytes: &[u8], base: u64) -> u64 {
    let mut off = 0usize;
    let mut acc = 0u64;
    while off < bytes.len() {
        let s = scan_one(&bytes[off..], base + off as u64);
        if s.len == 0 {
            break; // no guessed resynchronization
        }
        acc = acc
            .wrapping_add(s.len as u64)
            .wrapping_add(u64::from(s.allowlisted_movable));
        off += s.len;
    }
    acc
}

fn iced_stream(bytes: &[u8], base: u64) -> u64 {
    let mut dec = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut acc = 0u64;
    while dec.can_decode() {
        let ins = dec.decode();
        if ins.is_invalid() || ins.len() == 0 {
            break; // benches run only after the fail-closed gate
        }
        acc = acc.wrapping_add(ins.len() as u64);
    }
    acc
}

fn supported_stream(bytes: &[u8], base: u64, boundaries: u64) -> u64 {
    // Sequential S3-A supported decoding over the validated
    // boundary count. The corpora used here have zero skipped
    // bytes, so each call advances by one valid instruction even
    // when admission refuses it.
    let mut dec = SupportedDecoder::new(bytes, base);
    let mut acc = 0u64;
    for _ in 0..boundaries {
        acc = acc.wrapping_add(u64::from(dec.next_supported().is_ok()));
    }
    acc
}

fn fast_end_to_end(bytes: &[u8], base: u64, dst: &mut [u8]) -> u64 {
    let mut full = SupportedDecoder::new(bytes, base);
    let mut off = 0usize;
    let mut run = 0usize;
    let mut acc = 0u64;
    while off < bytes.len() {
        let s = scan_one(&bytes[off..], base + off as u64);
        if s.allowlisted_movable {
            off += s.len;
            continue;
        }
        if run < off {
            dst[run..off].copy_from_slice(&bytes[run..off]);
        }
        // The next boundary comes from the full decoder, never
        // from a guessed scanner step: use its admitted length,
        // or iced's decoded length when admission refuses.
        let supported = full
            .reset(base + off as u64)
            .and_then(|()| full.next_supported());
        let step = match &supported {
            Ok(d) => d.len,
            Err(_) => match decode_one(&bytes[off..], base + off as u64) {
                Some(d) => d.len,
                None => break,
            },
        };
        acc = acc
            .wrapping_add(u64::from(supported.is_ok()))
            .wrapping_add(step as u64);
        dst[off..off + step].copy_from_slice(&bytes[off..off + step]);
        off += step;
        run = off;
    }
    if run < off {
        dst[run..off].copy_from_slice(&bytes[run..off]);
    }
    acc.wrapping_add(dst[bytes.len() / 2] as u64)
}

fn full_end_to_end(bytes: &[u8], base: u64, dst: &mut [u8]) -> u64 {
    let mut dec = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut off = 0usize;
    let mut acc = 0u64;
    while off < bytes.len() {
        dec.set_position(off).expect("full position");
        dec.set_ip(base + off as u64);
        if !dec.can_decode() {
            break;
        }
        let ins = dec.decode();
        if ins.is_invalid() || ins.len() == 0 {
            break;
        }
        let supported = decode_supported(&bytes[off..], base + off as u64);
        acc = acc
            .wrapping_add(u64::from(supported.is_ok()))
            .wrapping_add(ins.len() as u64);
        dst[off..off + ins.len()].copy_from_slice(&bytes[off..off + ins.len()]);
        off += ins.len();
    }
    acc.wrapping_add(dst[bytes.len() / 2] as u64)
}

fn reps_for(len: usize) -> u64 {
    if len < 4_000_000 { 20 } else { 1 }
}

fn rate_mbs(len: usize, sec_per_rep: f64) -> f64 {
    len as f64 / sec_per_rep / 1e6
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = if args.is_empty() {
        vec![
            "/lib64/libc.so.6".to_string(),
            "/usr/lib64/libLLVM.so.22.1".to_string(),
        ]
    } else {
        args
    };
    println!("constraint=known-boundaries-only samples={SAMPLES} warmup=1");
    println!(
        "corpus,kind,vaddr,bytes,file_fnv1a64,boundaries,skipped,length_disagreements,false_movable,missed_movable,relative_mismatches,rip_mismatches,intercept_mismatches,fallback_fraction,scanner_movable_insn_fraction,scanner_movable_byte_fraction,relative_sites,rip_sites,intercept_sites"
    );
    let mut blocked = false;
    let mut segments = Vec::new();
    for path in &paths {
        let file_bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                println!("example,{path},read-error {e}");
                println!("BLOCKED: unreadable or malformed ELF input");
                return ExitCode::FAILURE;
            }
        };
        let hash = fnv1a(&file_bytes);
        let seg = match elf_text(&file_bytes) {
            Ok(seg) => seg,
            Err(msg) => {
                println!("example,{path},malformed-elf {msg}");
                println!("BLOCKED: unreadable or malformed ELF input");
                return ExitCode::FAILURE;
            }
        };
        let st = validate(&seg);
        let fallback = if st.boundaries == 0 {
            0.0
        } else {
            1.0 - st.scanner_movable_insns as f64 / st.boundaries as f64
        };
        println!(
            "{path},{},{:#x},{},{hash:#018x},{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{},{},{}",
            seg.kind,
            seg.vaddr,
            seg.bytes.len(),
            st.boundaries,
            st.skipped_bytes,
            st.length_disagreements,
            st.false_movable,
            st.missed_movable,
            st.relative_mismatches,
            st.rip_mismatches,
            st.intercept_mismatches,
            fallback,
            st.scanner_movable_insns as f64 / st.boundaries.max(1) as f64,
            st.scanner_movable_bytes as f64 / seg.bytes.len().max(1) as f64,
            st.relative_sites,
            st.rip_sites,
            st.intercept_sites
        );
        for e in &st.examples {
            println!("example,{path},{e}");
        }
        if st.skipped_bytes != 0
            || st.length_disagreements != 0
            || st.false_movable != 0
            || st.relative_mismatches != 0
            || st.rip_mismatches != 0
            || st.intercept_mismatches != 0
        {
            blocked = true;
        }
        segments.push((path.clone(), seg, st));
    }
    if blocked {
        println!(
            "BLOCKED: skipped/invalid boundary, length or class-flag disagreement, or non-conservative movable classification"
        );
        return ExitCode::FAILURE;
    }
    println!("corpus,mode,median_s_per_rep,iqr_s,mb_s,minsn_s,reps_per_sample");
    for (path, seg, st) in &segments {
        let bytes = &seg.bytes;
        let reps = reps_for(bytes.len());
        let mut dst = vec![0u8; bytes.len()];
        let minsn = |sec: f64| st.boundaries as f64 / sec / 1e6;
        let (m, q) = bench(reps, || scanner_seq(bytes, seg.vaddr));
        println!(
            "{path},scanner,{m:.6},{q:.6},{:.1},{:.2},{reps}",
            rate_mbs(bytes.len(), m),
            minsn(m)
        );
        let (m, q) = bench(reps, || iced_stream(bytes, seg.vaddr));
        println!(
            "{path},iced_stream,{m:.6},{q:.6},{:.1},{:.2},{reps}",
            rate_mbs(bytes.len(), m),
            minsn(m)
        );
        let (m, q) = bench(reps, || supported_stream(bytes, seg.vaddr, st.boundaries));
        println!(
            "{path},supported_stream,{m:.6},{q:.6},{:.1},{:.2},{reps}",
            rate_mbs(bytes.len(), m),
            minsn(m)
        );
        let (m, q) = bench(reps, || fast_end_to_end(bytes, seg.vaddr, &mut dst));
        println!(
            "{path},fast_end_to_end,{m:.6},{q:.6},{:.1},{:.2},{reps}",
            rate_mbs(bytes.len(), m),
            minsn(m)
        );
        let (m, q) = bench(reps, || full_end_to_end(bytes, seg.vaddr, &mut dst));
        println!(
            "{path},full_end_to_end,{m:.6},{q:.6},{:.1},{:.2},{reps}",
            rate_mbs(bytes.len(), m),
            minsn(m)
        );
    }
    ExitCode::SUCCESS
}
