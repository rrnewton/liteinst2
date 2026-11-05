//! S3 parallel-track component micro-benchmarks.
//!
//! Measures, over the executable PT_LOAD segment of a real ELF
//! (default /lib64/libc.so.6): streaming-copy throughput (plain,
//! AVX2, AVX2 non-temporal), iced-x86 decode-only throughput,
//! copy+scan (decode-classify branch/relocation sites), and
//! patch-in-place costs for insert-a-jump and insert-a-count at
//! sparse (1 in 100 sites) and dense (all sites) ratios.
//!
//! Every cell: exactly 10 timed samples after 1 warmup sample;
//! medians and IQRs are over the 10. These are component costs
//! only — no whole-program or comparative DBT claim is made.

use std::time::Instant;

use iced_x86::{Decoder, DecoderOptions, Mnemonic};

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

/// Run `f` `reps` times per sample; return median/IQR seconds per rep.
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

struct Aligned {
    ptr: *mut u8,
    len: usize,
    layout: std::alloc::Layout,
}

impl Aligned {
    fn new(len: usize) -> Aligned {
        let layout = std::alloc::Layout::from_size_align(len, 64).unwrap();
        // SAFETY: layout is nonzero for all bench sizes.
        let ptr = unsafe { std::alloc::alloc(layout) };
        assert!(!ptr.is_null(), "alloc {len}");
        Aligned { ptr, len, layout }
    }
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: owned allocation of `len` bytes.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
    fn as_slice(&self) -> &[u8] {
        // SAFETY: owned allocation of `len` bytes.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for Aligned {
    fn drop(&mut self) {
        // SAFETY: pairing the allocation above.
        unsafe { std::alloc::dealloc(self.ptr, self.layout) }
    }
}

/// Executable PT_LOAD segment bytes of an ELF64 file (minimal parse).
fn elf_exec_segment(path: &str) -> Vec<u8> {
    let f = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    assert_eq!(&f[0..4], b"\x7fELF", "ELF magic");
    let u64le = |o: usize| u64::from_le_bytes(f[o..o + 8].try_into().unwrap());
    let u32le = |o: usize| u32::from_le_bytes(f[o..o + 4].try_into().unwrap());
    let phoff = u64le(32) as usize;
    let u16le = |o: usize| u16::from_le_bytes(f[o..o + 2].try_into().unwrap());
    let phentsize = u16le(54) as usize;
    let phnum = u16le(56) as usize;
    let mut best: Option<(usize, usize)> = None;
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        let p_type = u32le(p);
        let p_flags = u32le(p + 4);
        if p_type == 1 && p_flags & 1 != 0 {
            let offset = u64le(p + 8) as usize;
            let filesz = u64le(p + 32) as usize;
            if best.is_none_or(|(_, l)| filesz > l) {
                best = Some((offset, filesz));
            }
        }
    }
    let (off, len) = best.expect("executable PT_LOAD");
    f[off..off + len].to_vec()
}

#[target_feature(enable = "avx2")]
unsafe fn copy_avx2(src: &[u8], dst: &mut [u8]) {
    use core::arch::x86_64::*;
    let n = src.len();
    let mut i = 0usize;
    while i + 32 <= n {
        // SAFETY: caller guarantees AVX2 and equal lengths.
        unsafe {
            let v = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
            _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, v);
        }
        i += 32;
    }
    dst[i..].copy_from_slice(&src[i..]);
}

#[target_feature(enable = "avx2")]
unsafe fn copy_avx2_nt(src: &[u8], dst: &mut [u8]) {
    use core::arch::x86_64::*;
    let n = src.len();
    let mut i = 0usize;
    while i + 32 <= n {
        // SAFETY: caller guarantees AVX2, equal lengths, and
        // 32-byte-aligned buffers (stream stores require it).
        unsafe {
            let v = _mm256_load_si256(src.as_ptr().add(i) as *const __m256i);
            _mm256_stream_si256(dst.as_mut_ptr().add(i) as *mut __m256i, v);
        }
        i += 32;
    }
    dst[i..].copy_from_slice(&src[i..]);
    // SAFETY: orders the non-temporal stores before later reads.
    _mm_sfence()
}

#[derive(Clone, Copy, Debug)]
struct Site {
    offset: usize,
    branch: bool,
}

/// Linear decode scan collecting branch/relocation patch sites.
/// Returns (instructions, skipped_bytes, sites).
fn scan(bytes: &[u8], sites: &mut Vec<Site>) -> (u64, u64) {
    let mut insns = 0u64;
    let mut skipped = 0u64;
    let mut ip = 0x10_0000u64;
    let base = ip;
    let mut off = 0usize;
    while off < bytes.len() {
        let mut dec = Decoder::with_ip(64, &bytes[off..], ip, DecoderOptions::NONE);
        if !dec.can_decode() {
            off += 1;
            ip += 1;
            skipped += 1;
            continue;
        }
        let ins = dec.decode();
        if ins.is_invalid() || ins.len() == 0 {
            off += 1;
            ip += 1;
            skipped += 1;
            continue;
        }
        insns += 1;
        let is_branch = ins.code().is_jcc_short()
            || ins.code().is_jcc_near()
            || ins.code().is_jmp_short()
            || ins.code().is_jmp_near()
            || ins.code().is_call_near()
            || matches!(
                ins.mnemonic(),
                Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne | Mnemonic::Ret
            );
        if is_branch || ins.is_ip_rel_memory_operand() {
            sites.push(Site {
                offset: (ip - base) as usize,
                branch: is_branch,
            });
        }
        off += ins.len();
        ip += ins.len() as u64;
    }
    (insns, skipped)
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/lib64/libc.so.6".to_string());
    let text = elf_exec_segment(&path);
    let len = text.len();
    let mut src = Aligned::new(len);
    src.as_mut().copy_from_slice(&text);
    let mut dst = Aligned::new(len);
    let has_avx2 = std::arch::is_x86_feature_detected!("avx2");
    println!("input={path} exec-segment-bytes={len} avx2={has_avx2} samples={SAMPLES}");
    println!("bench,median_s_per_rep,iqr_s,rate,reps_per_sample,note");

    let gbs = |s: f64| len as f64 / s / 1e9;
    // 1. Streaming copy.
    let (m, q) = bench(50, || {
        dst.as_mut().copy_from_slice(src.as_slice());
        dst.as_slice()[len / 2] as u64
    });
    let copy_plain = m;
    println!("copy_plain,{m:.6},{q:.6},{:.2} GB/s,50,", gbs(m));
    if has_avx2 {
        let (m, q) = bench(50, || {
            // SAFETY: AVX2 detected above; equal lengths.
            unsafe { copy_avx2(src.as_slice(), dst.as_mut()) };
            dst.as_slice()[len / 2] as u64
        });
        println!("copy_avx2,{m:.6},{q:.6},{:.2} GB/s,50,", gbs(m));
        let (m, q) = bench(50, || {
            // SAFETY: AVX2 detected; both buffers 64-byte aligned.
            unsafe { copy_avx2_nt(src.as_slice(), dst.as_mut()) };
            dst.as_slice()[len / 2] as u64
        });
        println!("copy_avx2_nt,{m:.6},{q:.6},{:.2} GB/s,50,", gbs(m));
    }

    // Large (256 MiB, DRAM-scale) copies: the 1.5 MiB working set
    // above is cache-resident, so tile the text into big buffers.
    {
        let big_len = 256usize << 20;
        let mut big_src = Aligned::new(big_len);
        let mut big_dst = Aligned::new(big_len);
        for chunk in big_src.as_mut().chunks_mut(len) {
            let n = chunk.len();
            chunk.copy_from_slice(&src.as_slice()[..n]);
        }
        let gbs_big = |s: f64| big_len as f64 / s / 1e9;
        let (m, q) = bench(3, || {
            big_dst.as_mut().copy_from_slice(big_src.as_slice());
            big_dst.as_slice()[big_len / 2] as u64
        });
        println!(
            "copy_large_plain,{m:.6},{q:.6},{:.2} GB/s,3,256MiB",
            gbs_big(m)
        );
        if has_avx2 {
            let (m, q) = bench(3, || {
                // SAFETY: AVX2 detected; equal lengths.
                unsafe { copy_avx2(big_src.as_slice(), big_dst.as_mut()) };
                big_dst.as_slice()[big_len / 2] as u64
            });
            println!(
                "copy_large_avx2,{m:.6},{q:.6},{:.2} GB/s,3,256MiB",
                gbs_big(m)
            );
            let (m, q) = bench(3, || {
                // SAFETY: AVX2 detected; 64-byte-aligned buffers.
                unsafe { copy_avx2_nt(big_src.as_slice(), big_dst.as_mut()) };
                big_dst.as_slice()[big_len / 2] as u64
            });
            println!(
                "copy_large_avx2_nt,{m:.6},{q:.6},{:.2} GB/s,3,256MiB",
                gbs_big(m)
            );
        }
    }

    // 2. Decode only.
    let mut sites: Vec<Site> = Vec::new();
    let (insns, skipped) = scan(src.as_slice(), &mut sites);
    let branches = sites.iter().filter(|s| s.branch).count();
    println!(
        "# scan census: instructions={insns} skipped={skipped} sites={} branch_sites={branches}",
        sites.len()
    );
    let (m, q) = bench(3, || {
        let tmp: Vec<Site> = Vec::with_capacity(sites.len());
        let mut dec = Decoder::with_ip(64, src.as_slice(), 0x10_0000, DecoderOptions::NONE);
        let mut n = 0u64;
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.len() == 0 {
                break;
            }
            n += 1;
        }
        std::hint::black_box(&tmp);
        n
    });
    println!(
        "decode_only,{m:.6},{q:.6},{:.1} MB/s {:.2} Minsn/s,3,linear-sweep",
        len as f64 / m / 1e6,
        insns as f64 / m / 1e6
    );

    // 3. Copy + length/classification scan.
    let (m, q) = bench(3, || {
        dst.as_mut().copy_from_slice(src.as_slice());
        let mut found: Vec<Site> = Vec::with_capacity(sites.len());
        let (n, _) = scan(dst.as_slice(), &mut found);
        std::hint::black_box(found.len());
        n
    });
    println!(
        "copy_plus_scan_perinsn_decoder,{m:.6},{q:.6},{:.1} MB/s,3,scan_incremental_vs_plain_copy={:.2} ms/rep (P1a-style per-insn Decoder)",
        len as f64 / m / 1e6,
        (m - copy_plain) * 1e3
    );
    // Streaming-decoder scan: one Decoder for the whole sweep.
    let (m, q) = bench(3, || {
        dst.as_mut().copy_from_slice(src.as_slice());
        let bytes = dst.as_slice();
        let mut found: Vec<Site> = Vec::with_capacity(sites.len());
        let mut dec = Decoder::with_ip(64, bytes, 0x10_0000, DecoderOptions::NONE);
        let mut n = 0u64;
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.len() == 0 || ins.is_invalid() {
                break;
            }
            n += 1;
            let is_branch = ins.code().is_jcc_short()
                || ins.code().is_jcc_near()
                || ins.code().is_jmp_short()
                || ins.code().is_jmp_near()
                || ins.code().is_call_near()
                || matches!(
                    ins.mnemonic(),
                    Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne | Mnemonic::Ret
                );
            if is_branch || ins.is_ip_rel_memory_operand() {
                found.push(Site {
                    offset: (ins.ip() - 0x10_0000) as usize,
                    branch: is_branch,
                });
            }
        }
        std::hint::black_box(found.len());
        n
    });
    println!(
        "copy_plus_scan_streaming,{m:.6},{q:.6},{:.1} MB/s,3,scan_incremental_vs_plain_copy={:.2} ms/rep",
        len as f64 / m / 1e6,
        (m - copy_plain) * 1e3
    );

    // 4. Patch-in-place costs. Jump = 5-byte rel32 overwrite at
    // branch sites; count = 47-byte stub template materialized per
    // branch site (P1a stub size) into a stub buffer.
    let branch_sites: Vec<usize> = sites
        .iter()
        .filter(|s| s.branch)
        .map(|s| s.offset)
        .collect();
    let template = [0x48u8; 47];
    let mut stub_buf = Aligned::new(64 << 20);
    for (label, stride) in [("sparse_1in100", 100usize), ("dense_all", 1usize)] {
        let chosen: Vec<usize> = branch_sites.iter().step_by(stride).copied().collect();
        let per_rep = chosen.len() as f64;
        let (m, q) = bench(50, || {
            let d = dst.as_mut();
            for &off in &chosen {
                if off + 5 <= d.len() {
                    d[off] = 0xe9;
                    d[off + 1..off + 5].copy_from_slice(&0x1000i32.to_le_bytes());
                }
            }
            d[chosen[0]] as u64
        });
        println!(
            "patch_jump_only,{m:.6},{q:.6},{:.2} ns/site,50,{label} sites={}",
            m / per_rep * 1e9,
            chosen.len()
        );
        let (m, q) = bench(50, || {
            dst.as_mut().copy_from_slice(src.as_slice());
            let d = dst.as_mut();
            for &off in &chosen {
                if off + 5 <= d.len() {
                    d[off] = 0xe9;
                    d[off + 1..off + 5].copy_from_slice(&0x1000i32.to_le_bytes());
                }
            }
            d[chosen[0]] as u64
        });
        println!(
            "copy_plus_patch_jump,{m:.6},{q:.6},{:.2} x_plain_copy {} ns/site-derived,50,{label}",
            m / copy_plain,
            ((m - copy_plain) / per_rep * 1e9).max(0.0)
        );
        let (m, q) = bench(50, || {
            let sb = stub_buf.as_mut();
            let mut cur = 0usize;
            for &off in &chosen {
                if cur + 47 > sb.len() {
                    break;
                }
                sb[cur..cur + 47].copy_from_slice(&template);
                sb[cur + 43..cur + 47].copy_from_slice(&(off as i32).to_le_bytes());
                cur += 47;
            }
            sb[0] as u64 + cur as u64
        });
        println!(
            "emit_count_stub_only,{m:.6},{q:.6},{:.2} ns/site,50,{label} sites={}",
            m / per_rep * 1e9,
            chosen.len()
        );
    }
}
