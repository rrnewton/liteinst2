//! Informational B0 synthetic scanner metrics; no patching or performance gate.
use liteinst_admission::entries::{Completeness, EntryProvenance, LegalEntrySet};
use liteinst_admission::scan::*;
use liteinst_admission::{Generation, MappingId};

fn main() {
    for (name, prefix, heads) in [
        ("clean", vec![0x90], vec![]),
        ("known_cpuid", vec![0x0f, 0xa2], vec![0x1000]),
        ("embedded_cpuid", vec![0xb8, 0x0f, 0xa2, 0, 0], vec![0x1000]),
        ("unresolved_rdseed", vec![0x0f, 0xc7, 0xf8], vec![]),
    ] {
        let mut bytes = vec![0xcc; 4096];
        bytes[..prefix.len()].copy_from_slice(&prefix);
        let snapshot = Snapshot::new(
            MappingId(1),
            Generation(1),
            0x1000,
            bytes,
            Boundary::NonExecutable,
            Boundary::NonExecutable,
            WriteControl::Owned,
        )
        .unwrap();
        let entries = LegalEntrySet::new(
            snapshot.mapping,
            snapshot.generation,
            1,
            snapshot.range(),
            Completeness::AllInstructionHeads,
            heads
                .into_iter()
                .map(|pc| (pc, EntryProvenance::VerifiedInstruction)),
            [],
        )
        .unwrap();
        let mut times = Vec::new();
        for _ in 0..100 {
            let report =
                RuntimeScan.inspect(&snapshot, snapshot.range(), &entries, &Policy::default());
            times.push(report.metrics().elapsed.as_nanos());
            std::hint::black_box(report);
        }
        times.sort_unstable();
        let report = RuntimeScan.inspect(&snapshot, snapshot.range(), &entries, &Policy::default());
        let m = report.metrics();
        println!(
            "{name}: verdict={:?} pages=100 p50_ns={} p95_ns={} p99_ns={} starts={} known={} embedded={} unresolved={} obligations={} classes={:?}",
            report.verdict(),
            times[49],
            times[94],
            times[98],
            m.decoded_starts,
            m.known_sites,
            m.embedded_candidates,
            m.unresolved_candidates,
            report.obligations().len(),
            m.by_class
        );
    }
}
