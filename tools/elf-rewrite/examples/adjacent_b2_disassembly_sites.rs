//! Fixed artifact-only producer; never maps or executes candidate code.
#![forbid(unsafe_code)]
#[path = "support/adjacent_publication.rs"]
mod publication;
#[cfg(test)]
use liteinst_rewrite::disassembly;
use publication::read;
#[cfg(test)]
use publication::{digest, snapshots_match, write};
#[cfg(test)]
use std::collections::BTreeMap;
use std::path::Path;
const PROFILE: &str = liteinst_rewrite::disassembly::adjacent_b2::PROFILE;
#[cfg(test)]
fn publish(
    output: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    original: &[u8],
    complete: bool,
    put: impl FnMut(&Path, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    publication::publish(
        publication::Profile::for_name(PROFILE)?,
        output,
        files,
        original,
        complete,
        put,
    )
}
fn run(args: &[String]) -> Result<bool, String> {
    run_with_read(args, read)
}
fn run_with_read(
    args: &[String],
    read: impl FnMut(&Path, usize) -> Result<Vec<u8>, String>,
) -> Result<bool, String> {
    publication::run_with_read(args, publication::Profile::for_name(PROFILE)?, read)
}
fn main() {
    match run(&std::env::args().collect::<Vec<_>>()) {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("profile={PROFILE} {error}");
            std::process::exit(1);
        }
    }
}
#[cfg(test)]
#[path = "fixtures/adjacent_b2_publication.rs"]
mod publication_fixture;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn f24_reread_every_input_and_complete_last() {
        let before = [b"original".to_vec(), b"ledger".to_vec(), b"policy".to_vec()];
        for changed in 0..3 {
            let mut after = before.clone();
            after[changed].push(0);
            assert!(snapshots_match(&before, &after).is_err());
        }
        assert!(snapshots_match(&before, &before).is_ok());
        let files = BTreeMap::from([("a".into(), vec![1]), ("b".into(), vec![2])]);
        let mut written = Vec::new();
        assert!(
            publish(Path::new("unused"), &files, b"original", true, |p, _| {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                if name == "b" {
                    return Err("injected write failure".into());
                }
                written.push(name);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(written, ["a"]);
        let mut written = Vec::new();
        publish(Path::new("unused"), &files, b"original", false, |p, b| {
            written.push((
                p.file_name().unwrap().to_string_lossy().into_owned(),
                b.to_vec(),
            ));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            written.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["a", "b", "COMPLETE"]
        );
        let closure = String::from_utf8(written.last().unwrap().1.clone()).unwrap();
        assert!(closure.contains("candidate_complete\tfalse\n"));
        assert!(closure.contains(&format!("profile\t{PROFILE}\n")));
    }
    #[test]
    fn f24_actual_rereads_and_create_new_publication_fail_closed() {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "li2-adjacent-publication-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        for changed in 0..3 {
            let output = root.join(format!("changed-{changed}"));
            let paths = [
                root.join("original"),
                root.join("ledger"),
                root.join("policy"),
            ];
            for (i, path) in paths.iter().enumerate() {
                std::fs::write(path, [i as u8 + 1]).unwrap();
            }
            let args = vec![
                "example".into(),
                paths[0].to_string_lossy().into_owned(),
                paths[1].to_string_lossy().into_owned(),
                "00".repeat(32),
                paths[2].to_string_lossy().into_owned(),
                "00".repeat(32),
                output.to_string_lossy().into_owned(),
            ];
            let mut calls = 0;
            let error = run_with_read(&args, |path, limit| {
                if calls == 3 {
                    std::fs::write(&paths[changed], b"changed").unwrap();
                }
                calls += 1;
                read(path, limit)
            })
            .unwrap_err();
            assert_eq!(error, "inputs changed during preparation");
            assert_eq!(calls, 6);
            assert!(!output.exists());
        }
        let output = root.join("partial");
        std::fs::create_dir(&output).unwrap();
        std::fs::write(output.join("b"), b"already exists").unwrap();
        let files = BTreeMap::from([("a".into(), vec![1]), ("b".into(), vec![2])]);
        assert!(publish(&output, &files, b"original", true, write).is_err());
        assert!(output.join("a").exists());
        assert!(!output.join("COMPLETE").exists());
        assert_eq!(std::fs::read(output.join("b")).unwrap(), b"already exists");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f24_complete_candidate_is_published_then_withheld_on_each_final_reread_change() {
        use super::publication_fixture as fixture;
        let frozen = [
            fixture::original(),
            fixture::LEDGER.to_vec(),
            fixture::POLICY.to_vec(),
        ];
        assert_eq!(digest(&frozen[0]), fixture::ORIGINAL_SHA256);
        assert_eq!(digest(&frozen[1]), fixture::LEDGER_SHA256);
        assert_eq!(digest(&frozen[2]), fixture::POLICY_SHA256);
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "li2-adjacent-valid-publication-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let paths = [
            root.join("original"),
            root.join("ledger"),
            root.join("policy"),
        ];
        let limits = [
            disassembly::INPUT_LIMIT,
            disassembly::TEXT_LIMIT,
            disassembly::TEXT_LIMIT,
        ];
        let args_for = |output: &Path| {
            vec![
                "example".into(),
                paths[0].to_string_lossy().into_owned(),
                paths[1].to_string_lossy().into_owned(),
                fixture::LEDGER_SHA256.into(),
                paths[2].to_string_lossy().into_owned(),
                fixture::POLICY_SHA256.into(),
                output.to_string_lossy().into_owned(),
            ]
        };
        for (path, bytes) in paths.iter().zip(&frozen) {
            std::fs::write(path, bytes).unwrap();
        }
        // Mandatory positive FIRST, with the exact same fixture, policy and caps
        // subsequently used by every refusal. An incomplete diagnostic is not enough.
        let output = root.join("unchanged");
        let mut calls = 0;
        assert!(
            run_with_read(&args_for(&output), |path, limit| {
                assert_eq!(path, paths[calls % 3].as_path());
                assert_eq!(limit, limits[calls % 3]);
                calls += 1;
                read(path, limit)
            })
            .expect("frozen complete candidate must publish without input changes")
        );
        assert_eq!(calls, 6);
        let closure = std::fs::read_to_string(output.join("COMPLETE")).unwrap();
        assert!(closure.starts_with(&format!("LI2DISASSEMBLY-DIRECTORY\t1\nprofile\t{PROFILE}\nobserved_original_sha256\t{}\ncandidate_complete\ttrue\nqualification_complete\tfalse\n", fixture::ORIGINAL_SHA256)));
        for name in [
            "candidate.elf",
            "source.li2sparse",
            "metadata.li2meta",
            "plan-ledger.tsv",
            "report.tsv",
            "selection.txt",
            "image-0000.bin",
            "image-0001.bin",
        ] {
            let bytes = std::fs::read(output.join(name)).unwrap();
            assert!(closure.contains(&format!(
                "file\t{name}\t{}\t{}\n",
                bytes.len(),
                digest(&bytes)
            )));
        }
        assert!(!output.join("program-failure.tsv").exists());
        let evidence = std::fs::read_to_string(output.join("adjacent-b2-evidence.txt")).unwrap();
        assert!(evidence.contains(
            "selected_count\t2\nbaseline_calls\t2\npair_calls\t1\nadjacent_counts\t2\t1\t2\n"
        ));
        assert!(
            evidence.contains("qualification_complete\tfalse\nclassification_complete\tfalse\n")
        );
        for changed in 0..3 {
            for (path, bytes) in paths.iter().zip(&frozen) {
                std::fs::write(path, bytes).unwrap();
            }
            let output = root.join(format!("changed-valid-{changed}"));
            let mut calls = 0;
            let error = run_with_read(&args_for(&output), |path, limit| {
                assert_eq!(path, paths[calls % 3].as_path());
                assert_eq!(limit, limits[calls % 3]);
                // run_with_read has already prepared the candidate before read #4.
                // All three initial inputs are still the exact successful bytes.
                if calls == 3 {
                    for (path, bytes) in paths.iter().zip(&frozen) {
                        assert_eq!(std::fs::read(path).unwrap(), *bytes);
                    }
                    let mut replacement = frozen[changed].clone();
                    *replacement.last_mut().unwrap() ^= 1;
                    std::fs::write(&paths[changed], replacement).unwrap();
                }
                calls += 1;
                read(path, limit)
            })
            .unwrap_err();
            assert_eq!(calls, 6, "all three final rereads remain mandatory");
            assert_eq!(error, "inputs changed during preparation");
            assert!(
                !output.exists(),
                "withhold directory and all candidate dispatch"
            );
            for (index, path) in paths.iter().enumerate() {
                let mut expected = frozen[index].clone();
                if index == changed {
                    *expected.last_mut().unwrap() ^= 1;
                }
                assert_eq!(std::fs::read(path).unwrap(), expected);
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
