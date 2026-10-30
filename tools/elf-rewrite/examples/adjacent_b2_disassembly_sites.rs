//! Explicit adjacent-B2 artifact profile. This executable never maps code.
#![forbid(unsafe_code)]
use formats::ContentId;
use liteinst_rewrite::{disassembly, prepare_disassembly_adjacent_b2, selection};
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

const PROFILE: &str = disassembly::adjacent_b2::PROFILE;
fn digest(bytes: &[u8]) -> String {
    ContentId::of(bytes)
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("input size bound".into());
    }
    Ok(bytes)
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}
fn snapshots_match(before: &[Vec<u8>; 3], after: &[Vec<u8>; 3]) -> Result<(), String> {
    if before != after {
        Err("inputs changed during preparation".into())
    } else {
        Ok(())
    }
}
fn publish(
    output: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    original: &[u8],
    complete: bool,
    mut put: impl FnMut(&Path, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    let mut index = format!(
        "LI2DISASSEMBLY-DIRECTORY\t1\nprofile\t{PROFILE}\nobserved_original_sha256\t{}\ncandidate_complete\t{complete}\nqualification_complete\tfalse\n",
        digest(original)
    );
    for (name, bytes) in files {
        put(&output.join(name), bytes)?;
        index.push_str(&format!(
            "file\t{name}\t{}\t{}\n",
            bytes.len(),
            digest(bytes)
        ));
    }
    put(&output.join("COMPLETE"), index.as_bytes())
}
fn run(args: &[String]) -> Result<bool, String> {
    run_with_read(args, read)
}
fn run_with_read(
    args: &[String],
    mut read: impl FnMut(&Path, usize) -> Result<Vec<u8>, String>,
) -> Result<bool, String> {
    // The executable itself fixes PROFILE before parsing or reading any input.
    if args.len() != 7 {
        return Err(format!(
            "{PROFILE}: adjacent_b2_disassembly_sites ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY"
        ));
    }
    let expected_ledger = selection::id(&args[3]).map_err(|e| e.to_string())?;
    let expected_policy = selection::id(&args[5]).map_err(|e| e.to_string())?;
    let paths = [
        Path::new(&args[1]),
        Path::new(&args[2]),
        Path::new(&args[4]),
    ];
    let limits = [
        disassembly::INPUT_LIMIT,
        disassembly::TEXT_LIMIT,
        disassembly::TEXT_LIMIT,
    ];
    let initial = [
        read(paths[0], limits[0])?,
        read(paths[1], limits[1])?,
        read(paths[2], limits[2])?,
    ];
    let [original, ledger, policy] = &initial;
    let mut files = BTreeMap::from([
        ("disassembly.txt".into(), ledger.clone()),
        ("disassembly-policy.txt".into(), policy.clone()),
    ]);
    let prepared = (|| {
        let imported = disassembly::import(original, ledger, expected_ledger)?;
        files.insert(
            "disassembly-inventory.tsv".into(),
            imported.inventory_adjacent_b2(),
        );
        let selected = imported.bind_adjacent_b2(policy, expected_policy)?;
        files.insert("selection.txt".into(), selected.manifest().to_vec());
        prepare_disassembly_adjacent_b2(original, &selected)
    })();
    let final_read = [
        read(paths[0], limits[0])?,
        read(paths[1], limits[1])?,
        read(paths[2], limits[2])?,
    ];
    snapshots_match(&initial, &final_read)?;
    let complete = match prepared {
        Ok(product) => {
            files.extend(product.files().clone());
            product.candidate_complete()
        }
        Err(error) => {
            let detail: String = error
                .to_string()
                .bytes()
                .map(|b| format!("{b:02x}"))
                .collect();
            files.insert("program-failure.tsv".into(), format!(
                "LI2DISASSEMBLY-FAILURE\t1\nprofile\t{PROFILE}\nobserved_original_sha256\t{}\nexpected_ledger_sha256\t{}\nexpected_policy_sha256\t{}\nqualification_complete\tfalse\ndetail_hex\t{detail}\n",
                digest(original), args[3], args[5]).into_bytes());
            false
        }
    };
    let output = Path::new(&args[6]);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| e.to_string())?;
    publish(output, &files, original, complete, write)?;
    std::fs::File::open(output)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!("profile={PROFILE} candidate_complete={complete} qualification_complete=false");
    Ok(complete)
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
