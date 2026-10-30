//! Fixed two-program producer. Never builds a DSO or executes candidate bytes.
#![forbid(unsafe_code)]
#[path = "support/publication_io.rs"]
mod io;
use liteinst_rewrite::{
    disassembly,
    offline_router::{self, Bound},
    selection,
};
use std::{collections::BTreeMap, os::unix::fs::DirBuilderExt as _, path::Path};
const NAMES: [&str; 2] = ["checksum", "rle-roundtrip"];
const MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
type Inputs = [Vec<u8>; 4];
fn inputs_match(before: &Inputs, after: &Inputs) -> Result<(), String> {
    io::snapshots_match(
        before[..3].try_into().expect("three originals"),
        after[..3].try_into().expect("three rereads"),
    )?;
    if before[3] != after[3] {
        return Err("startup policy changed during preparation".into());
    }
    Ok(())
}
fn publish(
    output: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    originals: [&[u8]; 2],
    complete: bool,
    mut put: impl FnMut(&Path, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    if files.len() > 512
        || files
            .values()
            .try_fold(0usize, |n, b| n.checked_add(b.len()))
            .is_none_or(|n| n > MAX_OUTPUT_BYTES)
    {
        return Err("whole output bound".into());
    }
    let mut marker = format!(
        "LI2BOOTSTRAP-DIRECTORY\t1\nprofile\t{}\nchecksum_original_sha256\t{}\nrle_original_sha256\t{}\nrequired_original_heads\t187\nrequired_selected_sites\t42\ncandidate_complete\t{complete}\nqualification_complete\tfalse\nexecution_authority\tnone\n",
        offline_router::PROFILE,
        io::digest(originals[0]),
        io::digest(originals[1])
    );
    for (name, bytes) in files {
        if name.contains('/') || name == "COMPLETE" {
            return Err("publication member name".into());
        }
        put(&output.join(name), bytes)?;
        marker.push_str(&format!(
            "file\t{name}\t{}\t{}\n",
            bytes.len(),
            io::digest(bytes)
        ));
    }
    // A failure before this call withholds the marker. This write or later sync
    // may leave partial/untrusted bytes; only returned Ok plus closed custody is
    // acceptance. Never delete or relabel a failed publication as a success.
    put(&output.join("COMPLETE"), marker.as_bytes())
}
fn run_with_read(
    args: &[String],
    mut read: impl FnMut(&Path, usize) -> Result<Vec<u8>, String>,
) -> Result<bool, String> {
    if args.len() != 16 {
        return Err("offline_router_sites CHECKSUM_ORIGINAL LEDGER LEDGER_SHA POLICY POLICY_SHA STARTUP STARTUP_SHA RLE_ORIGINAL LEDGER LEDGER_SHA POLICY POLICY_SHA STARTUP STARTUP_SHA NEW_DIRECTORY".into());
    }
    let mut initial = Vec::new();
    let mut paths = Vec::new();
    let mut identities = Vec::new();
    let limits = [
        disassembly::INPUT_LIMIT.min(formats::startup::MAX_FILE),
        disassembly::TEXT_LIMIT,
        disassembly::TEXT_LIMIT,
        offline_router::POLICY_LIMIT,
    ];
    for base in [1usize, 8] {
        let p = [
            Path::new(&args[base]),
            Path::new(&args[base + 1]),
            Path::new(&args[base + 3]),
            Path::new(&args[base + 5]),
        ];
        let ids = [base + 2, base + 4, base + 6]
            .map(|i| selection::id(&args[i]).map_err(|e| e.to_string()));
        identities.push([ids[0].clone()?, ids[1].clone()?, ids[2].clone()?]);
        initial.push([
            read(p[0], limits[0])?,
            read(p[1], limits[1])?,
            read(p[2], limits[2])?,
            read(p[3], limits[3])?,
        ]);
        paths.push(p);
    }
    let bindings = initial
        .iter()
        .zip(&identities)
        .map(|(x, id)| Bound::bind(&x[0], &x[1], id[0], &x[2], id[1], &x[3], id[2]))
        .collect::<Vec<_>>();
    let mut files = BTreeMap::new();
    for (i, name) in NAMES.iter().enumerate() {
        for (suffix, bytes) in [
            "original.elf",
            "disassembly.txt",
            "disassembly-policy.txt",
            "startup-policy.txt",
        ]
        .into_iter()
        .zip(&initial[i])
        {
            files.insert(format!("{name}-{suffix}"), bytes.clone());
        }
        if let Ok(bound) = &bindings[i] {
            for (suffix, bytes) in bound.binding_files() {
                files.insert(format!("{name}-{suffix}"), bytes);
            }
        }
    }
    // No program switch or subset flag; both bindings are ready before planning.
    let prepared = match (&bindings[0], &bindings[1]) {
        (Ok(a), Ok(b)) => {
            offline_router::prepare_programs([&initial[0][0], &initial[1][0]], [a, b])
                .map_err(|e| e.to_string())
        }
        _ => Err(format!(
            "binding failure: {:?}",
            bindings
                .iter()
                .enumerate()
                .filter_map(|(i, b)| b.as_ref().err().map(|e| (NAMES[i], e.to_string())))
                .collect::<Vec<_>>()
        )),
    };
    // Every input, including both runtime policies, is reread before result
    // dispatch or output creation. Failure custody uses the same snapshots.
    for i in 0..2 {
        let reread = [
            read(paths[i][0], limits[0])?,
            read(paths[i][1], limits[1])?,
            read(paths[i][2], limits[2])?,
            read(paths[i][3], limits[3])?,
        ];
        inputs_match(&initial[i], &reread)?;
    }
    let complete = match prepared {
        Ok(products) => {
            for (name, product) in NAMES.iter().zip(products) {
                for (suffix, bytes) in product.files() {
                    files.insert(format!("{name}-{suffix}"), bytes.clone());
                }
            }
            true
        }
        Err(error) => {
            files.insert("program-failure.tsv".into(),format!("LI2BOOTSTRAP-FAILURE\t1\nprofile\t{}\nrequired_programs\tchecksum,rle-roundtrip\nrequired_original_heads\t187\nrequired_selected_sites\t42\ncandidate_complete\tfalse\nqualification_complete\tfalse\ndetail_hex\t{}\n",offline_router::PROFILE,error.as_bytes().iter().map(|b|format!("{b:02x}")).collect::<String>()).into_bytes());
            false
        }
    };
    let output = Path::new(&args[15]);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| e.to_string())?;
    publish(
        output,
        &files,
        [&initial[0][0], &initial[1][0]],
        complete,
        io::write,
    )?;
    std::fs::File::open(output)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!(
        "profile={} candidate_complete={complete} qualification_complete=false required_programs=2 required_heads=187 required_selected=42",
        offline_router::PROFILE
    );
    Ok(complete)
}
fn main() {
    match run_with_read(&std::env::args().collect::<Vec<_>>(), io::read) {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(e) => {
            eprintln!("profile={} {e}", offline_router::PROFILE);
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
#[path = "fixtures/offline_router.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_eight_snapshots_are_exact() {
        let before = [
            b"original".to_vec(),
            b"ledger".to_vec(),
            b"planning".to_vec(),
            b"startup".to_vec(),
        ];
        for _program in 0..2 {
            for changed in 0..4 {
                let mut after = before.clone();
                after[changed].push(0);
                assert!(inputs_match(&before, &after).is_err());
            }
        }
        assert!(inputs_match(&before, &before).is_ok());
    }
    #[test]
    fn every_member_failure_is_terminal_and_complete_is_last() {
        let files = BTreeMap::from([
            ("checksum-catalog.li2boot".into(), vec![1]),
            ("rle-roundtrip-catalog.li2boot".into(), vec![2]),
        ]);
        for fail in 0..=2 {
            let mut written = Vec::new();
            let r = publish(
                Path::new("unused"),
                &files,
                [b"checksum", b"rle"],
                true,
                |p, _| {
                    let name = p.file_name().unwrap().to_str().unwrap().to_owned();
                    if written.len() == fail {
                        return Err("injected publication failure".into());
                    }
                    written.push(name);
                    Ok(())
                },
            );
            assert!(r.is_err());
            assert_eq!(written.len(), fail);
            assert!(!written.iter().any(|n| n == "COMPLETE"));
        }
        let mut written = Vec::new();
        publish(
            Path::new("unused"),
            &files,
            [b"checksum", b"rle"],
            true,
            |p, b| {
                written.push((
                    p.file_name().unwrap().to_str().unwrap().to_owned(),
                    b.to_vec(),
                ));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(written.last().unwrap().0, "COMPLETE");
        let marker = std::str::from_utf8(&written.last().unwrap().1).unwrap();
        assert!(marker.contains("required_original_heads\t187\nrequired_selected_sites\t42\ncandidate_complete\ttrue\nqualification_complete\tfalse\n"));
        assert_eq!(
            marker.lines().filter(|l| l.starts_with("file\t")).count(),
            2
        );
    }
    #[test]
    fn cli_requires_the_fixed_two_program_interface() {
        assert!(
            run_with_read(&["offline_router_sites".into()], |_, _| panic!(
                "must reject before read"
            ))
            .is_err()
        );
    }
    #[test]
    fn unchanged_valid_bundle_publishes_and_actual_reread_mutants_leave_no_directory() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let a = fixture::case(1);
        let b = fixture::case(2);
        let input = [
            a.original, a.ledger, a.planning, a.runtime, b.original, b.ledger, b.planning,
            b.runtime,
        ];
        for mutate in 0..=8 {
            let out = std::env::temp_dir().join(format!(
                "li2-startup-publication-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            assert!(!out.exists());
            let mut args = vec!["offline_router_sites".into()];
            for (i, name) in NAMES.iter().enumerate() {
                let at = i * 4;
                args.extend([
                    format!("{name}-original"),
                    format!("{name}-ledger"),
                    io::digest(&input[at + 1]),
                    format!("{name}-planning"),
                    io::digest(&input[at + 2]),
                    format!("{name}-startup"),
                    io::digest(&input[at + 3]),
                ]);
            }
            args.push(out.to_str().unwrap().into());
            let mut reads = 0usize;
            let result = run_with_read(&args, |_, cap| {
                let index = reads % 8;
                let mut bytes = input[index].clone();
                assert!(bytes.len() <= cap);
                if reads == 8 + mutate && mutate < 8 {
                    bytes.push(0);
                }
                reads += 1;
                Ok(bytes)
            });
            if mutate == 8 {
                assert_eq!(result, Ok(true));
                assert_eq!(reads, 16);
                let marker = std::fs::read(out.join("COMPLETE")).unwrap();
                assert!(
                    std::str::from_utf8(&marker)
                        .unwrap()
                        .contains("candidate_complete\ttrue\nqualification_complete\tfalse\n")
                );
                for name in NAMES {
                    assert!(out.join(format!("{name}-catalog.li2boot")).is_file());
                    assert!(out.join(format!("{name}-candidate.elf")).is_file());
                }
                std::fs::remove_dir_all(&out).unwrap();
            } else {
                assert!(result.is_err(), "reread mutant {mutate}");
                assert!(!out.exists());
                assert!((12..=16).contains(&reads));
            }
        }
    }
}
