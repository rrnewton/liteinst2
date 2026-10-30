//! One inspectable artifact attempt. Never maps or executes candidate bytes.
#![forbid(unsafe_code)]
use formats::ContentId;
use liteinst_rewrite::{disassembly, prepare_disassembly, selection};
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("input size bound".into());
    }
    Ok(bytes)
}
fn digest(bytes: &[u8]) -> String {
    ContentId::of(bytes)
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
// Choose the profile before any input read or binding, including refusal paths.
fn arguments(args: &[String]) -> Result<(&[String], bool), String> {
    if args.len() == 7 {
        Ok((&args[1..], false))
    } else if args.len() == 8
        && args[1] == "--short-neighbors-only"
        && !args[2..].iter().any(|s| s == "--short-neighbors-only")
    {
        Ok((&args[2..], true))
    } else {
        Err("disassembly_sites [--short-neighbors-only] ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into())
    }
}

fn labels(short_only: bool) -> (&'static str, &'static str, &'static str) {
    if short_only {
        (
            disassembly::SHORT_ONLY_PROFILE,
            "neighbor_victims\tshort-only\n",
            " neighbor_victims=short-only",
        )
    } else {
        (disassembly::PROFILE, "", "")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    LongOnly,
    ShortOnly,
    ShortT3Ownership,
    ShortT3Pending,
}

fn arguments_with_ownership(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--short-neighbors-owned" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--short-neighbors-only" | "--short-neighbors-owned"
            )
        }) {
            return Err("disassembly_sites --short-neighbors-owned ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::ShortT3Ownership))
    } else {
        arguments(args).map(|(args, short_only)| {
            (
                args,
                if short_only {
                    Mode::ShortOnly
                } else {
                    Mode::LongOnly
                },
            )
        })
    }
}

// Recognize only this new leading form; every legacy positional form delegates.
fn arguments_with_pending(args: &[String]) -> Result<(&[String], Mode), String> {
    if args.len() == 8 && args[1] == "--short-neighbors-pending" {
        if args[2..].iter().any(|s| {
            matches!(
                s.as_str(),
                "--short-neighbors-only" | "--short-neighbors-owned" | "--short-neighbors-pending"
            )
        }) {
            return Err("disassembly_sites --short-neighbors-pending ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY".into());
        }
        Ok((&args[2..], Mode::ShortT3Pending))
    } else {
        arguments_with_ownership(args)
    }
}

fn labels_with_ownership(mode: Mode) -> (&'static str, &'static str, &'static str) {
    match mode {
        Mode::LongOnly => labels(false),
        Mode::ShortOnly => labels(true),
        Mode::ShortT3Pending => (
            disassembly::SHORT_T3_PENDING_PROFILE,
            "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\n",
            " neighbor_victims=short-only neighbor_ownership=inherited-t3 pending_selected=full-instruction-ownership",
        ),
        Mode::ShortT3Ownership => (
            disassembly::SHORT_T3_OWNERSHIP_PROFILE,
            "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\n",
            " neighbor_victims=short-only neighbor_ownership=inherited-t3",
        ),
    }
}

fn run() -> Result<bool, String> {
    let raw_args: Vec<_> = std::env::args().collect();
    let (args, mode) = arguments_with_pending(&raw_args)?;
    let (profile, family, stdout_family) = labels_with_ownership(mode);
    let expected_ledger = selection::id(&args[2]).map_err(|e| e.to_string())?;
    let expected_policy = selection::id(&args[4]).map_err(|e| e.to_string())?;
    let original = read(Path::new(&args[0]), disassembly::INPUT_LIMIT)?;
    let ledger = read(Path::new(&args[1]), disassembly::TEXT_LIMIT)?;
    let policy = read(Path::new(&args[3]), disassembly::TEXT_LIMIT)?;
    let mut files = BTreeMap::from([
        ("disassembly.txt".to_owned(), ledger.clone()),
        ("disassembly-policy.txt".to_owned(), policy.clone()),
    ]);
    let prepared = (|| {
        let imported = disassembly::import(&original, &ledger, expected_ledger)?;
        // This denominator is retained even if policy/placement/loader refuses.
        files.insert(
            "disassembly-inventory.tsv".into(),
            match mode {
                Mode::LongOnly => imported.inventory(),
                Mode::ShortOnly => imported.inventory_short_neighbors(),
                Mode::ShortT3Ownership => imported.inventory_short_t3_ownership(),
                Mode::ShortT3Pending => imported.inventory_short_t3_pending(),
            },
        );
        let selected = match mode {
            Mode::LongOnly => imported.bind(&policy, expected_policy)?,
            Mode::ShortOnly => imported.bind_short_neighbors(&policy, expected_policy)?,
            Mode::ShortT3Ownership => imported.bind_short_t3_ownership(&policy, expected_policy)?,
            Mode::ShortT3Pending => imported.bind_short_t3_pending(&policy, expected_policy)?,
        };
        assert_eq!(selected.profile(), profile);
        files.insert("selection.txt".into(), selected.manifest().to_vec());
        prepare_disassembly(&original, &selected)
    })();
    // Same input reread ordering as the existing prepare CLI: no outcome is
    // dispatched and no output is published before all three snapshots agree.
    if read(Path::new(&args[0]), disassembly::INPUT_LIMIT)? != original
        || read(Path::new(&args[1]), disassembly::TEXT_LIMIT)? != ledger
        || read(Path::new(&args[3]), disassembly::TEXT_LIMIT)? != policy
    {
        return Err("inputs changed during preparation".into());
    }
    let complete = match prepared {
        Ok(product) => {
            files.extend(product.files().clone());
            product.candidate_complete()
        }
        Err(error) => {
            // An invalid/untrusted ledger has no verified denominator, but the
            // program failure and exact attempted inputs are never a success.
            let detail: String = error
                .to_string()
                .bytes()
                .map(|b| format!("{b:02x}"))
                .collect();
            files.insert("program-failure.tsv".into(), format!(
                "LI2DISASSEMBLY-FAILURE\t1\nprofile\t{profile}\n{family}observed_original_sha256\t{}\nexpected_ledger_sha256\t{}\nexpected_policy_sha256\t{}\nqualification_complete\tfalse\ndetail_hex\t{detail}\n",
                digest(&original), args[2], args[4]).into_bytes());
            false
        }
    };
    let output = Path::new(&args[5]);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| e.to_string())?;
    let mut index = format!(
        "LI2DISASSEMBLY-DIRECTORY\t1\nprofile\t{profile}\n{family}observed_original_sha256\t{}\ncandidate_complete\t{complete}\nqualification_complete\tfalse\n",
        digest(&original)
    );
    for (name, bytes) in &files {
        write(&output.join(name), bytes)?;
        index.push_str(&format!(
            "file\t{name}\t{}\t{}\n",
            bytes.len(),
            digest(bytes)
        ));
    }
    write(&output.join("COMPLETE"), index.as_bytes())?;
    std::fs::File::open(output)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!(
        "profile={profile}{stdout_family} candidate_complete={complete} qualification_complete=false"
    );
    Ok(complete)
}
fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_profile_cli_labels_mode_before_policy_binding() {
        let old: Vec<String> = [
            "program",
            "--literal-path",
            "ledger",
            "ledger-sha",
            "policy",
            "policy-sha",
            "out",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let (positional, mode) = arguments(&old).unwrap();
        assert_eq!(positional, &old[1..]);
        assert!(!mode);
        assert_eq!(labels(mode), (disassembly::PROFILE, "", ""));
        let mut short = old.clone();
        short.insert(1, "--short-neighbors-only".into());
        let (positional, mode) = arguments(&short).unwrap();
        assert_eq!(positional, &old[1..]);
        assert!(mode);
        let (profile, family, stdout) = labels(mode);
        assert_eq!(profile, disassembly::SHORT_ONLY_PROFILE);
        assert_eq!(family, "neighbor_victims\tshort-only\n");
        assert_eq!(stdout, " neighbor_victims=short-only");
        // These labels exist before an invalid original/ledger can be bound.
        assert!(disassembly::import(&[], &[], ContentId::of(&[])).is_err());
        assert_eq!(labels(mode), (profile, family, stdout));
        for bad in [
            short[..7]
                .iter()
                .cloned()
                .chain(["extra".into(), "extra".into()])
                .collect::<Vec<_>>(),
            {
                let mut a = short.clone();
                a[1] = "--unknown".into();
                a
            },
            {
                let mut a = short.clone();
                a.swap(1, 2);
                a
            },
            {
                let mut a = short.clone();
                a[2] = "--short-neighbors-only".into();
                a
            },
            old[..6].to_vec(),
        ] {
            assert!(arguments(&bad).is_err());
        }
    }

    #[test]
    fn owned_short_cli_preserves_positional_paths_and_exact_prebind_labels() {
        let base: Vec<String> = [
            "program",
            "original",
            "ledger",
            "ledger-sha",
            "policy",
            "policy-sha",
            "out",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        for path in ["--short-neighbors-only", "--short-neighbors-owned"] {
            let mut old = base.clone();
            old[1] = path.into();
            let (positional, mode) = arguments_with_ownership(&old).unwrap();
            assert_eq!(positional, &old[1..]);
            assert_eq!(mode, Mode::LongOnly);
            assert_eq!(labels_with_ownership(mode), labels(false));
        }
        let mut old_short = base.clone();
        old_short[1] = "--short-neighbors-owned".into(); // an existing legal positional filename
        old_short.insert(1, "--short-neighbors-only".into());
        let (positional, mode) = arguments_with_ownership(&old_short).unwrap();
        assert_eq!(positional, &old_short[2..]);
        assert_eq!(mode, Mode::ShortOnly);
        assert_eq!(labels_with_ownership(mode), labels(true));
        let mut owned = base.clone();
        owned.insert(1, "--short-neighbors-owned".into());
        let (positional, mode) = arguments_with_ownership(&owned).unwrap();
        assert_eq!(positional, &base[1..]);
        assert_eq!(mode, Mode::ShortT3Ownership);
        let expected = (
            disassembly::SHORT_T3_OWNERSHIP_PROFILE,
            "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\n",
            " neighbor_victims=short-only neighbor_ownership=inherited-t3",
        );
        assert_eq!(labels_with_ownership(mode), expected);
        assert!(disassembly::import(&[], &[], ContentId::of(&[])).is_err());
        assert_eq!(labels_with_ownership(mode), expected);
        for flag in ["--short-neighbors-only", "--short-neighbors-owned"] {
            let mut bad = owned.clone();
            bad[2] = flag.into();
            assert!(arguments_with_ownership(&bad).is_err());
        }
        let mut unknown = owned.clone();
        unknown[1] = "--unknown".into();
        assert_eq!(
            arguments_with_ownership(&unknown).unwrap_err(),
            arguments(&unknown).unwrap_err()
        );
        assert!(arguments_with_ownership(&owned[..6]).is_err());
        let mut extra = owned;
        extra.push("extra".into());
        assert!(arguments_with_ownership(&extra).is_err());
    }

    #[test]
    fn pending_short_cli_preserves_legacy_paths_and_exact_prebind_labels() {
        let base: Vec<String> = [
            "program",
            "original",
            "ledger",
            "ledger-sha",
            "policy",
            "policy-sha",
            "out",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let flags = [
            "--short-neighbors-only",
            "--short-neighbors-owned",
            "--short-neighbors-pending",
        ];
        for path in flags {
            let mut old = base.clone();
            old[1] = path.into();
            assert_eq!(arguments_with_pending(&old), arguments_with_ownership(&old));
            let (positional, mode) = arguments_with_pending(&old).unwrap();
            assert_eq!(positional, &old[1..]);
            assert_eq!(mode, Mode::LongOnly);
            assert_eq!(labels_with_ownership(mode), labels(false));
        }
        for path in ["--short-neighbors-owned", "--short-neighbors-pending"] {
            let mut old_short = base.clone();
            old_short[1] = path.into();
            old_short.insert(1, "--short-neighbors-only".into());
            assert_eq!(
                arguments_with_pending(&old_short),
                arguments_with_ownership(&old_short)
            );
            let (positional, mode) = arguments_with_pending(&old_short).unwrap();
            assert_eq!(positional, &old_short[2..]);
            assert_eq!(mode, Mode::ShortOnly);
            assert_eq!(labels_with_ownership(mode), labels(true));
        }
        let mut pending = base.clone();
        pending.insert(1, "--short-neighbors-pending".into());
        let (positional, mode) = arguments_with_pending(&pending).unwrap();
        assert_eq!(positional, &base[1..]);
        assert_eq!(mode, Mode::ShortT3Pending);
        let expected = (
            disassembly::SHORT_T3_PENDING_PROFILE,
            "neighbor_victims\tshort-only\nneighbor_ownership\tinherited-t3\npending_selected\tfull-instruction-ownership\n",
            " neighbor_victims=short-only neighbor_ownership=inherited-t3 pending_selected=full-instruction-ownership",
        );
        assert_eq!(labels_with_ownership(mode), expected);
        assert!(disassembly::import(&[], &[], ContentId::of(&[])).is_err());
        assert_eq!(labels_with_ownership(mode), expected);
        for position in 2..8 {
            for flag in flags {
                let mut bad = pending.clone();
                bad[position] = flag.into();
                assert!(arguments_with_pending(&bad).is_err());
            }
        }
        // Seven arguments are still six literal paths, even if this resembles
        // a truncated pending invocation. It must never activate pending mode.
        let (positional, mode) = arguments_with_pending(&pending[..7]).unwrap();
        assert_eq!(positional, &pending[1..7]);
        assert_eq!(mode, Mode::LongOnly);
        assert_eq!(
            arguments_with_pending(&pending[..7]),
            arguments_with_ownership(&pending[..7])
        );
        for flag in flags {
            let mut mixed = pending.clone();
            mixed.insert(2, flag.into());
            assert!(arguments_with_pending(&mixed).is_err());
        }
        let mut unknown = pending.clone();
        unknown[1] = "--unknown".into();
        assert_eq!(
            arguments_with_pending(&unknown),
            arguments_with_ownership(&unknown)
        );
        assert!(arguments_with_pending(&unknown).is_err());
        let mut misplaced = pending.clone();
        misplaced.swap(1, 2);
        assert!(arguments_with_pending(&misplaced).is_err());
        assert!(arguments_with_pending(&pending[..6]).is_err());
        let mut extra = pending;
        extra.push("extra".into());
        assert!(arguments_with_pending(&extra).is_err());
    }
}
