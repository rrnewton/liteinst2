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
fn run() -> Result<bool, String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 {
        return Err(
            "disassembly_sites ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY"
                .into(),
        );
    }
    let expected_ledger = selection::id(&args[3]).map_err(|e| e.to_string())?;
    let expected_policy = selection::id(&args[5]).map_err(|e| e.to_string())?;
    let original = read(Path::new(&args[1]), disassembly::INPUT_LIMIT)?;
    let ledger = read(Path::new(&args[2]), disassembly::TEXT_LIMIT)?;
    let policy = read(Path::new(&args[4]), disassembly::TEXT_LIMIT)?;
    let mut files = BTreeMap::from([
        ("disassembly.txt".to_owned(), ledger.clone()),
        ("disassembly-policy.txt".to_owned(), policy.clone()),
    ]);
    let prepared = (|| {
        let imported = disassembly::import(&original, &ledger, expected_ledger)?;
        // This denominator is retained even if policy/placement/loader refuses.
        files.insert("disassembly-inventory.tsv".into(), imported.inventory());
        let selected = imported.bind(&policy, expected_policy)?;
        files.insert("selection.txt".into(), selected.manifest().to_vec());
        prepare_disassembly(&original, &selected)
    })();
    // Same input reread ordering as the existing prepare CLI: no outcome is
    // dispatched and no output is published before all three snapshots agree.
    if read(Path::new(&args[1]), disassembly::INPUT_LIMIT)? != original
        || read(Path::new(&args[2]), disassembly::TEXT_LIMIT)? != ledger
        || read(Path::new(&args[4]), disassembly::TEXT_LIMIT)? != policy
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
                "LI2DISASSEMBLY-FAILURE\t1\nprofile\t{}\nobserved_original_sha256\t{}\nexpected_ledger_sha256\t{}\nexpected_policy_sha256\t{}\nqualification_complete\tfalse\ndetail_hex\t{detail}\n",
                disassembly::PROFILE, digest(&original), args[3], args[5]).into_bytes());
            false
        }
    };
    let output = Path::new(&args[6]);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| e.to_string())?;
    let mut index = format!(
        "LI2DISASSEMBLY-DIRECTORY\t1\nprofile\t{}\nobserved_original_sha256\t{}\ncandidate_complete\t{complete}\nqualification_complete\tfalse\n",
        disassembly::PROFILE,
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
        "profile={} candidate_complete={complete} qualification_complete=false",
        disassembly::PROFILE
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
