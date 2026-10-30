//! Explicit adjacent-B2 artifact profile. This executable never maps code.
#![forbid(unsafe_code)]
use liteinst_rewrite::{
    disassembly, prepare_disassembly_adjacent_b2, prepare_disassembly_adjacent_routed_jmp,
    selection,
};
use std::collections::BTreeMap;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;
#[path = "publication_io.rs"]
mod publication_io;
pub use publication_io::{digest, read, snapshots_match, write};

#[derive(Clone, Copy)]
pub enum Profile {
    AdjacentB2,
    RoutedJmp,
}
impl Profile {
    pub fn for_name(name: &str) -> Result<Self, String> {
        match name {
            disassembly::adjacent_b2::PROFILE => Ok(Self::AdjacentB2),
            disassembly::adjacent_routed_jmp::PROFILE => Ok(Self::RoutedJmp),
            _ => Err("unknown fixed producer profile".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::AdjacentB2 => disassembly::adjacent_b2::PROFILE,
            Self::RoutedJmp => disassembly::adjacent_routed_jmp::PROFILE,
        }
    }
    fn executable(self) -> &'static str {
        match self {
            Self::AdjacentB2 => "adjacent_b2_disassembly_sites",
            Self::RoutedJmp => "adjacent_routed_jmp_disassembly_sites",
        }
    }
}
pub fn publish(
    profile: Profile,
    output: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    original: &[u8],
    complete: bool,
    mut put: impl FnMut(&Path, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    let profile = profile.name();
    let mut index = format!(
        "LI2DISASSEMBLY-DIRECTORY\t1\nprofile\t{profile}\nobserved_original_sha256\t{}\ncandidate_complete\t{complete}\nqualification_complete\tfalse\n",
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
pub fn run_with_read(
    args: &[String],
    selected_profile: Profile,
    mut read: impl FnMut(&Path, usize) -> Result<Vec<u8>, String>,
) -> Result<bool, String> {
    // Each executable fixes its profile before parsing or reading any input.
    let profile = selected_profile.name();
    let executable = selected_profile.executable();
    if args.len() != 7 {
        return Err(format!(
            "{profile}: {executable} ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY"
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
        match selected_profile {
            Profile::AdjacentB2 => {
                files.insert(
                    "disassembly-inventory.tsv".into(),
                    imported.inventory_adjacent_b2(),
                );
                let selected = imported.bind_adjacent_b2(policy, expected_policy)?;
                files.insert("selection.txt".into(), selected.manifest().to_vec());
                prepare_disassembly_adjacent_b2(original, &selected)
            }
            Profile::RoutedJmp => {
                files.insert(
                    "disassembly-inventory.tsv".into(),
                    imported.inventory_adjacent_routed_jmp(),
                );
                let selected = imported.bind_adjacent_routed_jmp(policy, expected_policy)?;
                files.insert("selection.txt".into(), selected.manifest().to_vec());
                prepare_disassembly_adjacent_routed_jmp(original, &selected)
            }
        }
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
                "LI2DISASSEMBLY-FAILURE\t1\nprofile\t{profile}\nobserved_original_sha256\t{}\nexpected_ledger_sha256\t{}\nexpected_policy_sha256\t{}\nqualification_complete\tfalse\ndetail_hex\t{detail}\n",
                digest(original), args[3], args[5]).into_bytes());
            false
        }
    };
    let output = Path::new(&args[6]);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| e.to_string())?;
    publish(selected_profile, output, &files, original, complete, write)?;
    std::fs::File::open(output)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!("profile={profile} candidate_complete={complete} qualification_complete=false");
    Ok(complete)
}
