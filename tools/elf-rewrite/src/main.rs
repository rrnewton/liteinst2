//! CLI: create a new inspectable, non-executable artifact directory.
use liteinst_rewrite::{Error, prepare};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let file = std::fs::File::open(path).map_err(|e| io("read", e))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io("read", e))?;
    if bytes.len() > limit {
        return Err(io("read-limit", path.display()));
    }
    Ok(bytes)
}
fn io(stage: &'static str, error: impl std::fmt::Display) -> Error {
    Error {
        stage,
        detail: error.to_string(),
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| io("create", e))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| io("write", e))
}
fn run() -> Result<bool, Error> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 || args[1] != "prepare" {
        return Err(io(
            "usage",
            "liteinst-rewrite prepare INPUT_ELF SELECTION NEW_DIRECTORY",
        ));
    }
    let input = PathBuf::from(&args[2]);
    let selection = PathBuf::from(&args[3]);
    let output = PathBuf::from(&args[4]);
    let manifest = read_bounded(&selection, 1024 * 1024)?;
    let limits = liteinst_rewrite::selection::parse(&manifest)?.limits;
    let original = read_bounded(&input, limits.input_bytes)?;
    let prepared = prepare(&original, &manifest);
    // Reauthenticate before creating any output. A concurrent path replacement
    // cannot make the producer report another file as the original input.
    if read_bounded(&input, limits.input_bytes)? != original
        || read_bounded(&selection, 1024 * 1024)? != manifest
    {
        return Err(io("input-changed", "inputs changed during planning"));
    }
    // Both the successful product and the global-failure report use the same
    // authenticated snapshots. Do not dispatch on Err before the rereads.
    let product = match prepared {
        Ok(product) => product,
        Err(error) => {
            // A valid selection still receives one failed row per requested ID
            // when global ELF/identity/loader ownership preflight fails. Such a
            // report cannot claim authentic metadata for a stale original.
            let declared = liteinst_rewrite::selection::parse(&manifest)?;
            let digest = |bytes: &[u8]| -> String {
                formats::ContentId::of(bytes)
                    .0
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            };
            let detail: String = error
                .detail
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let mut report = format!(
                "LI2INPUTFAIL\t1\nselection_sha256\t{}\nobserved_original_sha256\t{}\nqualification_complete\tfalse\nsite\tpc\tfile_offset\tlength\tstage\tdetail_hex\n",
                digest(&manifest),
                digest(&original)
            );
            for site in &declared.sites {
                report.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\n",
                    site.id, site.pc, site.file_offset, site.length, error.stage, detail
                ));
            }
            std::fs::create_dir(&output).map_err(|e| io("new-directory", e))?;
            write_new(&output.join("selection.txt"), &manifest)?;
            write_new(&output.join("input-failure.tsv"), report.as_bytes())?;
            write_new(
                &output.join("COMPLETE"),
                format!(
                    "LI2TOOL-INPUT-FAILURE 1\nreport_sha256 {}\nqualification_complete false\n",
                    digest(report.as_bytes())
                )
                .as_bytes(),
            )?;
            return Err(error);
        }
    };
    std::fs::create_dir(&output).map_err(|e| io("new-directory", e))?;
    for (name, bytes) in product.files() {
        write_new(&output.join(name), bytes)?;
    }
    // No existing paths replaced, no executable bits, marker created last.
    let index = &product.files()["bundle-index.tsv"];
    let identity = formats::ContentId::of(index);
    let digest: String = identity.0.iter().map(|b| format!("{b:02x}")).collect();
    write_new(&output.join("COMPLETE"),format!("LI2TOOL-DIRECTORY 1\nindex_sha256 {digest}\ncandidate_complete {}\nqualification_complete false\n",product.candidate_complete()).as_bytes())?;
    std::fs::File::open(&output)
        .and_then(|f| f.sync_all())
        .map_err(|e| io("directory-sync", e))?;
    println!(
        "candidate_complete={} qualification_complete=false sites={}",
        product.candidate_complete(),
        product.reports().len()
    );
    Ok(product.candidate_complete())
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
