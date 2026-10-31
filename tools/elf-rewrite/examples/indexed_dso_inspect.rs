//! First actual-artifact gate for the opt-in compiled DSO experiment.
//! No loading, native call, CFI registration or generated execution occurs here.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/caller.rs"]
mod caller;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/elf.rs"]
mod elf;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(dead_code)]
#[path = "indexed_dso_support/leaf.rs"]
mod leaf;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn inspect() -> Result<(), String> {
    use formats::ContentId;
    use liteinst_rewrite::carrier::{
        dynamic,
        unwind::{IndexLimits, OriginalIndex},
    };
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

    fn digest(text: &std::ffi::OsStr) -> Result<ContentId, String> {
        let text = text.to_str().ok_or("non-UTF8 digest")?;
        if text.len() != 64
            || !text
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err("expected lowercase SHA256".into());
        }
        let mut bytes = [0; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
        }
        Ok(ContentId(bytes))
    }
    fn read(path: &Path, expected: ContentId) -> Result<Vec<u8>, String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| e.to_string())?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.len() > elf::BYTE_LIMIT {
            return Err("expected bounded regular ELF input".into());
        }
        let mut bytes = Vec::new();
        file.take(elf::BYTE_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > elf::BYTE_LIMIT || ContentId::of(&bytes) != expected {
            return Err("whole input SHA256/size mismatch".into());
        }
        Ok(bytes)
    }
    fn hex(id: ContentId) -> String {
        use std::fmt::Write;
        let mut value = String::with_capacity(64);
        for byte in id.0 {
            write!(&mut value, "{byte:02x}").unwrap();
        }
        value
    }

    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 {
        return Err(
            "usage: indexed_dso_inspect SUBJECT SUBJECT_SHA256 CALLER CALLER_SHA256".into(),
        );
    }
    let subject_id = digest(&args[1])?;
    let caller_id = digest(&args[3])?;
    let subject = elf::Snapshot::parse(read(Path::new(&args[0]), subject_id)?)
        .map_err(|e| format!("subject ELF: {e:?}"))?;
    let caller_bytes = read(Path::new(&args[2]), caller_id)?;
    let caller = elf::caller_image::CallerImage::inspect(&caller_bytes)
        .map_err(|e| format!("caller ELF/CFG: {e:?}"))?;
    let symbols = subject.symbols();
    let code = subject
        .code(&symbols.work)
        .map_err(|e| format!("work bytes: {e:?}"))?;
    let cfi = subject
        .source_record(symbols.selected.address)
        .map_err(|e| format!("original work CFI: {e:?}"))?;
    let heads = leaf::prove(
        code.bytes,
        symbols.work.address,
        symbols.selected.address,
        &cfi,
    )
    .map_err(|e| format!("work CFG/exact CFI rows: {e:?}"))?;
    let input = subject.elf().map_err(|e| format!("subject ELF: {e:?}"))?;
    let index = OriginalIndex::inspect(&input, IndexLimits::default(), dynamic::Limits::default())
        .map_err(|e| format!("subject original index: {e:?}"))?;
    // Addresses are ELF coordinates, never process addresses. Caller CFI is
    // retained by its view but is not semantically qualified by this command.
    println!(
        concat!(
            "{{\"schema\":\"li2-indexed-dso-inspection-v1\",",
            "\"status\":\"STRUCTURAL_INSPECTION_ONLY\",",
            "\"subject_sha256\":\"{}\",\"caller_sha256\":\"{}\",",
            "\"work_heads\":{},\"selected\":{},\"continuation\":{},",
            "\"subject_original_fdes\":{},\"caller_original_fdes\":{},",
            "\"work_caller_call\":{},\"work_caller_return\":{},",
            "\"reference_caller_call\":{},\"reference_caller_return\":{},",
            "\"caller_cfi_qualified\":false,\"native_qualification\":false}}"
        ),
        hex(subject.identity()),
        hex(caller.identity()),
        heads.len(),
        symbols.selected.address,
        symbols.continuation.address,
        index.intervals().count(),
        caller.original_fdes().len(),
        caller.work().proof().target_call().address,
        caller.work().proof().return_pc(),
        caller.reference().proof().target_call().address,
        caller.reference().proof().return_pc()
    );
    Ok(())
}

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if let Err(error) = inspect() {
        eprintln!("indexed DSO inspection refused: {error}");
        std::process::exit(1);
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        eprintln!("indexed DSO inspection requires Linux x86-64");
        std::process::exit(1);
    }
}
