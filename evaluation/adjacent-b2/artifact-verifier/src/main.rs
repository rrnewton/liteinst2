//! Read-only structural verifier. Input is a closed adapter-owned byte transport;
//! this executable never opens a product, creates an executable, or dispatches it.
mod verify;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use verify::{Expected, FILE, Files, Result, TEXT, checked, digest, fields, host, number, require};

#[derive(Clone)]
struct Memory(BTreeMap<String, Vec<u8>>);
impl Files for Memory {
    fn read(&self, name: &str, cap: usize) -> Result<Vec<u8>> {
        let b = self.0.get(name).ok_or_else(|| format!("missing {name}"))?;
        require(b.len() <= cap, "file allocation cap")?;
        Ok(b.clone())
    }
    fn names(&self) -> BTreeSet<String> {
        self.0.keys().cloned().collect()
    }
}
const MAX_MEMBERS: usize = 262;
const BODY_BYTES: usize = 70 * TEXT;
// At most one 256-byte header per member, one preamble and one terminator.
// Content caps (1 + 5 + 64 MiB) remain unchanged.
const FRAMING_BYTES: usize = (MAX_MEMBERS + 2) * 256;
const TRANSPORT_BYTES: usize = BODY_BYTES + FRAMING_BYTES;
fn transport_bound(bytes: u64) -> Result<()> {
    require(
        bytes <= TRANSPORT_BYTES as u64,
        "complete transport framing bound",
    )
}
fn line(input: &mut impl Read) -> Result<String> {
    let mut bytes = Vec::new();
    loop {
        let mut b = [0];
        checked(input.read_exact(&mut b))?;
        if b[0] == b'\n' {
            break;
        }
        require(
            bytes.len() < 255 && (b[0] == b'\t' || b[0].is_ascii_graphic()),
            "bounded transport line",
        )?;
        bytes.push(b[0]);
    }
    checked(String::from_utf8(bytes))
}
fn transport(input: &mut impl Read) -> Result<(String, Vec<u8>, Expected, Memory)> {
    let header = line(input)?;
    let f = fields(&header, 4)?;
    require(f[..2] == ["LI2W01-INPUT", "1"], "transport schema")?;
    verify::denominator(f[2])?;
    let program = f[2].to_string();
    let count = host(number(f[3])?)?;
    require(
        (1 + verify::EXPECTED_FILES.len()..=MAX_MEMBERS).contains(&count),
        "transport member count before allocation",
    )?;
    let mut original = None;
    let mut expected = BTreeMap::new();
    let mut product = BTreeMap::new();
    let mut prior = String::new();
    let mut used = 0usize;
    for _ in 0..count {
        let header = line(input)?;
        let f = fields(&header, 3)?;
        let name = f[0];
        let length = host(number(f[1])?)?;
        require(
            name > prior.as_str()
                && name.len() <= 160
                && f[2].len() == 64
                && verify::unhex(f[2])?.len() == 32,
            "ordered unique transport member/digest",
        )?;
        prior = name.to_string();
        let (group, leaf) = name.split_once('/').ok_or("transport namespace")?;
        require(
            !leaf.is_empty()
                && leaf.len() <= 128
                && leaf
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                && leaf != "."
                && leaf != "..",
            "transport filename",
        )?;
        let cap = match group {
            "input" => {
                require(
                    leaf == "original" && original.is_none(),
                    "one immutable original",
                )?;
                TEXT
            }
            "expected" => {
                require(
                    verify::EXPECTED_FILES.contains(&leaf),
                    "expected transport roster",
                )?;
                TEXT
            }
            "product" => FILE,
            _ => return Err("transport namespace".into()),
        };
        require(length <= cap, "transport per-file bound before allocation")?;
        if group == "product" {
            used = used.checked_add(length).ok_or("aggregate overflow")?;
            require(
                used <= 64 * TEXT && product.len() < 256,
                "64 MiB product transport/member bounds",
            )?;
        }
        let mut bytes = vec![0; length];
        checked(input.read_exact(&mut bytes))?;
        require(digest(&bytes) == f[2], "transport member bytes")?;
        match group {
            "input" => original = Some(bytes),
            "expected" => {
                require(
                    expected.insert(leaf.to_string(), bytes).is_none(),
                    "expected duplicate",
                )?;
            }
            "product" => {
                require(
                    product.insert(leaf.to_string(), bytes).is_none(),
                    "product duplicate",
                )?;
            }
            _ => unreachable!(),
        }
    }
    require(line(input)? == "END", "transport end")?;
    let mut tail = [0];
    require(
        checked(input.read(&mut tail))? == 0,
        "transport trailing bytes",
    )?;
    Ok((
        program.clone(),
        original.ok_or("missing original")?,
        Expected {
            program,
            files: expected,
        },
        Memory(product),
    ))
}
fn indices(original: &[u8], product: &Memory) -> Result<()> {
    let original = digest(original);
    let mut complete = format!(
        "LI2DISASSEMBLY-DIRECTORY\t1\nprofile\t{}\nobserved_original_sha256\t{original}\ncandidate_complete\ttrue\nqualification_complete\tfalse\n",
        verify::PROFILE
    );
    let mut bundle = format!(
        "LI2BUNDLE\t1\noriginal_sha256\t{original}\nqualification_complete\tfalse\nconsumer_action\tRuntimeScan-while-gated-until-qualified\n"
    );
    for (name, bytes) in &product.0 {
        if name != "COMPLETE" {
            let row = format!("file\t{name}\t{}\t{}\n", bytes.len(), digest(bytes));
            complete.push_str(&row);
            if name != "bundle-index.tsv" {
                bundle.push_str(&row);
            }
        }
    }
    // Both entire index bytes are checked, including order and final LF.
    require(
        product.read("bundle-index.tsv", TEXT)? == bundle.as_bytes()
            && product.read("COMPLETE", TEXT)? == complete.as_bytes(),
        "complete exact nested indices",
    )
}
fn run() -> Result<()> {
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    };
    let args: Vec<_> = std::env::args_os().collect();
    require(
        args.len() == 3 && cfg!(target_os = "linux"),
        "usage: verifier TRANSPORT SHA256 (Linux read-only transport)",
    )?;
    let expected_hash = checked(std::str::from_utf8(args[2].as_bytes()))?;
    require(
        expected_hash.len() == 64 && verify::unhex(expected_hash)?.len() == 32,
        "transport hash",
    )?;
    // Linux O_NOFOLLOW | O_NONBLOCK: never follow a substituted transport link
    // or block while opening a non-regular inode. No product paths are opened.
    let mut input = checked(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x20000 | 0x800)
            .open(&args[1]),
    )?;
    let before = checked(input.metadata())?;
    require(
        before.is_file(),
        "bounded regular transport before allocation",
    )?;
    transport_bound(before.len())?;
    let mut raw = Vec::with_capacity(host(before.len())?);
    checked(
        (&mut input)
            .take(TRANSPORT_BYTES as u64 + 1)
            .read_to_end(&mut raw),
    )?;
    let after = checked(input.metadata())?;
    let named = checked(std::fs::symlink_metadata(&args[1]))?;
    let stamp = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    require(
        stamp(&before) == stamp(&after)
            && stamp(&after) == stamp(&named)
            && raw.len() as u64 == before.len()
            && digest(&raw) == expected_hash,
        "immutable transport custody",
    )?;
    let (program, original, expected, product) = transport(&mut raw.as_slice())?;
    indices(&original, &product)?;
    let result = verify::verify(&program, &original, &expected, &product)?;
    println!(
        "LI2W01-PROGRAM\t1\nprogram\t{}\nselected\t{}\nimages\t{}\ncandidate_sha256\t{}\nstructural_joins_complete\ttrue\nqualification_complete\tfalse\nclassification_complete\tfalse\nnative_correctness_complete\tfalse\nperformance_eligible\tfalse",
        result.program, result.selected, result.images, result.candidate_sha256
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("W01 UNSATISFIED: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
