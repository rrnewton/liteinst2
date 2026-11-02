//! Fabricated input and metadata files only; no executable is loaded or run.
use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

fn explicit(pin: &str, original: &str, csv: &str, csv_pin: &str, output: &str) -> Vec<String> {
    [
        "bridge",
        "--input-profile",
        input::PROFILE,
        "--original-sha256",
        pin,
        "--trusted-complete-code",
        original,
        csv,
        csv_pin,
        output,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[test]
fn explicit_input_preserves_legacy_selectors_and_rejects_mixed_or_unpinned_profiles() {
    let old: Vec<_> = [
        "bridge",
        "--trusted-complete-code",
        "original",
        "csv",
        "pin",
        "out",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert!(input::arguments(&old).unwrap().is_none());
    assert_eq!(arguments(&old).unwrap(), (old.as_slice(), Profile::Legacy));
    let mut whole = old.clone();
    whole.insert(1, "--whole-program-4096".to_owned());
    assert!(input::arguments(&whole).unwrap().is_none());
    assert_eq!(
        arguments(&whole).unwrap(),
        (&whole[1..], Profile::Whole4096)
    );
    let pin = "0".repeat(64);
    let args = explicit(&pin, "original", "csv", "pin", "out");
    let parsed = input::arguments(&args).unwrap().unwrap();
    assert_eq!(parsed.args, old);
    assert_eq!(parsed.expected, ContentId([0; 32]));
    for (index, value) in [
        (2, "legacy"),
        (3, "--whole-program-4096"),
        (4, "not-a-digest"),
        (5, "--input-profile"),
        (6, "--whole-program-4096"),
        (7, "--input-profile"),
        (9, "--policy-profile"),
    ] {
        let mut bad = args.clone();
        bad[index] = value.into();
        assert!(input::arguments(&bad).is_err(), "accepted {bad:?}");
    }
    let mut duplicate = args.clone();
    duplicate.push("--input-profile".into());
    assert!(input::arguments(&duplicate).is_err());
    assert!(input::arguments(&args[..9]).is_err());
}

#[test]
fn explicit_et_exec_keeps_independent_import_and_pin_before_elf_refusal() {
    let (mut original, csv) = ordinary();
    let dynamic_pin = sha(&original);
    let dynamic = input::arguments(&explicit(&dynamic_pin, "original", "csv", "pin", "out"))
        .unwrap()
        .unwrap();
    assert_eq!(
        dynamic.verify(&original).unwrap_err(),
        "input profile requires ET_EXEC"
    );
    put(&mut original, 16, 2, 2);
    assert_eq!(
        dynamic.verify(&original).unwrap_err(),
        "original first pin mismatch"
    );
    let exec = input::arguments(&explicit(&sha(&original), "original", "csv", "pin", "out"))
        .unwrap()
        .unwrap();
    exec.verify(&original).unwrap();
    let missing = text(&csv).replace("0x403000,+12288,1\n", "");
    assert!(
        bridge_profile(
            &original,
            missing.as_bytes(),
            "/fixed/original",
            Profile::Whole4096
        )
        .is_err()
    );
    let mut wrong_isa = original.clone();
    put(&mut wrong_isa, 18, 2, 3);
    let wrong = input::arguments(&explicit(&sha(&wrong_isa), "original", "csv", "pin", "out"))
        .unwrap()
        .unwrap();
    assert!(wrong.verify(&wrong_isa).unwrap_err().starts_with("ELF:"));
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "li2-direct-policy-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn explicit_material_and_policy_cli_retain_complete_success_and_refusal_outputs() {
    use liteinst_rewrite::disassembly::whole::policy;
    let dir = Temp::new();
    let (mut original, csv) = ordinary();
    put(&mut original, 16, 2, 2);
    fs::write(dir.path("original"), &original).unwrap();
    fs::write(dir.path("dump.csv"), &csv).unwrap();
    let old: Vec<_> = [
        "bridge".to_owned(),
        "--trusted-complete-code".into(),
        dir.path("original"),
        dir.path("dump.csv"),
        "invalid-csv-pin".into(),
        dir.path("old"),
    ]
    .into_iter()
    .collect();
    assert_eq!(run(&old).unwrap_err(), "not the pinned original e9patch");
    assert!(!dir.0.join("old").exists());
    let mut args = explicit(
        &sha(&original),
        &dir.path("original"),
        &dir.path("dump.csv"),
        &sha(&csv),
        &dir.path("materials"),
    );
    assert!(run(&args).unwrap());
    let materials = dir.0.join("materials");
    let ledger = fs::read(materials.join("ledger.txt")).unwrap();
    let inventory = fs::read(materials.join("sites.tsv")).unwrap();
    let complete = fs::read_to_string(materials.join("COMPLETE")).unwrap();
    assert!(complete.contains(&format!("profile\t{}\n", input::PROFILE)));
    assert!(complete.contains(&format!("original_sha256\t{}\n", sha(&original))));
    assert!(complete.contains("heads\t8\nsites\t3\n"));
    assert!(complete.contains(
        "caller_supplied_not_proved\nplanning_attempted\tfalse\nqualification_complete\tfalse\n"
    ));
    let imported = disassembly::import(&original, &ledger, ContentId::of(&ledger)).unwrap();
    assert_eq!(inventory, imported.inventory_whole_program());
    args[4] = "0".repeat(64);
    args[9] = dir.path("bad-pin");
    assert_eq!(run(&args).unwrap_err(), "original first pin mismatch");
    assert!(!dir.0.join("bad-pin").exists());

    let start = BASE + 0x40000;
    let length = 0x40000;
    let mut records = String::new();
    for site in imported.jumps() {
        writeln!(
            records,
            "search {} preferred 64 256 64 none 256 4096",
            site.id
        )
        .unwrap();
        for role in ["selected", "victim"] {
            writeln!(
                records,
                "allocation {} {role} {start} 1 4096 {start}:{length}",
                site.id
            )
            .unwrap();
        }
    }
    let target = b"target fxsave64\n";
    fs::write(dir.path("target"), target).unwrap();
    fs::write(dir.path("rows"), records.as_bytes()).unwrap();
    let mut policy_args = vec![
        "bridge".into(),
        "--policy-profile".into(),
        policy::PROFILE.into(),
        "--trusted-complete-code".into(),
        dir.path("original"),
        sha(&original),
        materials.join("ledger.txt").to_str().unwrap().into(),
        sha(&ledger),
        dir.path("target"),
        sha(target),
        dir.path("rows"),
        sha(records.as_bytes()),
        "1".into(),
        start.to_string(),
        length.to_string(),
        "lowest".into(),
        "after-loads".into(),
        dir.path("policy"),
    ];
    assert!(run(&policy_args).unwrap());
    let raw = fs::read(dir.0.join("policy/policy.txt")).unwrap();
    let selected = imported
        .clone()
        .bind_whole_program(&raw, ContentId::of(&raw))
        .unwrap();
    assert!(
        std::str::from_utf8(selected.manifest())
            .unwrap()
            .contains("site 3 ")
    );
    assert_eq!(fs::read(dir.0.join("policy/sites.tsv")).unwrap(), inventory);
    let failed_rows = records.replace(
        &format!("{start}:{length}"),
        &format!("{}:4096", start + length),
    );
    fs::write(dir.path("rows"), failed_rows.as_bytes()).unwrap();
    policy_args[11] = sha(failed_rows.as_bytes());
    policy_args[17] = dir.path("refused-policy");
    assert!(!run(&policy_args).unwrap());
    assert_eq!(
        fs::read(dir.0.join("refused-policy/sites.tsv")).unwrap(),
        inventory
    );
    assert_eq!(
        fs::read(dir.0.join("refused-policy/ledger.txt")).unwrap(),
        ledger
    );
    assert!(
        fs::read_to_string(dir.0.join("refused-policy/COMPLETE"))
            .unwrap()
            .contains("status\tPOLICY_REFUSED\ncomplete_jump_count\t3\n")
    );
    assert!(
        fs::read_to_string(dir.0.join("refused-policy/refusal.txt"))
            .unwrap()
            .contains("no in-arena permit")
    );
    assert!(!dir.0.join("refused-policy/policy.txt").exists());
}
