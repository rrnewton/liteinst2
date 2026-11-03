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

fn jump_stack_fixture() -> (Vec<u8>, Vec<u8>) {
    let (mut original, csv) = fixture(
        &[
            0xeb, 2, 0x54, 0x5c, 0xf3, 0x50, 0x66, 0x50, 0xff, 0xf0, 0x8f, 0xc0, 0xe8, 0, 0, 0, 0,
            0xc3,
        ],
        &[2, 1, 1, 2, 2, 2, 2, 5, 1],
    );
    put(&mut original, 16, 2, 2);
    (original, csv)
}

#[test]
fn jump_stack_material_selection_joins_every_rpc_patch_and_keeps_caps() {
    let (original, csv) = jump_stack_fixture();
    let material =
        bridge_profile(&original, &csv, "/fixed/original", Profile::JumpStack4096).unwrap();
    assert_eq!(
        (material.heads, material.sites, material.classes),
        (12, 5, Some([2, 2, 1]))
    );
    let imported = disassembly::jump_stack::import(
        &original,
        &material.ledger,
        ContentId::of(&material.ledger),
    )
    .unwrap();
    assert_eq!(material.inventory, imported.inventory());
    let heads = csv_heads(&csv).unwrap();
    let indices = selected_heads(&heads, imported.sites().iter().map(|s| s.geometry())).unwrap();
    assert_eq!(indices, [1, 2, 3, 4, 5]);
    let request = material.rpc.unwrap();
    let patches: Vec<usize> = text(&request)
        .lines()
        .filter(|l| l.contains("\"method\":\"patch\""))
        .map(|l| {
            l.split("\"offset\":")
                .nth(1)
                .unwrap()
                .split('}')
                .next()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    assert_eq!(patches, [4356, 4355, 4354, 4352, 4112]);
    for site in imported.sites() {
        let s = site.geometry();
        assert!(text(&request).contains(&format!(
            "\"address\":{},\"length\":{},\"offset\":{}",
            s.pc, s.length, s.file_offset
        )));
    }
    for field in [0, 1] {
        let mut wrong = heads.clone();
        if field == 0 {
            wrong[indices[2]].offset += 1;
        } else {
            wrong[indices[2]].length += 1;
        }
        assert_eq!(
            selected_heads(&wrong, imported.sites().iter().map(|s| s.geometry())).unwrap_err(),
            "imported selected geometry"
        );
    }
    let mut missing = heads.clone();
    missing.remove(indices[2]);
    assert_eq!(
        selected_heads(&missing, imported.sites().iter().map(|s| s.geometry())).unwrap_err(),
        "imported site missing head"
    );
    let old = bridge_profile(&original, &csv, "/fixed/original", Profile::Whole4096).unwrap();
    assert_eq!((old.heads, old.sites, old.classes), (12, 2, None));
    assert_eq!(old.ledger, material.ledger);
    // Full union is retained even when the unchanged 4096 transport cap refuses.
    let mut code = vec![0x50; 4096];
    code.push(0xc3);
    let (original, csv) = fixture(&code, &vec![1; 4097]);
    let refused =
        bridge_profile(&original, &csv, "/fixed/original", Profile::JumpStack4096).unwrap();
    assert_eq!((refused.sites, refused.classes), (4097, Some([1, 4096, 0])));
    assert!(text(&refused.inventory).contains("complete_site_count\t4097\n"));
    assert_eq!(
        refused.rpc.unwrap_err(),
        "site bound: required 4097, limit 4096"
    );
}

#[test]
fn jump_stack_input_selectors_keep_pin_type_and_mixed_mode_refusals() {
    let (mut original, _) = jump_stack_fixture();
    let mut args = explicit(&sha(&original), "original", "csv", "pin", "out");
    args[2] = input::JUMP_STACK_PROFILE.into();
    let selected = input::arguments(&args).unwrap().unwrap();
    assert_eq!(selected.profile, Profile::JumpStack4096);
    assert_eq!(selected.name(), input::JUMP_STACK_PROFILE);
    selected.verify(&original).unwrap();
    for flag in [
        "--whole-program-4096",
        "--whole-program-fixed-exec-packed-overlapping-jump-stack64-4096",
        "--policy-profile",
        "--input-profile",
        "--short-neighbors-only",
    ] {
        let mut mixed = args.clone();
        mixed[6] = flag.into();
        assert!(input::arguments(&mixed).is_err());
    }
    put(&mut original, 16, 2, 3);
    assert_eq!(
        selected.verify(&original).unwrap_err(),
        "original first pin mismatch"
    );
    args[4] = sha(&original);
    assert_eq!(
        input::arguments(&args)
            .unwrap()
            .unwrap()
            .verify(&original)
            .unwrap_err(),
        "input profile requires ET_EXEC"
    );
    args[2] = input::PROFILE.into();
    assert_eq!(
        input::arguments(&args).unwrap().unwrap().profile,
        Profile::Whole4096
    );
}

#[test]
fn jump_stack_material_policy_files_keep_full_counts_on_policy_refusal() {
    use liteinst_rewrite::disassembly::whole::policy;
    let dir = Temp::new();
    let (original, csv) = jump_stack_fixture();
    fs::write(dir.path("original"), &original).unwrap();
    fs::write(dir.path("csv"), &csv).unwrap();
    let mut args = explicit(
        &sha(&original),
        &dir.path("original"),
        &dir.path("csv"),
        &sha(&csv),
        &dir.path("material"),
    );
    args[2] = input::JUMP_STACK_PROFILE.into();
    assert!(run(&args).unwrap());
    let complete = fs::read_to_string(dir.path("material/COMPLETE")).unwrap();
    let census = "selection_profile\tjumps-gpr-stack64-v1\ncomplete_site_count\t5\njump_count\t2\npush_r64_count\t2\npop_r64_count\t1\n";
    assert!(complete.contains(census));
    assert!(complete.contains("heads\t12\nsites\t5\n"));
    let ledger = fs::read(dir.path("material/ledger.txt")).unwrap();
    let inventory = fs::read(dir.path("material/sites.tsv")).unwrap();
    let mut records = String::new();
    for id in 1..=5 {
        writeln!(records, "search {id} preferred 64 256 64 none 256 4096").unwrap();
        for role in ["selected", "victim"] {
            writeln!(
                records,
                "allocation {id} {role} none 1 4096 16777216:520093696"
            )
            .unwrap();
        }
    }
    let target = b"target fxsave64\n";
    fs::write(dir.path("target"), target).unwrap();
    fs::write(dir.path("rows"), &records).unwrap();
    let mut policy_args = vec![
        "bridge".into(),
        "--policy-profile".into(),
        policy::JUMP_STACK_PROFILE.into(),
        "--trusted-complete-code".into(),
        dir.path("original"),
        sha(&original),
        dir.path("material/ledger.txt"),
        sha(&ledger),
        dir.path("target"),
        sha(target),
        dir.path("rows"),
        sha(records.as_bytes()),
        "7".into(),
        "16777216".into(),
        "520093696".into(),
        "lowest".into(),
        "after-loads".into(),
        dir.path("policy"),
    ];
    assert!(run(&policy_args).unwrap());
    assert_eq!(fs::read(dir.path("policy/sites.tsv")).unwrap(), inventory);
    let policy_bytes = fs::read(dir.path("policy/policy.txt")).unwrap();
    assert!(policy_bytes.starts_with(b"LI2DISASM-JUMP-STACK-WHOLE-POLICY 1\n"));
    assert!(
        fs::read_to_string(dir.path("policy/COMPLETE"))
            .unwrap()
            .contains(census)
    );
    assert!(
        disassembly::import(&original, &ledger, ContentId::of(&ledger))
            .unwrap()
            .bind_whole_program(&policy_bytes, ContentId::of(&policy_bytes))
            .is_err()
    );
    let missing = records
        .lines()
        .filter(|line| !line.starts_with("allocation 5 victim "))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(dir.path("rows"), &missing).unwrap();
    policy_args[11] = sha(missing.as_bytes());
    policy_args[17] = dir.path("refused");
    assert!(!run(&policy_args).unwrap());
    assert_eq!(fs::read(dir.path("refused/sites.tsv")).unwrap(), inventory);
    let refused = fs::read_to_string(dir.path("refused/COMPLETE")).unwrap();
    assert!(refused.contains("status\tPOLICY_REFUSED\n"));
    assert!(refused.contains(census));
    assert!(!dir.0.join("refused/policy.txt").exists());
    policy_args[6] = "--whole-program-4096".into();
    assert!(run(&policy_args).is_err());
}
