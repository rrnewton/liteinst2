//! Small explicit policy example using the existing bridge's bounded I/O.
use super::*;
use li2core::contracts::AddressRange;
use liteinst_rewrite::disassembly::whole::policy::{self, Carrier, NullHook, PolicyOptions};
use liteinst_rewrite::selection;

fn options(args: &[String]) -> Result<PolicyOptions> {
    need(
        args.len() == 18
            && args[1] == "--policy-profile"
            && args[2] == policy::PROFILE
            && args[3] == "--trusted-complete-code"
            && !args[4..].iter().any(|s| {
                matches!(
                    s.as_str(),
                    "--policy-profile"
                        | "--input-profile"
                        | "--whole-program-4096"
                        | "--trusted-complete-code"
                )
            }),
        "full_program_bridge --policy-profile et-exec-whole-bounded-512m-v1 --trusted-complete-code ORIGINAL ORIGINAL_SHA LEDGER LEDGER_SHA TARGET TARGET_SHA ROWS ROWS_SHA DOMAIN ARENA_START ARENA_LEN lowest|HOOK after-loads|CARRIER OUT",
    )?;
    let number = |s: &str| selection::num(s).map_err(|e| e.to_string());
    let arena = AddressRange::new(
        number(&args[13])?,
        usize::try_from(number(&args[14])?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(PolicyOptions {
        domain: number(&args[12])?,
        arena,
        hook: if args[15] == "lowest" {
            NullHook::LowestOriginalRet
        } else {
            NullHook::Address(number(&args[15])?)
        },
        carrier: if args[16] == "after-loads" {
            Carrier::AfterLoads
        } else {
            Carrier::Address(number(&args[16])?)
        },
    })
}

pub(super) fn run(args: &[String]) -> Result<bool> {
    let options = options(args)?;
    let paths = [
        Path::new(&args[4]),
        Path::new(&args[6]),
        Path::new(&args[8]),
        Path::new(&args[10]),
    ];
    let caps = [FILE_LIMIT, TEXT_LIMIT, TEXT_LIMIT, TEXT_LIMIT];
    let mut inputs = Vec::new();
    let mut resolved = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let captured = read(path, caps[index])?;
        let expected = selection::id(&args[5 + 2 * index]).map_err(|e| e.to_string())?;
        need(
            ContentId::of(&captured.0) == expected,
            "policy input first pin mismatch",
        )?;
        inputs.push(captured);
        resolved.push(path.canonicalize().map_err(|e| e.to_string())?);
    }
    let mut files = Vec::new();
    let mut sites = None;
    let result = disassembly::import(&inputs[0].0, &inputs[1].0, ContentId::of(&inputs[1].0))
        .and_then(|imported| {
            sites = Some(imported.jumps().len());
            // Preserve the complete input/inventory even when policy binding refuses.
            files.push(("ledger.txt", inputs[1].0.clone()));
            files.push(("sites.tsv", imported.inventory_whole_program()));
            let spec = policy::spec_from_records(
                &imported,
                &inputs[0].0,
                options,
                &inputs[2].0,
                &inputs[3].0,
            )?;
            policy::build_policy(&imported, &inputs[0].0, &spec)
        });
    for (index, path) in paths.iter().enumerate() {
        need(
            read(path, caps[index])? == inputs[index]
                && read(&resolved[index], caps[index])? == inputs[index],
            "policy inputs changed before publication",
        )?;
    }
    let ready = match result {
        Ok(policy) => {
            files.push(("policy.txt", policy));
            true
        }
        Err(error) => {
            files.push(("refusal.txt", format!("{error}\n").into_bytes()));
            false
        }
    };
    let mut complete = format!(
        "LI2FULL-PROGRAM-POLICY\t1\nprofile\t{}\nstatus\t{}\ncomplete_jump_count\t{}\ncomplete_code_premise\tcaller_supplied_not_proved\nplanning_attempted\tfalse\nqualification_complete\tfalse\n",
        policy::PROFILE,
        if ready {
            "POLICY_READY"
        } else {
            "POLICY_REFUSED"
        },
        sites.map_or_else(|| "unavailable".into(), |n| n.to_string())
    );
    for (name, captured) in ["original", "ledger", "target", "rows"].iter().zip(&inputs) {
        writeln!(
            complete,
            "input\t{name}\t{}\t{}",
            captured.0.len(),
            sha(&captured.0)
        )
        .unwrap();
    }
    for (name, bytes) in &files {
        writeln!(complete, "file\t{name}\t{}\t{}", bytes.len(), sha(bytes)).unwrap();
    }
    let total = files.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() + complete.len();
    need(total <= FILE_LIMIT, "total policy output exceeds 16 MiB")?;
    let output = Path::new(&args[17]);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| e.to_string())?;
    for (name, bytes) in files {
        write(&output.join(name), &bytes)?;
    }
    write(&output.join("COMPLETE"), complete.as_bytes())?;
    File::open(output)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!("policy_ready={ready} planning_attempted=false qualification_complete=false");
    Ok(ready)
}
