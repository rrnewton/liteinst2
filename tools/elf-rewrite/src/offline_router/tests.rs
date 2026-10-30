//! All tests are prospective; real opaque plans feed the catalog bridge.
use super::*;
#[path = "../../examples/fixtures/offline_router.rs"]
mod fixture;
fn bind(c: &fixture::Case) -> Result<Bound, Error> {
    Bound::bind(
        &c.original,
        &c.ledger,
        ContentId::of(&c.ledger),
        &c.planning,
        ContentId::of(&c.planning),
        &c.runtime,
        ContentId::of(&c.runtime),
    )
}
#[test]
fn complete_two_program_transaction_uses_real_plans_and_exact_catalog_bytes() {
    let a = fixture::case(1);
    let b = fixture::case(2);
    let aa = bind(&a).unwrap();
    let bb = bind(&b).unwrap();
    let products = prepare_programs([&a.original, &b.original], [&aa, &bb]).unwrap();
    for (index, (product, bound)) in products.iter().zip([&aa, &bb]).enumerate() {
        assert!(product.candidate_complete());
        assert!(!product.qualification_complete());
        assert_eq!(product.reports().len(), [16, 26][index]);
        assert!(
            product
                .reports()
                .iter()
                .all(|r| r.candidate_emitted && r.refusal.is_none())
        );
        let f = product.files();
        let catalog = boot::Catalog::decode(&f["catalog.li2boot"]).unwrap();
        let input = catalog.input();
        assert_eq!(input.main, f["candidate.elf"]);
        assert_eq!(input.metadata, f["metadata.li2meta"]);
        assert_eq!(input.ledger, f["ledger.tsv"]);
        assert_eq!(input.target, f["target.tsv"]);
        assert_eq!(input.selection, bound.manifest());
        assert_eq!(
            (input.heads.len(), input.steps.len(), input.images.len()),
            ([80, 107][index], [16, 26][index], [16, 26][index])
        );
        assert_eq!(
            input.policy.bootstrap_dso,
            format!("/pkg/{}.so", program_name(index as u64 + 1)).as_bytes()
        );
        assert_eq!(catalog.encode().unwrap(), f["catalog.li2boot"]);
        assert!(catalog.routes().is_empty());
        let elf = boot::parse(&input.main).unwrap();
        assert_eq!(
            elf.header().entry,
            boot::parse(&input.original).unwrap().header().entry
        );
        assert_eq!(
            elf.segments(carrier::elf64::SegmentType::Dynamic).count(),
            1
        );
        assert_eq!(
            elf.segments(carrier::elf64::SegmentType::Interpreter)
                .count(),
            1
        );
        for (i, image) in input.images.iter().enumerate() {
            assert_eq!(image.body.bytes, f[&format!("image-{i:04}.bin")]);
        }
        assert!(
            std::str::from_utf8(&f["bundle-index.tsv"])
                .unwrap()
                .contains(&format!(
                    "file\tcatalog.li2boot\t{}\t{}\n",
                    f["catalog.li2boot"].len(),
                    ledger::hex(&ContentId::of(&f["catalog.li2boot"]).0)
                ))
        );
    }
}
#[test]
fn every_final_boundary_error_keeps_both_attempts_and_no_product_escape() {
    let a = fixture::case(1);
    let b = fixture::case(2);
    let aa = bind(&a).unwrap();
    let bb = bind(&b).unwrap();
    for stop in [
        "evidence-serialization",
        "carrier-construction",
        "sparse-serialization",
        "complete-output-serialization",
        "startup-catalog",
    ] {
        let mut first_boundaries = Vec::new();
        let mut second_boundaries = Vec::new();
        let result =
            prepare_programs_with_gate([&a.original, &b.original], [&aa, &bb], |program, stage| {
                if program == 1 {
                    first_boundaries.push(stage);
                } else {
                    second_boundaries.push(stage);
                }
                if program == 1 && stage == stop {
                    Err(Error::new("injected-final-boundary", stop))
                } else {
                    Ok(())
                }
            });
        assert!(result.is_err(), "required terminal boundary {stop}");
        assert_eq!(first_boundaries.last(), Some(&stop));
        assert_eq!(
            second_boundaries
                .iter()
                .filter(|&&s| s == "evidence-serialization")
                .count(),
            1
        );
        assert_eq!(second_boundaries.last(), Some(&"startup-catalog"));
    }
}
#[test]
fn immutable_denominator_and_distinct_dso_paths_refuse_before_planning() {
    let a = fixture::case(1);
    let b = fixture::case(2);
    let aa = bind(&a).unwrap();
    let mut bb = bind(&b).unwrap();
    assert!(
        prepare_programs_with_gate([&a.original, &b.original], [&bb, &aa], |_, _| panic!(
            "wrong program order reached planner"
        ))
        .is_err()
    );
    bb.runtime.bootstrap_dso = aa.runtime.bootstrap_dso.clone();
    assert!(
        prepare_programs_with_gate([&a.original, &b.original], [&aa, &bb], |_, _| panic!(
            "aliased DSO reached planner"
        ))
        .is_err()
    );
    let mut missing = fixture::case(1);
    missing.runtime = String::from_utf8(missing.runtime)
        .unwrap()
        .replace("program checksum", "program rle-roundtrip")
        .into_bytes();
    assert!(bind(&missing).is_err());
    let mut removed = fixture::case(1);
    let mut rows = String::from_utf8(removed.ledger)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    rows.pop();
    removed.ledger = (rows.join("\n") + "\n").into_bytes();
    assert!(bind(&removed).is_err());
}
#[test]
fn runtime_policy_is_canonical_and_fully_bound_before_planning() {
    let base = fixture::case(1);
    bind(&base).unwrap();
    let text = std::str::from_utf8(&base.runtime).unwrap();
    for (from, to) in [
        ("LI2BOOTSTRAP-POLICY 1", "LI2BOOTSTRAP-POLICY 2"),
        ("program checksum", "program subset"),
        ("/pkg/ld.so", "pkg/ld.so"),
        (
            "bootstrap /pkg/checksum.so",
            "bootstrap /pkg/../checksum.so",
        ),
        ("app-stack 6291456 65536", "app-stack 6291456 65535"),
        ("4096 4096 4097 112", "4097 4096 4097 112"),
        ("4096 4096 4097 112", "04096 4096 4097 112"),
        ("dependency /pkg/ld.so", "dependency /pkg/other.so"),
    ] {
        let mut c = fixture::case(1);
        c.runtime = text.replace(from, to).into_bytes();
        assert!(bind(&c).is_err(), "required policy mutant {from}");
    }
    let mut duplicate = fixture::case(1);
    let line = text.lines().last().unwrap();
    duplicate
        .runtime
        .extend_from_slice(format!("{line}\n").as_bytes());
    assert!(bind(&duplicate).is_err());
    assert!(
        Bound::bind(
            &base.original,
            &base.ledger,
            ContentId::of(&base.ledger),
            &base.planning,
            ContentId::of(&base.planning),
            &base.runtime,
            ContentId::of(b"wrong expected policy")
        )
        .is_err()
    );
}
#[test]
fn old_profile_outputs_remain_separate_and_keep_original_limits() {
    let a = fixture::case(1);
    let bound = bind(&a).unwrap();
    let old = prepare_disassembly_adjacent_routed_jmp(&a.original, &bound.selected).unwrap();
    assert!(old.candidate_complete());
    assert!(!old.files().contains_key("catalog.li2boot"));
    assert!(!old.files().contains_key("startup-policy.txt"));
    let original_policy = bound.selected.base.files["disassembly-policy.txt"].clone();
    assert_eq!(original_policy, a.planning);
    assert_eq!(bound.selected.base.selection.limits.new_load_pages, 128);
    assert_eq!(bound.selected.base.selection.limits.images, 64);
    assert_eq!(
        bound.selected.limits,
        disassembly::adjacent_routed_jmp::AdjacentRoutedJmpLimits {
            upper: 2,
            lower: 1,
            joint: 2
        }
    );
    let elf = boot::parse(&old.files()["candidate.elf"]).unwrap();
    assert_eq!(
        elf.segments(carrier::elf64::SegmentType::Interpreter)
            .count(),
        0
    );
    assert_eq!(
        elf.segments(carrier::elf64::SegmentType::Dynamic).count(),
        0
    );
}

#[test]
fn existing_page_cap_refusal_withholds_whole_bundle_without_retry() {
    let mut a = fixture::case(1);
    let b = fixture::case(2);
    let old = ContentId::of(&a.planning);
    a.planning = String::from_utf8(a.planning)
        .unwrap()
        .replace("262144 128 2097152", "262144 0 2097152")
        .into_bytes();
    a.runtime = String::from_utf8(a.runtime)
        .unwrap()
        .replace(
            &ledger::hex(&old.0),
            &ledger::hex(&ContentId::of(&a.planning).0),
        )
        .into_bytes();
    let aa = bind(&a).unwrap();
    let bb = bind(&b).unwrap();
    let mut seen = [0usize; 2];
    let error =
        prepare_programs_with_gate([&a.original, &b.original], [&aa, &bb], |program, stage| {
            if stage == "evidence-serialization" {
                seen[program as usize - 1] += 1;
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(seen, [1, 1]);
    assert_eq!(error.stage, "startup-whole-programs");
    assert!(
        error
            .detail
            .contains("checksum local_candidate_complete=false")
    );
    assert!(
        error
            .detail
            .contains("rle-roundtrip local_candidate_complete=true")
    );
    assert_eq!(aa.selected.base.selection.sites.len(), 16);
    assert_eq!(bb.selected.base.selection.sites.len(), 26);
}

// Rebind the exact affected identities in dependency order. No stale digest or
// malformed-region rejection may stand in for the denominator control below.
fn identity_row(bytes: &mut Vec<u8>, tag: &str, id: ContentId) {
    let text = std::str::from_utf8(bytes).unwrap();
    let prefix = format!("{tag} ");
    let mut count = 0;
    let rows = text
        .lines()
        .map(|row| {
            if row.starts_with(&prefix) {
                assert_eq!(row.split(' ').count(), 2);
                count += 1;
                format!("{tag} {}", ledger::hex(&id.0))
            } else {
                row.to_owned()
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(count, 1);
    *bytes = (rows.join("\n") + "\n").into_bytes();
}
fn coherent_rebind(case: &mut fixture::Case) {
    let original = ContentId::of(&case.original);
    identity_row(&mut case.ledger, "original", original);
    let disassembly = ContentId::of(&case.ledger);
    identity_row(&mut case.planning, "original", original);
    identity_row(&mut case.planning, "ledger", disassembly);
    let planning = ContentId::of(&case.planning);
    identity_row(&mut case.runtime, "original", original);
    identity_row(&mut case.runtime, "disassembly", disassembly);
    identity_row(&mut case.runtime, "planning-policy", planning);
}
fn replace_exact_row(bytes: &mut Vec<u8>, old: &str, new: &str) {
    let text = std::str::from_utf8(bytes).unwrap();
    assert_eq!(text.lines().filter(|&row| row == old).count(), 1);
    *bytes = (text
        .lines()
        .filter_map(|row| {
            if row == old {
                if new.is_empty() { None } else { Some(new) }
            } else {
                Some(row)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n")
        .into_bytes();
}
fn assert_denominator_refusal(case: &fixture::Case) {
    let error = bind(case).unwrap_err();
    assert_eq!(error.stage, "startup-policy");
    assert_eq!(error.detail, "\"full original denominator\"");
}
#[test]
fn coherently_rebound_head_count_only_refuses_exact_full_denominator() {
    for program in [1, 2] {
        let base = fixture::case(program);
        let checked = bind(&base).unwrap();
        let (nh, ns) = denominator(program).unwrap();
        assert_eq!(
            (
                checked.heads.len(),
                checked.selected.base.selection.sites.len()
            ),
            (nh, ns)
        );
        let mut changed = fixture::case(program);
        let at = 4096 + ns * 5;
        let pc = 0x400000 + at as u64;
        assert_eq!(&changed.original[at..at + 2], &[0x90, 0x90]);
        changed.original[at..at + 2].copy_from_slice(&[0x66, 0x90]);
        replace_exact_row(
            &mut changed.ledger,
            &format!("head {pc} 90"),
            &format!("head {pc} 6690"),
        );
        replace_exact_row(&mut changed.ledger, &format!("head {} 90", pc + 1), "");
        coherent_rebind(&mut changed);
        assert_eq!(&changed.original[..at], &base.original[..at]);
        assert_eq!(&changed.original[at + 2..], &base.original[at + 2..]);
        let imported = disassembly::import(
            &changed.original,
            &changed.ledger,
            ContentId::of(&changed.ledger),
        )
        .unwrap();
        assert_eq!(
            imported.original_heads(),
            checked
                .heads
                .iter()
                .copied()
                .filter(|&h| h != pc + 1)
                .collect::<Vec<_>>()
        );
        let selected = imported
            .bind_adjacent_routed_jmp(&changed.planning, ContentId::of(&changed.planning))
            .unwrap();
        assert_eq!(selected.base.selection.sites.len(), ns);
        assert_eq!(
            selected.base.selection.hooks[0].pc,
            checked.selected.base.selection.hooks[0].pc
        );
        let (bound_program, _, _) = parse_policy(
            &changed.runtime,
            ContentId::of(&changed.runtime),
            &changed.original,
            ContentId::of(&changed.ledger),
            ContentId::of(&changed.planning),
            &selected.base.selection,
        )
        .unwrap();
        assert_eq!(bound_program, program);
        assert_denominator_refusal(&changed);
    }
}
#[test]
fn coherently_rebound_selected_count_only_refuses_exact_full_denominator() {
    for program in [1, 2] {
        let base = fixture::case(program);
        let checked = bind(&base).unwrap();
        let (nh, ns) = denominator(program).unwrap();
        assert_eq!(
            (
                checked.heads.len(),
                checked.selected.base.selection.sites.len()
            ),
            (nh, ns)
        );
        let mut changed = fixture::case(program);
        let at = 4096 + (ns - 1) * 5;
        let pc = 0x400000 + at as u64;
        assert_eq!(changed.original[at], 0xe9);
        let old = ledger::hex(&changed.original[at..at + 5]);
        changed.original[at..at + 5].copy_from_slice(&[0xb8, 1, 0, 0, 0]);
        replace_exact_row(
            &mut changed.ledger,
            &format!("head {pc} {old}"),
            &format!("head {pc} b801000000"),
        );
        let policy = std::str::from_utf8(&changed.planning).unwrap();
        let mut removed = 0;
        let final_id = ns.to_string();
        let rows = policy
            .lines()
            .filter(|row| {
                let f = row.split(' ').collect::<Vec<_>>();
                let remove =
                    f.len() >= 2 && matches!(f[0], "search" | "allocation") && f[1] == final_id;
                if remove {
                    removed += 1;
                }
                !remove
            })
            .collect::<Vec<_>>();
        assert_eq!(removed, 3);
        changed.planning = (rows.join("\n") + "\n").into_bytes();
        coherent_rebind(&mut changed);
        assert_eq!(&changed.original[..at], &base.original[..at]);
        assert_eq!(&changed.original[at + 5..], &base.original[at + 5..]);
        let imported = disassembly::import(
            &changed.original,
            &changed.ledger,
            ContentId::of(&changed.ledger),
        )
        .unwrap();
        assert_eq!(imported.original_heads(), checked.heads);
        let selected = imported
            .bind_adjacent_routed_jmp(&changed.planning, ContentId::of(&changed.planning))
            .unwrap();
        assert_eq!(selected.base.selection.sites.len(), ns - 1);
        assert_eq!(
            selected.base.selection.hooks[0].pc,
            checked.selected.base.selection.hooks[0].pc
        );
        assert_eq!(
            selected
                .base
                .selection
                .sites
                .iter()
                .map(|s| s.id)
                .collect::<Vec<_>>(),
            (1..ns as u64).collect::<Vec<_>>()
        );
        let (bound_program, _, _) = parse_policy(
            &changed.runtime,
            ContentId::of(&changed.runtime),
            &changed.original,
            ContentId::of(&changed.ledger),
            ContentId::of(&changed.planning),
            &selected.base.selection,
        )
        .unwrap();
        assert_eq!(bound_program, program);
        assert_denominator_refusal(&changed);
    }
}

fn bind_absolute(c: &fixture::Case) -> Result<Bound, Error> {
    Bound::bind_absolute_prerequisites(
        &c.original,
        &c.ledger,
        ContentId::of(&c.ledger),
        &c.planning,
        ContentId::of(&c.planning),
        &c.runtime,
        ContentId::of(&c.runtime),
    )
}

#[test]
fn absolute_pair_uses_all_real_plans_and_the_same_original_planning_contract() {
    let a = fixture::absolute_case(1);
    let b = fixture::absolute_case(2);
    let aa = bind_absolute(&a).unwrap();
    let bb = bind_absolute(&b).unwrap();
    let products = prepare_programs([&a.original, &b.original], [&aa, &bb]).unwrap();
    for (index, (product, bound)) in products.iter().zip([&aa, &bb]).enumerate() {
        let old_case = fixture::case(index as u64 + 1);
        let old_bound = bind(&old_case).unwrap();
        assert_eq!(bound.manifest(), old_bound.manifest());
        assert_eq!(bound.selected.limits, old_bound.selected.limits);
        assert_eq!(
            bound.binding_files()["disassembly-policy.txt"],
            old_case.planning
        );
        assert_eq!(bound.profile(), ABSOLUTE_PREREQUISITES_PROFILE);
        assert!(product.candidate_complete());
        assert!(!product.qualification_complete());
        assert_eq!(product.reports().len(), [16, 26][index]);
        assert!(
            product
                .reports()
                .iter()
                .all(|r| r.candidate_emitted && r.refusal.is_none())
        );
        let files = product.files();
        let catalog = boot::Catalog::decode(&files["catalog.li2boot"]).unwrap();
        assert_eq!(
            catalog.startup_class(),
            boot::StartupClass::AbsolutePrerequisites(boot::AbsolutePrerequisites {
                libgcc_dependency: 2,
                libc_dependency: 1
            })
        );
        assert_eq!(&files["catalog.li2boot"][8..16], &3u64.to_le_bytes());
        let input = catalog.input();
        assert_eq!(
            (input.heads.len(), input.steps.len(), input.images.len()),
            ([80, 107][index], [16, 26][index], [16, 26][index])
        );
        assert_eq!(input.main, files["candidate.elf"]);
        assert_eq!(input.metadata, files["metadata.li2meta"]);
        assert_eq!(input.ledger, files["ledger.tsv"]);
        assert_eq!(input.target, files["target.tsv"]);
        assert_eq!(input.selection, bound.manifest());
        assert_eq!(catalog.encode().unwrap(), files["catalog.li2boot"]);
        assert!(catalog.routes().is_empty());
        let elf = boot::parse(&input.main).unwrap();
        assert_eq!(
            elf.header().entry,
            boot::parse(&input.original).unwrap().header().entry
        );
        let dynamic = elf
            .segments(carrier::elf64::SegmentType::Dynamic)
            .collect::<Vec<_>>();
        assert_eq!(dynamic.len(), 1);
        assert_eq!((dynamic[0].file_size, dynamic[0].memory_size), (144, 144));
        assert!(catalog.validate_startup(&elf).is_ok());
        assert!(boot::validate_startup(&elf, &input.policy).is_err());
        for (i, image) in input.images.iter().enumerate() {
            assert_eq!(image.body.bytes, files[&format!("image-{i:04}.bin")]);
        }
        let profile = std::str::from_utf8(&files["startup-profile.tsv"]).unwrap();
        assert!(profile.contains(&format!("profile\t{ABSOLUTE_PREREQUISITES_PROFILE}\n")));
        assert!(profile.contains("qualification_complete\tfalse\nexecution_authority\tnone\n"));
    }
}

#[test]
fn absolute_binding_is_explicit_and_mixed_pairs_refuse_before_any_planning() {
    let a = fixture::absolute_case(1);
    let b = fixture::case(2);
    assert!(bind(&a).is_err());
    assert!(bind_absolute(&b).is_err());
    let aa = bind_absolute(&a).unwrap();
    let bb = bind(&b).unwrap();
    assert!(
        prepare_programs_with_gate([&a.original, &b.original], [&aa, &bb], |_, _| {
            panic!("mixed startup classes reached planner")
        })
        .is_err()
    );
    assert!(
        Bound::bind_absolute_prerequisites(
            &a.original,
            &a.ledger,
            ContentId::of(&a.ledger),
            &a.planning,
            ContentId::of(&a.planning),
            &a.runtime,
            ContentId::of(b"stale policy")
        )
        .is_err()
    );
}

#[test]
fn absolute_policy_charges_the_complete_name_roster_and_rejects_unbound_roles() {
    let base = fixture::absolute_case(1);
    bind_absolute(&base).unwrap();
    let text = std::str::from_utf8(&base.runtime).unwrap();
    for (from, to) in [
        ("LI2BOOTSTRAP-POLICY 2", "LI2BOOTSTRAP-POLICY 1"),
        (boot::ABSOLUTE_PREREQUISITES_PROFILE, boot::PROFILE),
        (
            "absolute-prerequisites /pkg/libgcc.so /pkg/libc.so",
            "absolute-prerequisites /pkg/libc.so /pkg/libc.so",
        ),
        (
            "absolute-prerequisites /pkg/libgcc.so",
            "absolute-prerequisites /pkg/missing.so",
        ),
        (
            "absolute-prerequisites /pkg/libgcc.so",
            "absolute-prerequisites /pkg/ld.so",
        ),
        ("/pkg/libgcc.so", "/pkg/$LIB.so"),
        ("4096 4096 4097 144", "4096 4096 4097 112"),
        ("4096 4096 4097 144", "4096 4096 4097 145"),
        ("4096 4096 4097 144", "4096 30 4097 144"),
        ("4096 4096 4097 144", "4096 4096 30 144"),
    ] {
        assert!(text.contains(from));
        let mut changed = fixture::absolute_case(1);
        changed.runtime = text.replace(from, to).into_bytes();
        assert!(
            bind_absolute(&changed).is_err(),
            "required absolute policy mutant {from} -> {to}"
        );
    }
    let mut missing = fixture::absolute_case(1);
    missing.runtime = (text
        .lines()
        .filter(|r| !r.starts_with("dependency /pkg/libgcc.so "))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n")
        .into_bytes();
    assert!(bind_absolute(&missing).is_err());
}

#[test]
fn absolute_pair_final_refusals_still_attempt_both_and_release_no_product() {
    let a = fixture::absolute_case(1);
    let b = fixture::absolute_case(2);
    let aa = bind_absolute(&a).unwrap();
    let bb = bind_absolute(&b).unwrap();
    for stop in [
        "evidence-serialization",
        "carrier-construction",
        "sparse-serialization",
        "complete-output-serialization",
        "startup-catalog",
    ] {
        let mut first = Vec::new();
        let mut second = Vec::new();
        let result =
            prepare_programs_with_gate([&a.original, &b.original], [&aa, &bb], |program, stage| {
                if program == 1 {
                    first.push(stage);
                } else {
                    second.push(stage);
                }
                if program == 1 && stage == stop {
                    Err(Error::new("injected-absolute-boundary", stop))
                } else {
                    Ok(())
                }
            });
        assert!(result.is_err(), "required terminal boundary {stop}");
        assert_eq!(first.last(), Some(&stop));
        assert_eq!(
            second
                .iter()
                .filter(|&&s| s == "evidence-serialization")
                .count(),
            1
        );
        assert_eq!(second.last(), Some(&"startup-catalog"));
    }
}
