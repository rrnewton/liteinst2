//! Pure actual-importer/binder controls; no image is mapped or executed.
use super::*;
use crate::disassembly::whole::policy::{self, Carrier, NullHook, PolicyOptions};

fn input() -> (Vec<u8>, String, Disassembly, PolicyOptions) {
    let (mut original, ledger) = fixture(&[&[0xeb, 0], &[0x75, 0], &[0xc3]]);
    let before = digest(&original);
    // A non-code memory-only LOAD ends beyond every imported code region.
    put16(&mut original, 56, 3);
    let at = 64 + 2 * 56;
    put32(&mut original, at, 1);
    put32(&mut original, at + 4, 6);
    put64(&mut original, at + 16, BASE + 0x9000);
    put64(&mut original, at + 24, BASE + 0x9000);
    put64(&mut original, at + 40, 0x3000);
    put64(&mut original, at + 48, 4096);
    let ledger = ledger.replace(&before, &digest(&original));
    let imported = checked(&original, &ledger).unwrap();
    let options = PolicyOptions {
        domain: 1,
        hook: NullHook::LowestOriginalRet,
        carrier: Carrier::AfterLoads,
        arena: addr(BASE + 0x40000, 0x40000).unwrap(),
    };
    (original, ledger, imported, options)
}

fn records(imported: &Disassembly, options: PolicyOptions) -> String {
    let mut text = String::new();
    let start = options.arena.start();
    let end = options.arena.end();
    for site in imported.jumps() {
        writeln!(text, "search {} preferred 64 256 64 none 256 4096", site.id).unwrap();
        writeln!(
            text,
            "allocation {} selected {} 1 4096 {}:8192 {start}:4096 {end}:4096",
            site.id,
            end + 4096,
            start - 4096
        )
        .unwrap();
        writeln!(
            text,
            "allocation {} victim none 1 4096 {start}:8192 {}:8192",
            site.id,
            start + 4096
        )
        .unwrap();
    }
    text
}

#[test]
fn direct_policy_joins_actual_loads_complete_heads_target_and_ordered_permits() {
    let (original, _, imported, options) = input();
    let spec = policy::spec_from_records(
        &imported,
        &original,
        options,
        b"target xsave64 7 4:576:256\n",
        records(&imported, options).as_bytes(),
    )
    .unwrap();
    let raw = policy::build_policy(&imported, &original, &spec).unwrap();
    let text = std::str::from_utf8(&raw).unwrap();
    assert!(text.contains(&format!("carrier {}\n", BASE + 0xc000)));
    assert!(text.contains(&format!("null-hook {}\n", PC + 4)));
    assert!(
        text.contains("limits 1048576 4096 2896 11862016 2936 12120064 12026544 2910 536870912\n")
    );
    let selected = imported
        .clone()
        .bind_whole_program(&raw, ContentId::of(&raw))
        .unwrap();
    assert_eq!(selected.selection.sites.len(), imported.jumps.len());
    assert_eq!(selected.selection.target, spec.target);
    assert_eq!(selected.selection.target.mask(), 7);
    for (site, source) in selected.selection.sites.iter().zip(imported.jumps()) {
        assert_eq!(
            (site.id, site.pc, usize::from(site.length), site.file_offset),
            (source.id, source.pc, source.length, source.file_offset)
        );
        assert_eq!(site.completeness, EntryCompleteness::AllInstructionHeads);
        assert_eq!(
            site.heads.iter().map(|h| h.address).collect::<Vec<_>>(),
            [PC, PC + 2, PC + 4]
        );
        let page = addr(options.arena.start(), 4096).unwrap();
        assert_eq!(site.selected_allocation.ranges, [page, page]);
        assert_eq!(
            site.selected_allocation.preferred_address,
            Some(options.arena.end() + 4096)
        );
        assert_eq!(
            site.victim_allocation.ranges,
            [
                addr(options.arena.start(), 8192).unwrap(),
                addr(options.arena.start() + 4096, 8192).unwrap()
            ]
        );
        assert_eq!(site.victim_allocation.preferred_address, None);
        assert_eq!(
            (
                site.search.max_upstream_bytes,
                site.search.max_displaced_bytes,
                site.search.max_sites,
                site.max_victims,
                site.max_pairs
            ),
            (64, 256, 64, 256, 4096)
        );
        assert_eq!(
            (
                site.selected_allocation.max_candidates,
                site.selected_allocation.max_mappings,
                site.selected_allocation.max_mapped_bytes
            ),
            (1, 1, 4096)
        );
    }
    // Lowest-C3 choice is not a replacement for the explicit original-head check.
    let mut same = spec.clone();
    same.options.hook = NullHook::Address(PC + 4);
    same.options.carrier = Carrier::Address(BASE + 0xc000);
    assert_eq!(
        policy::build_policy(&imported, &original, &same).unwrap(),
        raw
    );
}

#[test]
fn direct_policy_refuses_incomplete_or_widened_inputs_without_filtering_sites() {
    let (original, _, imported, options) = input();
    let rows = records(&imported, options);
    for bad in [
        rows.lines().skip(3).collect::<Vec<_>>().join("\n") + "\n",
        rows.replace("search 2 ", "search 1 "),
        rows.replace("preferred 64 256 64", "preferred 65 256 64"),
        rows.replace("preferred 64 256 64", "B1 64 256 64"),
        rows.replace(" 1 4096 ", " 2 4096 "),
        rows.replace("none 256 4096", "none 256 4097"),
    ] {
        assert!(
            policy::spec_from_records(
                &imported,
                &original,
                options,
                b"target fxsave64\n",
                bad.as_bytes()
            )
            .is_err()
        );
    }
    let mut swapped: Vec<_> = rows.lines().collect();
    swapped.swap(1, 2);
    assert!(
        policy::spec_from_records(
            &imported,
            &original,
            options,
            b"target fxsave64\n",
            (swapped.join("\n") + "\n").as_bytes()
        )
        .is_err()
    );
    assert!(
        policy::spec_from_records(
            &imported,
            &original,
            options,
            b"target fxsave64\ntarget fxsave64\n",
            rows.as_bytes()
        )
        .is_err()
    );
    let spec = policy::spec_from_records(
        &imported,
        &original,
        options,
        b"target fxsave64\n",
        rows.as_bytes(),
    )
    .unwrap();
    for kind in 0..5 {
        let mut bad = spec.clone();
        match kind {
            0 => {
                bad.sites.pop();
            }
            1 => bad.sites.swap(0, 1),
            2 => bad.sites[0].selected.permits = vec![addr(options.arena.end(), 4096).unwrap()],
            3 => bad.sites[0].victim.permits = vec![addr(options.arena.start() + 1, 4096).unwrap()],
            4 => bad.sites[1].victim.permits = vec![options.arena; 17],
            _ => unreachable!(),
        }
        assert!(
            policy::build_policy(&imported, &original, &bad).is_err(),
            "accepted mutation {kind}"
        );
    }
    let mut changed = original.clone();
    put16(&mut changed, 16, 3);
    assert!(
        policy::build_policy(&imported, &changed, &spec)
            .unwrap_err()
            .detail
            .contains("policy original identity")
    );
    let mut bad = spec.clone();
    bad.options.hook = NullHook::Address(PC + 1);
    assert!(policy::build_policy(&imported, &original, &bad).is_err());
    bad = spec.clone();
    bad.options.carrier = Carrier::Address(BASE + 0x9000); // non-code LOAD is still occupied.
    assert!(policy::build_policy(&imported, &original, &bad).is_err());
    bad = spec.clone();
    bad.options.arena = addr(BASE + 0xc000, 4096).unwrap(); // carrier reservation, not code.
    assert!(policy::build_policy(&imported, &original, &bad).is_err());
    assert_eq!(spec.sites.len(), 2);
    assert!(policy::build_policy(&imported, &original, &spec).is_ok());
}

#[test]
fn direct_policy_original_c3_candidate_and_shared_reservation_keep_old_checks() {
    let (original, ledger, _, options) = input();
    let mut dynamic = original.clone();
    put16(&mut dynamic, 16, 3);
    let dynamic_ledger = ledger.replace(&digest(&original), &digest(&dynamic));
    let dynamic_import = checked(&dynamic, &dynamic_ledger).unwrap();
    assert!(
        policy::spec_from_records(
            &dynamic_import,
            &dynamic,
            options,
            b"target fxsave64\n",
            records(&dynamic_import, options).as_bytes()
        )
        .unwrap_err()
        .detail
        .contains("ET_EXEC")
    );
    let (mut no_hook, ledger) = fixture(&[&[0xeb, 0], &[0xf3, 0xc3]]);
    let before = digest(&no_hook);
    no_hook[0x1f00] = 0x90;
    let ledger = ledger
        .replace(&before, &digest(&no_hook))
        .replace(&format!("head {HOOK} c3"), &format!("head {HOOK} 90"));
    let imported = checked(&no_hook, &ledger).unwrap();
    assert!(
        policy::spec_from_records(
            &imported,
            &no_hook,
            options,
            b"target fxsave64\n",
            records(&imported, options).as_bytes()
        )
        .unwrap_err()
        .detail
        .contains("no original C3 head")
    );
    for headers in [0, 1, 64, 2910, 4096, usize::MAX] {
        let predecessor = (headers as u64)
            .checked_mul(56)
            .and_then(|v| v.checked_add(128))
            .ok_or_else(|| Error::new("carrier-reservation", "overflow"))
            .and_then(crate::round_page);
        assert_eq!(crate::carrier_table_reservation(headers), predecessor);
    }
    assert_eq!(crate::carrier_table_reservation(2910).unwrap(), 163840);
}
