//! Structural controls only. Every candidate remains unqualified for execution.
use super::*;
use li2core::engine::Tactic;
use liteinst_rewrite::prepare_with_owned_neighbors;

const VICTIM: u64 = S + 64;

fn two_owners() -> (Vec<u8>, String) {
    let (mut bytes, _) = input(2, "T3");
    // A separately declared function: NOP10; MOV EAX,42; RET. The MOV is
    // selected independently; the NOP remains only an auxiliary victim.
    bytes[0x1140..0x1150].copy_from_slice(&[
        0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3,
    ]);
    let provenance = hex(&ContentId::of(b"two distinct complete function owners").0);
    let selected = S + 0x4000000;
    let victim_image = S + 0x6000000;
    let second_image = S + 0x8000000;
    let second_pc = VICTIM + 10;
    let manifest = format!(
        "LI2TOOL 1\noriginal {}\ntarget fxsave64\ndomain 1\ncarrier {}\nlimits 1048576 16 16 65536 64 1048576 262144 64 4294967296\nhook 7 {HOOK} 1 {}\nsite 1 {S} 2 4352 {S} 4 {S} 4 {S} 2 7 observe original-decode\nentries 1 complete {provenance} {S}:0 {}:0 {}:0\nresumes 1 none\nsearch 1 T3 0 80 1 {VICTIM} 64 256\nallocation 1 selected {selected} 256 8192 {}:8192\nallocation 1 victim {victim_image} 256 8192 {}:8192\nsite 2 {second_pc} 5 4426 {VICTIM} 16 {VICTIM} 16 {VICTIM} 16 7 observe original-decode\nentries 2 complete {provenance} {VICTIM}:0 {second_pc}:0 {}:0\nresumes 2 none\nsearch 2 B1 0 80 1 none 64 256\nallocation 2 selected {second_image} 256 8192 {}:8192\nallocation 2 victim {victim_image} 256 8192 {}:8192\n",
        hex(&ContentId::of(&bytes).0),
        BASE + 0x8000,
        hex(&ContentId::of(&[0xc3]).0),
        S + 2,
        S + 3,
        selected & !4095,
        victim_image & !4095,
        VICTIM + 15,
        second_image & !4095,
        victim_image & !4095,
    );
    (bytes, manifest)
}

#[test]
fn opt_in_keeps_both_selected_hooks_and_foreign_victim_is_auxiliary() {
    let (bytes, manifest) = two_owners();
    let original = bytes.clone();
    let old = prepare(&bytes, manifest.as_bytes()).unwrap();
    assert!(!old.candidate_complete());
    assert!(old.reports()[0].refusal.is_some());
    assert!(!old.files().contains_key("planning-profile.tsv"));
    let new = prepare_with_owned_neighbors(&bytes, manifest.as_bytes()).unwrap();
    assert!(new.candidate_complete(), "{:?}", new.reports());
    assert!(!new.qualification_complete());
    assert_eq!(bytes, original);
    assert_eq!(
        new.reports().iter().map(|r| r.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(new.reports()[0].core_tactic, Some(Tactic::NeighborEviction));
    assert_eq!(new.reports()[1].core_tactic, Some(Tactic::Relocation));
    assert!(
        new.reports()
            .iter()
            .all(|r| r.candidate_emitted && r.refusal.is_none())
    );
    assert_eq!(
        new.files()
            .keys()
            .filter(|name| name.starts_with("image-"))
            .count(),
        3
    );
    assert_eq!(
        new.files()["planning-profile.tsv"],
        b"LI2PLANNING\t1\nprofile\towned-foreign-neighbors-v1\nqualification_complete\tfalse\n"
    );
    assert_eq!(metadata(&new, &manifest).sites().len(), 2);
}

#[test]
fn missing_foreign_head_or_unresolved_resume_keeps_full_failed_report() {
    let (bytes, manifest) = two_owners();
    for changed in [
        manifest.replace(&format!("{VICTIM}:0 "), ""),
        manifest.replace("resumes 2 none", "resumes 2 unknown"),
        manifest.replace("entries 2 complete", "entries 2 unknown"),
    ] {
        let product = prepare_with_owned_neighbors(&bytes, changed.as_bytes()).unwrap();
        assert!(!product.candidate_complete());
        assert!(!product.qualification_complete());
        assert_eq!(product.reports().len(), 2);
        assert!(product.reports().iter().all(|r| r.refusal.is_some()));
        assert!(!product.files().contains_key("candidate.elf"));
        assert!(!product.files().contains_key("source.li2sparse"));
    }
}

#[test]
fn declared_block_must_match_the_decoded_control_flow() {
    let (bytes, manifest) = two_owners();
    let changed = manifest.replace(
        &format!("{VICTIM} 16 {VICTIM} 16 {VICTIM} 16 7 observe"),
        &format!("{VICTIM} 16 {VICTIM} 16 {} 6 7 observe", VICTIM + 10),
    );
    assert_ne!(changed, manifest);
    let product = prepare_with_owned_neighbors(&bytes, changed.as_bytes()).unwrap();
    assert!(!product.candidate_complete());
    assert_eq!(
        product.reports()[0].refusal.as_ref().unwrap().stage,
        "neighbor-declared-block"
    );
    assert_eq!(product.reports().len(), 2);
}

#[test]
fn forced_unknown_victim_and_zero_original_budget_do_not_substitute() {
    let (bytes, manifest) = two_owners();
    for changed in [
        manifest.replace(
            &format!("search 1 T3 0 80 1 {VICTIM} 64 256"),
            &format!("search 1 T3 0 80 1 {} 64 256", VICTIM + 1),
        ),
        manifest.replace(
            &format!("search 1 T3 0 80 1 {VICTIM} 64 256"),
            &format!("search 1 T3 0 80 1 {VICTIM} 0 256"),
        ),
        manifest.replace(
            &format!("search 1 T3 0 80 1 {VICTIM} 64 256"),
            &format!("search 1 T3 0 80 1 {VICTIM} 64 0"),
        ),
    ] {
        assert_ne!(changed, manifest);
        let product = prepare_with_owned_neighbors(&bytes, changed.as_bytes()).unwrap();
        assert!(!product.candidate_complete());
        assert_eq!(product.reports().len(), 2);
        assert!(product.reports()[0].refusal.is_some());
    }
}

#[test]
fn duplicate_function_declarations_must_agree_on_entry_provenance() {
    let (bytes, mut manifest) = two_owners();
    let pc = VICTIM + 15;
    let other = hex(&ContentId::of(b"conflicting entry declaration").0);
    let selected = S + 0xa000000;
    let victim = S + 0xc000000;
    manifest.push_str(&format!(
        "site 3 {pc} 1 4431 {VICTIM} 16 {VICTIM} 16 {VICTIM} 16 7 observe original-decode\nentries 3 complete {other} {VICTIM}:0 {}:0 {pc}:0\nresumes 3 none\nsearch 3 B1 0 80 1 none 64 256\nallocation 3 selected {selected} 256 8192 {}:8192\nallocation 3 victim {victim} 256 8192 {}:8192\n",
        VICTIM + 10, selected & !4095, victim & !4095,
    ));
    let product = prepare_with_owned_neighbors(&bytes, manifest.as_bytes()).unwrap();
    assert!(!product.candidate_complete());
    assert_eq!(product.reports().len(), 3);
    assert!(
        product
            .reports()
            .iter()
            .all(|report| report.refusal.as_ref().unwrap().stage == "neighbor-owner-conflict")
    );
}
