//! Authored byte/overlay controls over the shared writer and real core plans.
use super::*;
use li2core::composition::Composition;
use li2core::contracts::*;
use li2core::emission::{
    ArtifactEmission, ArtifactPlan, ArtifactRequest, PlanningSite, SymbolicHook, TargetProfile,
};
use li2core::planner::HookSemantics;
use li2core::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
use li2core::quiescent::{ArtifactObservationRequest, plan_artifact_observation_window_after};
use li2core::trampoline::SavedExtendedStateLayout;

const PC: u64 = 0x400000;
fn limits(steps: usize, reads: usize, bytes: usize) -> Limits {
    Limits::new(
        ReadContract {
            max_steps: steps,
            max_reads_per_step: reads,
            max_read_bytes: bytes,
        },
        ENVELOPE_BYTES,
        0,
    )
    .unwrap()
}
fn selection(original: &[u8]) -> Selection {
    Selection {
        original: ContentId::of(original),
        manifest: b"codec-only-authored-selection".to_vec(),
        target: SavedExtendedStateLayout::describe_target_fxsave64(),
        bias_domain: 7,
        carrier_pc: 0x30000000,
        limits: crate::model::Limits {
            input_bytes: 4096,
            sites: 2,
            images: 2,
            image_bytes: 8192,
            new_load_pages: 2,
            output_bytes: 65536,
            added_file_bytes: 32768,
            program_headers: 16,
            virtual_span: 0x20000000,
        },
        hooks: vec![],
        sites: vec![],
    }
}
fn real_plans() -> (Vec<u8>, Selection, Vec<(u64, ArtifactPlan)>, Composition) {
    // Two exact five-byte NOPs, followed by a repeated snapshot and a short tail.
    // The second actual planner read must include the first E9 source edit.
    let mut original = vec![0x90; 773];
    original[..10].copy_from_slice(&[0x0f, 0x1f, 0x44, 0, 0, 0x0f, 0x1f, 0x44, 0, 0]);
    let s = selection(&original);
    let identity = CodeIdentity {
        source: SourceIdentity(s.original.0),
        mapping: 7,
        generation: 1,
    };
    let scope = AddressRange::new(PC, original.len()).unwrap();
    let entries = LegalEntrySet {
        identity,
        scope,
        provenance: EntryProvenance::Declared("codec authored complete linear heads".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: vec![LegalEntry {
            address: PC,
            requires_endbr: false,
        }],
        resumes: ResumeObligation::NoneExist,
    };
    let mut composition = Composition::new(
        identity,
        vec![ExpectedBytes {
            address: PC,
            bytes: original.clone(),
        }],
    )
    .unwrap();
    let mut accepted = Vec::new();
    let mut occupied = Vec::new();
    for i in 0..2 {
        let logical = PC + i * 5;
        let allocation = AllocationPolicy {
            ranges: vec![AddressRange::new(0x01000000, 0x1f000000).unwrap()],
            preferred_address: Some(0x01000000 + i * 4096),
            max_candidates: 1,
            max_mappings: 1,
            max_mapped_bytes: 4096,
        };
        let emission = ArtifactEmission::new(
            TargetProfile::linux_x86_64_legacy_evex(s.target, 7).unwrap(),
            SymbolicHook {
                identity: 2,
                address: Some(PC + 4096),
            },
            occupied.clone(),
        );
        let pcs = [logical];
        let group = plan_artifact_observation_window_after(
            &ArtifactObservationRequest {
                artifact: ArtifactRequest {
                    site: PlanningSite {
                        identity,
                        code: &original,
                        base_address: PC,
                        function: scope,
                        block: scope,
                        logical_pc: logical,
                        entries: &entries,
                        semantics: HookSemantics::Observe,
                        allocation: &allocation,
                        search: SearchPolicy {
                            tactics: TacticPolicy::RelocationOnly,
                            max_upstream_bytes: 64,
                            max_displaced_bytes: 256,
                            max_sites: 64,
                        },
                    },
                    emission: &emission,
                },
                physical_pc: logical,
                end: logical + 5,
                observation_pcs: &pcs,
            },
            &composition,
            &[],
        )
        .unwrap();
        let plan = group.artifact().clone();
        assert_eq!(plan.source_steps().len(), 1);
        assert_eq!(plan.images().count(), 1);
        for step in plan.source_steps() {
            composition.append(step).unwrap();
            occupied.extend(step.parts().allocations.iter().map(|a| a.range));
        }
        accepted.push((i + 1, plan));
    }
    (original, s, accepted, composition)
}
fn header() -> String {
    "LI2LEDGER\t1\nqualification_complete\tfalse\n".into()
}
fn authored(reads: &[ExpectedBytes]) -> EncodedPlan {
    let mut out = PlanWriter::new(header(), Some(limits(1, reads.len(), 1024)));
    writeln!(out, "step\t7\t0\trelocation\t4096\t4096\t4096\t4101").unwrap();
    writeln!(
        out,
        "live-prerequisites-not-receipts\t7\t0\ttrue\ttrue\tfalse"
    )
    .unwrap();
    out.reads(7, 0, reads);
    writeln!(out, "semantic-write\t7\t0\t4096\te900000000").unwrap();
    out.finish().unwrap()
}
fn error(encoded: &EncodedPlan, lim: Limits) -> Error {
    LedgerView::new(&encoded.ledger, &encoded.ledger, &encoded.table, lim)
        .err()
        .expect("must refuse")
}
fn replace(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert_eq!(text.matches(from).count(), 1);
    text.replacen(from, to, 1).into_bytes()
}
fn repin_table(encoded: &EncodedPlan, table: Vec<u8>) -> EncodedPlan {
    let old = format!(
        "read-storage\t{PROFILE}\t{}\t{}",
        encoded.table.len(),
        crate::ledger::hex(&ContentId::of(&encoded.table).0)
    );
    let new = format!(
        "read-storage\t{PROFILE}\t{}\t{}",
        table.len(),
        crate::ledger::hex(&ContentId::of(&table).0)
    );
    EncodedPlan {
        ledger: replace(&encoded.ledger, &old, &new),
        table,
    }
}

#[test]
fn same_real_multi_step_plans_expand_exactly_and_replay_current_overlay() {
    let (original, s, accepted, composition) = real_plans();
    let plans: Vec<_> = accepted.iter().map(|(id, p)| (*id, p)).collect();
    let inline = crate::ledger::plans_view(&s, &plans, &composition, &[]).unwrap();
    let encoded = encode_plan(&s, &plans, &composition, &[], limits(2, 1, original.len())).unwrap();
    assert_ne!(ContentId::of(&inline), ContentId::of(&encoded.ledger));
    let view = LedgerView::new(
        &encoded.ledger,
        &encoded.ledger,
        &encoded.table,
        limits(2, 1, original.len()),
    )
    .unwrap();
    let mut expanded = Vec::new();
    let summary = view.write_inline(&mut expanded).unwrap();
    assert_eq!(expanded, inline);
    assert_eq!(summary.bytes, inline.len());
    assert_eq!(summary.sha256, ContentId::of(&inline));
    assert_eq!(
        summary.counts,
        Counts {
            steps: 2,
            reads: 2,
            references: 8
        }
    );
    assert_eq!(view.summary().unwrap(), summary);
    let mut overlay = original.clone();
    for (row, (_, plan)) in view
        .records()
        .filter_map(|r| {
            if let Record::Read(r) = r {
                Some(r)
            } else {
                None
            }
        })
        .zip(&accepted)
    {
        assert_eq!((row.address, row.ordinal, row.step), (PC, 0, 0));
        row.compare_current(&overlay).unwrap();
        for write in &plan.source_steps()[0].parts().writes {
            let at = (write.address - PC) as usize;
            overlay[at..at + write.bytes.len()].copy_from_slice(&write.bytes);
        }
    }
    assert_eq!(overlay, composition.final_bytes()[0].bytes);
    assert_ne!(
        accepted[1].1.source_steps()[0].parts().reads[0].bytes,
        original
    );
    // Final carrier rows change physical digests; read expansion is identical
    // to appending those same literal rows to the inline plan.
    let tail = b"CARRIER-EXTENSION\t1\ncandidate_sha256\tfixture-only\n";
    let mut final_ledger = encoded.ledger.clone();
    final_ledger.extend_from_slice(tail);
    let final_view = LedgerView::new(
        &encoded.ledger,
        &final_ledger,
        &encoded.table,
        limits(2, 1, original.len()),
    )
    .unwrap();
    let mut expected = inline;
    expected.extend_from_slice(tail);
    let mut actual = Vec::new();
    final_view.write_inline(&mut actual).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn repinned_stale_second_read_fails_overlay_not_only_container_hash() {
    let (original, s, accepted, composition) = real_plans();
    let plans: Vec<_> = accepted.iter().map(|(id, p)| (*id, p)).collect();
    let lim = limits(2, 1, original.len());
    let encoded = encode_plan(&s, &plans, &composition, &[], lim).unwrap();
    let checked = LedgerView::new(&encoded.ledger, &encoded.ledger, &encoded.table, lim).unwrap();
    let stale = [ExpectedBytes {
        address: PC,
        bytes: original.clone(),
    }];
    let mut replacement = PlanWriter::new("LI2LEDGER\t1\n".into(), Some(lim));
    for record in checked.records().skip(1) {
        match record {
            Record::Other(line) => writeln!(replacement, "{line}").unwrap(),
            Record::Read(read) => replacement.reads(
                read.site,
                read.step,
                if read.site == 2 {
                    &stale
                } else {
                    &accepted[0].1.source_steps()[0].parts().reads
                },
            ),
        }
    }
    let repinned = replacement.finish().unwrap();
    assert_ne!(
        ContentId::of(&repinned.ledger),
        ContentId::of(&encoded.ledger)
    );
    let view = LedgerView::new(&repinned.ledger, &repinned.ledger, &repinned.table, lim).unwrap();
    let second = view
        .records()
        .filter_map(|r| {
            if let Record::Read(r) = r {
                Some(r)
            } else {
                None
            }
        })
        .nth(1)
        .unwrap();
    second.compare_current(&original).unwrap(); // its own new digest is consistent
    let actual = &accepted[1].1.source_steps()[0].parts().reads[0].bytes;
    assert_eq!(
        second.compare_current(actual).unwrap_err(),
        fail("current read mismatch")
    );
}

#[test]
fn empty_repeated_same_address_and_short_tail_reads_keep_exact_ordinals() {
    let repeated = vec![0x3a; 513];
    let reads = [
        ExpectedBytes {
            address: 1,
            bytes: vec![],
        },
        ExpectedBytes {
            address: 2,
            bytes: repeated.clone(),
        },
        ExpectedBytes {
            address: 1000,
            bytes: repeated.clone(),
        },
        ExpectedBytes {
            address: 2,
            bytes: vec![0x7b; 513],
        },
    ];
    let encoded = authored(&reads);
    let view = LedgerView::new(
        &encoded.ledger,
        &encoded.ledger,
        &encoded.table,
        limits(1, 4, 1024),
    )
    .unwrap();
    let rows: Vec<_> = view
        .records()
        .filter_map(|r| {
            if let Record::Read(r) = r {
                Some(r)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(rows.len(), 4);
    for (i, (r, expected)) in rows.iter().zip(&reads).enumerate() {
        assert_eq!(
            (r.site, r.step, r.ordinal, r.address, r.len),
            (7, 0, i, expected.address, expected.bytes.len())
        );
        r.compare_current(&expected.bytes).unwrap();
    }
    assert_eq!(rows[0].sha256, ContentId::of(&[]));
    assert_eq!(rows[1].ids, rows[2].ids);
    assert_eq!(
        rows[1].chunks().map(<[u8]>::len).collect::<Vec<_>>(),
        [256, 256, 1]
    );
    assert_ne!(rows[1].ids, rows[3].ids);
    let mut inline = PlanWriter::new(header(), None);
    writeln!(inline, "step\t7\t0\trelocation\t4096\t4096\t4096\t4101").unwrap();
    writeln!(
        inline,
        "live-prerequisites-not-receipts\t7\t0\ttrue\ttrue\tfalse"
    )
    .unwrap();
    inline.reads(7, 0, &reads);
    writeln!(inline, "semantic-write\t7\t0\t4096\te900000000").unwrap();
    let expected = inline.finish().unwrap().ledger;
    let mut got = Vec::new();
    view.write_inline(&mut got).unwrap();
    assert_eq!(got, expected);
    let empty = authored(&[]);
    let empty_view =
        LedgerView::new(&empty.ledger, &empty.ledger, &empty.table, limits(1, 0, 0)).unwrap();
    assert_eq!(
        empty_view.summary().unwrap().counts,
        Counts {
            steps: 1,
            reads: 0,
            references: 0
        }
    );
    let s = selection(&[]);
    let c = Composition::new(
        CodeIdentity {
            source: SourceIdentity(s.original.0),
            mapping: 7,
            generation: 1,
        },
        vec![],
    )
    .unwrap();
    let encoded = encode_plan(&s, &[], &c, &[], limits(0, 0, 0)).unwrap();
    let view = LedgerView::new(
        &encoded.ledger,
        &encoded.ledger,
        &encoded.table,
        limits(0, 0, 0),
    )
    .unwrap();
    assert_eq!(view.summary().unwrap().counts, Counts::default());
}

#[test]
fn table_identity_canonical_ids_reference_order_and_lengths_are_checked() {
    let reads = [ExpectedBytes {
        address: 4096,
        bytes: vec![0x11; 257],
    }];
    let e = authored(&reads);
    let lim = limits(1, 1, 1024);
    let bad_table = replace(&e.table, "chunk\t1\t1\t11", "chunk\t1\t1\t22");
    let unpinned = EncodedPlan {
        ledger: e.ledger.clone(),
        table: bad_table.clone(),
    };
    assert_eq!(error(&unpinned, lim), fail("table identity"));
    let repinned = repin_table(&e, bad_table);
    assert_eq!(error(&repinned, lim), fail("read digest"));
    let ordinal = EncodedPlan {
        ledger: replace(
            &e.ledger,
            "step-read-ref\t7\t0\t0\t",
            "step-read-ref\t7\t0\t1\t",
        ),
        table: e.table.clone(),
    };
    assert_eq!(error(&ordinal, lim), fail("read order"));
    let ids = EncodedPlan {
        ledger: replace(&e.ledger, "\t0,1\n", "\t1,0\n"),
        table: e.table.clone(),
    };
    assert_eq!(error(&ids, lim), fail("chunk first-encounter order"));
    let tail = EncodedPlan {
        ledger: replace(&e.ledger, "\t0,1\n", "\t0,0\n"),
        table: e.table.clone(),
    };
    assert_eq!(error(&tail, lim), fail("read chunk tail"));
    let excessive = EncodedPlan {
        ledger: replace(&e.ledger, "\t0,1\n", "\t0,0,0\n"),
        table: e.table.clone(),
    };
    assert_eq!(error(&excessive, lim), fail("read reference count"));
    let omitted = EncodedPlan {
        ledger: replace(&e.ledger, "step-reads\t7\t0\t1\n", "step-reads\t7\t0\t2\n"),
        table: e.table.clone(),
    };
    assert_eq!(
        error(&omitted, limits(1, 2, 1024)),
        fail("read declaration/count")
    );
    let noncanonical = repin_table(&e, replace(&e.table, "chunk\t1\t1\t11", "chunk\t01\t1\t11"));
    assert_eq!(error(&noncanonical, lim), fail("noncanonical number"));
    let extra = repin_table(
        &e,
        replace(
            &e.table,
            "LI2READ-CHUNKS\t1\t256\t2",
            "LI2READ-CHUNKS\t1\t256\t3",
        ),
    );
    assert_eq!(error(&extra, lim), fail("table count"));
    let mut final_ledger = e.ledger.clone();
    final_ledger.push(b'x');
    assert_eq!(
        LedgerView::new(&e.ledger, &final_ledger, &e.table, lim)
            .err()
            .unwrap(),
        fail("line envelope")
    );
    let mut bad = e.ledger.clone();
    bad[0] = b'X';
    assert_eq!(
        LedgerView::new(&e.ledger, &bad, &e.table, lim)
            .err()
            .unwrap(),
        fail("physical plan prefix")
    );

    let mut unused = String::from_utf8(replace(
        &e.table,
        "LI2READ-CHUNKS\t1\t256\t2",
        "LI2READ-CHUNKS\t1\t256\t3",
    ))
    .unwrap();
    unused.push_str("chunk\t2\t1\tff\n");
    assert_eq!(
        error(&repin_table(&e, unused.into_bytes()), lim),
        fail("unreferenced chunk")
    );
    let mut duplicate = String::from_utf8(replace(
        &e.table,
        "LI2READ-CHUNKS\t1\t256\t2",
        "LI2READ-CHUNKS\t1\t256\t3",
    ))
    .unwrap();
    duplicate.push_str(&format!("chunk\t2\t256\t{}\n", "11".repeat(256)));
    assert_eq!(
        error(&repin_table(&e, duplicate.into_bytes()), lim),
        fail("duplicate chunk bytes")
    );
    let read_line = std::str::from_utf8(&e.ledger)
        .unwrap()
        .lines()
        .find(|l| l.starts_with("step-read-ref\t"))
        .unwrap()
        .to_owned()
        + "\n";
    let missing = EncodedPlan {
        ledger: replace(&e.ledger, &read_line, ""),
        table: e.table.clone(),
    };
    assert_eq!(error(&missing, lim), fail("read declaration/count"));
    let repeated = EncodedPlan {
        ledger: replace(&e.ledger, &read_line, &read_line.repeat(2)),
        table: e.table.clone(),
    };
    assert_eq!(error(&repeated, lim), fail("read declaration/count"));
    let overflow = EncodedPlan {
        ledger: replace(
            &e.ledger,
            "\t4096\t257\t",
            &format!("\t{}\t257\t", u64::MAX),
        ),
        table: e.table.clone(),
    };
    assert_eq!(error(&overflow, lim), fail("read length/address"));
    let competing = EncodedPlan {
        ledger: replace(&e.ledger, "LI2LEDGER\t2\n", "LI2LEDGER\t3\n"),
        table: b"also corrupt\n".to_vec(),
    };
    assert_eq!(error(&competing, lim), fail("ledger version"));
    let table_version = repin_table(
        &e,
        replace(
            &e.table,
            "LI2READ-CHUNKS\t1\t256\t2",
            "LI2READ-CHUNKS\t2\t256\t2",
        ),
    );
    assert_eq!(error(&table_version, lim), fail("table version"));
}

#[test]
fn shared_extensions_preserve_grouped_and_fixed_canonical_records() {
    let (original, s, accepted, composition) = real_plans();
    let plans: Vec<_> = accepted.iter().map(|(id, p)| (*id, p)).collect();
    let lim = limits(2, 1, original.len());
    let associations = b"GROUP-ASSOCIATIONS\t1\nfixture-only\tno-native-authority\n";
    let mut inline =
        crate::ledger::grouped_plans(&s, &plans, &composition, &[], associations).unwrap();
    let mut encoded = encode_plan(&s, &plans, &composition, &[], lim).unwrap();
    crate::ledger::append_entry_veneers(&mut encoded.ledger, &plans).unwrap();
    encoded.ledger =
        crate::ledger::apply_grouped_associations(encoded.ledger, associations, 2).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity(s.original.0),
        mapping: 7,
        generation: 1,
    };
    let binding = li2core::emission::FixedImageBinding::zero_bias(identity, 7).unwrap();
    crate::ledger::fixed_binding(&mut inline, binding);
    crate::ledger::fixed_binding(&mut encoded.ledger, binding);
    lim.check_storage_lengths(
        encoded.ledger.len(),
        encoded.ledger.len(),
        encoded.table.len(),
    )
    .unwrap();
    let view = LedgerView::new(&encoded.ledger, &encoded.ledger, &encoded.table, lim).unwrap();
    let mut expanded = Vec::new();
    view.write_inline(&mut expanded).unwrap();
    assert_eq!(expanded, inline);
    assert_eq!(view.summary().unwrap().sha256, ContentId::of(&inline));
    assert_eq!(
        crate::ledger::apply_grouped_associations(b"LI2LEDGER\t1\n".to_vec(), associations, 3)
            .unwrap_err()
            .stage,
        "grouped-ledger"
    );
}

#[test]
fn advertised_work_and_aggregate_staging_refuse_without_expansion_allocation() {
    assert_eq!(
        Limits::new(
            ReadContract {
                max_steps: usize::MAX,
                max_reads_per_step: 2,
                max_read_bytes: 256
            },
            ENVELOPE_BYTES,
            0
        )
        .unwrap_err(),
        fail("size overflow")
    );
    let lim = limits(1, 1, 1024);
    assert_eq!(
        lim.check_storage_lengths(MEMBER_BYTES + 1, 0, 0)
            .unwrap_err(),
        fail("member byte limit")
    );
    assert_eq!(
        lim.check_storage_lengths(MEMBER_BYTES, MEMBER_BYTES, 1)
            .unwrap_err(),
        fail("encoding envelope")
    );
    let staging = Limits::new(
        ReadContract {
            max_steps: 1,
            max_reads_per_step: 1,
            max_read_bytes: 1024,
        },
        ENVELOPE_BYTES,
        1,
    )
    .unwrap();
    assert_eq!(
        staging
            .check_storage_lengths(MEMBER_BYTES, MEMBER_BYTES, 0)
            .unwrap_err(),
        fail("encoding envelope")
    );
    let reads = [ExpectedBytes {
        address: 4096,
        bytes: vec![0x11; 257],
    }];
    let e = authored(&reads);
    let oversized = EncodedPlan {
        ledger: replace(
            &e.ledger,
            "\t4096\t257\t",
            &format!("\t4096\t{}\t", usize::MAX),
        ),
        table: e.table.clone(),
    };
    assert_eq!(error(&oversized, lim), fail("read length/address"));
    let small = Limits::new(
        ReadContract {
            max_steps: 1,
            max_reads_per_step: 1,
            max_read_bytes: 1024,
        },
        1,
        0,
    )
    .unwrap();
    assert_eq!(error(&e, small), fail("working byte limit"));
    // A predeclared zero read budget refuses the actual read, not a subset.
    assert_eq!(error(&e, limits(1, 0, 1024)), fail("unique chunk limit"));
}

#[test]
fn first_codec_error_is_retained_but_existing_semantic_error_still_wins() {
    // The declaration write exhausts working bytes before the actual one-byte
    // read violates the zero-byte read contract. The first codec error survives.
    let oversized = [ExpectedBytes {
        address: PC,
        bytes: vec![0x90],
    }];
    let tiny = Limits::new(
        ReadContract {
            max_steps: 1,
            max_reads_per_step: 1,
            max_read_bytes: 0,
        },
        1,
        0,
    )
    .unwrap();
    let mut writer = PlanWriter::new(header(), Some(tiny));
    writer.reads(7, 0, &oversized);
    assert_eq!(writer.finish().unwrap_err(), fail("working byte limit"));

    // Deferred format errors never skip or outrank the old semantic checks.
    // Real image fields retain domain7 while the caller ledger requests domain8.
    let (original, mut s, accepted, composition) = real_plans();
    assert!(
        accepted[0]
            .1
            .images()
            .next()
            .unwrap()
            .metadata()
            .fields()
            .iter()
            .any(|f| f.bias_domain == 7)
    );
    s.bias_domain = 8;
    let plans: Vec<_> = accepted.iter().map(|(id, p)| (*id, p)).collect();
    let tiny = Limits::new(
        ReadContract {
            max_steps: 2,
            max_reads_per_step: 1,
            max_read_bytes: original.len(),
        },
        1,
        0,
    )
    .unwrap();
    let expected = Error::new("field", "producer arithmetic/domain mismatch");
    assert_eq!(
        crate::ledger::plans_view(&s, &plans, &composition, &[]).unwrap_err(),
        expected
    );
    assert_eq!(
        encode_plan(&s, &plans, &composition, &[], tiny).unwrap_err(),
        expected
    );
}
