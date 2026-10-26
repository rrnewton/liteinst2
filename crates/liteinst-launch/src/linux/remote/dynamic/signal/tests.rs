//! Pure pre-launch configuration controls. No child, frame, signal disposition,
//! mapping permission, publication or native cleanup is exercised here.
use super::*;
use std::collections::BTreeSet;

const IMAGE: u64 = 0x401000;
const DELIVERY: u64 = 0x401080;
const HANDLER: u64 = 0x402000;
const RESTORER: u64 = 0x403000;
const LANDING: u64 = 0x405000;
const NORMAL: u64 = 0x700000;
const ALTERNATE: u64 = 0x800000;
const LIFETIME: usize = 64 * 1024 * 1024;

fn profile() -> DynamicSignalProfile {
    DynamicSignalProfile {
        signal: 44,
        action_mask: 1 << 14,
        queued_value: 0x13579bdf2468ace0,
        handler: HANDLER,
        restorer: RESTORER,
        delivery_pc: DELIVERY,
        normal_stack: NORMAL..NORMAL + 0x10000,
        alternate_stack: None,
        frame_edits: None,
    }
}

fn edits() -> DynamicSignalFrameEdits {
    DynamicSignalFrameEdits {
        landing_pc: LANDING,
        rax: (-22_i64) as u64,
        clear_carry: true,
        signal_mask: 1 << 9,
        xmm0: [0x9d; 16],
    }
}

fn facts() -> Vec<ImageFacts> {
    // Synthetic source bytes and declared heads only: this does not assert a
    // complete native instruction census or substitute for RuntimeScan.
    let mut bytes = vec![0x90; 0x5000];
    for (pc, encoding) in [
        (DELIVERY, &[0xeb, 0xfe][..]),
        (HANDLER, &[0x0f, 0xa2][..]),
        (RESTORER, &[0xb8, 15, 0, 0, 0, 0x0f, 0x05][..]),
        (LANDING, &[0x0f, 0xa2][..]),
    ] {
        let offset = (pc - IMAGE) as usize;
        bytes[offset..offset + encoding.len()].copy_from_slice(encoding);
    }
    vec![ImageFacts {
        start: IMAGE,
        bytes,
        heads: BTreeSet::from([DELIVERY, HANDLER, RESTORER, RESTORER + 5, LANDING]),
    }]
}

fn refuses(value: &DynamicSignalProfile, sources: &[ImageFacts]) {
    assert!(
        value
            .validate(&DynamicAdmissionOptions::default(), sources)
            .is_err()
    );
}

#[test]
fn closed_profiles_accept_ordinary_alternate_and_declared_edit_configuration() {
    let sources = facts();
    let options = DynamicAdmissionOptions::default();
    assert_eq!(options.lifecycle.creation, DynamicCreationPolicy::Refuse);
    assert_eq!(options.lifecycle.max_tasks, 1);
    assert_eq!(options.limits.source_fact_bytes, LIFETIME);
    for alternate in [false, true] {
        for edited in [false, true] {
            for signal in [34, 44, 64] {
                let mut value = profile();
                value.signal = signal;
                value.alternate_stack = alternate.then_some(ALTERNATE..ALTERNATE + 0x10000);
                value.frame_edits = edited.then(edits);
                value.validate(&options, &sources).unwrap();
            }
        }
    }
}

#[test]
fn signal_profile_never_enables_a_non_singleton_lifecycle() {
    let value = profile();
    let sources = facts();
    for creation in [
        DynamicCreationPolicy::Refuse,
        DynamicCreationPolicy::Fork,
        DynamicCreationPolicy::ThreadClone,
    ] {
        for max_tasks in [0, 1, 2, 3, usize::MAX] {
            let options = DynamicAdmissionOptions {
                lifecycle: DynamicLifecycleOptions {
                    creation,
                    max_tasks,
                },
                ..DynamicAdmissionOptions::default()
            };
            assert_eq!(
                value.validate(&options, &sources).is_ok(),
                creation == DynamicCreationPolicy::Refuse && max_tasks == 1,
                "creation={creation:?}, max_tasks={max_tasks}"
            );
        }
    }
}

#[test]
fn only_application_rt_signals_and_blockable_masks_are_accepted() {
    let sources = facts();
    for signal in [0, 1, 9, 19, 31, 32, 33, 65, u8::MAX] {
        let mut value = profile();
        value.signal = signal;
        refuses(&value, &sources);
    }
    // Native SIGKILL=9 and SIGSTOP=19 are literal UAPI bit positions here.
    for bit in [8, 18] {
        let mut value = profile();
        value.action_mask |= 1_u64 << bit;
        refuses(&value, &sources);
        value = profile();
        let mut changed = edits();
        changed.signal_mask |= 1_u64 << bit;
        value.frame_edits = Some(changed);
        refuses(&value, &sources);
    }
    let mut value = profile();
    value.action_mask = !(1_u64 << 8) & !(1_u64 << 18);
    let mut changed = edits();
    changed.signal_mask = value.action_mask;
    value.frame_edits = Some(changed);
    value
        .validate(&DynamicAdmissionOptions::default(), &sources)
        .unwrap();
}

#[test]
fn declared_stack_ranges_are_bounded_aligned_disjoint_and_canonical() {
    let sources = facts();
    let invalid = [
        0..0x10000,
        std::ops::Range {
            start: NORMAL,
            end: NORMAL,
        },
        std::ops::Range {
            start: NORMAL + 0x10000,
            end: NORMAL,
        },
        NORMAL + 1..NORMAL + 0x10000,
        NORMAL..NORMAL + 0x10001,
        NORMAL..NORMAL + 0x3000,
        NORMAL..NORMAL + 0x101000,
        (1_u64 << 47) - 0x10000..(1_u64 << 47),
        u64::MAX - 0xffff..u64::MAX,
    ];
    for range in invalid {
        let mut value = profile();
        value.normal_stack = range.clone();
        refuses(&value, &sources);
        value = profile();
        value.alternate_stack = Some(range);
        refuses(&value, &sources);
    }
    for range in [
        NORMAL..NORMAL + 0x10000,
        NORMAL - 0x1000..NORMAL + 0x3000,
        NORMAL + 0xf000..NORMAL + 0x13000,
    ] {
        let mut value = profile();
        value.alternate_stack = Some(range);
        refuses(&value, &sources);
    }
    for range in [
        NORMAL - 0x4000..NORMAL,
        NORMAL + 0x10000..NORMAL + 0x14000,
        ALTERNATE..ALTERNATE + 0x100000,
        (1_u64 << 47) - 0x5000..(1_u64 << 47) - 0x1000,
    ] {
        let mut value = profile();
        value.alternate_stack = Some(range);
        value
            .validate(&DynamicAdmissionOptions::default(), &sources)
            .unwrap();
    }
}

#[test]
fn source_overlap_and_overflow_cannot_be_hidden_by_valid_primary_heads() {
    for alternate in [false, true] {
        let mut value = profile();
        if alternate {
            value.alternate_stack = Some(0x400000..0x410000);
        } else {
            value.normal_stack = 0x400000..0x410000;
        }
        refuses(&value, &facts());
    }
    let mut sources = facts();
    sources.push(ImageFacts {
        start: u64::MAX - 7,
        bytes: vec![0x90; 16],
        heads: BTreeSet::new(),
    });
    refuses(&profile(), &sources);
    let mut sources = facts();
    sources.push(ImageFacts {
        start: NORMAL + 0xf000,
        bytes: vec![0x90; 0x2000],
        heads: BTreeSet::new(),
    });
    refuses(&profile(), &sources);
}

#[test]
fn every_original_role_needs_one_distinct_declared_head() {
    for head in [DELIVERY, HANDLER, RESTORER, RESTORER + 5] {
        let mut sources = facts();
        assert!(sources[0].heads.remove(&head));
        refuses(&profile(), &sources);
        let mut sources = facts();
        let mut duplicate = sources[0].clone();
        duplicate.heads = BTreeSet::from([head]);
        sources.push(duplicate);
        refuses(&profile(), &sources);
    }
    for role in 0..3 {
        for pc in [0, DELIVERY, HANDLER, RESTORER, LANDING + 1] {
            let mut value = profile();
            let original = [value.delivery_pc, value.handler, value.restorer][role];
            if pc == original {
                continue;
            }
            match role {
                0 => value.delivery_pc = pc,
                1 => value.handler = pc,
                _ => value.restorer = pc,
            }
            refuses(&value, &facts());
        }
    }
}

#[test]
fn fixed_handler_loop_and_restorer_encodings_are_exact() {
    for (pc, length) in [(HANDLER, 2), (DELIVERY, 2), (RESTORER, 7)] {
        for index in 0..length {
            let mut sources = facts();
            sources[0].bytes[(pc - IMAGE) as usize + index] ^= 1;
            refuses(&profile(), &sources);
        }
    }
    let separate = || {
        vec![
            ImageFacts {
                start: DELIVERY,
                bytes: vec![0xeb, 0xfe],
                heads: BTreeSet::from([DELIVERY]),
            },
            ImageFacts {
                start: HANDLER,
                bytes: vec![0x0f, 0xa2],
                heads: BTreeSet::from([HANDLER]),
            },
            ImageFacts {
                start: RESTORER,
                bytes: vec![0xb8, 15, 0, 0, 0, 0x0f, 0x05],
                heads: BTreeSet::from([RESTORER, RESTORER + 5]),
            },
        ]
    };
    profile()
        .validate(&DynamicAdmissionOptions::default(), &separate())
        .unwrap();
    for index in 0..3 {
        let mut sources = separate();
        sources[index].bytes.pop();
        refuses(&profile(), &sources);
    }
}

#[test]
fn fixed_encoding_and_unique_head_must_belong_to_the_same_source_fact() {
    for pc in [DELIVERY, HANDLER, RESTORER] {
        let mut sources = facts();
        let mut headless = sources[0].clone();
        headless.heads.clear();
        sources[0].bytes[(pc - IMAGE) as usize] ^= 1;
        sources.push(headless);
        // The head remains uniquely declared, and some overlapping bytes still
        // have the wanted opcode. Combining the two is not a valid binding.
        refuses(&profile(), &sources);
    }
}

#[test]
fn prospective_landing_needs_its_own_exact_original_head() {
    for pc in [0, DELIVERY, HANDLER, RESTORER, LANDING + 1, u64::MAX] {
        let mut value = profile();
        let mut changed = edits();
        changed.landing_pc = pc;
        value.frame_edits = Some(changed);
        refuses(&value, &facts());
    }
    let mut value = profile();
    value.frame_edits = Some(edits());
    let mut sources = facts();
    assert!(sources[0].heads.remove(&LANDING));
    refuses(&value, &sources);
    let mut sources = facts();
    let mut duplicate = sources[0].clone();
    duplicate.heads = BTreeSet::from([LANDING]);
    sources.push(duplicate);
    refuses(&value, &sources);
}

#[test]
fn prelaunch_evidence_reservation_refuses_insufficient_fixed_limits() {
    let sources = facts();
    let mut options = DynamicAdmissionOptions::default();
    assert_eq!(options.limits.source_fact_bytes, LIFETIME);
    let original = SignalBudget::new(&sources, &options).unwrap();
    assert!(original.bytes > 0 && original.bytes < LIFETIME);
    // Discover the exact accepted boundary without constructing an expectation
    // from production's internal component-size formula. Every query is pure.
    let mut refused = 0;
    let mut accepted = LIFETIME;
    while accepted - refused > 1 {
        let middle = refused + (accepted - refused) / 2;
        options.limits.source_fact_bytes = middle;
        if SignalBudget::new(&sources, &options).is_ok() {
            accepted = middle;
        } else {
            refused = middle;
        }
    }
    assert_eq!(accepted, refused + 1);
    assert!(
        accepted > original.bytes,
        "original-source evidence also consumes budget"
    );
    options.limits.source_fact_bytes = accepted;
    assert_eq!(SignalBudget::new(&sources, &options).unwrap(), original);
    options.limits.source_fact_bytes = refused;
    for _ in 0..3 {
        assert!(SignalBudget::new(&sources, &options).is_err());
        assert_eq!(options.limits.source_fact_bytes, refused);
    }
    options.limits.source_fact_bytes = accepted;
    let mut larger = facts();
    larger[0].bytes.extend_from_slice(&[0x90; 4096]);
    assert!(SignalBudget::new(&larger, &options).is_err());
    let mut more_heads = facts();
    assert!(more_heads[0].heads.insert(IMAGE + 1));
    assert!(SignalBudget::new(&more_heads, &options).is_err());
    assert_eq!(SignalBudget::new(&sources, &options).unwrap(), original);
    assert_eq!(
        DynamicAdmissionOptions::default().limits.source_fact_bytes,
        LIFETIME
    );
}
